//! Synthetic fixtures only: keys are generated here, wrapped with this user's DPAPI, and the
//! documents use obvious fake values. The user's real legacy dir is never read.
use std::path::Path;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use vpnte_base::{AppError, ErrorKind};

use super::*;
use crate::test_support::{TempDir, package_keys};

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).unwrap();
    bytes
}

fn key() -> ChromiumKey {
    ChromiumKey::from_bytes(random())
}

/// `b"v10" ‖ nonce[12] ‖ AES-256-GCM(plain) ‖ tag[16]`, as Electron's `safeStorage.encryptString`.
fn seal_bytes(key: &ChromiumKey, plain: &[u8]) -> Vec<u8> {
    let nonce: [u8; 12] = random();
    let cipher = Aes256Gcm::new_from_slice(key.bytes()).unwrap();
    let sealed = cipher
        .encrypt(&Nonce::<Aes256Gcm>::try_from(&nonce[..]).unwrap(), plain)
        .unwrap();
    [b"v10".as_slice(), &nonce, &sealed].concat()
}

fn seal(key: &ChromiumKey, plain: &str) -> Vec<u8> {
    seal_bytes(key, plain.as_bytes())
}

/// The old `SecretRef` envelope; `prefixed` = written since PR #21.
fn envelope(blob: &[u8], prefixed: bool) -> Value {
    let prefix = if prefixed { "enc:dpapi:v1:" } else { "" };
    json!({"__vpnteSecretRef": "vpnte-safe-storage-v1", "ciphertext": format!("{prefix}{}", B64.encode(blob))})
}

/// `CryptProtectData` for this user without entropy, as Chromium wraps its key.
fn dpapi_protect(plain: &[u8]) -> Vec<u8> {
    crate::dpapi::protect(plain, None).unwrap()
}

/// A synthetic `Local State` in `dir` holding `key` wrapped the way Chromium does.
fn local_state(dir: &TempDir, key: &ChromiumKey) {
    let wrapped = [b"DPAPI".as_slice(), &dpapi_protect(key.bytes())].concat();
    let state = json!({"os_crypt": {"audit_enabled": true, "encrypted_key": B64.encode(wrapped)}});
    dir.write("Local State", state.to_string());
}

/// Storage §7.2 "v10 layout": open, tampered tag, short blob (AT-01-001).
#[test]
fn v10_blobs_open_and_reject_tampering() {
    let key = key();
    let blob = seal(&key, "FAKE-SECRET");
    assert_eq!(open_v10(&key, &blob).unwrap(), "FAKE-SECRET");
    for i in blob.len() - 16..blob.len() {
        let mut bad = blob.clone();
        bad[i] ^= 0x01;
        assert_eq!(open_v10(&key, &bad), Err(SecretFault::Auth), "tag byte {i}");
    }
    let mut bad_nonce = blob.clone();
    bad_nonce[3] ^= 0x80;
    assert_eq!(open_v10(&key, &bad_nonce), Err(SecretFault::Auth));
    for len in 0..31 {
        assert_eq!(
            open_v10(&key, &blob[..len]),
            Err(SecretFault::Format),
            "len {len}"
        );
    }
    assert_eq!(open_v10(&self::key(), &blob), Err(SecretFault::Auth));
    assert_eq!(open_v10(&key, &blob[3..]), Err(SecretFault::Format));
    // Empty plaintext is a valid 31-byte blob.
    assert_eq!(open_v10(&key, &seal(&key, "")).unwrap(), "");
    assert_eq!(
        open_v10(&key, &seal_bytes(&key, b"\xff\xfe")),
        Err(SecretFault::Utf8)
    );
}

/// Storage §7.2 "legacy unprefixed SecretRef" opens, and so does the prefixed form (AT-01-001).
#[test]
fn envelopes_open_with_and_without_the_prefix() {
    let key = key();
    let blob = seal(&key, "vless://FAKE-UUID@vpn.test:443");
    for prefixed in [false, true] {
        let v = envelope(&blob, prefixed);
        assert_eq!(
            legacy_secret(Some(&key), Some(&v)),
            LegacyValue::Opened("vless://FAKE-UUID@vpn.test:443".into())
        );
        // Without the key the value waits; it is not lost.
        assert_eq!(legacy_secret(None, Some(&v)), LegacyValue::Locked);
    }
}

/// Storage §7.2 "test cipher": `test:` ciphertext is always refused (AT-01-010).
#[test]
fn test_cipher_is_always_refused() {
    let v = json!({"__vpnteSecretRef": "vpnte-safe-storage-v1", "ciphertext": "test:UFJJVkFURQ=="});
    let refused = LegacyValue::Invalid(SecretFault::TestCipher);
    assert_eq!(legacy_secret(Some(&key()), Some(&v)), refused);
    assert_eq!(legacy_secret(None, Some(&v)), refused);
    assert_eq!(open_ciphertext(None, "test:UFJJVkFURQ=="), refused);
}

/// Storage §7.2 "invalid base64": the old regex `^[A-Za-z0-9+/]+={0,2}$` (AT-01-010).
#[test]
fn malformed_base64_is_invalid_with_or_without_key() {
    let key = key();
    for bad in [
        "invalid!",
        "",
        "====",
        "abc===",
        "ab=c",
        "enc:dpapi:v1:",
        "djEw-_",
        " djEw",
    ] {
        let bad_encoding = LegacyValue::Invalid(SecretFault::Encoding);
        assert_eq!(open_ciphertext(Some(&key), bad), bad_encoding, "{bad:?}");
        assert_eq!(open_ciphertext(None, bad), bad_encoding, "{bad:?}");
    }
    // Node decodes unpadded base64; so do we (the old regex allowed zero `=`).
    let blob = seal(&key, "FAKE");
    let unpadded = B64.encode(&blob).trim_end_matches('=').to_owned();
    assert_eq!(
        open_ciphertext(Some(&key), &unpadded),
        LegacyValue::Opened("FAKE".into())
    );
}

/// A blob that is too short to be `v10` can never open, even once the key is back.
#[test]
fn short_v10_blob_is_invalid_not_locked() {
    let short = B64.encode(b"v10short");
    assert_eq!(
        open_ciphertext(None, &short),
        LegacyValue::Invalid(SecretFault::Format)
    );
    assert_eq!(
        open_ciphertext(Some(&key()), &short),
        LegacyValue::Invalid(SecretFault::Format)
    );
}

/// Pre-Chromium-80 blobs are bare DPAPI (inferred, never observed here; storage §2.6).
#[test]
fn bare_dpapi_blob_opens_without_the_chromium_key() {
    let blob = B64.encode(dpapi_protect("FAKE-OLD-SECRET".as_bytes()));
    assert_eq!(
        open_ciphertext(None, &blob),
        LegacyValue::Opened("FAKE-OLD-SECRET".into())
    );
    let junk = B64.encode(b"definitely not a DPAPI blob");
    // With the Chromium key DPAPI demonstrably works, so the blob itself is bad.
    assert_eq!(
        open_ciphertext(Some(&key()), &junk),
        LegacyValue::Invalid(SecretFault::Format)
    );
    assert_eq!(open_ciphertext(None, &junk), LegacyValue::Locked);
}

/// Storage §2.4 A1: decide by JSON type (envelope vs plaintext), never by `schemaVersion`.
#[test]
fn secret_positions_are_classified_by_json_type() {
    let key = key();
    assert_eq!(legacy_secret(Some(&key), None), LegacyValue::Absent);
    assert_eq!(
        legacy_secret(Some(&key), Some(&Value::Null)),
        LegacyValue::Absent
    );
    for plain in [
        json!("vless://FAKE@vpn.test:443"),
        json!([]),
        json!({"uuid": "FAKE-UUID"}),
        json!(""),
    ] {
        assert_eq!(
            legacy_secret(Some(&key), Some(&plain)),
            LegacyValue::Plain(plain.clone())
        );
    }
    // Envelope recognition is exact: tag value, non-array object, string ciphertext.
    let ct = B64.encode(seal(&key, "x"));
    for not_envelope in [
        json!({"__vpnteSecretRef": "vpnte-safe-storage-v2", "ciphertext": ct}),
        json!({"__vpnteSecretRef": "vpnte-safe-storage-v1", "ciphertext": 5}),
        json!({"__vpnteSecretRef": "vpnte-safe-storage-v1"}),
        json!([{"__vpnteSecretRef": "vpnte-safe-storage-v1", "ciphertext": ct}]),
    ] {
        assert_eq!(secret_ref_ciphertext(&not_envelope), None);
    }
    let with_extra = json!({"__vpnteSecretRef": "vpnte-safe-storage-v1", "ciphertext": ct, "x": 1});
    assert_eq!(
        legacy_secret(Some(&key), Some(&with_extra)),
        LegacyValue::Opened("x".into())
    );
}

/// Storage §7.2 "DPAPI Local State" (Windows integration test; AT-01-001): the key Chromium
/// wrapped with DPAPI comes back, and every malformed `Local State` is a distinct error.
#[test]
fn chromium_key_is_unwrapped_from_local_state() {
    let dir = TempDir::new("legacy");
    assert!(matches!(chromium_key(dir.path()), Err(KeyError::Missing)));

    let key = key();
    local_state(&dir, &key);
    let loaded = chromium_key(dir.path()).unwrap();
    assert_eq!(loaded.bytes(), key.bytes());
    assert_eq!(format!("{loaded:?}"), "ChromiumKey(..)");
    let blob = seal(&key, "FAKE-SECRET");
    assert_eq!(open_v10(&loaded, &blob).unwrap(), "FAKE-SECRET");

    let state =
        |encrypted_key: Value| json!({"os_crypt": {"encrypted_key": encrypted_key}}).to_string();
    let wrapped = dpapi_protect(key.bytes());
    let short_key = [b"DPAPI".as_slice(), &dpapi_protect(&[7; 16])].concat();
    // Expected error, as the start of its `Debug` text.
    let cases = [
        ("{not json".to_owned(), "Malformed"),
        (json!({"os_crypt": {}}).to_string(), "NoKey"),
        (state(json!(42)), "NoKey"),
        (state(json!("not base64!")), "Encoding"),
        (
            state(json!(B64.encode([b"DPAPX".as_slice(), &wrapped].concat()))),
            "Header",
        ),
        (
            state(json!(B64.encode(b"DPAPIgarbage that DPAPI cannot open"))),
            "Dpapi(",
        ),
        (state(json!(B64.encode(short_key))), "Length(16)"),
    ];
    for (text, expected) in cases {
        dir.write("Local State", &text);
        let err = chromium_key(dir.path()).unwrap_err();
        assert!(
            format!("{err:?}").starts_with(expected),
            "{err:?} for {text}"
        );
    }
}

#[test]
fn key_errors_map_to_app_errors() {
    let e: AppError = KeyError::Missing.into();
    assert_eq!(
        (e.kind, e.user_msg().key.as_ref()),
        (ErrorKind::Internal, "core.legacy.keyUnavailable")
    );
    let e: AppError = KeyError::Dpapi(windows::core::Error::empty()).into();
    assert_eq!(e.kind, ErrorKind::Permission);
    let e: AppError = KeyError::Header.into();
    assert_eq!(e.kind, ErrorKind::Validation);
    let e: AppError = SecretFault::Auth.into();
    assert_eq!(e.user_msg().key, "core.legacy.secretUnreadable");
}

/// Storage §7.3: settings / server-picker at absent, 0, 1, 2; groups at absent, 0; one newer is
/// skipped; malformed versions are invalid (AT-00-006).
#[test]
fn schema_versions_are_admitted_like_the_old_app() {
    for store in ["settings", "server-picker"] {
        let doc = LegacyDoc::from_value(store, json!({})).unwrap();
        assert_eq!((doc.store(), doc.version()), (store, 0));
        for version in [json!(0), json!(1), json!(2), json!(2.0), json!(-0.0)] {
            let doc = LegacyDoc::from_value(store, json!({"schemaVersion": version})).unwrap();
            assert!(doc.version() <= 2, "{store} {version}");
        }
        let err = LegacyDoc::from_value(store, json!({"schemaVersion": 3})).unwrap_err();
        assert!(
            matches!(
                err,
                DocError::Newer {
                    found: 3,
                    supported: 2
                }
            ),
            "{err:?}"
        );
        assert_eq!(err.reason(), "newer");
    }
    assert!(LegacyDoc::from_value("server-groups", json!({"schemaVersion": 0})).is_ok());
    let err = LegacyDoc::from_value("server-groups", json!({"schemaVersion": 1})).unwrap_err();
    assert_eq!(err.reason(), "newer");
    assert_eq!(
        LegacyDoc::from_value("live-server-checks", json!({"schemaVersion": 1}))
            .unwrap()
            .version(),
        1
    );

    for bad in [
        json!(null),
        json!("2"),
        json!(-1),
        json!(0.5),
        json!({"secret": "x"}),
        json!(9_007_199_254_740_992u64),
    ] {
        let err = LegacyDoc::from_value("settings", json!({"schemaVersion": bad})).unwrap_err();
        assert!(matches!(err, DocError::InvalidVersion), "{bad}: {err:?}");
        assert_eq!(err.reason(), "invalid");
    }
    for not_object in [json!([]), json!("settings"), json!(null), json!(2)] {
        assert!(matches!(
            LegacyDoc::from_value("settings", not_object),
            Err(DocError::Corrupt)
        ));
    }
    assert!(matches!(
        LegacyDoc::from_value("widget-layout", json!({})),
        Err(DocError::Unregistered(_))
    ));
}

/// Storage §7.2 "encrypted backup envelope": recognised and never imported (AT-01-001).
#[test]
fn encrypted_backups_are_recognised_and_refused() {
    let backup =
        json!({"__vpnteEncryptedBackup": 1, "contents": envelope(&seal(&key(), "{}"), false)});
    assert!(is_encrypted_backup(&backup));
    assert!(!is_encrypted_backup(&json!({"settings": {}})));
    let err = LegacyDoc::from_value("settings", backup).unwrap_err();
    assert_eq!(err.reason(), "backup");
}

#[test]
fn doc_errors_map_to_app_errors() {
    let e: AppError = DocError::Newer {
        found: 3,
        supported: 2,
    }
    .into();
    assert_eq!(
        (e.kind, e.user_msg().key.as_ref()),
        (ErrorKind::Conflict, "core.legacy.fileNewer")
    );
    let e: AppError = DocError::Io(std::io::ErrorKind::PermissionDenied.into()).into();
    assert_eq!(
        (e.kind, e.user_msg().key.as_ref()),
        (ErrorKind::Permission, "core.legacy.fileUnreadable")
    );
    let e: AppError = DocError::Corrupt.into();
    assert_eq!(
        (e.kind, e.user_msg().key.as_ref()),
        (ErrorKind::Validation, "core.legacy.fileInvalid")
    );
    let e: AppError = DocError::Unregistered("x".into()).into();
    assert_eq!(e.kind, ErrorKind::Internal);
}

/// Storage §7.3 fixtures (`storeMigrations.test.ts:36-45` with placeholders), plaintext form.
fn plaintext_fixtures() -> [(&'static str, Value); 3] {
    [
        (
            "settings",
            json!({"settings": {
                "proxyOverride": "http://user:FAKE-PASS@127.0.0.1:8080",
                "directVpnInput": "vless://FAKE-INPUT@vpn.test:443",
                "directVpnCachedInput": "vless://FAKE-INPUT@vpn.test:443",
                "directVpnCachedSource": "FAKE-SOURCE",
                "directVpnCachedProfiles": [{"name": "Fixture", "outbound": {"type": "vless", "uuid": "FAKE-UUID"}}]
            }, "schemaVersion": 0, "extension": {"preserve": [1, 2]}}),
        ),
        (
            "server-picker",
            json!({"activeProfileId": "p1", "profiles": [{
                "id": "p1", "name": "Fixture", "protocol": "vless", "server": "vpn.test", "port": 443,
                "outbound": {"type": "vless", "uuid": "FAKE-UUID", "server": "vpn.test"},
                "sourceUri": "vless://FAKE-UUID@vpn.test:443"
            }], "extension": {"preserve": [1, 2]}}),
        ),
        (
            "server-groups",
            json!({"groups": [{"id": "g1", "name": "Fixture", "source": "subscription",
                "sourceUrl": "https://subscription.test/FAKE-TOKEN"}], "extension": {"preserve": [1, 2]}}),
        ),
    ]
}

/// The same documents as the encrypting builds wrote them: one envelope per secret field, JSON
/// text for `directVpnCachedProfiles` / `outbound`, the WHOLE group object as one envelope.
fn encrypt_fixture(store: &str, plain: &Value, key: &ChromiumKey, prefixed: bool) -> Value {
    let wrap = |v: &Value| {
        let text = v.as_str().map_or_else(|| v.to_string(), str::to_owned);
        envelope(&seal(key, &text), prefixed)
    };
    let mut doc = plain.clone();
    let mut wrap_at = |pointer: &str| {
        let slot = doc.pointer_mut(pointer).unwrap();
        *slot = wrap(slot);
    };
    match store {
        "settings" => {
            for field in [
                "proxyOverride",
                "directVpnInput",
                "directVpnCachedInput",
                "directVpnCachedSource",
                "directVpnCachedProfiles",
            ] {
                wrap_at(&format!("/settings/{field}"));
            }
        }
        "server-picker" => {
            wrap_at("/profiles/0/outbound");
            wrap_at("/profiles/0/sourceUri");
        }
        _ => wrap_at("/groups/0"),
    }
    doc
}

fn contains_envelope(v: &Value) -> bool {
    secret_ref_ciphertext(v).is_some()
        || match v {
            Value::Object(map) => map.values().any(contains_envelope),
            Value::Array(items) => items.iter().any(contains_envelope),
            _ => false,
        }
}

/// Storage §7.3: each fixture opens with SecretRef values (prefixed and bare) and passes through
/// with plaintext values; unknown keys (`extension`) are left as they are (AT-00-006, AT-01-001).
#[test]
fn store_shapes_open_to_the_plaintext_documents() {
    let key = key();
    for (store, plain) in plaintext_fixtures() {
        let as_plain = LegacyDoc::from_value(store, plain.clone())
            .unwrap()
            .open(Some(&key));
        assert_eq!(as_plain.value, plain, "{store} plaintext passes through");
        assert_eq!(
            (
                as_plain.opened,
                as_plain.locked.len(),
                as_plain.invalid.len()
            ),
            (0, 0, 0)
        );

        for prefixed in [false, true] {
            let stored = encrypt_fixture(store, &plain, &key, prefixed);
            assert!(contains_envelope(&stored));
            let doc = LegacyDoc::from_value(store, stored.clone()).unwrap();
            let opened = doc.open(Some(&key));
            assert_eq!(opened.value, plain, "{store} prefixed={prefixed}");
            assert!(!contains_envelope(&opened.value));
            assert!(opened.locked.is_empty() && opened.invalid.is_empty());
            let expected = match store {
                "settings" => 5,
                "server-picker" => 2,
                _ => 1,
            };
            assert_eq!(opened.opened, expected, "{store}");
            // Opening works on a copy: the admitted document keeps its envelopes.
            assert_eq!(doc.raw(), &stored);
        }
    }
}

/// Storage §6.6: without the key every secret is kept as "locked" (the key import can be retried
/// later); with a wrong key nothing can ever open.
#[test]
fn secrets_without_the_key_are_marked_locked() {
    let key = key();
    for (store, plain) in plaintext_fixtures() {
        let doc = LegacyDoc::from_value(store, encrypt_fixture(store, &plain, &key, true)).unwrap();
        let opened = doc.open(None);
        assert_eq!(opened.opened, 0);
        assert!(opened.invalid.is_empty());
        let expected: &[&str] = match store {
            "settings" => &[
                "/settings/proxyOverride",
                "/settings/directVpnInput",
                "/settings/directVpnCachedInput",
                "/settings/directVpnCachedSource",
                "/settings/directVpnCachedProfiles",
            ],
            "server-picker" => &["/profiles/0/outbound", "/profiles/0/sourceUri"],
            _ => &["/groups/0"],
        };
        assert_eq!(opened.locked, expected, "{store}");
        for pointer in expected {
            let slot = opened.value.pointer(pointer).unwrap();
            assert!(is_locked(slot), "{store} {pointer}");
            assert!(!contains_envelope(slot));
        }
        assert_eq!(opened.value["extension"], json!({"preserve": [1, 2]}));

        let wrong = doc.open(Some(&self::key()));
        assert!(wrong.locked.is_empty());
        assert_eq!(wrong.invalid.len(), expected.len());
        assert!(
            wrong
                .invalid
                .iter()
                .all(|(_, fault)| *fault == SecretFault::Auth)
        );
        for pointer in expected {
            assert_eq!(wrong.value.pointer(pointer), Some(&Value::Null));
        }
    }
    assert!(!is_locked(&json!({"__vpnteLocked": "yes"})));
    assert!(!is_locked(&json!(null)));
}

/// Secrets that can never open become `null` and are reported with their position and reason.
#[test]
fn unopenable_secrets_become_null_and_are_reported() {
    let key = key();
    let doc = json!({"profiles": [
        {"id": "p1", "outbound": {"__vpnteSecretRef": "vpnte-safe-storage-v1", "ciphertext": "test:UFJJVkFURQ=="}},
        {"id": "p2", "outbound": envelope(&seal(&key, "not json {"), true), "sourceUri": envelope(&seal(&key, "{\"a\":1}"), true)},
        {"id": "p/~3", "sourceUri": {"__vpnteSecretRef": "vpnte-safe-storage-v1", "ciphertext": "invalid!"}}
    ]});
    let opened = LegacyDoc::from_value("server-picker", doc)
        .unwrap()
        .open(Some(&key));
    assert_eq!(
        opened.invalid,
        [
            ("/profiles/0/outbound".to_owned(), SecretFault::TestCipher),
            ("/profiles/1/outbound".to_owned(), SecretFault::Json),
            ("/profiles/2/sourceUri".to_owned(), SecretFault::Encoding),
        ]
    );
    // `sourceUri` is a string position: JSON-looking text stays text.
    assert_eq!(opened.value["profiles"][1]["sourceUri"], json!("{\"a\":1}"));
    assert_eq!(opened.value["profiles"][0]["outbound"], Value::Null);
    assert_eq!(opened.value["profiles"][2]["id"], json!("p/~3"));
    assert_eq!(opened.opened, 1);
}

/// Storage §7.3 "adaptive-bypass": the bare install secret opens in both forms (AT-00-006).
#[test]
fn adaptive_install_secret_opens_with_and_without_the_prefix() {
    let key = key();
    let secret = B64.encode(random::<32>());
    assert_eq!(secret.len(), 44);
    let bare = B64.encode(seal(&key, &secret));
    let learning = json!({"v2:FAKE-NET:FAKE-PROFILE": {"mode": "tls-compatibility", "learnedAt": 1, "lastUsedAt": 2, "expiresAt": 3}});
    for stored in [format!("enc:dpapi:v1:{bare}"), bare.clone()] {
        let doc = json!({"encryptedInstallSecret": stored, "learning": learning});
        let opened = LegacyDoc::from_value("adaptive-bypass", doc)
            .unwrap()
            .open(Some(&key));
        assert_eq!(opened.value["encryptedInstallSecret"], json!(secret));
        assert_eq!(opened.value["learning"], learning);
        assert_eq!(opened.opened, 1);
    }
    let locked = LegacyDoc::from_value("adaptive-bypass", json!({"encryptedInstallSecret": bare}))
        .unwrap()
        .open(None);
    assert_eq!(locked.locked, ["/encryptedInstallSecret"]);
    // The pre-encryption plaintext secret is not ciphertext and passes through.
    let fallback = json!({"fallbackInstallSecret": secret, "learning": {}});
    let opened = LegacyDoc::from_value("adaptive-bypass", fallback.clone())
        .unwrap()
        .open(None);
    assert_eq!((opened.value, opened.opened), (fallback, 0));
    // An empty install secret meant "none" to the old app (`if (encrypted)`), not a broken one.
    let empty = json!({"encryptedInstallSecret": "", "learning": {}});
    let opened = LegacyDoc::from_value("adaptive-bypass", empty.clone())
        .unwrap()
        .open(Some(&key));
    assert_eq!(opened.value, empty);
    assert!(opened.invalid.is_empty() && opened.locked.is_empty());
    // Elsewhere a bare string is never taken for ciphertext.
    let settings = json!({"settings": {"directVpnInput": bare}});
    let opened = LegacyDoc::from_value("settings", settings.clone())
        .unwrap()
        .open(Some(&key));
    assert_eq!(opened.value, settings);
}

/// Storage §7.3: `{"groups": []}` imports as empty and needs no key (AT-00-006).
#[test]
fn empty_groups_need_no_key() {
    let opened = LegacyDoc::from_value("server-groups", json!({"groups": []}))
        .unwrap()
        .open(None);
    assert_eq!(opened.value, json!({"groups": []}));
    assert_eq!(
        (opened.opened, opened.locked.len(), opened.invalid.len()),
        (0, 0, 0)
    );
}

/// Files are read like Node read them: BOM ignored, invalid UTF-8 replaced, lone surrogate
/// escapes (a name cut inside an emoji by `JSON.stringify`) replaced instead of failing the file.
#[test]
fn documents_parse_leniently() {
    let parse = |bytes: &[u8]| LegacyDoc::parse("themes", bytes).map(|d| d.raw().clone());
    assert_eq!(
        parse(b"\xEF\xBB\xBF{\"activeThemeId\":\"builtin-dark\"}").unwrap()["activeThemeId"],
        "builtin-dark"
    );
    assert_eq!(parse(b"{\"a\":\"x\xff\"}").unwrap()["a"], "x\u{FFFD}");
    assert_eq!(parse(br#"{"a":"\ud83d"}"#).unwrap()["a"], "\u{FFFD}");
    assert_eq!(
        parse(br#"{"a":"x\udc00y\ud83d\ude00\ud83d"}"#).unwrap()["a"],
        "x\u{FFFD}y\u{1F600}\u{FFFD}"
    );
    // An escaped backslash followed by `ud800` is plain text, not an escape.
    assert_eq!(
        parse(br#"{"a":"\\ud800","b":"\ud800"}"#).unwrap()["a"],
        r"\ud800"
    );
    assert_eq!(parse(br#"{"\ud800":1}"#).unwrap()["\u{FFFD}"], 1);
    for corrupt in [&b""[..], b"{", b"{\"a\":}", b"\x00\x01", br#"{"a":"\ud800"#] {
        assert!(
            matches!(parse(corrupt), Err(DocError::Corrupt)),
            "{corrupt:?}"
        );
    }
}

/// Every file under `dir`: name, bytes and modification time.
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>, std::time::SystemTime)> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let meta = e.metadata().unwrap();
            let bytes = if meta.is_file() {
                std::fs::read(e.path()).unwrap()
            } else {
                Vec::new()
            };
            (
                e.file_name().into_string().unwrap(),
                bytes,
                meta.modified().unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

/// Storage §6.6: the legacy dir is never written, renamed or deleted; a newer file is skipped and
/// left untouched; plaintext leftovers are listed by name only (B9; AT-00-006).
#[test]
fn reading_the_legacy_dir_changes_nothing() {
    let key = key();
    let dir = TempDir::new("legacy");
    local_state(&dir, &key);
    let [(_, settings), (_, picker), (_, groups)] = plaintext_fixtures();
    let picker = encrypt_fixture("server-picker", &picker, &key, true);
    dir.write(
        "settings.json",
        serde_json::to_string_pretty(
            &json!({"settings": settings["settings"], "schemaVersion": 3}),
        )
        .unwrap(),
    );
    dir.write(
        "server-picker.json",
        serde_json::to_string_pretty(&picker).unwrap(),
    );
    // Storage §7.2 "invalid base64": a second group the old app could not have opened either.
    let mut groups = encrypt_fixture("server-groups", &groups, &key, false);
    groups["groups"]
        .as_array_mut()
        .unwrap()
        .push(json!({"__vpnteSecretRef": "vpnte-safe-storage-v1", "ciphertext": "invalid!"}));
    dir.write("server-groups.json", groups.to_string());
    dir.write("live-server-checks.json", "{ damaged");
    dir.write(
        "live-server-checks.json.bak",
        r#"{"schemaVersion": 1, "global": []}"#,
    );
    dir.write("live-server-checks.json.v0.bak", "{}");
    dir.write(
        "settings.json.bak-20260511-192925",
        r#"{"settings": {"directVpnInput": "FAKE"}}"#,
    );
    dir.write("settings.json.pre-safe-storage-v1.bak", "{}");
    dir.write("widget-layout.json", r#"{"widgetLayout": []}"#);
    std::fs::create_dir(dir.path().join("tun-runtime")).unwrap();
    let before = snapshot(dir.path());

    let legacy = LegacyDir::at(dir.path());
    assert_eq!(legacy.path(), dir.path());
    assert_eq!(
        legacy.stores_present().unwrap(),
        [
            "settings",
            "server-picker",
            "server-groups",
            "live-server-checks"
        ]
    );
    assert_eq!(
        legacy.plaintext_leftovers(),
        [
            "live-server-checks.json.bak",
            "live-server-checks.json.v0.bak",
            "settings.json.bak-20260511-192925"
        ]
    );
    let err = legacy.read("settings").unwrap_err();
    assert!(matches!(
        err,
        DocError::Newer {
            found: 3,
            supported: 2
        }
    ));
    let key = legacy.chromium_key().unwrap();
    let opened = legacy
        .read("server-picker")
        .unwrap()
        .unwrap()
        .open(Some(&key));
    assert_eq!(
        opened.value["profiles"][0]["sourceUri"],
        "vless://FAKE-UUID@vpn.test:443"
    );
    let opened = legacy
        .read("server-groups")
        .unwrap()
        .unwrap()
        .open(Some(&key));
    assert_eq!(
        opened.value["groups"][0]["sourceUrl"],
        "https://subscription.test/FAKE-TOKEN"
    );
    assert_eq!(opened.value["groups"][1], Value::Null);
    assert_eq!(
        opened.invalid,
        [("/groups/1".to_owned(), SecretFault::Encoding)]
    );
    assert!(matches!(
        legacy.read("live-server-checks"),
        Err(DocError::Corrupt)
    ));
    let backup = legacy.read_backup("live-server-checks").unwrap().unwrap();
    assert_eq!(backup.version(), 1);
    assert!(legacy.read("themes").unwrap().is_none());
    assert!(legacy.read_backup("settings").unwrap().is_none());
    assert!(matches!(
        legacy.read("widget-layout"),
        Err(DocError::Unregistered(_))
    ));

    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn a_missing_legacy_dir_is_simply_empty() {
    let dir = TempDir::new("legacy");
    let legacy = LegacyDir::at(dir.path().join("never-created"));
    assert!(legacy.stores_present().unwrap().is_empty());
    assert!(legacy.plaintext_leftovers().is_empty());
    assert!(legacy.read("settings").unwrap().is_none());
    assert!(matches!(legacy.chromium_key(), Err(KeyError::Missing)));
    assert!(!dir.path().join("never-created").exists());
    // "Nothing to import" ends the import for good, so a failed check is an error, not "absent"
    // (`<` makes Windows answer ERROR_INVALID_NAME instead of "not found").
    assert!(
        LegacyDir::at(dir.path().join("bad<name"))
            .stores_present()
            .is_err()
    );
}

#[test]
fn oversized_documents_are_refused() {
    let dir = TempDir::new("legacy");
    let file = std::fs::File::create(dir.path().join("traffic-domains.json")).unwrap();
    file.set_len(super::dir::MAX_DOC_BYTES + 1).unwrap();
    drop(file);
    let err = LegacyDir::at(dir.path())
        .read("traffic-domains")
        .unwrap_err();
    assert_eq!(err.reason(), "too-large");
}

/// The `core-legacy` fragment holds exactly the keys the error conversions return.
#[test]
fn locale_fragment_holds_the_package_keys() {
    let used = [
        AppError::from(KeyError::Missing).user_msg().key,
        AppError::from(SecretFault::Auth).user_msg().key,
        AppError::from(DocError::Corrupt).user_msg().key,
        AppError::from(DocError::Newer {
            found: 1,
            supported: 0,
        })
        .user_msg()
        .key,
        AppError::from(DocError::Io(std::io::ErrorKind::NotFound.into()))
            .user_msg()
            .key,
    ];
    let used: std::collections::BTreeSet<String> =
        used.into_iter().map(|k| k.into_owned()).collect();
    assert_eq!(package_keys("core-legacy"), used);
}

/// Contract rule 9: a stray `{:?}` in a log line must not print a key.
#[test]
fn debug_output_never_shows_secrets() {
    let key = key();
    let [(store, plain), ..] = plaintext_fixtures();
    let doc = LegacyDoc::from_value(store, encrypt_fixture(store, &plain, &key, true)).unwrap();
    let opened = doc.open(Some(&key));
    let plain_doc = LegacyDoc::from_value(store, plain).unwrap();
    let value = legacy_secret(Some(&key), opened.value.pointer("/settings/directVpnInput"));
    let shown = format!(
        "{doc:?} {opened:?} {plain_doc:?} {value:?} {:?}",
        open_ciphertext(Some(&key), &B64.encode(seal(&key, "FAKE-INPUT")))
    );
    assert!(!shown.contains("FAKE"), "{shown}");
    assert!(
        shown.contains("Opened(10 bytes)") && shown.contains("Plain(..)"),
        "{shown}"
    );
}

/// Storage §7.3: every fixture opens at every version the old app wrote for it, plaintext or
/// encrypted (the version says nothing about encryption); `{settings: null}` is admitted as is
/// (AT-00-006).
#[test]
fn fixtures_open_at_every_supported_version() {
    let key = key();
    for (store, plain) in plaintext_fixtures() {
        let versions: &[Option<u64>] = if store == "server-groups" {
            &[None, Some(0)]
        } else {
            &[None, Some(0), Some(1), Some(2)]
        };
        for version in versions {
            let mut plain = plain.clone();
            match version {
                Some(v) => plain["schemaVersion"] = json!(v),
                None => {
                    plain.as_object_mut().unwrap().remove("schemaVersion");
                }
            }
            for stored in [plain.clone(), encrypt_fixture(store, &plain, &key, true)] {
                let doc = LegacyDoc::from_value(store, stored).unwrap();
                assert_eq!(doc.version(), version.unwrap_or(0));
                assert_eq!(doc.open(Some(&key)).value, plain, "{store} {version:?}");
            }
        }
    }
    let null_settings = json!({"settings": null, "schemaVersion": 2});
    let doc = LegacyDoc::from_value("settings", null_settings.clone()).unwrap();
    assert_eq!(doc.open(None).value, null_settings);
}
