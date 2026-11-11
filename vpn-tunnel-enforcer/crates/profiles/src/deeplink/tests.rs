//! Deep-link vectors (profiles spec §7.2 "happ unwrap", "happ add list", "MantaRay crypt", §7.3 P-22).
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use super::*;

fn ok(input: &str) -> Option<String> {
    unwrap_deeplink(input).unwrap_or_else(|e| panic!("{input}: {e}"))
}

fn err(input: &str) -> DeepLinkError {
    unwrap_deeplink(input).expect_err(input)
}

fn encrypted(app: &'static str, variant: &str) -> DeepLinkError {
    DeepLinkError::Encrypted {
        app,
        variant: variant.into(),
    }
}

/// The old `verify-happ-unwrap` vectors.
#[test]
fn happ_unwrap_vectors() {
    assert_eq!(
        ok("happ://add/https%3A%2F%2Fsosa.example%2Fsub%2Fabc123").as_deref(),
        Some("https://sosa.example/sub/abc123")
    );
    assert_eq!(
        ok("happ://add/https://example.com/sub/xyz").as_deref(),
        Some("https://example.com/sub/xyz")
    );
    assert_eq!(
        ok("happ://add/aHR0cHM6Ly9leGFtcGxlLmNvbS9zdWIvYWJjMTIz").as_deref(),
        Some("https://example.com/sub/abc123")
    );
    assert_eq!(
        ok("happ://add/vless%3A%2F%2Fuuid%40host%3A443").as_deref(),
        Some("vless://uuid@host:443")
    );
    assert_eq!(ok("https://example.com/sub"), None);
    assert_eq!(err("happ://crypt3/AAAA"), encrypted("Happ", "crypt3"));
    assert_eq!(err("happ://crypt5/AAAA"), encrypted("Happ", "crypt5"));
    assert_eq!(
        err("happ://routing/onadd/AAAA"),
        DeepLinkError::RoutingProfile
    );
    assert_eq!(
        err("happ://weird/something"),
        DeepLinkError::UnknownHost("happ://weird".into())
    );
}

/// K17: `happ://add/<base64 list>` yields only the first link.
#[test]
fn happ_add_list_yields_the_first_link() {
    let list = "vless://00000000-0000-4000-8000-000000000000@one.example.com:443?security=tls#One\n# comment\n\
                trojan://secret@two.example.com:443?sni=front.example.com#Two";
    let link = format!("happ://add/{}", URL_SAFE_NO_PAD.encode(list));
    assert_eq!(
        ok(&link).as_deref(),
        Some("vless://00000000-0000-4000-8000-000000000000@one.example.com:443?security=tls#One")
    );
}

/// P-22 (owner decision 10.3(A)): a JSON `{"url": …}` payload, `link` as fallback.
#[test]
fn happ_add_json_payload() {
    assert_eq!(
        ok("happ://add/eyJ1cmwiOiJodHRwczovL3N1Yi5leGFtcGxlLmNvbS9zIn0").as_deref(),
        Some("https://sub.example.com/s")
    );
    let link = format!(
        "happ://add/{}",
        STANDARD.encode(r#"{"link":"vless://u@h.example:443?security=tls#L"}"#)
    );
    assert_eq!(
        ok(&link).as_deref(),
        Some("vless://u@h.example:443?security=tls#L")
    );
    let pct = "happ://add/%7B%22url%22%3A%22https%3A%2F%2Fsub.example.com%2Fp%22%7D";
    assert_eq!(ok(pct).as_deref(), Some("https://sub.example.com/p"));
}

/// K18: encrypted links are refused, and nothing user-visible echoes the payload.
#[test]
fn encrypted_links_never_echo_the_payload() {
    let e = err("mantaray://crypt/super-secret-payload");
    assert_eq!(e, encrypted("MantaRay", "crypt"));
    let msg = e.msg();
    assert_eq!(msg.key, "profiles.deeplink.encryptedMantaray");
    let shown = format!("{e} {msg:?}");
    assert!(!shown.contains("super-secret-payload"), "{shown}");
    // New: `crypt` / `crypt2` were "unknown scheme" in the old app.
    assert_eq!(err("happ://crypt/AAAA"), encrypted("Happ", "crypt"));
    assert_eq!(err("happ://crypt2/AAAA"), encrypted("Happ", "crypt2"));
    assert_eq!(err("HAPP://CRYPT4/AAAA"), encrypted("Happ", "crypt4"));
    assert_eq!(err("happ://crypto/AAAA"), encrypted("Happ", "crypto"));
    assert_eq!(err("v2raytun://crypt/AAAA"), encrypted("v2RayTun", "crypt"));
    assert_eq!(
        err("happ://crypt4/AAAA").msg().key,
        "profiles.deeplink.encryptedHapp"
    );
    assert_eq!(
        err("v2raytun://crypt/AAAA").msg().key,
        "profiles.deeplink.encrypted"
    );
    // A payload without a `/` would be the "host": never shown.
    let e = err("happ://eyJ1cmwiOiJodHRwczovL3NlY3JldC5leGFtcGxlL3N1YiJ9");
    assert_eq!(e, DeepLinkError::UnknownHost("happ://…".into()));
}

#[test]
fn mantaray_and_plain_wrappers() {
    for host in ["add", "import", "sub", "subscription"] {
        assert_eq!(
            ok(&format!("mantaray://{host}/https%3A%2F%2Fm.example%2Fs")).as_deref(),
            Some("https://m.example/s")
        );
    }
    assert_eq!(
        err("mantaray://other/x"),
        DeepLinkError::UnknownHost("mantaray://other".into())
    );
    assert_eq!(
        err("mantaray://add/"),
        DeepLinkError::AddPayloadUnrecognised
    );
    assert_eq!(
        ok("v2raytun://import/https://v.example/sub").as_deref(),
        Some("https://v.example/sub")
    );
    let key = "vless://u@h.example:443?security=reality#V";
    assert_eq!(
        ok(&format!("incy://add/{}", STANDARD.encode(key))).as_deref(),
        Some(key)
    );
    assert_eq!(
        ok(&format!("incy://import/{}", STANDARD.encode(key))).as_deref(),
        Some(key)
    );
    assert_eq!(err("incy://crypt/x"), encrypted("INCY", "crypt"));
}

#[test]
fn payload_forms() {
    // Percent-encoded base64 padding.
    let b64 = STANDARD.encode("https://example.com/s?x=1");
    assert!(b64.ends_with('='));
    assert_eq!(
        ok(&format!("happ://add/{}", b64.replace('=', "%3D"))).as_deref(),
        Some("https://example.com/s?x=1")
    );
    // A whole key line keeps a name with spaces; a key inside text loses glued punctuation.
    let line = "vless://u@h.example:443?security=tls#Germany (1)";
    let encoded: String =
        percent_encoding::utf8_percent_encode(line, percent_encoding::NON_ALPHANUMERIC).collect();
    assert_eq!(ok(&format!("happ://add/{encoded}")).as_deref(), Some(line));
    let text = STANDARD.encode("Ваш ключ (vless://u@h.example:443#N).");
    assert_eq!(
        ok(&format!("happ://add/{text}")).as_deref(),
        Some("vless://u@h.example:443#N")
    );
    let naive = "naive+https://user:pass@n.example:443#N";
    assert_eq!(
        ok(&format!("happ://add/{}", STANDARD.encode(naive))).as_deref(),
        Some(naive)
    );
    // A URL never carries what follows its first whitespace.
    let two = STANDARD.encode("https://a.example/s\nhttps://b.example/s");
    assert_eq!(
        ok(&format!("happ://add/{two}")).as_deref(),
        Some("https://a.example/s")
    );
    // Case-insensitive scheme and host; surrounding whitespace and BOM ignored.
    assert_eq!(
        ok("\u{feff}  HAPP://ADD/https%3A%2F%2Fa.example%2Fs \n").as_deref(),
        Some("https://a.example/s")
    );
    // A malformed escape leaves the text as is (decodeURIComponent semantics).
    assert_eq!(
        ok("happ://add/https://a.example/%E0%A4%A").as_deref(),
        Some("https://a.example/%E0%A4%A")
    );
}

#[test]
fn unrecognised_payloads_are_explicit_errors() {
    assert_eq!(err("happ://add"), DeepLinkError::AddPayloadUnrecognised);
    assert_eq!(err("happ://add/"), DeepLinkError::AddPayloadUnrecognised);
    assert_eq!(
        err("happ://add/hello%20world"),
        DeepLinkError::AddPayloadUnrecognised
    );
    assert_eq!(
        err("happ://add/AAAA"),
        DeepLinkError::AddPayloadUnrecognised
    );
    assert_eq!(
        err(r#"happ://add/{"url":"ftp://x.example/s"}"#),
        DeepLinkError::AddPayloadUnrecognised
    );
}

#[test]
fn other_input_is_not_a_deep_link() {
    for input in [
        "",
        "   ",
        "vless://u@h.example:443#N",
        "https://example.com/sub",
        "happ:///x",
        "happ://add/https%3A%2F%2Fa.example\nvless://u@h.example:443",
        "hiddify://import/https://x.example/s",
        "not a link",
    ] {
        assert_eq!(ok(input), None, "{input:?}");
    }
}

/// Every error key exists in both languages and `profiles.deeplink` holds nothing else.
#[test]
fn locale_fragments_cover_every_message() {
    let deeplink = [
        DeepLinkError::Encrypted {
            app: "Happ",
            variant: "crypt4".into(),
        },
        DeepLinkError::Encrypted {
            app: "MantaRay",
            variant: "crypt".into(),
        },
        DeepLinkError::Encrypted {
            app: "v2RayTun",
            variant: "crypt".into(),
        },
        DeepLinkError::RoutingProfile,
        DeepLinkError::AddPayloadUnrecognised,
        DeepLinkError::UnknownHost("happ://weird".into()),
    ];
    let used: std::collections::BTreeSet<String> =
        deeplink.iter().map(|e| e.msg().key.into_owned()).collect();
    for key in &used {
        crate::test_locales::assert_localized(key);
    }
    let own: std::collections::BTreeSet<String> =
        crate::test_locales::package_keys("profiles-native")
            .into_iter()
            .filter(|k| k.starts_with("profiles.deeplink."))
            .collect();
    assert_eq!(used, own, "unused locale keys");
}
