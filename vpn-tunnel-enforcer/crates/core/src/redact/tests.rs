//! Redaction tests: storage spec §7.8 vectors (B4 / B6), IP pseudonyms.
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::json as j;

use super::*;

fn random_key(rng: &mut fastrand::Rng, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.u8(..)).collect()
}

/// AT-01-011: the B4 fail-open gaps (research D-4) are closed.
#[test]
fn closes_the_fail_open_gaps() {
    let out = text(r#"{"type":"shadowsocks","password":"S3cretPw-FAKE"}"#);
    assert!(!out.contains("S3cretPw"), "{out}");
    assert_eq!(
        out,
        r#"{"type":"shadowsocks","password":"<redacted-credential>"}"#
    );
    assert!(serde_json::from_str::<Value>(&out).is_ok(), "stays JSON");

    let plus_key = format!("+{}=", "A1b2C3d4E5".repeat(5).get(..42).unwrap_or_default());
    assert_eq!(plus_key.len(), 44);
    let out = text(&format!("key {plus_key} end")).into_owned();
    assert_eq!(out, "key <redacted-key> end");
    let slash_key = format!("/{}", &plus_key[1..]);
    assert_eq!(text(&format!("pk:{slash_key}")), "pk:<redacted-key>");

    let control = format!("{}=", "Zz9".repeat(15).get(..43).unwrap_or_default());
    assert_eq!(text(&format!("k {control}")), "k <redacted-key>");

    for uuid in [
        "1ef3a5c2-7b1d-6e00-8f00-0123456789ab", // v6
        "0190f1d2-3c4b-7a8e-9f00-0123456789ab", // v7
        "0190f1d2-3c4b-8a8e-bf00-0123456789ab", // v8
    ] {
        let out = text(&format!(r#"{{"uuid":"{uuid}"}}"#)).into_owned();
        assert!(!out.contains(uuid), "{out}");
        let out = text(&format!("bad id {uuid} in handshake")).into_owned();
        assert_eq!(out, "bad id <redacted-uuid> in handshake");
        let out = text(&format!("vless://{uuid}@node.example.test:443?type=tcp#n")).into_owned();
        assert_eq!(out, "<redacted-vpn-uri>");
    }
}

/// AT-01-011 (review): more gaps of the B4 kind are closed.
#[test]
fn closes_the_review_gaps() {
    // `?value` in a tracing field prints a JSON string with escaped quotes.
    let out = text(r#"body "{\"type\":\"ss\",\"password\":\"S3cret Pw\"}""#);
    assert!(!out.contains("S3cret") && !out.contains("Pw"), "{out}");
    assert!(
        out.contains(r#"\"password\":\"<redacted-credential>\"}"#),
        "{out}"
    );

    // A key right after `=` (the spec's boundary left `=` out; the old `\b` did not).
    let bare = "A1b2C3d4E5"
        .repeat(5)
        .get(..43)
        .unwrap_or_default()
        .to_owned();
    assert_eq!(text(&format!("key={bare}=")), "key=<redacted-key>");
    assert_eq!(text(&format!("key={bare}")), "key=<redacted-key>");
    assert_eq!(
        text(&format!("pair {bare}={bare}=")),
        "pair <redacted-key><redacted-key>=",
        "the second key lost its boundary to the first match"
    );

    // UUIDs glued to a word character.
    let uuid = "0190f1d2-3c4b-7a8e-9f00-0123456789ab";
    assert_eq!(
        text(&format!("read profile_{uuid}.json and {uuid}_tag")),
        "read profile_<redacted-uuid>.json and <redacted-uuid>_tag"
    );

    // Every share-link and deep-link scheme the importers accept.
    for link in [
        "naive+quic://user:pass@h.example:443#Q",
        "naive+https://user:pass@h.example:443#N",
        "v2raytun://import/c3ViLmV4YW1wbGUvdG9rZW4",
        "incy://add/c3ViLmV4YW1wbGUvdG9rZW4",
    ] {
        assert_eq!(
            text(&format!("got {link} ok")),
            "got <redacted-vpn-uri> ok",
            "{link}"
        );
    }
}

/// AT-00-004/005: the cause and the failure location survive, the secrets do not.
#[test]
fn subscription_error_keeps_cause_and_location() {
    let raw = concat!(
        "HTTP 403; TLS verification failed; Could not resolve host: private.example.test ",
        "token=PRIVATE-TOKEN https://sub.example.test/PRIVATE-URL\n",
        "    at refreshGroupUnlocked (serverGroups.ts:463:5)\n",
        r"    at C:\Users\PrivateUser\vpn\main.js:20:4",
    );
    let out = for_log(raw);
    for kept in [
        "HTTP 403",
        "TLS verification failed",
        "Could not resolve host:",
        "serverGroups.ts:463:5",
    ] {
        assert!(out.contains(kept), "{kept} missing in {out}");
    }
    for gone in [
        "PRIVATE-TOKEN",
        "PRIVATE-URL",
        "private.example.test",
        "PrivateUser",
    ] {
        assert!(!out.contains(gone), "{gone} leaked in {out}");
    }
}

/// AT-01-002: share links, proxy URLs and bearer tokens are removed whole.
#[test]
fn masks_links_and_tokens() {
    assert_eq!(
        text("trojan://FAKE-PASS@credential.test:443"),
        "<redacted-vpn-uri>"
    );
    assert_eq!(
        text("import sing-box://import-remote-profile?url=https%3A%2F%2Fsub.test%2Fx now"),
        "import <redacted-vpn-uri> now"
    );
    assert_eq!(
        text("Authorization: Bearer abc.DEF-123_x=="),
        "Authorization: <redacted-credential>"
    );
    assert_eq!(text("got Bearer abc.def"), "got Bearer <redacted-token>");
    assert_eq!(
        text("proxy-authorization=Basic dXNlcjpwYXNz; next"),
        "proxy-authorization=<redacted-credential>; next"
    );
    assert_eq!(text("open https://a.example/x"), "open <redacted-url>");
    assert_eq!(
        text("see http://a.b/"),
        "see http://a.b/",
        "too short to carry a secret"
    );
    assert_eq!(
        text("x-hwid: 0123ABCD client_secret='s p' access_token=t1"),
        "x-hwid: <redacted-credential> client_secret='<redacted-credential>' access_token=<redacted-credential>"
    );
    // An unencoded `'` inside a password or a user name does not end the match early.
    assert_eq!(
        text("dial trojan://pa'ss@host.test:443 failed"),
        "dial <redacted-vpn-uri> failed"
    );
    let out = text(r"open C:\Users\O'Brien\AppData\x.json failed");
    assert!(!out.contains("Brien"), "{out}");
    assert_eq!(
        text(r#"{"link":"vless://u@h.test:443?sid=ab#n","ok":true}"#),
        r#"{"link":"<redacted-vpn-uri>","ok":true}"#,
        "JSON text stays valid"
    );
}

/// AT-08-001: safe failure metadata is not mistaken for a secret.
#[test]
fn keeps_safe_metadata() {
    for clean in [
        "UPSTREAM_TCP_OK_ENGINE_EGRESS_UNCONFIRMED",
        "stage=tls code=ETIMEDOUT target=cloudflare-ip-trace",
        "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "token_count=5 tokens=3 HTTP 403 at 2026-11-11T08:00:00.000Z",
        "vpnte_base::error::AppError at serverGroups.ts:463:5",
    ] {
        assert_eq!(text(clean), clean);
        assert_eq!(for_log(clean), clean);
    }
    let mut v = j!({"stage": "tls", "code": "ETIMEDOUT", "target": "cloudflare-ip-trace",
        "count": 7, "enabled": true, "phase": "ready"});
    let before = v.clone();
    json(&mut v);
    assert_eq!(v, before);
}

/// AT-01-011: REALITY public keys are 43 chars of unpadded base64url.
#[test]
fn masks_unpadded_keys() {
    let mut rng = fastrand::Rng::with_seed(1004);
    let mut masked = 0;
    for _ in 0..1000 {
        let key = URL_SAFE_NO_PAD.encode(random_key(&mut rng, 32));
        assert_eq!(key.len(), 43);
        if text(&format!("pubkey {key}.")) == "pubkey <redacted-key>." {
            masked += 1;
        }
    }
    // The character-mix check spares ~0.1 % of random keys (no digit in 43 chars).
    assert!(masked >= 990, "{masked}");
    let word = "ConfigurationHelperForWindowsAdaptersAbcdef";
    assert_eq!(word.len(), 43);
    assert_eq!(text(word), word, "no digit: an identifier, not a key");
}

/// AT-01-011 (old property test): keys, credential assignments and user paths are scrubbed.
#[test]
fn scrubs_keys_assignments_and_paths() {
    let mut rng = fastrand::Rng::with_seed(1004);
    for _ in 0..1000 {
        let key = STANDARD.encode(random_key(&mut rng, 32));
        let n = rng.u32(1..=999_999);
        let path = format!(r"C:\Users\user{n}\private\config.json");
        let uuid = format!("123e4567-e89b-42d3-a456-{n:012}");
        for line in [
            format!("private_key={key} {uuid} {path}"),
            format!("peer {key} id {uuid} file {path}"),
        ] {
            let out = text(&line);
            assert!(!out.contains(&key), "{out}");
            assert!(!out.contains(&uuid), "{out}");
            assert!(!out.contains(&path), "{out}");
        }
    }
    let escaped = r#"{"file":"C:\\Users\\Bob\\AppData\\x.json"}"#;
    assert!(!text(escaped).contains("Bob"));
    assert!(!text("open /home/bob/.config/x failed").contains("bob"));
}

/// AT-00-005: SOCKS URLs with encoded credentials go, the adjacent reason stays.
#[test]
fn removes_socks_urls() {
    let mut rng = fastrand::Rng::with_seed(1019);
    let alphabet = ['a', 'Z', '9', ':', '@', '/', '%', 'я'];
    for _ in 0..1000 {
        let scheme = ["socks", "socks4", "socks4a", "socks5", "socks5h", "SOCKS5H"][rng.usize(..6)];
        let raw: String = (0..rng.usize(8..=32))
            .map(|_| alphabet[rng.usize(..alphabet.len())])
            .collect();
        let password: String = url::form_urlencoded::byte_serialize(raw.as_bytes()).collect();
        let uri = format!("{scheme}://private-user:{password}@[2001:db8::1]:1080");
        let out = for_log(&format!("connection failed {uri} retry pending")).into_owned();
        assert!(
            !out.contains(&password) && !out.contains("private-user"),
            "{out}"
        );
        assert!(!out.contains("2001:db8::1"), "{out}");
        assert!(out.starts_with("connection failed ") && out.ends_with(" retry pending"));
    }
}

/// AT-01-011 (old property test): complete share links go, the text around them stays.
#[test]
fn removes_complete_share_links() {
    let mut rng = fastrand::Rng::with_seed(1004);
    for _ in 0..1000 {
        let scheme = ["vless", "trojan", "ss", "vmess", "hysteria2", "tuic"][rng.usize(..6)];
        let payload: String = (0..rng.usize(1..40))
            .map(|_| char::from(rng.u8(0x21..0x7f)))
            .collect();
        let encoded: String = url::form_urlencoded::byte_serialize(payload.as_bytes()).collect();
        let uri = format!("{scheme}://{encoded}@vpn.example:443?token=secret");
        let out = text(&format!("before {uri} after")).into_owned();
        assert_eq!(out, "before <redacted-vpn-uri> after");
    }
}

/// AT-01-011 (old property test): values under secret keys never come back.
#[test]
fn json_masks_secret_keys_whatever_the_value() {
    let mut rng = fastrand::Rng::with_seed(1004);
    for _ in 0..1000 {
        let key = [
            "uuid",
            "password",
            "token",
            "client_secret",
            "private_key",
            "short-id",
        ][rng.usize(..6)];
        let secret: String = (0..rng.usize(8..=128))
            .map(|_| rng.alphanumeric())
            .collect();
        let mut v = j!({"safeCounter": 7, "nested": {key: secret}});
        json(&mut v);
        let out = v.to_string();
        assert!(!out.contains(&secret) && out.contains(REDACTED), "{out}");
        assert!(out.contains(r#""safeCounter":7"#));
    }
    let mut v = j!({"server": "203.0.113.7", "server_port": 443, "ID": 5, "pbk": "k",
        "vpnte_xray": {"outbounds": []}, "headers": {"Host": "x"}, "name": "token=abc",
        "users": [{"user": "u-FAKE", "pass": "p-FAKE"}], "username": "n-FAKE"});
    json(&mut v);
    assert_eq!(
        v,
        j!({"server": REDACTED, "server_port": REDACTED, "ID": REDACTED, "pbk": REDACTED,
            "vpnte_xray": REDACTED, "headers": REDACTED, "name": "token=<redacted-credential>",
            "users": [{"user": REDACTED, "pass": REDACTED}], "username": REDACTED})
    );
    assert!(is_secret_field("api_key") && is_secret_field("sid"));
    assert!(!is_secret_field("id") && !is_secret_field("server") && !is_secret_field("insider"));
}

/// AT-01-002 (§7.8 topology): public addresses become stable pseudonyms, private ones stay.
#[test]
fn pseudonymizes_public_addresses() {
    let line = "adapter 192.0.2.44 saw mac aa:bb:cc:dd:ee:ff via 203.0.113.10:443";
    let out = for_log(line);
    assert!(
        !out.contains("192.0.2.44") && !out.contains("203.0.113.10"),
        "{out}"
    );
    assert!(!out.contains("aa:bb:cc:dd:ee:ff"), "{out}");
    assert!(out.ends_with(":443"), "the port stays: {out}");
    let pseudonym = ip_pseudonym(
        "192.0.2.44"
            .parse()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    );
    assert!(
        pseudonym.starts_with("ip_") && pseudonym.len() == 11,
        "{pseudonym}"
    );
    assert!(pseudonym[3..].bytes().all(|b| b.is_ascii_hexdigit()));

    for kept in [
        "10.1.2.3",
        "172.19.0.1",
        "192.168.0.10",
        "127.0.0.1",
        "100.64.0.1",
        "169.254.1.1",
        "198.18.0.5",
        "0.0.0.0",
        "224.0.0.251",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fdfe:dcba:9876::1",
        "fc00::5",
        "ff02::fb",
        "::ffff:192.168.1.1",
    ] {
        let ip: IpAddr = kept.parse().unwrap_or(IpAddr::V4(Ipv4Addr::BROADCAST));
        assert_eq!(ip_pseudonym(ip), ip.to_canonical().to_string(), "{kept}");
    }
    for public in [
        "8.8.8.8",
        "203.0.113.10",
        "2001:db8::1",
        "2a00:1450:4010::8a",
    ] {
        let line = format!("to [{public}]:443 ok");
        assert!(for_log(&line).starts_with("to [ip_"), "{public}");
    }
    assert_eq!(
        for_log("ff02::fb and fe80::1%12 local"),
        "ff02::fb and fe80::1%12 local"
    );
    assert_eq!(
        ips("v1.2.3.4.5 build 10.0.26300.1"),
        "v1.2.3.4.5 build 10.0.26300.1"
    );
}

/// The pseudonym is HMAC-SHA256(key, octets): stable for one key, IPv4-mapped equals IPv4.
#[test]
fn pseudonym_follows_the_installed_key() {
    let key = [7u8; 32];
    set_ip_key(&key);
    let ip: IpAddr = "8.8.4.4"
        .parse()
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let mut mac = HmacSha256::new_from_slice(&key).expect("any key length");
    mac.update(&[8, 8, 4, 4]);
    let expected = format!("ip_{}", hex::encode(&mac.finalize().into_bytes()[..4]));
    assert_eq!(ip_pseudonym(ip), expected);
    let mapped: IpAddr = "::ffff:8.8.4.4".parse().unwrap_or(ip);
    assert_eq!(ip_pseudonym(mapped), expected);
    assert_ne!(ip_pseudonym("8.8.8.8".parse().unwrap_or(ip)), expected);
}
