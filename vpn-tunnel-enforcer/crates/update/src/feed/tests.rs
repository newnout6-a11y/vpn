use super::*;
use crate::test_support::{TestKey, sample_feed};

fn signed(key: &TestKey, seq: u64) -> (Vec<u8>, String) {
    let bytes = serde_json::to_vec_pretty(&sample_feed(seq)).unwrap();
    let sig = key.sign(&bytes);
    (bytes, sig)
}

/// AT-11-010: a feed signed by a trusted key verifies and parses; the same bytes with one byte
/// changed, another key's signature or no keys at all are refused by the one check every reader
/// (network check, install, elevated pin check, helper service) runs.
#[test]
fn only_a_trusted_signature_over_the_exact_bytes_verifies() {
    let (key, other) = (TestKey::new(), TestKey::new());
    let (bytes, sig) = signed(&key, 7);
    let feed = verify(&bytes, &sig, &[other.public(), key.public()]).unwrap();
    assert_eq!(feed.seq, 7);
    assert_eq!(
        feed.engine("xray")
            .map(|e| e.version.to_string())
            .as_deref(),
        Some("26.11.20")
    );

    let mut changed = bytes.clone();
    let at = changed.iter().position(|&b| b == b'7').unwrap();
    changed[at] = b'8';
    assert_eq!(
        verify(&changed, &sig, &[key.public()]),
        Err(FeedError::Signature)
    );
    assert_eq!(
        verify(&bytes, &sig, &[other.public()]),
        Err(FeedError::Signature)
    );
    assert_eq!(
        verify(&bytes, "not a signature", &[key.public()]),
        Err(FeedError::Signature)
    );
    assert_eq!(verify(&bytes, &sig, &[]), Err(FeedError::NoKeys));
}

/// A signed feed of a newer layout says "too old", not "broken"; signed garbage is a format
/// error.
#[test]
fn schema_and_format_are_checked_after_the_signature() {
    let key = TestKey::new();
    let mut value = serde_json::to_value(sample_feed(1)).unwrap();
    value["schema"] = 2.into();
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        verify(&bytes, &key.sign(&bytes), &[key.public()]),
        Err(FeedError::Schema(2))
    );
    let junk = b"{\"schema\": 1}".to_vec();
    assert!(matches!(
        verify(&junk, &key.sign(&junk), &[key.public()]),
        Err(FeedError::Format(_))
    ));
}

/// The published layout of research §4.3 reads as is (unknown fields and severities ignored).
#[test]
fn the_documented_layout_parses() {
    let text = r#"{
      "schema": 1, "seq": 42, "issued": "2026-11-12T10:00:00Z", "future": true,
      "app": { "stable": { "version": "2.0.1", "severity": "security",
          "notes": { "ru": "…", "en": "…" },
          "file": { "name": "VPN-Tunnel-Enforcer-Setup-2.0.1.exe", "size": 45000000,
                    "sha256": "ab", "urls": ["https://github.com/x"] },
          "rollback_to": "2.0.0" },
        "beta": null, "warn_below": "2.0.1" },
      "engines": [ { "id": "sing-box", "version": "1.14.5", "app": ">=2.0.0 <2.1.0",
          "severity": "urgent", "archive": { "url": "u", "size": 1, "sha256": "cd" },
          "files": [ { "path": "d/sing-box.exe", "name": "sing-box.exe", "sha256": "ef" } ] } ]
    }"#;
    let feed: Feed = serde_json::from_str(text).unwrap();
    let stable = feed.app.stable.unwrap();
    assert!(stable.severity.is_security());
    assert_eq!(
        stable.rollback_to.map(|v| v.to_string()).as_deref(),
        Some("2.0.0")
    );
    assert_eq!(feed.engines[0].severity, Severity::Normal);
    assert!(feed.service.is_none() && feed.app.beta.is_none());
}
