//! Header and body vectors of the provider controls (ru-2026 items 2, 3, 22; Happ app-management
//! docs, Hiddify URL-scheme docs). Every URL is a fake.
use super::*;

fn keys(lines: &str) -> ProviderKeys {
    body_keys(lines)
}

/// Happ toggles: `true` / `1` on, any other non-blank value off, blank ignored.
#[test]
fn toggles_follow_happ() {
    for (value, want) in [
        ("1", Some(true)),
        ("true", Some(true)),
        ("TRUE", Some(true)),
        ("0", Some(false)),
        ("false", Some(false)),
        ("yes", Some(false)),
        ("", None),
    ] {
        let got = header_keys([("Hide-Settings", value)], ProviderKeys::default());
        assert_eq!(got.controls.hide_settings, want, "{value:?}");
    }
    let on = keys("#hide-settings: 1\nvless://x");
    assert!(on.controls.hides_settings());
    assert!(!Controls::default().hides_settings());
}

#[test]
fn autoconnect_and_its_pick() {
    let got = keys(
        "#subscription-autoconnect: true\n#subscription-autoconnect-type: lowestdelay\nvless://x",
    );
    assert_eq!(got.controls.autoconnect, Some(true));
    assert_eq!(
        got.controls.autoconnect_pick,
        Some(AutoconnectPick::LowestDelay)
    );
    for (value, want) in [
        ("lastused", Some(AutoconnectPick::LastUsed)),
        ("LowestDelay", Some(AutoconnectPick::LowestDelay)),
        ("random", Some(AutoconnectPick::Random)),
        ("fastest", None),
    ] {
        let got = header_keys(
            [("subscription-autoconnect-type", value)],
            ProviderKeys::default(),
        );
        assert_eq!(got.controls.autoconnect_pick, want, "{value}");
    }
    let json = serde_json::to_string(&got.controls).unwrap();
    assert_eq!(
        json,
        r#"{"autoconnect":true,"autoconnectPick":"lowestdelay"}"#
    );
}

/// Hiddify reads `//` lines as well as `#`; a `routing` key wins over a routing link line.
#[test]
fn routing_from_key_header_or_body_link() {
    let link = "happ://routing/onadd/eyJOYW1lIjoiUlUifQ==";
    let from_key = keys(&format!("//routing: {link}\nvless://x"));
    assert_eq!(from_key.controls.routing.as_deref(), Some(link));
    let from_line = keys(&format!("#profile-title: P\nvless://x\n{link}\n"));
    assert_eq!(from_line.controls.routing.as_deref(), Some(link));
    let both = keys(&format!("#routing: base64:e30=\n{link}"));
    assert_eq!(both.controls.routing.as_deref(), Some("base64:e30="));
    let header = header_keys([("routing", link)], from_line);
    assert_eq!(header.controls.routing.as_deref(), Some(link));
    let huge = format!("#routing: {}\n", "a".repeat(MAX_ROUTING_BYTES + 1));
    assert_eq!(keys(&huge).controls.routing, None);
    assert_eq!(keys("#routing: a\u{7}b\n").controls.routing, None);
}

#[test]
fn relocation_keys_are_vetted() {
    let got = keys(concat!(
        "#fallback-url: https://mirror.example/sub/TOKEN\n",
        "#new-url: \"https://new.example/sub/TOKEN\"\n",
        "#new-domain: next.example:8443\n",
        "vless://x\n"
    ));
    let r = &got.relocation;
    assert_eq!(
        r.fallback_url.as_deref(),
        Some("https://mirror.example/sub/TOKEN")
    );
    assert_eq!(r.new_url.as_deref(), Some("https://new.example/sub/TOKEN"));
    assert_eq!(r.new_domain.as_deref(), Some("next.example:8443"));
    let hiddify = header_keys(
        [("moved-permanently-to", "https://moved.example/s")],
        ProviderKeys::default(),
    );
    assert_eq!(
        hiddify.relocation.new_url.as_deref(),
        Some("https://moved.example/s")
    );
    for bad in ["ftp://x.example/s", "happ://add/x", "not a url", ""] {
        let got = header_keys([("fallback-url", bad)], ProviderKeys::default());
        assert_eq!(got.relocation.fallback_url, None, "{bad}");
    }
    for (value, want) in [
        ("next.example", Some("next.example")),
        ("next.example/", Some("next.example")),
        ("NEXT.example:443", Some("next.example:443")),
        ("https://next.example", None),
        ("next.example/sub", None),
        ("user@next.example", None),
        ("next.example?x=1", None),
    ] {
        let got = header_keys([("new-domain", value)], ProviderKeys::default());
        assert_eq!(got.relocation.new_domain.as_deref(), want, "{value}");
    }
}

/// The URLs are access tokens: `Debug` (logs, test failures) never prints them.
#[test]
fn relocation_debug_hides_the_urls() {
    let got = keys("#fallback-url: https://mirror.example/sub/SECRET-TOKEN\nvless://x");
    let text = format!("{got:?}");
    assert!(!text.contains("SECRET-TOKEN") && text.contains("fallback_url: true"));
}

/// Headers win field by field, the body fills the gaps; the last usable repeat wins.
#[test]
fn headers_over_body() {
    let body = keys("#hide-settings: 1\n#subscription-autoconnect: 1\nvless://x");
    let got = header_keys(
        [
            ("hide-settings", "0"),
            ("fallback-url", "https://a.example/s"),
            ("fallback-url", "nonsense"),
        ],
        body,
    );
    assert_eq!(got.controls.hide_settings, Some(false));
    assert_eq!(got.controls.autoconnect, Some(true));
    assert_eq!(
        got.relocation.fallback_url.as_deref(),
        Some("https://a.example/s")
    );
}

/// diag-a8: stored controls with a pick a newer build named keep everything else, `hide-settings`
/// above all, instead of failing the whole server list.
#[test]
fn unknown_stored_pick_reads_as_none() {
    let stored = r#"{"hideSettings":true,"autoconnect":true,"autoconnectPick":"fastest-ever"}"#;
    let controls: Controls = serde_json::from_str(stored).unwrap();
    assert!(controls.hides_settings());
    assert_eq!(controls.autoconnect, Some(true));
    assert_eq!(controls.autoconnect_pick, None);
    let known: Controls = serde_json::from_str(r#"{"autoconnectPick":"random"}"#).unwrap();
    assert_eq!(known.autoconnect_pick, Some(AutoconnectPick::Random));
    let round = serde_json::to_string(&known).unwrap();
    assert_eq!(serde_json::from_str::<Controls>(&round).unwrap(), known);
}

/// Item 18: Happ / limcore `fragmentation-*` keys become the provider's TLS tricks: off with
/// `enable` 0 / false, the preset where length or pause are not sent, headers over the body.
#[test]
fn fragmentation_keys_set_tls_tricks() {
    use crate::model::{HelloSplit, Span, TlsTricks};
    let tricks = |lines: &str| keys(lines).controls.tls_tricks;
    assert_eq!(
        tricks("#fragmentation-enable: 1\nvless://x"),
        Some(TlsTricks::STRONG)
    );
    assert_eq!(
        tricks("#fragmentation-enable: false\n#fragmentation-packets: tlshello\nvless://x"),
        Some(TlsTricks::Off)
    );
    let split = HelloSplit {
        len: Span::new(40, 60),
        interval_ms: Span::new(30, 50),
    };
    assert_eq!(
        tricks(
            "#fragmentation-enable: true\n#fragmentation-packets: 1-3\n#fragmentation-length: 40-60\n#fragmentation-interval: 30-50\nvless://x"
        ),
        Some(TlsTricks::Hello(split))
    );
    // No `enable`: no instruction; an unreadable range: nothing rather than a guess.
    assert_eq!(tricks("#fragmentation-packets: tlshello\nvless://x"), None);
    assert_eq!(
        tricks("#fragmentation-enable: 1\n#fragmentation-length: 200-100\nvless://x"),
        None
    );
    let body = keys("#fragmentation-packets: 1-3\nvless://x");
    let merged = header_keys([("Fragmentation-Enable", "1")], body);
    assert_eq!(
        merged.controls.tls_tricks,
        Some(TlsTricks::Hello(HelloSplit::PRESET))
    );
    // The group stores it; older groups without it load unchanged.
    let stored = serde_json::to_value(&merged.controls).expect("serialises");
    let back: Controls = serde_json::from_value(stored).expect("reads back");
    assert_eq!(back, merged.controls);
    let old: Controls =
        serde_json::from_value(serde_json::json!({ "hideSettings": true })).expect("old group");
    assert_eq!(old.tls_tricks, None);
}
