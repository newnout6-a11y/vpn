//! Stored-form compatibility of the model: records written before AmneziaWG became a kind load
//! unchanged, and AmneziaWG profiles round-trip through their stored JSON.
use serde_json::json;

use super::*;

/// A WireGuard row stored by an older build, with the AmneziaWG note it wrote then, reads back
/// as the same plain WireGuard profile and serialises to the same JSON.
#[test]
fn old_wireguard_records_load_unchanged() {
    let stored = json!({
        "name": "WG", "server": "203.0.113.7", "port": 51820,
        "kind": { "protocol": "wireguard", "private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            "local_address": ["10.8.1.2/32"], "mtu": null, "dns": [],
            "peers": [{ "host": "203.0.113.7", "port": 51820, "public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                "pre_shared_key": null, "allowed_ips": [], "keepalive_s": null, "reserved": null }] },
        "source": { "kind": "wgini" },
        "notes": [{ "note": "other", "detail": "profiles.wgIni.amneziaIncompatible" }]
    });
    let p: Profile = serde_json::from_value(stored.clone()).expect("an old record loads");
    assert!(matches!(p.kind, Kind::Wireguard(_)));
    assert_eq!(serde_json::to_value(&p).expect("serialise"), stored);
    // The note text still exists for such rows (it now says to import the key again).
    crate::test_locales::assert_localized("profiles.wgIni.amneziaIncompatible");
    crate::test_locales::assert_localized("profiles.wgIni.amneziaJunkDropped");
}

/// The stored form of an AmneziaWG profile: `protocol: amneziawg`, the WireGuard part under
/// `wg`, the parameters under `awg` (ranges as `a-b` text, unset values left out).
#[test]
fn amneziawg_stored_form() {
    let wg = WireGuard {
        private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
        local_address: vec!["10.8.1.2/32".parse().expect("net")],
        mtu: Some(1376),
        dns: vec![],
        peers: vec![],
    };
    let awg = Awg {
        generation: AwgGeneration::V3,
        jc: Some(4),
        s: [Some(12); 4],
        h: [AwgRange::parse("5-10"), None, None, None],
        timers: [AwgRange::parse("100-120"), None, None, None, None],
        random_trailers: Some(true),
        ..Awg::default()
    };
    let kind = Kind::Amneziawg {
        wg,
        awg: Box::new(awg),
    };
    let value = serde_json::to_value(&kind).expect("serialise");
    assert_eq!(value["protocol"], "amneziawg");
    assert_eq!(
        value["awg"],
        json!({ "generation": "3", "jc": 4, "s": [12, 12, 12, 12], "h": ["5-10", null, null, null],
            "timers": ["100-120", null, null, null, null], "random_trailers": true })
    );
    let back: Kind = serde_json::from_value(value).expect("deserialise");
    assert_eq!(back, kind);
    assert!(format!("{back:?}").contains("<hidden>"));
}

/// Item 18: the fragment triple of share links and provider keys, in Xray's meaning.
#[test]
fn tls_tricks_read_the_xray_fragment_triple() {
    let split = |len: (u16, u16), ms: (u16, u16)| HelloSplit {
        len: Span::new(len.0, len.1),
        interval_ms: Span::new(ms.0, ms.1),
    };
    let read = TlsTricks::from_fragment;
    assert_eq!(
        read("tlshello", Some("100-200"), Some("10-20")),
        Some(TlsTricks::STRONG)
    );
    // No pause: Xray writes the records at once, a record split only.
    assert_eq!(read("TLSHello", Some("50"), None), Some(TlsTricks::Record));
    assert_eq!(read("tlshello", None, Some("0")), Some(TlsTricks::Record));
    assert_eq!(
        read("1-3", Some("40-60"), Some("30-50")),
        Some(TlsTricks::Hello(split((40, 60), (30, 50))))
    );
    assert_eq!(
        read("1", None, Some("5")),
        Some(TlsTricks::Hello(split((100, 200), (5, 5))))
    );
    // Not the ClientHello, a zero length (Xray refuses it), garbage.
    assert_eq!(read("2-4", Some("10"), Some("5")), None);
    assert_eq!(read("tlshello", Some("0-10"), Some("5")), None);
    assert_eq!(read("tlshello", Some("200-100"), Some("5")), None);
    assert_eq!(read("hello", Some("10"), Some("5")), None);
}

/// Pasted sing-box options are the key's own tricks; the typed value wins over them.
#[test]
fn tls_tricks_lift_pasted_singbox_keys() {
    let extra = |pairs: Value| pairs.as_object().cloned().unwrap_or_default();
    let both = extra(json!({ "tls.fragment": true, "tls.record_fragment": true,
                             "tls.fragment_fallback_delay": "30ms" }));
    let lifted = TlsTricks::from_singbox(&both).expect("both keys");
    assert_eq!(
        lifted,
        TlsTricks::Both(HelloSplit {
            len: HelloSplit::PRESET.len,
            interval_ms: Span::new(30, 30)
        })
    );
    // sing-box's own 500 ms default would cost seconds per connection: the preset pause.
    let hello = extra(json!({ "tls.fragment": true }));
    assert_eq!(
        TlsTricks::from_singbox(&hello),
        Some(TlsTricks::Hello(HelloSplit::PRESET))
    );
    let off = extra(json!({ "tls.record_fragment": false }));
    assert_eq!(TlsTricks::from_singbox(&off), Some(TlsTricks::Off));
    assert_eq!(TlsTricks::from_singbox(&extra(json!({ "x": 1 }))), None);
}

/// The stored form is compact and old TLS records without the field load unchanged.
#[test]
fn tls_tricks_stored_form() {
    let tls = Tls {
        tricks: Some(TlsTricks::STRONG),
        ..Tls::default()
    };
    let stored = serde_json::to_value(&tls).expect("serialises");
    assert_eq!(
        stored["tricks"],
        json!({ "mode": "both", "len": "100-200", "intervalMs": "10-20" })
    );
    let back: Tls = serde_json::from_value(stored).expect("reads back");
    assert_eq!(back, tls);
    let old: Tls = serde_json::from_value(json!({ "server_name": "a.example" })).expect("old");
    assert_eq!(old.tricks, None);
    assert_eq!(TlsTricks::effective(None, false), TlsTricks::Off);
    assert_eq!(TlsTricks::effective(None, true), TlsTricks::STRONG);
    let own = Some(TlsTricks::Off);
    assert_eq!(TlsTricks::effective(own, true), TlsTricks::Off);
}
