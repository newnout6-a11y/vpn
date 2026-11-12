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
