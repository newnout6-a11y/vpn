//! Warnings of the Xray path (`warnings`): what the translation leaves out comes back as `Msg`s
//! for the user instead of debug logs (engine-audit "silent" rows).
use serde_json::{Map, json};
use vpnte_profiles::model::{DialPrefs, Kind, Mux, NativeXray, Profile, Reality, Tls, Transport};

use super::*;
use crate::xray_config::warnings;

fn keys(p: &Profile, tls_compat: bool) -> Vec<String> {
    warnings(p, tls_compat)
        .into_iter()
        .map(|m| m.key.into_owned())
        .collect()
}

fn with_fp(fp: &str, reality_on: bool) -> Profile {
    Profile {
        tls: Some(Tls {
            server_name: Some("front.example".into()),
            fingerprint: Some(fp.into()),
            reality: reality_on.then(|| Reality {
                public_key: PBK.into(),
                ..Reality::default()
            }),
            ..Tls::default()
        }),
        ..profile(vless())
    }
}

/// Nothing to say about a clean profile; every sing-box-only option of a profile is named.
#[test]
fn dropped_profile_options() {
    let clean = Profile {
        tls: tls("front.example"),
        ..profile(vless())
    };
    assert!(warnings(&clean, false).is_empty());
    let mut extra = Map::new();
    extra.insert("tls".into(), json!({"fragment": true}));
    let mut busy = Profile {
        mux: Some(Mux {
            enabled: true,
            ..Mux::default()
        }),
        dial: DialPrefs {
            tcp_fast_open: true,
            ..DialPrefs::default()
        },
        singbox_extra: extra,
        transport: Some(Transport::Ws {
            path: "/ws".into(),
            host: None,
            max_early_data: Some(2048),
            early_data_header: Some("X-Early".into()),
        }),
        ..clean
    };
    if let Some(t) = busy.tls.as_mut() {
        t.disable_sni = true;
    }
    assert_eq!(
        keys(&busy, false),
        [
            "engine.xray.warn.mux",
            "engine.xray.warn.dial",
            "engine.xray.warn.singboxExtra",
            "engine.xray.warn.disableSni",
            "engine.xray.warn.earlyData",
        ]
    );
}

/// Stealth fragments only a TCP TLS ClientHello on sing-box: REALITY, Hysteria2 and plain
/// profiles lose nothing; a provider graph never gets it.
#[test]
fn stealth_mode() {
    let tls_vless = Profile {
        tls: tls("front.example"),
        ..profile(vless())
    };
    assert_eq!(keys(&tls_vless, true), ["engine.xray.warn.stealth"]);
    let reality_vless = Profile {
        tls: reality("yahoo.com"),
        ..profile(vless())
    };
    let hy2 = Profile {
        tls: tls("hy.example"),
        ..profile(hysteria2())
    };
    for p in [reality_vless, hy2, profile(vmess())] {
        assert!(keys(&p, true).is_empty(), "{}", p.kind.label());
    }
    let native = Profile {
        native_xray: Some(super::select::native(1)),
        ..profile(vless())
    };
    assert_eq!(keys(&native, true), ["engine.xray.warn.stealth"]);
    assert!(keys(&native, false).is_empty());
}

/// Fingerprints (ru-2026-plan §2): unknown to Xray, refused by REALITY servers, broken anywhere;
/// the accepted presets and the TLS-only refusals say nothing.
#[test]
fn fingerprint_warnings() {
    let one = |fp: &str, reality_on: bool| {
        let all = warnings(&with_fp(fp, reality_on), false);
        all.first()
            .map(|m| (m.key.to_string(), m.args[0].1.clone()))
    };
    let pair = |key: &str, fp: &str| Some((format!("engine.xray.warn.{key}"), fp.to_owned()));
    assert_eq!(
        one("chrome_120", false),
        pair("fingerprintUnknown", "chrome_120")
    );
    assert_eq!(one("Edge", true), pair("fingerprintRejected", "Edge"));
    assert_eq!(
        one("randomized", true),
        pair("fingerprintRejected", "randomized")
    );
    assert_eq!(one("360", false), pair("fingerprintBroken", "360"));
    assert_eq!(one("android", true), pair("fingerprintRejected", "android"));
    for (fp, reality_on) in [
        ("chrome", true),
        ("Safari", true),
        ("edge", false),
        ("ios", false),
    ] {
        assert_eq!(one(fp, reality_on), None, "{fp}");
    }
    // QUIC has no uTLS: a Hysteria2 fingerprint is not Xray's business.
    let mut hy2 = with_fp("360", false);
    hy2.kind = hysteria2();
    assert!(warnings(&hy2, false).is_empty());
}

/// An unknown BBR preset is dropped (Xray would refuse the whole config) and named.
#[test]
fn hysteria2_bbr_profile() {
    let mut p = profile(hysteria2());
    if let Kind::Hysteria2 { bbr_profile, .. } = &mut p.kind {
        *bbr_profile = Some("turbo".into());
    }
    let all = warnings(&p, false);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].key, "engine.xray.warn.bbrProfile");
    assert_eq!(all[0].args, [("profile".into(), "turbo".to_owned())]);
}

/// A VLESS packet encoding other than XUDP is not used by Xray; an empty one (no UDP) and
/// `xudp` lose nothing.
#[test]
fn vless_packet_encoding() {
    let with = |encoding: &str| {
        let mut p = Profile {
            tls: tls("front.example"),
            ..profile(vless())
        };
        if let Kind::Vless {
            packet_encoding, ..
        } = &mut p.kind
        {
            *packet_encoding = Some(encoding.into());
        }
        keys(&p, false)
    };
    assert_eq!(with("packetaddr"), ["engine.xray.warn.packetEncoding"]);
    assert!(with("XUDP").is_empty() && with("").is_empty());
}

/// A provider graph that combines XHTTP with mux.cool: the mux goes, and the user is told.
#[test]
fn provider_xhttp_mux() {
    let mut graph: NativeXray = super::select::native(1);
    graph.outbounds = vec![json!({"tag": "entry", "protocol": "vless",
        "settings": {"vnext": [{"address": "nl.example", "port": 443,
            "users": [{"id": UUID, "encryption": "none"}]}]},
        "mux": {"enabled": true, "concurrency": 8},
        "streamSettings": {"network": "xhttp", "security": "tls",
            "tlsSettings": {"serverName": "nl.example"}, "xhttpSettings": {"path": "/x"}}})];
    let p = Profile {
        native_xray: Some(graph),
        ..profile(vless())
    };
    assert_eq!(keys(&p, false), ["engine.xray.warn.xhttpMux"]);
    let compiled =
        crate::xray_config::proxy_graph(&p, vpnte_base::types::ClientDevice::Pc).expect("compiles");
    let text = format!(
        "{:?}",
        crate::xray_config::build_config(&compiled, &super::config::endpoint(20010))
    );
    assert!(!text.contains("concurrency"), "{text}");
}

/// Every warning has a sentence in both languages.
#[test]
fn every_warning_has_text() {
    for key in [
        "stealth",
        "xhttpMux",
        "mux",
        "dial",
        "singboxExtra",
        "disableSni",
        "fingerprintUnknown",
        "fingerprintRejected",
        "fingerprintBroken",
        "earlyData",
        "packetEncoding",
        "bbrProfile",
    ] {
        let key = format!("engine.xray.warn.{key}");
        assert!(
            !text(RU, &key).is_empty() && !text(EN, &key).is_empty(),
            "{key}"
        );
    }
    let key = "engine.xray.config.invalid";
    assert!(!text(RU, key).is_empty() && !text(EN, key).is_empty());
}
