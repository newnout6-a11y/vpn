//! TLS / REALITY translation (xray-engine spec §2.3 "TLS", "REALITY", "FP"; B2, B6) and the
//! names pinned before pre-resolution (§3.10).
use serde_json::{Value, json};
use vpnte_base::types::ClientDevice;
use vpnte_profiles::model::{Kind, Profile, Reality, Tls, Transport};
use vpnte_profiles::xray_native::NativeError;

use super::*;
use crate::xray_config::{SingBoxOnly, XrayConfigError, translate};

fn stream_of(p: &Profile, device: ClientDevice) -> Value {
    translate(p, device).expect("translates")["streamSettings"].clone()
}

fn with_tls(tls: Tls) -> Profile {
    Profile {
        tls: Some(tls),
        ..profile(trojan())
    }
}

/// B2: an insecure profile reaches Xray only with a pinned certificate, which is emitted;
/// `allowInsecure` never appears. ALPN only when explicit (B6).
#[test]
fn tls_pin_alpn_and_versions() {
    let pin = "ab".repeat(32);
    let p = with_tls(Tls {
        server_name: Some("front.example".into()),
        insecure: true,
        cert_pin_sha256: Some(pin.clone()),
        alpn: vec!["h2".into()],
        min_version: Some("1.2".into()),
        max_version: Some("1.3".into()),
        ..Tls::default()
    });
    let s = stream_of(&p, ClientDevice::Pc);
    assert_eq!(
        s["tlsSettings"],
        json!({"serverName": "front.example", "fingerprint": "chrome", "alpn": ["h2"],
               "pinnedPeerCertSha256": pin, "minVersion": "1.2", "maxVersion": "1.3"})
    );
    assert!(!s.to_string().contains("allowInsecure"));
    let unpinned = with_tls(Tls {
        insecure: true,
        ..Tls::default()
    });
    assert_eq!(
        translate(&unpinned, ClientDevice::Pc),
        Err(XrayConfigError::Feature(SingBoxOnly::InsecureWithoutPin))
    );
}

/// sing-box's own trust anchor maps to an Xray `verify` certificate without the system roots.
#[test]
fn custom_certificate_replaces_system_roots() {
    let p = with_tls(Tls {
        certificate_pem: Some(CERT_PEM.into()),
        ..Tls::default()
    });
    let t = &stream_of(&p, ClientDevice::Pc)["tlsSettings"];
    assert_eq!(t["disableSystemRoot"], true);
    assert_eq!(t["certificates"][0]["usage"], "verify");
    let lines = t["certificates"][0]["certificate"]
        .as_array()
        .expect("lines");
    assert_eq!(lines.first(), Some(&json!("-----BEGIN CERTIFICATE-----")));
    assert_eq!(lines.last(), Some(&json!("-----END CERTIFICATE-----")));
}

/// REALITY: `spiderX` gets its leading `/`, an empty one is omitted.
#[test]
fn reality_spider_x() {
    let spider = |value: Option<&str>| {
        let p = Profile {
            tls: Some(Tls {
                server_name: Some("yahoo.com".into()),
                reality: Some(Reality {
                    public_key: PBK.into(),
                    short_id: String::new(),
                    spider_x: value.map(str::to_owned),
                }),
                ..Tls::default()
            }),
            ..profile(vless())
        };
        stream_of(&p, ClientDevice::Pc)["realitySettings"]
            .get("spiderX")
            .cloned()
    };
    assert_eq!(spider(Some("abc")), Some(json!("/abc")));
    assert_eq!(spider(Some("/x?y=1")), Some(json!("/x?y=1")));
    assert_eq!(spider(Some("")), None);
    assert_eq!(spider(None), None);
}

/// Provider fingerprint when Xray knows it (any case), even one servers refuse (a warning says
/// so); otherwise the device default when servers accept it, else `chrome` (ru-2026-plan §2:
/// the Android / iOS presets are broken or refused). REALITY never takes `unsafe`.
#[test]
fn fingerprints() {
    let fp = |provider: Option<&str>, reality_on: bool, device: ClientDevice| {
        let mut tls = Tls {
            server_name: Some("front.example".into()),
            fingerprint: provider.map(str::to_owned),
            ..Tls::default()
        };
        if reality_on {
            tls.reality = Some(Reality {
                public_key: PBK.into(),
                ..Reality::default()
            });
        }
        let p = Profile {
            tls: Some(tls),
            ..profile(vless())
        };
        let s = stream_of(&p, device);
        let key = if reality_on {
            "realitySettings"
        } else {
            "tlsSettings"
        };
        s[key]["fingerprint"].as_str().map(str::to_owned)
    };
    use ClientDevice::{Android, Ios, Mac, Pc};
    assert_eq!(fp(Some("Firefox"), false, Pc).as_deref(), Some("firefox"));
    assert_eq!(
        fp(Some("chrome_120"), false, Android).as_deref(),
        Some("chrome")
    );
    assert_eq!(fp(None, false, Pc).as_deref(), Some("chrome"));
    assert_eq!(fp(None, false, Ios).as_deref(), Some("chrome"));
    assert_eq!(fp(None, false, Android).as_deref(), Some("chrome"));
    assert_eq!(fp(None, false, Mac).as_deref(), Some("safari"));
    assert_eq!(fp(None, true, Ios).as_deref(), Some("chrome"));
    assert_eq!(fp(None, true, Mac).as_deref(), Some("safari"));
    assert_eq!(fp(Some("ios"), true, Pc).as_deref(), Some("ios"));
    assert_eq!(fp(Some("android"), false, Pc).as_deref(), Some("android"));
    assert_eq!(fp(Some("unsafe"), false, Pc).as_deref(), Some("unsafe"));
    assert_eq!(fp(Some("unsafe"), true, Android).as_deref(), Some("chrome"));
}

/// §3.10: SNI and Host are pinned to the original name before the address becomes an IP; an IP
/// server without names gets the literal as SNI (IPv6 in brackets) and no Host.
#[test]
fn names_survive_pre_resolution() {
    let ws = || {
        Some(Transport::Ws {
            path: "/".into(),
            host: None,
            max_early_data: None,
            early_data_header: None,
        })
    };
    let no_sni = Profile {
        tls: Some(Tls::default()),
        transport: ws(),
        ..profile(vless())
    };
    let s = stream_of(&no_sni, ClientDevice::Pc);
    assert_eq!(s["tlsSettings"]["serverName"], "nl.example");
    assert_eq!(s["wsSettings"]["host"], "nl.example");
    let v6 = Profile {
        server: ip("2001:db8::1"),
        ..no_sni.clone()
    };
    let s = stream_of(&v6, ClientDevice::Pc);
    assert_eq!(s["tlsSettings"]["serverName"], "[2001:db8::1]");
    assert!(s["wsSettings"].get("host").is_none(), "{s}");
    let mut v6_sni = v6.clone();
    if let Some(t) = v6_sni.tls.as_mut() {
        t.server_name = Some("2001:db8::2".into());
    }
    let s = stream_of(&v6_sni, ClientDevice::Pc);
    assert_eq!(s["tlsSettings"]["serverName"], "[2001:db8::2]");
    let explicit = Profile {
        transport: Some(Transport::Ws {
            path: "/".into(),
            host: Some("front.example".into()),
            max_early_data: None,
            early_data_header: None,
        }),
        ..no_sni
    };
    assert_eq!(
        stream_of(&explicit, ClientDevice::Pc)["wsSettings"]["host"],
        "front.example"
    );
    let reality_no_sni = Profile {
        tls: Some(Tls {
            reality: Some(Reality {
                public_key: PBK.into(),
                ..Reality::default()
            }),
            ..Tls::default()
        }),
        ..profile(vless())
    };
    assert_eq!(
        stream_of(&reality_no_sni, ClientDevice::Pc)["realitySettings"]["serverName"],
        "nl.example"
    );
}

/// What Xray cannot run is an error, never a silently degraded config.
#[test]
fn untranslatable_profiles() {
    let tuic = profile(Kind::Tuic {
        uuid: UUID.into(),
        password: PW.into(),
        congestion: None,
        udp_relay_mode: None,
        zero_rtt: false,
        heartbeat_s: None,
    });
    assert_eq!(
        translate(&tuic, ClientDevice::Pc),
        Err(XrayConfigError::Protocol("tuic"))
    );
    // SOCKS over TLS would send its UDP beside the TLS.
    let socks_tls = Profile {
        tls: tls("proxy.example"),
        ..profile(Kind::Socks {
            username: None,
            password: None,
        })
    };
    assert_eq!(
        translate(&socks_tls, ClientDevice::Pc),
        Err(XrayConfigError::Protocol("socks"))
    );
    let h2 = Profile {
        tls: tls("front.example"),
        transport: Some(Transport::Http {
            hosts: Vec::new(),
            path: "/".into(),
        }),
        ..profile(vless())
    };
    assert_eq!(
        translate(&h2, ClientDevice::Pc),
        Err(XrayConfigError::Feature(SingBoxOnly::H2Transport))
    );
    let plaintext = Profile {
        server: ip("203.0.113.10"),
        ..profile(vless())
    };
    assert_eq!(
        translate(&plaintext, ClientDevice::Pc),
        Err(XrayConfigError::Feature(SingBoxOnly::Plaintext))
    );
}

/// B14 for share links: XHTTP `extra` is provider JSON for an elevated engine, so local files
/// (incl. `masterKeyLog`) and unpinned `allowInsecure` are refused like in a native graph.
#[test]
fn xhttp_extra_is_checked() {
    let with_extra = |extra: Value| Profile {
        tls: tls("front.example"),
        transport: Some(Transport::Xhttp {
            host: String::new(),
            path: "/".into(),
            mode: None,
            extra: extra.as_object().cloned(),
        }),
        ..profile(trojan())
    };
    let key_log = with_extra(json!({"downloadSettings": {"address": "dl.example",
        "tlsSettings": {"masterKeyLog": "C:/temp/keys.log"}}}));
    assert_eq!(
        translate(&key_log, ClientDevice::Pc),
        Err(XrayConfigError::Native(NativeError::LocalFileReference))
    );
    let insecure =
        with_extra(json!({"downloadSettings": {"tlsSettings": {"AllowInsecure": true}}}));
    assert_eq!(
        translate(&insecure, ClientDevice::Pc),
        Err(XrayConfigError::Native(NativeError::InsecureWithoutPin))
    );
    // A pin replaces the CA check on its own; the flag Xray 26.11 refuses is dropped.
    let pinned = with_extra(json!({"downloadSettings": {"tlsSettings": {
        "allowInsecure": true, "pinnedPeerCertSha256": "ab".repeat(32)}}}));
    let text = translate(&pinned, ClientDevice::Pc)
        .expect("pinned")
        .to_string();
    assert!(
        !text.contains("allowInsecure") && text.contains("pinnedPeerCertSha256"),
        "{text}"
    );
    let fine = with_extra(
        json!({"downloadSettings": {"address": "dl.example", "port": 443,
        "network": "xhttp", "security": "tls", "tlsSettings": {"serverName": "dl.example"}}}),
    );
    assert!(translate(&fine, ClientDevice::Pc).is_ok());
}
