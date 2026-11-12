//! Engine selection vectors (xray-engine spec §7 "Engine selection"; AT-00-001 / AT-00-004).
use vpnte_base::types::{Engine, EnginePref};
use vpnte_profiles::model::{
    Ech, Kind, NativeEntry, NativeXray, Profile, ShadowTlsLayer, Tls, Transport,
};

use super::*;
use crate::xray_config::{
    Decision, Reject, SelectReason, SingBoxOnly, XrayLacks, select_engine, server_pref,
};

const AUTO: EnginePref = EnginePref::Auto;
const SING_BOX: EnginePref = EnginePref::SingBox;
const XRAY: EnginePref = EnginePref::Xray;

fn xray(reason: SelectReason) -> Decision {
    Decision::Selected {
        engine: Engine::Xray,
        reason,
    }
}

fn sing_box(reason: SelectReason) -> Decision {
    Decision::Selected {
        engine: Engine::SingBox,
        reason,
    }
}

fn xhttp() -> Option<Transport> {
    Some(Transport::Xhttp {
        host: String::new(),
        path: "/".into(),
        mode: None,
        extra: None,
    })
}

fn grpc(multi_mode: Option<bool>) -> Option<Transport> {
    Some(Transport::Grpc {
        service_name: "svc".into(),
        multi_mode,
    })
}

fn ws() -> Option<Transport> {
    Some(Transport::Ws {
        path: "/ws".into(),
        host: None,
        max_early_data: None,
        early_data_header: None,
    })
}

/// Minimal native graph of the old vector `{version:1, selectedTag:'entry', ...}`.
pub(super) fn native(version: u8) -> NativeXray {
    NativeXray {
        version,
        selected_tag: "entry".into(),
        entry: NativeEntry {
            outbound_tag: Some("entry".into()),
            balancer_tag: None,
        },
        outbounds: Vec::new(),
        routing: None,
        observatory: None,
        burst_observatory: None,
        policy: None,
    }
}

fn tls_vless() -> Profile {
    Profile {
        tls: tls("example.com"),
        ..profile(vless())
    }
}

/// AT-00-001: the plain profile runs on sing-box, a forced preference is honoured.
#[test]
fn defaults_and_preferences() {
    assert_eq!(
        select_engine(&tls_vless(), AUTO),
        sing_box(SelectReason::Default)
    );
    assert_eq!(
        select_engine(&tls_vless(), XRAY),
        xray(SelectReason::Preference)
    );
    assert_eq!(
        select_engine(&tls_vless(), SING_BOX),
        sing_box(SelectReason::Preference)
    );
    // VMess without TLS is legal on Xray (only VLESS / Trojan need TLS there).
    assert_eq!(
        select_engine(&profile(vmess()), XRAY),
        xray(SelectReason::Preference)
    );
}

/// TUIC, Naive, AnyTLS and ShadowTLS have no Xray outbound (`unknown config id`); SOCKS over TLS
/// and a stream transport under Hysteria2 are not translated either. Auto and forced sing-box run
/// them on sing-box; forced Xray refuses them visibly.
#[test]
fn protocols_without_xray_outbound_are_never_switched_silently() {
    let shadowtls = profile(Kind::Shadowsocks {
        method: "aes-128-gcm".into(),
        password: PW.into(),
        plugin: None,
        shadowtls: Some(ShadowTlsLayer {
            version: 3,
            password: PW.into(),
            server_name: "cdn.example".into(),
        }),
        uot: None,
    });
    let tuic = profile(Kind::Tuic {
        uuid: UUID.into(),
        password: PW.into(),
        congestion: None,
        udp_relay_mode: None,
        zero_rtt: false,
        heartbeat_s: None,
    });
    let anytls = profile(Kind::Anytls {
        password: PW.into(),
        idle_check_s: None,
        idle_timeout_s: None,
        min_idle: None,
    });
    let socks_tls = Profile {
        tls: tls("proxy.example"),
        ..profile(socks())
    };
    let hy2_ws = Profile {
        transport: ws(),
        ..profile(hysteria2())
    };
    let naive = profile(Kind::Naive {
        username: "user".into(),
        password: PW.into(),
        quic: false,
        extra_headers: Vec::new(),
        insecure_concurrency: None,
    });
    let cases = [
        (shadowtls, XrayLacks::Client("ShadowTLS")),
        (tuic, XrayLacks::Client("TUIC")),
        (naive, XrayLacks::Client("NaiveProxy")),
        (anytls, XrayLacks::Client("AnyTLS")),
        (socks_tls, XrayLacks::Form("SOCKS")),
        (hy2_ws, XrayLacks::Form("Hysteria2")),
    ];
    for (p, lacks) in cases {
        let kind = p.kind.label();
        assert_eq!(
            select_engine(&p, AUTO),
            sing_box(SelectReason::Protocol),
            "{kind}"
        );
        assert_eq!(
            select_engine(&p, SING_BOX),
            sing_box(SelectReason::Protocol),
            "{kind}"
        );
        // Forced Xray never starts sing-box behind the user's back.
        assert_eq!(
            select_engine(&p, XRAY),
            Decision::Rejected(Reject::XrayLacks(lacks)),
            "{kind}"
        );
    }
}

/// The refusal names the protocol and offers Auto / sing-box (its own locale key per case).
#[test]
fn xray_lacks_messages_name_the_protocol() {
    let msg = Reject::XrayLacks(XrayLacks::Client("TUIC")).msg();
    assert_eq!(msg.key, "engine.xray.reject.noXrayClient");
    assert_eq!(msg.args[0].1, "TUIC");
    let msg = Reject::XrayLacks(XrayLacks::Form("SOCKS")).msg();
    assert_eq!(msg.key, "engine.xray.reject.xrayForm");
    let err: vpnte_base::AppError = Reject::XrayLacks(XrayLacks::Client("TUIC")).into();
    assert_eq!(err.kind, vpnte_base::ErrorKind::Validation);
}

/// Every reason has its caption; the per-server override wins over the setting, its Auto
/// follows the setting.
#[test]
fn reasons_and_server_override() {
    for (reason, key) in [
        (SelectReason::Default, "default"),
        (SelectReason::Protocol, "protocol"),
        (SelectReason::Preference, "preference"),
        (SelectReason::Reality, "reality"),
        (SelectReason::XrayTransport, "xrayTransport"),
        (SelectReason::NativeXray, "nativeXray"),
        (SelectReason::CertPin, "certPin"),
        (SelectReason::SingBoxOnly(SingBoxOnly::Ech), "singBoxOnly"),
    ] {
        assert_eq!(reason.msg().key, format!("engine.xray.reason.{key}"));
    }
    assert_eq!(server_pref(XRAY, EnginePref::Auto), XRAY);
    assert_eq!(server_pref(XRAY, SING_BOX), SING_BOX);
    assert_eq!(server_pref(AUTO, XRAY), XRAY);
    assert_eq!(server_pref(AUTO, EnginePref::Auto), AUTO);
}

/// Hysteria2, WireGuard, SOCKS and HTTP (also over TLS) run on Xray when it is forced; Auto and
/// forced sing-box keep them on sing-box.
#[test]
fn new_xray_outbounds_follow_the_preference() {
    let https = Profile {
        tls: tls("proxy.example"),
        ..profile(http())
    };
    for p in [
        profile(hysteria2()),
        profile(wireguard()),
        profile(socks()),
        profile(http()),
        https,
    ] {
        let kind = p.kind.label();
        assert_eq!(
            select_engine(&p, XRAY),
            xray(SelectReason::Preference),
            "{kind}"
        );
        assert_eq!(
            select_engine(&p, AUTO),
            sing_box(SelectReason::Default),
            "{kind}"
        );
        assert_eq!(
            select_engine(&p, SING_BOX),
            sing_box(SelectReason::Preference),
            "{kind}"
        );
    }
}

/// A certificate pin moves Auto to Xray: sing-box would drop the pin (it pins public keys only).
/// An insecure Hysteria2 key without a pin stays a sing-box-only feature; REALITY ignores pins.
#[test]
fn cert_pin_prefers_xray() {
    let pinned = |kind: Kind, insecure: bool, pin: Option<&str>| Profile {
        tls: Some(Tls {
            server_name: Some("hy.example".into()),
            insecure,
            cert_pin_sha256: pin.map(str::to_owned),
            ..Tls::default()
        }),
        ..profile(kind)
    };
    let pin = "ab".repeat(32);
    let hy2 = pinned(hysteria2(), true, Some(&pin));
    assert_eq!(select_engine(&hy2, AUTO), xray(SelectReason::CertPin));
    assert_eq!(select_engine(&hy2, XRAY), xray(SelectReason::Preference));
    assert_eq!(
        select_engine(&hy2, SING_BOX),
        sing_box(SelectReason::Preference)
    );
    let vless_pinned = pinned(vless(), false, Some(&pin));
    assert_eq!(
        select_engine(&vless_pinned, AUTO),
        xray(SelectReason::CertPin)
    );
    let f = SingBoxOnly::InsecureWithoutPin;
    let hy2_insecure = pinned(hysteria2(), true, None);
    assert_eq!(
        select_engine(&hy2_insecure, AUTO),
        sing_box(SelectReason::SingBoxOnly(f))
    );
    assert_eq!(
        select_engine(&hy2_insecure, XRAY),
        Decision::Rejected(Reject::SingBoxOnly(f))
    );
    let mut reality_pinned = Profile {
        tls: reality("yahoo.com"),
        ..profile(vless())
    };
    if let Some(t) = reality_pinned.tls.as_mut() {
        t.cert_pin_sha256 = Some(pin.clone());
    }
    assert_eq!(
        select_engine(&reality_pinned, AUTO),
        xray(SelectReason::Reality)
    );
}

/// A static ECH config runs on Xray (`echConfigList`); one that needs a DNS lookup, or ECH with
/// REALITY or over QUIC, stays sing-box only. SS UDP-over-TCP runs on Xray with 2022 ciphers.
#[test]
fn ech_and_udp_over_tcp() {
    let ech = |kind: Kind, lines: &[&str]| {
        let mut p = Profile {
            tls: tls("front.example"),
            ..profile(kind)
        };
        if let Some(t) = p.tls.as_mut() {
            t.ech = Some(Ech {
                config_lines: lines.iter().map(|l| (*l).to_owned()).collect(),
                query_server_name: None,
            });
        }
        p
    };
    let fixed = ech(vless(), &[ECH_CONFIG]);
    assert_eq!(select_engine(&fixed, XRAY), xray(SelectReason::Preference));
    assert_eq!(select_engine(&fixed, AUTO), sing_box(SelectReason::Default));
    let f = SingBoxOnly::Ech;
    let mut reality_ech = ech(vless(), &[ECH_CONFIG]);
    if let Some(t) = reality_ech.tls.as_mut() {
        t.reality = reality("yahoo.com").and_then(|r| r.reality);
    }
    for p in [
        ech(vless(), &[" "]),
        ech(hysteria2(), &[ECH_CONFIG]),
        reality_ech,
    ] {
        assert_eq!(
            select_engine(&p, XRAY),
            Decision::Rejected(Reject::SingBoxOnly(f))
        );
    }
    let uot = |method: &str| {
        let mut p = profile(shadowsocks(method));
        if let Kind::Shadowsocks { uot, .. } = &mut p.kind {
            *uot = Some(2);
        }
        p
    };
    assert_eq!(
        select_engine(&uot("2022-blake3-aes-128-gcm"), XRAY),
        xray(SelectReason::Preference)
    );
    assert_eq!(
        select_engine(&uot("chacha20-ietf-poly1305"), XRAY),
        Decision::Rejected(Reject::SingBoxOnly(SingBoxOnly::ShadowsocksUdpOverTcp))
    );
}

/// AT-00-004: REALITY goes to Xray in Auto; forced sing-box keeps it there. The typed model has
/// no `tls.enabled = false` with REALITY (B22): such a key imports without TLS.
#[test]
fn reality_prefers_xray() {
    let p = Profile {
        server: ip("1.2.3.4"),
        tls: reality("yahoo.com"),
        ..profile(vless())
    };
    assert_eq!(select_engine(&p, AUTO), xray(SelectReason::Reality));
    assert_eq!(
        select_engine(&p, SING_BOX),
        sing_box(SelectReason::Preference)
    );
    assert_eq!(select_engine(&p, XRAY), xray(SelectReason::Preference));
    let disabled = Profile {
        server: ip("192.168.1.10"),
        ..profile(vless())
    };
    assert_eq!(
        select_engine(&disabled, AUTO),
        sing_box(SelectReason::Default)
    );
}

/// Xray-only transports and features: Xray in Auto, rejected under forced sing-box (with the
/// old app's text). Explicit gRPC gun stays an ordinary sing-box transport when forced (B18).
#[test]
fn xray_only_transports() {
    for kind in [vless(), trojan(), vmess()] {
        let p = Profile {
            tls: tls("front.example"),
            transport: xhttp(),
            ..profile(kind)
        };
        assert_eq!(select_engine(&p, AUTO), xray(SelectReason::XrayTransport));
        assert_eq!(
            select_engine(&p, SING_BOX),
            Decision::Rejected(Reject::XrayTransport)
        );
    }
    assert_eq!(
        text(RU, &Reject::XrayTransport.msg().key),
        "Параметры транспорта требуют Xray; выберите Auto или Xray."
    );
    let gun = Profile {
        tls: tls("front.example"),
        transport: grpc(Some(false)),
        ..profile(trojan())
    };
    assert_eq!(select_engine(&gun, AUTO), xray(SelectReason::XrayTransport));
    assert_eq!(
        select_engine(&gun, SING_BOX),
        sing_box(SelectReason::Preference)
    );
    let multi = Profile {
        transport: grpc(Some(true)),
        ..gun.clone()
    };
    assert_eq!(
        select_engine(&multi, SING_BOX),
        Decision::Rejected(Reject::XrayTransport)
    );
    let plain_grpc = Profile {
        transport: grpc(None),
        ..gun
    };
    assert_eq!(
        select_engine(&plain_grpc, AUTO),
        sing_box(SelectReason::Default)
    );
}

/// B32: VLESS Encryption and the RAW HTTP header mask are Xray-only.
#[test]
fn vless_encryption_and_http_header_need_xray() {
    let enc = profile(Kind::Vless {
        uuid: UUID.into(),
        flow: None,
        packet_encoding: None,
        encryption: Some("mlkem768x25519plus.native.0rtt.AAAA".into()),
    });
    assert_eq!(select_engine(&enc, AUTO), xray(SelectReason::XrayTransport));
    assert_eq!(
        select_engine(&enc, SING_BOX),
        Decision::Rejected(Reject::XrayTransport)
    );
    let header = Profile {
        transport: Some(Transport::TcpHttpHeader {
            host: vec!["h.example".into()],
            path: vec!["/".into()],
        }),
        ..tls_vless()
    };
    assert_eq!(
        select_engine(&header, AUTO),
        xray(SelectReason::XrayTransport)
    );
}

/// A provider graph runs on Xray; forced sing-box refuses it with the old text and the decision
/// carries no profile data (AT-00-001).
#[test]
fn native_graph_needs_xray() {
    let p = Profile {
        native_xray: Some(native(1)),
        kind: Kind::Trojan {
            password: "SYNTHETIC_SECRET".into(),
        },
        ..profile(vless())
    };
    assert_eq!(select_engine(&p, AUTO), xray(SelectReason::NativeXray));
    assert_eq!(select_engine(&p, XRAY), xray(SelectReason::NativeXray));
    let rejected = select_engine(&p, SING_BOX);
    assert_eq!(rejected, Decision::Rejected(Reject::NativeXray));
    assert_eq!(rejected.engine(), Err(Reject::NativeXray));
    let json = serde_json::to_string(&rejected).expect("serializes");
    assert!(!json.contains("SYNTHETIC_SECRET"), "{json}");
    // The old app's reason names (`native-xray`, `xray-transport`, …), for both outcomes.
    assert_eq!(json, r#"{"rejected":"native-xray"}"#);
    assert_eq!(
        serde_json::to_value(select_engine(&p, AUTO)).expect("serializes"),
        serde_json::json!({"selected": {"engine": "xray", "reason": "native-xray"}})
    );
    assert_eq!(
        text(RU, &Reject::NativeXray.msg().key),
        "Этот JSON-профиль содержит настройки Xray; выберите Auto или Xray для сохранения маршрута."
    );
}

/// New sing-box-only rows: Auto stays on sing-box, forced Xray is refused (B1, B2, B5, B29).
#[test]
fn sing_box_only_features() {
    let h2 = Profile {
        transport: Some(Transport::Http {
            hosts: Vec::new(),
            path: "/".into(),
        }),
        tls: reality("yahoo.com"),
        ..profile(vless())
    };
    let f = SingBoxOnly::H2Transport;
    assert_eq!(
        select_engine(&h2, AUTO),
        sing_box(SelectReason::SingBoxOnly(f))
    );
    let reality_ws = Profile {
        transport: ws(),
        tls: reality("yahoo.com"),
        ..profile(vless())
    };
    let f = SingBoxOnly::RealityTransport;
    assert_eq!(
        select_engine(&reality_ws, AUTO),
        sing_box(SelectReason::SingBoxOnly(f))
    );
    assert_eq!(
        select_engine(&reality_ws, XRAY),
        Decision::Rejected(Reject::SingBoxOnly(f))
    );
    let mut uot = profile(shadowsocks("aes-256-gcm"));
    if let Kind::Shadowsocks { uot: u, .. } = &mut uot.kind {
        *u = Some(2);
    }
    let f = SingBoxOnly::ShadowsocksUdpOverTcp;
    assert_eq!(
        select_engine(&uot, AUTO),
        sing_box(SelectReason::SingBoxOnly(f))
    );
    assert_eq!(
        select_engine(&uot, XRAY),
        Decision::Rejected(Reject::SingBoxOnly(f))
    );
    let f = SingBoxOnly::ShadowsocksMethod;
    let old_cipher = profile(shadowsocks("aes-192-gcm"));
    assert_eq!(
        select_engine(&old_cipher, XRAY),
        Decision::Rejected(Reject::SingBoxOnly(f))
    );
    let ss = profile(shadowsocks("CHACHA20-IETF-POLY1305"));
    assert_eq!(select_engine(&ss, XRAY), xray(SelectReason::Preference));
    assert_eq!(
        text(RU, &Reject::SingBoxOnly(SingBoxOnly::H2Transport).msg().key),
        "Профиль использует возможности, которых нет в Xray (транспорт HTTP/2); выберите Auto или sing-box."
    );
}

/// B30: VLESS / Trojan without TLS are refused by Xray 26.11 unless the server is a private
/// literal; with an Xray-only transport that is a conflict.
#[test]
fn plaintext_vless_and_trojan() {
    let public = Profile {
        server: ip("203.0.113.10"),
        ..profile(Kind::Vless {
            uuid: UUID.into(),
            flow: None,
            packet_encoding: None,
            encryption: Some("none".into()),
        })
    };
    let f = SingBoxOnly::Plaintext;
    assert_eq!(
        select_engine(&public, XRAY),
        Decision::Rejected(Reject::SingBoxOnly(f))
    );
    let private = Profile {
        server: ip("192.168.1.10"),
        ..public.clone()
    };
    assert_eq!(
        select_engine(&private, XRAY),
        xray(SelectReason::Preference)
    );
    let xhttp_plain = Profile {
        transport: xhttp(),
        ..public
    };
    assert_eq!(
        select_engine(&xhttp_plain, AUTO),
        Decision::Rejected(Reject::Conflict(f))
    );
    let bare_trojan = Profile {
        server: ip("203.0.113.10"),
        ..profile(trojan())
    };
    assert_eq!(
        select_engine(&bare_trojan, XRAY),
        Decision::Rejected(Reject::SingBoxOnly(f))
    );
    // Host names never count as private: the choice stays pure (no DNS).
    let named = profile(trojan());
    assert_eq!(
        select_engine(&named, XRAY),
        Decision::Rejected(Reject::SingBoxOnly(f))
    );
    let v6_ula = Profile {
        server: ip("fd00::10"),
        ..profile(trojan())
    };
    assert_eq!(select_engine(&v6_ula, XRAY), xray(SelectReason::Preference));
}

/// B2: certificate checks may be skipped on Xray only through a pinned certificate; SPKI pins
/// and ECH have no Xray counterpart; REALITY ignores both `insecure` and pins.
#[test]
fn certificate_checks_and_pins() {
    let insecure = |pin: Option<&str>| Profile {
        tls: Some(Tls {
            server_name: Some("front.example".into()),
            insecure: true,
            cert_pin_sha256: pin.map(str::to_owned),
            ..Tls::default()
        }),
        transport: xhttp(),
        ..profile(vless())
    };
    let f = SingBoxOnly::InsecureWithoutPin;
    assert_eq!(
        select_engine(&insecure(None), AUTO),
        Decision::Rejected(Reject::Conflict(f))
    );
    let pinned = insecure(Some(&"ab".repeat(32)));
    assert_eq!(
        select_engine(&pinned, AUTO),
        xray(SelectReason::XrayTransport)
    );
    // A blank pin is no pin (translation would emit none).
    assert_eq!(
        select_engine(&insecure(Some(" ")), AUTO),
        Decision::Rejected(Reject::Conflict(f))
    );
    assert_eq!(
        text(RU, &Reject::Conflict(f).msg().key),
        "Профилю нужен транспорт Xray, но он использует отключённую проверку сертификата, которую \
         Xray не поддерживает (для отключения проверки сертификата укажите pinnedPeerCertSha256 / pcs)."
    );
    let spki = Profile {
        tls: Some(Tls {
            server_name: Some("front.example".into()),
            spki_pin_sha256: vec!["AAAA".into()],
            ..Tls::default()
        }),
        ..profile(trojan())
    };
    let f = SingBoxOnly::SpkiPin;
    assert_eq!(
        select_engine(&spki, XRAY),
        Decision::Rejected(Reject::SingBoxOnly(f))
    );
    let mut ech = tls_vless();
    if let Some(t) = ech.tls.as_mut() {
        t.ech = Some(Default::default());
    }
    let f = SingBoxOnly::Ech;
    assert_eq!(
        select_engine(&ech, AUTO),
        sing_box(SelectReason::SingBoxOnly(f))
    );
    let mut reality_insecure = Profile {
        tls: reality("yahoo.com"),
        ..profile(vless())
    };
    if let Some(t) = reality_insecure.tls.as_mut() {
        t.insecure = true;
        t.spki_pin_sha256 = vec!["AAAA".into()];
    }
    assert_eq!(
        select_engine(&reality_insecure, AUTO),
        xray(SelectReason::Reality)
    );
}

/// Every rejection has a sentence in both languages.
#[test]
fn every_rejection_has_text() {
    let features = [
        SingBoxOnly::H2Transport,
        SingBoxOnly::QuicTransport,
        SingBoxOnly::InsecureWithoutPin,
        SingBoxOnly::SpkiPin,
        SingBoxOnly::Ech,
        SingBoxOnly::ShadowsocksPlugin,
        SingBoxOnly::ShadowsocksUdpOverTcp,
        SingBoxOnly::ShadowsocksMethod,
        SingBoxOnly::RealityTransport,
        SingBoxOnly::Plaintext,
    ];
    let mut rejects = vec![Reject::NativeXray, Reject::XrayTransport];
    rejects.extend(features.iter().map(|&f| Reject::SingBoxOnly(f)));
    rejects.extend(features.iter().map(|&f| Reject::Conflict(f)));
    rejects.push(Reject::XrayLacks(XrayLacks::Client("TUIC")));
    rejects.push(Reject::XrayLacks(XrayLacks::Form("SOCKS")));
    let reasons = [
        SelectReason::Default,
        SelectReason::Protocol,
        SelectReason::Preference,
        SelectReason::Reality,
        SelectReason::XrayTransport,
        SelectReason::NativeXray,
        SelectReason::CertPin,
        SelectReason::SingBoxOnly(SingBoxOnly::Ech),
    ];
    let keys = rejects
        .iter()
        .map(Reject::msg)
        .chain(reasons.iter().map(|r| r.msg()));
    for msg in keys {
        let key = msg.key;
        assert!(
            !text(RU, &key).is_empty() && !text(EN, &key).is_empty(),
            "{key}"
        );
    }
}
