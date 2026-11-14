//! T1a (owner, 14.11.2026): Auto runs plain TLS keys on Xray (Chrome 155 hello) instead of
//! sing-box (Chrome 133, rate-limited by the TSPU), only where Xray loses nothing; per protocol
//! and transport.
use serde_json::json;
use vpnte_base::types::{Engine, EnginePref};
use vpnte_profiles::model::{Ech, Kind, Mux, Profile, Tls, Transport};

use super::*;
use crate::xray_config::{Decision, SelectReason, select_engine};

const XRAY: Decision = Decision::Selected {
    engine: Engine::Xray,
    reason: SelectReason::TlsHello,
};
const SING_BOX: Decision = Decision::Selected {
    engine: Engine::SingBox,
    reason: SelectReason::Default,
};

/// The transports Auto moves, by name.
fn transports() -> [(&'static str, Option<Transport>); 4] {
    [
        ("raw", None),
        (
            "ws",
            Some(Transport::Ws {
                path: "/ws".into(),
                host: Some("cdn.example".into()),
                max_early_data: None,
                early_data_header: None,
            }),
        ),
        (
            "httpupgrade",
            Some(Transport::HttpUpgrade {
                host: "cdn.example".into(),
                path: "/up".into(),
            }),
        ),
        (
            "grpc",
            Some(Transport::Grpc {
                service_name: "svc".into(),
                multi_mode: None,
            }),
        ),
    ]
}

fn key(kind: Kind, transport: Option<Transport>) -> Profile {
    Profile {
        tls: tls("front.example"),
        transport,
        ..profile(kind)
    }
}

/// VLESS, VMess and Trojan over TLS on RAW, WebSocket, HTTPUpgrade and gRPC move to Xray in Auto;
/// the user's forced sing-box stays (also per server).
#[test]
fn plain_tls_keys_run_on_xray_in_auto() {
    for kind in [vless(), vmess(), trojan()] {
        for (name, transport) in transports() {
            let p = key(kind.clone(), transport);
            let what = format!("{} {name}", p.kind.label());
            assert_eq!(select_engine(&p, EnginePref::Auto), XRAY, "{what}");
            let forced = select_engine(&p, EnginePref::SingBox);
            assert_eq!(forced.engine(), Ok(Engine::SingBox), "{what}");
        }
    }
}

/// Every key Auto moves passes `xray run -test` in its slot config (skipped without the binary).
#[test]
fn every_moved_key_passes_xray_test() {
    if crate::test_support::xray_exe().is_none() {
        return;
    }
    for kind in [vless(), vmess(), trojan()] {
        for (name, transport) in transports() {
            let p = key(kind.clone(), transport);
            let label = format!("{} {name}", p.kind.label());
            super::check::assert_runs(&p, &label);
        }
    }
}

/// Whatever Xray would drop or warn about keeps the key on sing-box: mux, dial options, pasted
/// sing-box options, SNI off, a fingerprint Xray does not know, WebSocket early data, ECH.
#[test]
fn keys_xray_would_change_stay_on_sing_box() {
    let base = || key(vless(), transports()[1].1.clone());
    let mut mux = base();
    mux.mux = Some(Mux {
        enabled: true,
        protocol: Some("h2mux".into()),
        ..Mux::default()
    });
    let mut dial = base();
    dial.dial.tcp_fast_open = true;
    let mut extra = base();
    extra
        .singbox_extra
        .insert("tls.utls.enabled".into(), json!(true));
    let mut no_sni = base();
    let mut unknown_fp = base();
    let mut ech = base();
    if let (Some(a), Some(b), Some(c)) = (
        no_sni.tls.as_mut(),
        unknown_fp.tls.as_mut(),
        ech.tls.as_mut(),
    ) {
        a.disable_sni = true;
        b.fingerprint = Some("netscape".into());
        c.ech = Some(Ech {
            config_lines: vec![ECH_CONFIG.into()],
            query_server_name: None,
        });
    }
    let early = key(
        trojan(),
        Some(Transport::Ws {
            path: "/ws".into(),
            host: None,
            max_early_data: Some(2048),
            // Xray sends early data only in `Sec-WebSocket-Protocol`.
            early_data_header: Some("X-Early-Data".into()),
        }),
    );
    for (what, p) in [
        ("mux", mux),
        ("dial", dial),
        ("extra", extra),
        ("no sni", no_sni),
        ("unknown fp", unknown_fp),
        ("ech", ech),
        ("early data", early),
    ] {
        assert_eq!(select_engine(&p, EnginePref::Auto), SING_BOX, "{what}");
    }
}

/// Only plain TLS moves: no TLS, other protocols and a mux disabled by the provider.
#[test]
fn other_keys_keep_their_engine() {
    let plain = profile(vmess());
    let https = Profile {
        tls: tls("proxy.example"),
        ..profile(http())
    };
    let ss = profile(shadowsocks("aes-128-gcm"));
    for p in [plain, https, ss, profile(hysteria2())] {
        assert_eq!(
            select_engine(&p, EnginePref::Auto),
            SING_BOX,
            "{}",
            p.kind.label()
        );
    }
    let mut off = key(trojan(), None);
    off.mux = Some(Mux::default());
    assert_eq!(select_engine(&off, EnginePref::Auto), XRAY, "mux off");
    let provider_fp = Profile {
        tls: Some(Tls {
            fingerprint: Some("firefox".into()),
            ..tls("front.example").unwrap_or_default()
        }),
        ..profile(vless())
    };
    assert_eq!(select_engine(&provider_fp, EnginePref::Auto), XRAY);
}
