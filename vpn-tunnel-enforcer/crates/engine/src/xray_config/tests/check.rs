//! Real-binary checks: every generated shape must pass `xray run -test -config stdin:` on the
//! bundled Xray (26.11.9, stricter than the old pinned 26.7.28). Skipped quietly when
//! `resources/xray.exe` is absent.
use serde_json::json;
use vpnte_base::types::ClientDevice;
use vpnte_profiles::model::{Kind, Profile, Reality, Tls, Transport};

use super::config::{endpoint, imported, norway};
use super::*;
use crate::test_support::{xray_check, xray_exe};
use crate::xray_config::{ProxyGraph, build_config, proxy_graph};

/// Builds the full slot config of `p` and asserts the bundled Xray accepts it.
fn assert_runs(p: &Profile, label: &str) {
    let graph = proxy_graph(p, ClientDevice::Pc).unwrap_or_else(|e| panic!("{label}: {e}"));
    let config = build_config(&graph, &endpoint(20002));
    if let Err(out) = xray_check(&config) {
        panic!("{label}: xray refused the config: {out}");
    }
}

fn with(p: Profile, transport: Option<Transport>) -> Profile {
    Profile { transport, ..p }
}

/// The harness itself: Xray must refuse what it refuses (REALITY over ws), so a pass means
/// something.
#[test]
fn harness_detects_a_refused_config() {
    let bad = json!({"tag": "proxy", "protocol": "vless",
        "settings": {"vnext": [{"address": "192.0.2.1", "port": 443, "users": [{"id": UUID, "encryption": "none"}]}]},
        "streamSettings": {"network": "ws", "security": "reality",
            "realitySettings": {"serverName": "yahoo.com", "publicKey": PBK, "fingerprint": "chrome"}}});
    let config = build_config(&ProxyGraph::Translated(bad), &endpoint(20003));
    match xray_check(&config) {
        Ok(false) => {}
        Ok(true) => panic!("xray accepted REALITY over ws"),
        Err(out) => assert!(out.contains("REALITY only supports"), "{out}"),
    }
}

/// The old real-binary vectors (xrayEngine.itest.ts:37-64) plus the slot sniffing config.
#[test]
fn basic_profiles_pass_xray_test() {
    if xray_check(&build_config(&freedom_graph(), &endpoint(20004))) == Ok(false) {
        return;
    }
    let reality = Profile {
        tls: Some(Tls {
            server_name: Some("yahoo.com".into()),
            fingerprint: Some("chrome".into()),
            reality: Some(Reality {
                public_key: PBK.into(),
                short_id: String::new(),
                spider_x: Some("abc".into()),
            }),
            ..Tls::default()
        }),
        ..profile(Kind::Vless {
            uuid: UUID.into(),
            flow: Some("xtls-rprx-vision".into()),
            packet_encoding: None,
            encryption: None,
        })
    };
    assert_runs(&reality, "vless reality vision");
    let vmess_ws = Profile {
        tls: tls("cdn.example"),
        transport: Some(Transport::Ws {
            path: "/ws".into(),
            host: None,
            max_early_data: Some(2048),
            early_data_header: None,
        }),
        ..profile(vmess())
    };
    assert_runs(&vmess_ws, "vmess ws tls");
    assert_runs(
        &Profile {
            tls: tls("front.example"),
            ..profile(trojan())
        },
        "trojan tls",
    );
    for method in [
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "2022-blake3-aes-256-gcm",
    ] {
        let password = match method {
            "2022-blake3-aes-256-gcm" => "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            _ => PW,
        };
        let ss = Profile {
            port: 8388,
            ..profile(Kind::Shadowsocks {
                method: method.into(),
                password: password.into(),
                plugin: None,
                shadowtls: None,
                uot: None,
            })
        };
        assert_runs(&ss, method);
    }
}

fn freedom_graph() -> ProxyGraph {
    ProxyGraph::Translated(json!({"tag": "proxy", "protocol": "freedom"}))
}

/// Every XHTTP mode with `extra`, gRPC gun / multi (transportCompatibility.test.ts:66-81), and
/// the other transports this package writes.
#[test]
fn transports_pass_xray_test() {
    if xray_exe().is_none() {
        return;
    }
    let base = Profile {
        tls: tls("front.example.com"),
        ..profile(vless())
    };
    let extra = json!({"noSSEHeader": true, "headers": {"Host": "moved.example"}});
    for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
        let xhttp = Transport::Xhttp {
            host: String::new(),
            path: "/a%2Fb".into(),
            mode: Some(mode.into()),
            extra: extra.as_object().cloned(),
        };
        assert_runs(&with(base.clone(), Some(xhttp)), mode);
    }
    // Split download with a pinned certificate: the refused `allowInsecure` flag is dropped.
    let download = json!({"downloadSettings": {"address": "dl.example", "port": 443,
        "network": "xhttp", "security": "tls", "xhttpSettings": {"path": "/d"},
        "tlsSettings": {"serverName": "dl.example", "allowInsecure": true,
                        "pinnedPeerCertSha256": "ab".repeat(32)}}});
    let split = Transport::Xhttp {
        host: String::new(),
        path: "/u".into(),
        mode: Some("packet-up".into()),
        extra: download.as_object().cloned(),
    };
    assert_runs(&with(base.clone(), Some(split)), "xhttp split download");
    for multi in [Some(false), Some(true)] {
        let grpc = Transport::Grpc {
            service_name: "service-name".into(),
            multi_mode: multi,
        };
        assert_runs(&with(base.clone(), Some(grpc)), "grpc");
    }
    let plain_grpc = Profile {
        transport: Some(Transport::Grpc {
            service_name: "svc".into(),
            multi_mode: Some(true),
        }),
        ..profile(vmess())
    };
    assert_runs(&plain_grpc, "vmess grpc without tls");
    let upgrade = Transport::HttpUpgrade {
        host: String::new(),
        path: "/up".into(),
    };
    assert_runs(&with(base.clone(), Some(upgrade)), "httpupgrade");
    let header = Profile {
        port: 80,
        transport: Some(Transport::TcpHttpHeader {
            host: vec!["h.example".into()],
            path: vec!["/a".into(), "/b".into()],
        }),
        ..profile(vmess())
    };
    assert_runs(&header, "tcp http header");
    let encrypted = Profile {
        transport: Some(Transport::Xhttp {
            host: String::new(),
            path: "/x".into(),
            mode: None,
            extra: None,
        }),
        ..profile(Kind::Vless {
            uuid: UUID.into(),
            flow: Some("xtls-rprx-vision".into()),
            packet_encoding: None,
            encryption: Some(format!("mlkem768x25519plus.native.0rtt.{PBK}")),
        })
    };
    assert_runs(&encrypted, "vless encryption");
}

/// TLS options and every fingerprint the translator may write, for TLS and REALITY.
#[test]
fn security_options_pass_xray_test() {
    if xray_exe().is_none() {
        return;
    }
    let tls_profile = |tls: Tls| Profile {
        tls: Some(tls),
        ..profile(trojan())
    };
    let pinned = tls_profile(Tls {
        server_name: Some("front.example".into()),
        insecure: true,
        cert_pin_sha256: Some("ab".repeat(32)),
        alpn: vec!["h2".into(), "http/1.1".into()],
        min_version: Some("1.2".into()),
        max_version: Some("1.3".into()),
        ..Tls::default()
    });
    assert_runs(&pinned, "pinned certificate");
    let own_ca = tls_profile(Tls {
        certificate_pem: Some(CERT_PEM.into()),
        ..Tls::default()
    });
    assert_runs(&own_ca, "custom certificate");
    let fingerprints = [
        "chrome",
        "firefox",
        "safari",
        "ios",
        "android",
        "edge",
        "360",
        "qq",
        "random",
        "randomized",
        "randomizednoalpn",
        "unsafe",
        "made-up",
    ];
    for fp in fingerprints {
        let tls = Tls {
            server_name: Some("front.example".into()),
            fingerprint: Some(fp.into()),
            ..Tls::default()
        };
        assert_runs(&tls_profile(tls.clone()), fp);
        let reality = Tls {
            reality: Some(Reality {
                public_key: PBK.into(),
                short_id: SID.into(),
                spider_x: None,
            }),
            ..tls
        };
        assert_runs(
            &Profile {
                tls: Some(reality),
                ..profile(vless())
            },
            fp,
        );
    }
    for device in [ClientDevice::Android, ClientDevice::Ios, ClientDevice::Mac] {
        let p = Profile {
            tls: reality("yahoo.com"),
            ..profile(vless())
        };
        let graph = proxy_graph(&p, device).expect("translates");
        let config = build_config(&graph, &endpoint(20005));
        assert!(xray_check(&config).is_ok(), "{device:?}");
    }
}

/// The full synthetic provider graph and its exported document re-imported
/// (nativeXrayCompatibility.test.ts:292-308).
#[test]
fn native_graph_passes_xray_test() {
    if xray_exe().is_none() {
        return;
    }
    let p = imported(&norway());
    assert_runs(&p, "native graph");
    let graph = p.native_xray.as_ref().expect("graph");
    let exported = vpnte_profiles::xray_native::export_document(graph, &p.name).expect("exports");
    let again = imported(&exported);
    assert_eq!(again.name, "Norway");
    assert_runs(&again, "re-imported native graph");
}
