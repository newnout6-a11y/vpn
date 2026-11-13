//! Unit tests and ported spec vectors (profiles §7, tunnel-core §7.6-7.8, §7.12).
use serde_json::{Map, Value, json};
use vpnte_base::ErrorKind;
use vpnte_base::types::ClientDevice;

use super::*;
use crate::model::{
    DialPrefs, Ech, Host, Hy2Obfs, Kind, Mux, NativeEntry, NativeXray, Profile, Reality,
    ShadowTlsLayer, Source, SsPlugin, Tls, Transport, WgPeer, WireGuard,
};

pub(super) const UUID: &str = "00000000-0000-4000-8000-000000000001";
/// Public sample key from the sing-box docs (not a credential).
pub(super) const PBK: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";
/// ECHConfigList generated for `ech.example.com` by `sing-box generate ech-keypair` (key discarded).
pub(super) const ECH_B64: &str = "AEr+DQBGAAAgACDmE7uowausShfpJWZmCnNnBe+4fC0+FRniliUD1HH0UAAMAAEAAQABAAIAAQADAA9lY2guZXhhbXBsZS5jb20AAA==";

pub(super) fn profile(server: &str, port: u16, kind: Kind) -> Profile {
    Profile {
        name: "test".into(),
        description: None,
        server: server
            .parse()
            .map(Host::Ip)
            .unwrap_or_else(|_| Host::Domain(server.into())),
        port,
        kind,
        tls: None,
        transport: None,
        mux: None,
        dial: DialPrefs::default(),
        native_xray: None,
        singbox_extra: Map::new(),
        source: Source::Json,
        notes: Vec::new(),
    }
}

pub(super) fn tls(sni: &str) -> Tls {
    Tls {
        server_name: Some(sni.into()),
        ..Tls::default()
    }
}

pub(super) fn reality() -> Reality {
    Reality {
        public_key: PBK.into(),
        short_id: "1234".into(),
        spider_x: Some("/test-path".into()),
        ..Reality::default()
    }
}

pub(super) fn vless(server: &str) -> Profile {
    let kind = Kind::Vless {
        uuid: UUID.into(),
        flow: None,
        packet_encoding: None,
        encryption: None,
    };
    profile(server, 443, kind)
}

pub(super) fn vmess(server: &str) -> Profile {
    let kind = Kind::Vmess {
        uuid: UUID.into(),
        security: "auto".into(),
        global_padding: false,
        authenticated_length: false,
    };
    profile(server, 443, kind)
}

pub(super) fn trojan(server: &str) -> Profile {
    profile(
        server,
        443,
        Kind::Trojan {
            password: "SYNTHETIC".into(),
        },
    )
}

pub(super) fn ss(method: &str, password: &str) -> Profile {
    let kind = Kind::Shadowsocks {
        method: method.into(),
        password: password.into(),
        plugin: None,
        shadowtls: None,
        uot: None,
    };
    profile("ss.example.com", 8388, kind)
}

pub(super) fn hy2(server: &str) -> Profile {
    let kind = Kind::Hysteria2 {
        password: "secret".into(),
        obfs: None,
        ports: Vec::new(),
        hop_interval_s: None,
        hop_interval_max_s: None,
        up_mbps: None,
        down_mbps: None,
        bbr_profile: None,
    };
    profile(server, 443, kind)
}

pub(super) fn tuic(server: &str) -> Profile {
    let kind = Kind::Tuic {
        uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
        password: "secret".into(),
        congestion: Some("bbr".into()),
        udp_relay_mode: Some("native".into()),
        zero_rtt: false,
        heartbeat_s: None,
    };
    profile(server, 443, kind)
}

pub(super) fn naive(server: &str) -> Profile {
    let kind = Kind::Naive {
        username: "user".into(),
        password: "pass".into(),
        quic: false,
        extra_headers: Vec::new(),
        insecure_concurrency: None,
    };
    let mut p = profile(server, 443, kind);
    p.tls = Some(tls("front.example.com"));
    p
}

pub(super) fn anytls(server: &str) -> Profile {
    let kind = Kind::Anytls {
        password: "secret".into(),
        idle_check_s: None,
        idle_timeout_s: None,
        min_idle: None,
    };
    profile(server, 443, kind)
}

pub(super) fn peer(host: &str, allowed: &[&str]) -> WgPeer {
    WgPeer {
        host: host
            .parse()
            .map(Host::Ip)
            .unwrap_or_else(|_| Host::Domain(host.into())),
        port: 51820,
        public_key: "PUB".into(),
        pre_shared_key: None,
        allowed_ips: allowed.iter().map(|a| a.parse().expect("prefix")).collect(),
        keepalive_s: None,
        reserved: None,
    }
}

pub(super) fn wireguard(peers: Vec<WgPeer>) -> Profile {
    let wg = WireGuard {
        private_key: "PRIV".into(),
        local_address: vec!["10.0.0.2/32".parse().expect("prefix")],
        mtu: None,
        dns: Vec::new(),
        peers,
    };
    profile("203.0.113.5", 51820, Kind::Wireguard(wg))
}

pub(super) fn emit(p: &Profile, policy: &EmitPolicy) -> SingBoxFragment {
    emit_singbox(p, "proxy-out", policy).expect("emit")
}

pub(super) fn out(p: &Profile, policy: &EmitPolicy) -> Value {
    match emit(p, policy) {
        SingBoxFragment::Outbound(v) => v,
        other => panic!("not a single outbound: {other:?}"),
    }
}

fn stealth() -> EmitPolicy {
    EmitPolicy {
        tls_compat: true,
        ..EmitPolicy::default()
    }
}

fn device(d: ClientDevice) -> EmitPolicy {
    EmitPolicy {
        device: Some(d),
        ..EmitPolicy::default()
    }
}

fn fp(v: &Value) -> &str {
    v["tls"]["utls"]["fingerprint"]
        .as_str()
        .expect("utls fingerprint")
}

/// AT-04-006 (tunnel-core §7.6): rotation hashes computed with a replica of the old code.
#[test]
fn stealth_rotation_matches_the_old_hash() {
    for (seed, expected) in [
        ("example.com:443:abc", "edge"),
        ("s0.example.com:443:u0", "edge"),
        ("s1.example.com:443:u1", "chrome"),
        ("192.0.2.1:443:SYNTHETIC", "chrome"),
        ("198.51.100.2:443:", "chrome"),
        (
            "server.test:443:00000000-0000-4000-8000-000000000000",
            "firefox",
        ),
        ("example.com:8443:PASSWORD_PLACEHOLDER", "chrome"),
        ("сервер.test:443:x", "edge"),
        ("::", "edge"),
    ] {
        assert_eq!(stealth_fingerprint(seed), expected, "{seed}");
    }
    // h == i32::MIN must not overflow (JS Math.abs gives 2147483648 -> index 2).
    assert_eq!(i32::MIN.unsigned_abs() % 3, 2);
}

/// AT-04-006: 50 servers in stealth mode rotate among Windows-plausible browsers only.
#[test]
fn stealth_rotation_never_picks_safari() {
    for i in 0..50 {
        let mut p = trojan(&format!("s{i}.example.com"));
        p.kind = Kind::Trojan {
            password: format!("u{i}"),
        };
        p.tls = Some(tls("front.example.com"));
        let o = out(&p, &stealth());
        assert!(
            ["chrome", "firefox", "edge"].contains(&fp(&o)),
            "{}",
            fp(&o)
        );
        assert_eq!(o["tls"]["record_fragment"], true);
    }
    // The profile seed is exactly `server:port:credential`.
    let mut p = trojan("example.com");
    p.kind = Kind::Trojan {
        password: "abc".into(),
    };
    p.tls = Some(tls("example.com"));
    assert_eq!(fp(&out(&p, &stealth())), "edge");
}

/// profiles §7.2 "device default fp": TLS outbound without provider fingerprint.
#[test]
fn device_picks_the_default_fingerprint() {
    let mut p = vless("v.example.com");
    p.tls = Some(tls("v.example.com"));
    assert_eq!(fp(&out(&p, &EmitPolicy::default())), "chrome");
    for (d, expected) in [
        (ClientDevice::Pc, "chrome"),
        (ClientDevice::Android, "android"),
        (ClientDevice::Ios, "ios"),
        (ClientDevice::Mac, "safari"),
    ] {
        assert_eq!(fp(&out(&p, &device(d))), expected);
        // Device + stealth: the device wins over rotation, the fragment is still added.
        let policy = EmitPolicy {
            device: Some(d),
            tls_compat: true,
            ..EmitPolicy::default()
        };
        let o = out(&p, &policy);
        assert_eq!(
            (fp(&o), &o["tls"]["record_fragment"]),
            (expected, &json!(true))
        );
    }
    // Plain Shadowsocks has no TLS to touch.
    let o = out(&ss("aes-256-gcm", "pass"), &device(ClientDevice::Android));
    assert!(o.get("tls").is_none());
}

/// RU 2026 plan: REALITY servers since Xray 26.9.8 refuse the `android` / `ios` hellos, so a
/// REALITY key without a provider fingerprint gets `chrome` on every device; the provider's own
/// choice still wins (the importers note the risky ones).
#[test]
fn reality_default_fingerprint_is_chrome() {
    let mut p = vless("v.example.com");
    p.tls = Some(Tls {
        reality: Some(reality()),
        ..tls("www.example.com")
    });
    for d in [
        ClientDevice::Pc,
        ClientDevice::Android,
        ClientDevice::Ios,
        ClientDevice::Mac,
    ] {
        for tls_compat in [false, true] {
            let policy = EmitPolicy {
                device: Some(d),
                tls_compat,
                ..EmitPolicy::default()
            };
            assert_eq!(fp(&out(&p, &policy)), "chrome", "{d:?}");
            assert_eq!(effective_fingerprint(&p, &policy), Some("chrome"));
        }
    }
    p.tls = Some(Tls {
        fingerprint: Some("ios".into()),
        reality: Some(reality()),
        ..tls("www.example.com")
    });
    assert_eq!(fp(&out(&p, &device(ClientDevice::Android))), "ios");
}

/// AT-04-006 (K3): the provider's fingerprint and ALPN win over device and stealth defaults.
#[test]
fn provider_fingerprint_and_alpn_win() {
    let mut p = vless("v.example.com");
    p.tls = Some(Tls {
        fingerprint: Some("firefox".into()),
        alpn: vec!["http/1.1".into()],
        ..tls("v.example.com")
    });
    for policy in [
        device(ClientDevice::Pc),
        device(ClientDevice::Android),
        EmitPolicy {
            device: Some(ClientDevice::Pc),
            tls_compat: true,
            ..EmitPolicy::default()
        },
        stealth(),
    ] {
        let o = out(&p, &policy);
        assert_eq!(fp(&o), "firefox");
        assert_eq!(o["tls"]["alpn"], json!(["http/1.1"]));
    }
    // A name sing-box does not know would stop the engine: the app default is used instead.
    p.tls = Some(Tls {
        fingerprint: Some("randomizednoalpn".into()),
        ..tls("v.example.com")
    });
    assert_eq!(fp(&out(&p, &device(ClientDevice::Android))), "android");
    assert_eq!(
        effective_fingerprint(&p, &device(ClientDevice::Android)),
        Some("android")
    );
}

/// tunnel-core §7.6: plain TLS + stealth fragments; Reality never does; Reality keeps uTLS.
#[test]
fn record_fragment_only_for_tcp_tls_without_reality() {
    let mut p = vless("v.example.com");
    p.tls = Some(tls("v.example.com"));
    assert_eq!(out(&p, &stealth())["tls"]["record_fragment"], true);
    assert!(
        out(&p, &EmitPolicy::default())["tls"]
            .get("record_fragment")
            .is_none()
    );

    p.tls = Some(Tls {
        reality: Some(reality()),
        ..tls("www.example.com")
    });
    let o = out(&p, &stealth());
    assert!(o["tls"].get("record_fragment").is_none());
    // Reality without a device pin keeps chrome (no rotation), never `spider_x` (Xray only).
    assert_eq!(fp(&o), "chrome");
    assert_eq!(
        o["tls"]["reality"],
        json!({ "enabled": true, "public_key": PBK, "short_id": "1234" })
    );
    assert!(!o.to_string().contains("spider"));
}

/// P-01 / P-02 / B-06: no uTLS, ALPN or fragments on QUIC families and naive.
#[test]
fn quic_and_naive_get_no_utls_alpn_or_fragment() {
    let mut h = hy2("hy2.example.com");
    h.tls = Some(Tls {
        fingerprint: Some("chrome".into()),
        ..tls("front.example.com")
    });
    let o = out(&h, &stealth());
    assert_eq!(
        o["tls"],
        json!({ "enabled": true, "server_name": "front.example.com" })
    );
    assert_eq!(effective_fingerprint(&h, &stealth()), None);

    // Hysteria2 without TLS settings still gets the TLS sing-box requires, without ALPN.
    h.tls = None;
    assert_eq!(
        out(&h, &EmitPolicy::default())["tls"],
        json!({ "enabled": true })
    );

    // TUIC servers commonly expect h3: the only ALPN the emitter ever adds.
    let o = out(&tuic("tuic.example.com"), &stealth());
    assert_eq!(o["tls"], json!({ "enabled": true, "alpn": ["h3"] }));

    let mut n = naive("naive.example.com");
    n.tls = Some(Tls {
        insecure: true,
        alpn: vec!["h2".into()],
        fingerprint: Some("chrome".into()),
        ..tls("front.example.com")
    });
    let o = out(&n, &stealth());
    assert_eq!(
        o["tls"],
        json!({ "enabled": true, "server_name": "front.example.com" })
    );

    // The v2ray QUIC transport goes through the same QUIC TLS path.
    let mut v = vless("v.example.com");
    v.tls = Some(Tls {
        fingerprint: Some("firefox".into()),
        ..tls("v.example.com")
    });
    v.transport = Some(Transport::Quic);
    let o = out(&v, &stealth());
    assert!(o["tls"].get("utls").is_none() && o["tls"].get("record_fragment").is_none());
    assert_eq!(o["transport"], json!({ "type": "quic" }));
}

/// P-01: ALPN is never injected; ws / grpc / raw TCP rely on transport or preset defaults.
#[test]
fn alpn_is_provider_only() {
    let mut p = trojan("t.example.com");
    p.tls = Some(tls("t.example.com"));
    for t in [
        None,
        Some(Transport::Ws {
            path: "/ws".into(),
            host: None,
            max_early_data: None,
            early_data_header: None,
        }),
        Some(Transport::Grpc {
            service_name: "svc".into(),
            multi_mode: None,
        }),
    ] {
        p.transport = t;
        assert!(out(&p, &EmitPolicy::default())["tls"].get("alpn").is_none());
    }
    let mut h = hy2("hy2.example.com");
    h.tls = Some(Tls {
        alpn: vec!["h3".into()],
        ..tls("s.example")
    });
    assert_eq!(
        out(&h, &EmitPolicy::default())["tls"]["alpn"],
        json!(["h3"])
    );
}

/// Engine audit (P-03): `insecure` never goes out next to a certificate pin sing-box cannot
/// check (the key used to run with no certificate check at all); a public-key pin goes out as
/// `certificate_public_key_sha256`, which sing-box verifies even with `insecure` set.
#[test]
fn insecure_needs_an_enforced_pin() {
    const SPKI: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    let mut h = hy2("a.example");
    h.kind = Kind::Hysteria2 {
        password: "pw".into(),
        obfs: Some(Hy2Obfs {
            kind: "salamander".into(),
            password: "op".into(),
        }),
        ports: Vec::new(),
        hop_interval_s: None,
        hop_interval_max_s: None,
        up_mbps: None,
        down_mbps: None,
        bbr_profile: None,
    };
    let pinned = Tls {
        insecure: true,
        alpn: vec!["h3".into()],
        cert_pin_sha256: Some("ab".repeat(32)),
        ..tls("s.example")
    };
    h.tls = Some(pinned.clone());
    let refused = emit_singbox(&h, "proxy-out", &EmitPolicy::default());
    assert_eq!(refused, Err(EmitError::CertPinUnenforced));
    let err = AppError::from(EmitError::CertPinUnenforced);
    assert_eq!(
        (err.kind, err.user_msg().key.as_ref()),
        (ErrorKind::Validation, "profiles.emit.certPinUnenforced")
    );
    // The same rule for every TLS kind, the ShadowTLS dialer included.
    let mut t = trojan("t.example");
    t.tls = Some(pinned.clone());
    let mut chain = chained();
    chain.tls = Some(pinned.clone());
    for p in [&t, &chain] {
        let refused = emit_singbox(p, "proxy-out", &EmitPolicy::default());
        assert_eq!(
            refused,
            Err(EmitError::CertPinUnenforced),
            "{}",
            p.kind.label()
        );
    }

    h.tls = Some(Tls {
        spki_pin_sha256: vec![SPKI.into()],
        ..pinned.clone()
    });
    let o = out(&h, &EmitPolicy::default());
    assert_eq!(
        o["tls"],
        json!({ "enabled": true, "server_name": "s.example", "insecure": true, "alpn": ["h3"],
                "certificate_public_key_sha256": [SPKI] })
    );
    assert_eq!(o["obfs"], json!({ "type": "salamander", "password": "op" }));
    // Without `insecure` the CA check runs; the pin it cannot add stays a Note of the profile.
    h.tls = Some(Tls {
        insecure: false,
        ..pinned.clone()
    });
    assert_eq!(
        out(&h, &EmitPolicy::default())["tls"],
        json!({ "enabled": true, "server_name": "s.example", "alpn": ["h3"] })
    );
    // A blank pin is no pin: `insecure` as the provider asked.
    h.tls = Some(Tls {
        cert_pin_sha256: Some("  ".into()),
        ..pinned
    });
    assert_eq!(out(&h, &EmitPolicy::default())["tls"]["insecure"], true);
}

/// profiles §7.1 "HY2 advanced" / "HY2 comma ports", P-10: hopping, Go durations, int Mbps.
#[test]
fn hy2_ports_and_durations() {
    let mut h = hy2("hy2.example.com");
    h.kind = Kind::Hysteria2 {
        password: "secret".into(),
        obfs: Some(Hy2Obfs {
            kind: "salamander".into(),
            password: "pepper".into(),
        }),
        ports: vec![(8443, 8450), (9443, 9443), (10443, 10445)],
        hop_interval_s: Some(30),
        hop_interval_max_s: Some(60),
        up_mbps: Some(80),
        down_mbps: Some(200),
        bbr_profile: Some("standard".into()),
    };
    h.tls = Some(tls("front.example.com"));
    let o = out(&h, &EmitPolicy::default());
    assert_eq!(
        o["server_ports"],
        json!(["8443:8450", "9443:9443", "10443:10445"])
    );
    assert!(o.get("server_port").is_none() && o.get("network").is_none());
    assert_eq!(
        (&o["hop_interval"], &o["hop_interval_max"]),
        (&json!("30s"), &json!("60s"))
    );
    assert_eq!((&o["up_mbps"], &o["down_mbps"]), (&json!(80), &json!(200)));
    assert_eq!(o["bbr_profile"], "standard");

    // K13: a legacy tcp-only `network` is dropped so the UDP guard does not block QUIC.
    h.singbox_extra.insert("network".into(), json!("tcp"));
    assert!(out(&h, &EmitPolicy::default()).get("network").is_none());
    assert!(udp_capable(&h) && !block_quic(&h));
}

/// P-07: AnyTLS idle values are sing-box durations, not `*_ms` keys (30000 ms is stored as 30 s).
#[test]
fn anytls_idle_durations() {
    let mut a = anytls("any.example.com");
    a.kind = Kind::Anytls {
        password: "secret".into(),
        idle_check_s: Some(30),
        idle_timeout_s: Some(60),
        min_idle: Some(2),
    };
    a.tls = Some(tls("x"));
    a.dial.tcp_fast_open = true;
    let o = out(&a, &EmitPolicy::default());
    assert_eq!(o["idle_session_check_interval"], "30s");
    assert_eq!(o["idle_session_timeout"], "60s");
    assert_eq!(o["min_idle_session"], 2);
    assert!(!o.to_string().contains("_ms\""));
    // anytls refuses TCP Fast Open; the dial preference cannot apply there.
    assert!(o.get("tcp_fast_open").is_none());
    // TLS is mandatory for anytls even when the profile names none.
    a.tls = None;
    assert_eq!(out(&a, &EmitPolicy::default())["tls"]["enabled"], true);
}

/// P-32 / profiles §7.1 "ECH params": bare base64 becomes one `ECH CONFIGS` PEM block.
#[test]
fn ech_config_is_wrapped_in_pem() {
    let (head, tail) = ECH_B64.split_at(64);
    let mut n = naive("naive.example.com");
    let ech = Ech {
        config_lines: vec![head.into(), tail.into()],
        query_server_name: Some("cloudflare-ech.com".into()),
    };
    n.tls = Some(Tls {
        ech: Some(ech),
        ..tls("front.example.com")
    });
    let o = out(&n, &EmitPolicy::default());
    let pem = json!([
        "-----BEGIN ECH CONFIGS-----",
        head,
        tail,
        "-----END ECH CONFIGS-----"
    ]);
    assert_eq!(
        o["tls"]["ech"],
        json!({ "enabled": true, "config": pem, "query_server_name": "cloudflare-ech.com" })
    );

    // URL-safe, unpadded (as links carry it) gives the same canonical block.
    let url_safe = ECH_B64
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_owned();
    n.tls = Some(Tls {
        ech: Some(Ech {
            config_lines: vec![url_safe],
            query_server_name: None,
        }),
        ..tls("f.example")
    });
    assert_eq!(out(&n, &EmitPolicy::default())["tls"]["ech"]["config"], pem);

    // A provider PEM passes through; no config means "look it up in DNS".
    let lines = pem
        .as_array()
        .expect("lines")
        .iter()
        .map(|l| l.as_str().unwrap_or_default().to_owned())
        .collect();
    n.tls = Some(Tls {
        ech: Some(Ech {
            config_lines: lines,
            query_server_name: None,
        }),
        ..tls("f.example")
    });
    assert_eq!(out(&n, &EmitPolicy::default())["tls"]["ech"]["config"], pem);
    n.tls = Some(Tls {
        ech: Some(Ech::default()),
        ..tls("f.example")
    });
    assert_eq!(
        out(&n, &EmitPolicy::default())["tls"]["ech"],
        json!({ "enabled": true })
    );

    // The spec's synthetic `abc,def` is not base64: refused before the engine would refuse it.
    let bad = Ech {
        config_lines: vec!["abc".into(), "def".into()],
        query_server_name: None,
    };
    n.tls = Some(Tls {
        ech: Some(bad),
        ..tls("f.example")
    });
    assert_eq!(
        emit_singbox(&n, "x", &EmitPolicy::default()),
        Err(EmitError::EchConfig)
    );
}

/// Xray-only features (profiles §6.3) never reach sing-box.
#[test]
fn xray_only_features_are_refused() {
    let mut p = vless("v.example.com");
    p.kind = Kind::Vless {
        uuid: UUID.into(),
        flow: None,
        packet_encoding: None,
        encryption: Some("mlkem768x25519plus.native.0rtt.x".into()),
    };
    assert_eq!(
        emit_singbox(&p, "x", &EmitPolicy::default()),
        Err(EmitError::XrayOnly("VLESS encryption"))
    );
    // `encryption=none` (Clash, links) is plain VLESS: emitted without the key (P-06).
    p.kind = Kind::Vless {
        uuid: UUID.into(),
        flow: None,
        packet_encoding: None,
        encryption: Some("none".into()),
    };
    assert!(out(&p, &EmitPolicy::default()).get("encryption").is_none());

    let cases = [
        (
            Transport::Xhttp {
                host: "h".into(),
                path: "/a".into(),
                mode: Some("packet-up".into()),
                extra: None,
            },
            "XHTTP",
        ),
        (
            Transport::Grpc {
                service_name: "s".into(),
                multi_mode: Some(true),
            },
            "gRPC multiMode",
        ),
        (
            Transport::TcpHttpHeader {
                host: vec!["h".into()],
                path: vec!["/".into()],
            },
            "TCP header=http",
        ),
    ];
    for (t, feature) in cases {
        p.transport = Some(t);
        assert_eq!(
            emit_singbox(&p, "x", &EmitPolicy::default()),
            Err(EmitError::XrayOnly(feature))
        );
    }
    // An explicit gun mode is what sing-box's gRPC transport speaks (engine selection lets
    // sing-box run it; Auto still prefers Xray for it).
    p.transport = Some(Transport::Grpc {
        service_name: "s".into(),
        multi_mode: Some(false),
    });
    assert_eq!(
        out(&p, &EmitPolicy::default())["transport"],
        json!({ "type": "grpc", "service_name": "s" })
    );
    let mut n = trojan("t.example.com");
    n.native_xray = Some(NativeXray {
        version: 1,
        selected_tag: "leaf".into(),
        entry: NativeEntry {
            outbound_tag: Some("leaf".into()),
            balancer_tag: None,
        },
        outbounds: vec![json!({ "tag": "leaf", "protocol": "trojan" })],
        routing: None,
        observatory: None,
        burst_observatory: None,
        policy: None,
    });
    assert_eq!(
        emit_singbox(&n, "x", &EmitPolicy::default()),
        Err(EmitError::XrayOnly("Xray JSON"))
    );
}

/// tunnel-core §7.7 / §7.6: multiplex kept on the four sing-mux protocols, refused elsewhere.
#[test]
fn multiplex_rules() {
    let disabled = Mux {
        enabled: false,
        protocol: Some("smux".into()),
        max_connections: Some(3),
        padding: true,
        brutal: None,
    };
    let concurrency = Mux {
        enabled: true,
        max_connections: Some(6),
        padding: true,
        ..Mux::default()
    };
    for base in [
        vless("v.example.com"),
        vmess("m.example.com"),
        trojan("t.example.com"),
        ss("aes-128-gcm", "p"),
    ] {
        let mut p = base;
        p.mux = Some(disabled.clone());
        let o = out(&p, &EmitPolicy::default());
        assert_eq!(
            o["multiplex"],
            json!({ "enabled": false, "protocol": "smux", "max_connections": 3, "padding": true })
        );
        p.mux = Some(concurrency.clone());
        let o = out(&p, &EmitPolicy::default());
        assert_eq!(
            o["multiplex"],
            json!({ "enabled": true, "max_connections": 6, "padding": true })
        );
        assert!(o.get("mux").is_none());
        // The tunnel may forbid mux for this connection.
        let policy = EmitPolicy {
            allow_mux: false,
            ..EmitPolicy::default()
        };
        assert!(out(&p, &policy).get("multiplex").is_none());
    }
    // Reality + h2mux + padding (TSPU parallel-ClientHello mitigation) and TCP Brutal.
    let mut r = vless("r.example.com");
    r.tls = Some(Tls {
        reality: Some(reality()),
        ..tls("www.example.com")
    });
    r.mux = Some(Mux {
        enabled: true,
        protocol: Some("h2mux".into()),
        padding: true,
        brutal: Some((50, 100)),
        ..Mux::default()
    });
    let o = out(&r, &EmitPolicy::default());
    assert_eq!(
        o["multiplex"],
        json!({ "enabled": true, "protocol": "h2mux", "padding": true,
                "brutal": { "enabled": true, "up_mbps": 50, "down_mbps": 100 } })
    );
    let mut h = hy2("hy2.example.com");
    h.mux = Some(Mux {
        enabled: true,
        ..Mux::default()
    });
    assert_eq!(
        emit_singbox(&h, "x", &EmitPolicy::default()),
        Err(EmitError::MuxUnsupported("hysteria2"))
    );
    h.mux = Some(Mux::default());
    assert!(out(&h, &EmitPolicy::default()).get("multiplex").is_none());
    let err = AppError::from(EmitError::MuxUnsupported("hysteria2"));
    assert_eq!(
        (err.kind, err.user_msg().key.as_ref()),
        (ErrorKind::Validation, "profiles.emit.muxUnsupported")
    );
}

fn with_extra(mut p: Profile, key: &str, value: Value) -> Profile {
    p.singbox_extra.insert(key.into(), value);
    p
}

/// tunnel-core §7.8 (AT-02-008 / AT-06-001): UDP capability table.
#[test]
fn udp_capability_table() {
    let vless_pe = |pe: Option<&str>| {
        let mut p = vless("v.example.com");
        p.kind = Kind::Vless {
            uuid: UUID.into(),
            flow: None,
            packet_encoding: pe.map(Into::into),
            encryption: None,
        };
        p
    };
    let mut reality_vless = vless_pe(None);
    reality_vless.tls = Some(Tls {
        reality: Some(reality()),
        ..tls("www.example.com")
    });
    let wg = wireguard(vec![peer("203.0.113.5", &[])]);
    let socks = profile(
        "127.0.0.1",
        1080,
        Kind::Socks {
            username: None,
            password: None,
        },
    );
    let http = profile(
        "proxy.example.com",
        8080,
        Kind::Http {
            username: None,
            password: None,
        },
    );
    let cases: Vec<(Profile, bool)> = vec![
        (hy2("h.example"), true),
        (tuic("t.example"), true),
        (wg, true),
        (ss("aes-256-gcm", "p"), true),
        (vless_pe(Some("xudp")), true),
        (vless_pe(Some("packetaddr")), true),
        (vless_pe(None), true),
        (vless_pe(Some("")), false),
        (reality_vless, true),
        (with_extra(vless_pe(None), "network", json!("tcp")), false),
        (with_extra(vless_pe(None), "network", json!(["tcp"])), false),
        (
            with_extra(vless_pe(None), "network", json!(["tcp", "udp"])),
            true,
        ),
        (vmess("m.example"), true),
        (trojan("t.example"), true),
        (socks, true),
        (http, false),
        (naive("n.example"), false),
        // CHANGED: sing-box 1.14 anytls relays UDP over UoT v2 unconditionally, naive with
        // `udp_over_tcp` (tunnel-core §3.16 listed both as TCP-only).
        (anytls("a.example"), true),
        (
            with_extra(naive("n.example"), "udp_over_tcp", json!(true)),
            true,
        ),
        (
            with_extra(
                naive("n.example"),
                "udp_over_tcp",
                json!({ "enabled": true, "version": 2 }),
            ),
            true,
        ),
        (
            with_extra(naive("n.example"), "udp_over_tcp", json!({ "version": 2 })),
            false,
        ),
        (
            with_extra(anytls("a.example"), "network", json!("tcp")),
            false,
        ),
        // CHANGED (K13): the emitter drops HY2's legacy `network:"tcp"`, so UDP stays on.
        (with_extra(hy2("h.example"), "network", json!("tcp")), true),
    ];
    for (p, expected) in cases {
        assert_eq!(
            udp_capable(&p),
            expected,
            "{:?} {:?}",
            p.kind,
            p.singbox_extra
        );
    }
    // ShadowTLS is a TCP-only dialer: only UDP-over-TCP gets UDP through.
    let layer = ShadowTlsLayer {
        version: 3,
        password: "st".into(),
        server_name: "front.example.com".into(),
    };
    let mut chained = ss("aes-256-gcm", "p");
    chained.kind = Kind::Shadowsocks {
        method: "aes-256-gcm".into(),
        password: "p".into(),
        plugin: None,
        shadowtls: Some(layer),
        uot: None,
    };
    assert!(!udp_capable(&chained));
    if let Kind::Shadowsocks { uot, .. } = &mut chained.kind {
        *uot = Some(2);
    }
    assert!(udp_capable(&chained));
}

/// tunnel-core §7.8: when UDP/443 is rejected so browsers fall back from QUIC to TCP.
#[test]
fn quic_block_table() {
    let mut x = vless("v.example.com");
    assert!(block_quic(&x));
    x.kind = Kind::Vless {
        uuid: UUID.into(),
        flow: None,
        packet_encoding: Some("xudp".into()),
        encryption: None,
    };
    assert!(!block_quic(&x));
    assert!(!block_quic(&hy2("h.example")));
    assert!(block_quic(&profile(
        "p.example",
        8080,
        Kind::Http {
            username: None,
            password: None
        }
    )));
    assert!(!block_quic(&trojan("t.example")));
    assert!(!block_quic(&anytls("a.example")));
    assert!(block_quic(&naive("n.example")));

    // Native Xray graph: a muxed outbound rejects UDP/443 unless `xudpProxyUDP443` allows it.
    let graph = |muxes: Vec<Value>| NativeXray {
        version: 1,
        selected_tag: "leaf".into(),
        entry: NativeEntry {
            outbound_tag: Some("leaf".into()),
            balancer_tag: None,
        },
        outbounds: muxes
            .into_iter()
            .map(|mux| json!({ "tag": "leaf", "protocol": "vless", "mux": mux }))
            .collect(),
        routing: None,
        observatory: None,
        burst_observatory: None,
        policy: None,
    };
    for (mux, blocked) in [
        (json!({ "enabled": true }), true),
        (
            json!({ "enabled": true, "xudpProxyUDP443": "reject" }),
            true,
        ),
        (
            json!({ "enabled": true, "xudpConcurrency": -1, "xudpProxyUDP443": "reject" }),
            true,
        ),
        (
            json!({ "enabled": true, "xudpProxyUDP443": "allow" }),
            false,
        ),
        (json!({ "enabled": true, "xudpProxyUDP443": "skip" }), false),
        (
            json!({ "enabled": false, "xudpProxyUDP443": "reject" }),
            false,
        ),
    ] {
        x.native_xray = Some(graph(vec![mux.clone()]));
        assert_eq!(block_quic(&x), blocked, "{mux}");
        assert!(udp_capable(&x), "never an all-UDP block");
    }
    // An extra bridge outbound with mux on is enough.
    x.native_xray = Some(graph(vec![
        json!({ "enabled": false }),
        json!({ "enabled": true }),
    ]));
    assert!(block_quic(&x));
}

fn endpoint(p: &Profile, policy: &EmitPolicy) -> Value {
    match emit(p, policy) {
        SingBoxFragment::Endpoint(v) => v,
        other => panic!("not an endpoint: {other:?}"),
    }
}

/// tunnel-core §7.12 (AT-04-002 / F-047): WireGuard becomes an endpoint with the K21 defaults.
#[test]
fn wireguard_endpoint_shape() {
    let p = wireguard(vec![peer("203.0.113.5", &[])]);
    assert_eq!(
        endpoint(&p, &EmitPolicy::default()),
        json!({ "type": "wireguard", "tag": "proxy-out", "address": ["10.0.0.2/32"], "private_key": "PRIV",
                "peers": [{ "address": "203.0.113.5", "port": 51820, "public_key": "PUB",
                            "allowed_ips": ["0.0.0.0/0", "::/0"] }] })
    );

    let mut p = wireguard(vec![peer(
        "2001:db8::1",
        &["10.1.0.0/16", "192.0.2.7/32", "fd00::/8"],
    )]);
    if let Kind::Wireguard(wg) = &mut p.kind {
        wg.local_address = vec![
            "fd00::2/128".parse().expect("v6"),
            "10.0.0.2/24".parse().expect("v4"),
        ];
        wg.mtu = Some(1280);
        wg.dns = vec!["1.1.1.1".parse().expect("ip")];
        let peer = &mut wg.peers[0];
        peer.pre_shared_key = Some("PSK".into());
        peer.keepalive_s = Some(25);
        peer.reserved = Some([1, 2, 3]);
    }
    let e = endpoint(&p, &EmitPolicy::default());
    assert_eq!(e["address"], json!(["fd00::2/128", "10.0.0.2/24"]));
    assert_eq!(e["mtu"], 1280);
    assert!(e.get("dns_servers").is_none() && e.get("dns").is_none());
    assert_eq!(
        e["peers"][0],
        json!({ "address": "2001:db8::1", "port": 51820, "public_key": "PUB", "pre_shared_key": "PSK",
                "allowed_ips": ["10.1.0.0/16", "192.0.2.7/32", "fd00::/8"],
                "persistent_keepalive_interval": 25, "reserved": [1, 2, 3] })
    );
    // An empty pre-shared key is omitted; IPv6 peers are never bracketed.
    if let Kind::Wireguard(wg) = &mut p.kind {
        wg.peers[0].pre_shared_key = Some(String::new());
    }
    assert!(
        endpoint(&p, &EmitPolicy::default())["peers"][0]
            .get("pre_shared_key")
            .is_none()
    );
}

/// tunnel-core §7.12: privileged-core restrictions and the error cases.
#[test]
fn wireguard_restrictions_and_errors() {
    let mut p = wireguard(vec![peer("203.0.113.5", &[])]);
    for (key, value) in [
        ("system", json!(true)),
        ("name", json!("wg9")),
        ("listen_port", json!(10000)),
        ("detour", json!("direct")),
        ("udp_timeout", json!("5m")),
        ("workers", json!(2)),
    ] {
        p.singbox_extra.insert(key.into(), value);
    }
    let e = endpoint(&p, &EmitPolicy::default());
    for dropped in ["system", "name", "listen_port", "detour"] {
        assert!(e.get(dropped).is_none(), "{dropped}");
    }
    assert_eq!(
        (&e["udp_timeout"], &e["workers"]),
        (&json!("5m"), &json!(2))
    );

    let err =
        |p: &Profile| emit_singbox(p, "proxy-out", &EmitPolicy::default()).expect_err("must fail");
    let two = wireguard(vec![
        peer("203.0.113.5", &[]),
        peer("203.0.113.6", &["10.0.0.0/8"]),
    ]);
    assert_eq!(
        err(&two),
        EmitError::WireGuard(WgProblem::AllowedIpsRequired)
    );
    let ok = wireguard(vec![
        peer("203.0.113.5", &["0.0.0.0/0"]),
        peer("wg.example", &["10.0.0.0/8"]),
    ]);
    assert_eq!(
        endpoint(&ok, &EmitPolicy::default())["peers"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );

    let broken = |edit: fn(&mut WireGuard)| {
        let mut p = wireguard(vec![peer("203.0.113.5", &[])]);
        if let Kind::Wireguard(wg) = &mut p.kind {
            edit(wg);
        }
        err(&p)
    };
    assert_eq!(
        broken(|wg| wg.local_address.clear()),
        EmitError::WireGuard(WgProblem::NoAddress)
    );
    assert_eq!(
        broken(|wg| wg.private_key.clear()),
        EmitError::WireGuard(WgProblem::NoPrivateKey)
    );
    assert_eq!(
        broken(|wg| wg.peers.clear()),
        EmitError::WireGuard(WgProblem::NoPeer)
    );
    assert_eq!(
        broken(|wg| wg.peers[0].host = Host::Domain(String::new())),
        EmitError::WireGuard(WgProblem::NoPeerAddress)
    );
    assert_eq!(
        broken(|wg| wg.peers[0].port = 0),
        EmitError::WireGuard(WgProblem::BadPeerPort)
    );
    assert_eq!(
        broken(|wg| wg.peers[0].public_key.clear()),
        EmitError::WireGuard(WgProblem::NoPublicKey)
    );
    let msg = AppError::from(EmitError::WireGuard(WgProblem::NoPeer)).user_msg();
    assert_eq!(msg.key, "profiles.emit.wireguard.noPeer");
}

/// tunnel-core §7.12 "generated config": hostname peers need the bootstrap resolver.
#[test]
fn wireguard_bootstrap_dns() {
    let policy = EmitPolicy {
        domain_resolver: Some("dns-bootstrap".into()),
        ..EmitPolicy::default()
    };
    let ip = emit(&wireguard(vec![peer("203.0.113.5", &[])]), &policy);
    assert!(!ip.needs_bootstrap_dns());
    assert_eq!(
        ip.endpoint_ips(),
        vec!["203.0.113.5".parse::<std::net::IpAddr>().expect("ip")]
    );
    assert!(ip.endpoints()[0].get("domain_resolver").is_none());
    assert!(ip.outbounds().is_empty());

    let mixed = wireguard(vec![
        peer("wg.example", &["10.0.0.0/8"]),
        peer("203.0.113.6", &["10.1.0.0/16"]),
    ]);
    let fragment = emit(&mixed, &policy);
    assert!(fragment.needs_bootstrap_dns());
    assert_eq!(
        fragment.endpoints()[0]["domain_resolver"],
        json!({ "server": "dns-bootstrap", "strategy": "ipv4_only" })
    );
    // Without a resolver tag the engine's default resolver applies.
    assert!(
        endpoint(&mixed, &EmitPolicy::default())
            .get("domain_resolver")
            .is_none()
    );
}

fn chained() -> Profile {
    let layer = ShadowTlsLayer {
        version: 3,
        password: "st-pass".into(),
        server_name: "front.example.com".into(),
    };
    let mut p = ss("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==");
    p.kind = Kind::Shadowsocks {
        method: "2022-blake3-aes-128-gcm".into(),
        password: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
        plugin: None,
        shadowtls: Some(layer),
        uot: None,
    };
    p
}

/// P-11: Shadowsocks + ShadowTLS is one profile emitted as two outbounds linked by `detour`.
#[test]
fn shadowtls_chain_shape() {
    let mut p = chained();
    p.dial.connect_timeout_s = Some(5);
    let policy = EmitPolicy {
        domain_resolver: Some("dns-bootstrap".into()),
        ..EmitPolicy::default()
    };
    let SingBoxFragment::Chain(list) = emit(&p, &policy) else {
        panic!("not a chain")
    };
    assert_eq!(
        list[0],
        json!({ "type": "shadowsocks", "tag": "proxy-out", "server": "ss.example.com", "server_port": 8388,
                "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA==",
                "detour": "proxy-out-shadowtls" })
    );
    assert_eq!(
        list[1],
        json!({ "type": "shadowtls", "tag": "proxy-out-shadowtls", "server": "ss.example.com", "server_port": 8388,
                "version": 3, "password": "st-pass",
                "tls": { "enabled": true, "server_name": "front.example.com",
                         "utls": { "enabled": true, "fingerprint": "chrome" } },
                "connect_timeout": "5s",
                "domain_resolver": { "server": "dns-bootstrap", "strategy": "ipv4_only" } })
    );
    let fragment = SingBoxFragment::Chain(list);
    // Only the ShadowTLS dialer resolves the server; the detour outbound never dials itself.
    assert!(fragment.needs_bootstrap_dns());
    assert_eq!(
        effective_fingerprint(&p, &EmitPolicy::default()),
        Some("chrome")
    );
    // Stealth rotates the layer's fingerprint but never splits its ClientHello: the v3 server
    // authenticates the first TLS record as the whole hello.
    let stealthy = emit(&p, &stealth());
    let layer = &stealthy.outbounds()[1];
    assert!(layer["tls"].get("record_fragment").is_none());
    assert_eq!(Some(fp(layer)), effective_fingerprint(&p, &stealth()));
    // TLS on a plain Shadowsocks profile cannot be honoured: refused, not dropped.
    let mut plain = ss("aes-256-gcm", "p");
    plain.tls = Some(tls("x.example"));
    assert_eq!(
        emit_singbox(&plain, "x", &EmitPolicy::default()),
        Err(EmitError::TlsUnsupported("shadowsocks"))
    );
}

/// profiles §3.9 emit rules: transports, IPv6 hosts, protocol fields and Go durations.
#[test]
fn protocol_and_transport_fields() {
    let mut v = vless("2001:db8::1");
    v.tls = Some(Tls {
        alpn: vec!["h2".into()],
        ..tls("front.example.com")
    });
    v.transport = Some(Transport::Ws {
        path: "/ws".into(),
        host: Some("cdn.example".into()),
        max_early_data: Some(2048),
        early_data_header: Some("Sec-WebSocket-Protocol".into()),
    });
    let o = out(&v, &EmitPolicy::default());
    assert_eq!(o["server"], "2001:db8::1");
    assert_eq!(
        o["transport"],
        json!({ "type": "ws", "path": "/ws", "headers": { "Host": "cdn.example" }, "max_early_data": 2048,
                "early_data_header_name": "Sec-WebSocket-Protocol" })
    );
    v.transport = Some(Transport::HttpUpgrade {
        host: "cdn.example".into(),
        path: "/up".into(),
    });
    assert_eq!(
        out(&v, &EmitPolicy::default())["transport"],
        json!({ "type": "httpupgrade", "host": "cdn.example", "path": "/up" })
    );
    v.transport = Some(Transport::Http {
        hosts: vec!["a.example".into(), "b.example".into()],
        path: "/h".into(),
    });
    assert_eq!(
        out(&v, &EmitPolicy::default())["transport"],
        json!({ "type": "http", "host": ["a.example", "b.example"], "path": "/h" })
    );
    // sing-box knows one flow name and lower-case packet encodings only.
    v.kind = Kind::Vless {
        uuid: UUID.into(),
        flow: Some("xtls-rprx-vision-udp443".into()),
        packet_encoding: Some(" XUDP ".into()),
        encryption: None,
    };
    let o = out(&v, &EmitPolicy::default());
    assert_eq!(
        (&o["flow"], &o["packet_encoding"]),
        (&json!("xtls-rprx-vision"), &json!("xudp"))
    );

    let mut t = tuic("tuic.example.com");
    t.kind = Kind::Tuic {
        uuid: UUID.into(),
        password: "secret".into(),
        congestion: Some("bbr".into()),
        udp_relay_mode: Some("native".into()),
        zero_rtt: true,
        heartbeat_s: Some(10),
    };
    let o = out(&t, &EmitPolicy::default());
    assert_eq!(
        (&o["congestion_control"], &o["udp_relay_mode"]),
        (&json!("bbr"), &json!("native"))
    );
    assert_eq!(
        (&o["zero_rtt_handshake"], &o["heartbeat"]),
        (&json!(true), &json!("10s"))
    );

    let mut n = naive("naive.example.com");
    n.kind = Kind::Naive {
        username: "user".into(),
        password: "pass".into(),
        quic: true,
        extra_headers: vec![("X-Pad".into(), "1".into())],
        insecure_concurrency: Some(2),
    };
    let o = out(&n, &EmitPolicy::default());
    assert_eq!(
        (&o["quic"], &o["extra_headers"], &o["insecure_concurrency"]),
        (&json!(true), &json!({ "X-Pad": "1" }), &json!(2))
    );

    let socks = profile(
        "127.0.0.1",
        1080,
        Kind::Socks {
            username: Some("u".into()),
            password: Some("p w ".into()),
        },
    );
    let o = out(&socks, &EmitPolicy::default());
    assert_eq!(
        o,
        json!({ "type": "socks", "tag": "proxy-out", "server": "127.0.0.1", "server_port": 1080, "version": "5", "username": "u", "password": "p w " })
    );
    let mut over_tls = socks.clone();
    over_tls.tls = Some(Tls::default());
    assert_eq!(
        emit_singbox(&over_tls, "x", &EmitPolicy::default()),
        Err(EmitError::TlsUnsupported("socks"))
    );

    // HTTP over TLS is TCP-TLS: it gets the uTLS default like any other.
    let mut h = profile(
        "proxy.example.com",
        443,
        Kind::Http {
            username: None,
            password: None,
        },
    );
    h.tls = Some(tls("proxy.example.com"));
    assert_eq!(fp(&out(&h, &device(ClientDevice::Ios))), "ios");

    let mut s = ss("aes-256-gcm", "p");
    s.kind = Kind::Shadowsocks {
        method: "aes-256-gcm".into(),
        password: "p".into(),
        plugin: Some(SsPlugin {
            name: "obfs".into(),
            opts: "obfs=http;obfs-host=example.com".into(),
        }),
        shadowtls: None,
        uot: Some(2),
    };
    let o = out(&s, &EmitPolicy::default());
    assert_eq!(
        (&o["plugin"], &o["plugin_opts"]),
        (
            &json!("obfs-local"),
            &json!("obfs=http;obfs-host=example.com")
        )
    );
    assert_eq!(o["udp_over_tcp"], json!({ "enabled": true, "version": 2 }));
    s.kind = Kind::Shadowsocks {
        method: "aes-256-gcm".into(),
        password: "p".into(),
        plugin: Some(SsPlugin {
            name: "kcptun".into(),
            opts: String::new(),
        }),
        shadowtls: None,
        uot: None,
    };
    assert_eq!(
        emit_singbox(&s, "x", &EmitPolicy::default()),
        Err(EmitError::SsPlugin("kcptun".into()))
    );
    s.kind = Kind::Shadowsocks {
        method: "aes-256-gcm".into(),
        password: "p".into(),
        plugin: None,
        shadowtls: None,
        uot: None,
    };
    s.transport = Some(Transport::Quic);
    assert_eq!(
        emit_singbox(&s, "x", &EmitPolicy::default()),
        Err(EmitError::TransportUnsupported("shadowsocks"))
    );
}

/// tunnel-core §2.2.5 / §3.15: dial preferences and the bootstrap resolver for hostnames.
#[test]
fn dial_fields_and_domain_resolver() {
    let policy = EmitPolicy {
        domain_resolver: Some("dns-bootstrap".into()),
        ..EmitPolicy::default()
    };
    let mut p = trojan("t.example.com");
    p.dial = DialPrefs {
        connect_timeout_s: Some(5),
        tcp_fast_open: true,
        tcp_multi_path: true,
        udp_fragment: Some(false),
        dns_strategy: Some("prefer_ipv6".into()),
    };
    let o = out(&p, &policy);
    assert_eq!(
        (
            &o["connect_timeout"],
            &o["tcp_fast_open"],
            &o["tcp_multi_path"]
        ),
        (&json!("5s"), &json!(true), &json!(true))
    );
    assert_eq!(o["udp_fragment"], false);
    assert_eq!(
        o["domain_resolver"],
        json!({ "server": "dns-bootstrap", "strategy": "prefer_ipv6" })
    );
    assert!(
        o.get("domain_strategy").is_none(),
        "removed in sing-box 1.14"
    );
    // An unknown strategy falls back to the tunnel's IPv4-only default.
    p.dial.dns_strategy = Some("AsIs".into());
    assert_eq!(out(&p, &policy)["domain_resolver"]["strategy"], "ipv4_only");

    let ip = trojan("192.0.2.1");
    let fragment = emit(&ip, &policy);
    assert!(fragment.outbounds()[0].get("domain_resolver").is_none());
    assert!(!fragment.needs_bootstrap_dns());
    assert_eq!(
        fragment.endpoint_ips(),
        vec!["192.0.2.1".parse::<std::net::IpAddr>().expect("ip")]
    );
    let host = emit(&trojan("t.example.com"), &EmitPolicy::default());
    assert!(host.needs_bootstrap_dns() && host.endpoint_ips().is_empty());
}

/// profiles §6.5 #1: allow-listed pasted keys come back verbatim; typed values and the policy
/// win; dial-bind, detour and file references never come back.
#[test]
fn singbox_extra_merge() {
    let mut p = vless("v.example.com");
    p.tls = Some(tls("v.example.com"));
    p.mux = Some(Mux {
        enabled: true,
        protocol: Some("smux".into()),
        ..Mux::default()
    });
    for (key, value) in [
        ("tls.fragment", json!(true)),
        ("tls.server_name", json!("override.example")),
        ("tls.certificate_path", json!("C:/secret.pem")),
        ("multiplex.min_streams", json!(4)),
        ("network", json!("tcp")),
        ("bind_interface", json!("Ethernet")),
        ("detour", json!("direct")),
        ("transport.path", json!("/never")),
        (
            "tls",
            json!({ "curve_preferences": ["X25519"], "ech": { "config_path": "C:/ech.pem", "enabled": true } }),
        ),
    ] {
        p.singbox_extra.insert(key.into(), value);
    }
    let o = out(&p, &EmitPolicy::default());
    assert_eq!(o["tls"]["fragment"], true);
    assert_eq!(o["tls"]["server_name"], "v.example.com");
    assert_eq!(o["tls"]["curve_preferences"], json!(["X25519"]));
    assert_eq!(o["tls"]["ech"], json!({ "enabled": true }));
    assert_eq!(o["multiplex"]["min_streams"], 4);
    assert_eq!(o["network"], "tcp");
    for absent in ["bind_interface", "detour", "transport"] {
        assert!(o.get(absent).is_none(), "{absent}");
    }
    assert!(!o.to_string().contains("_path"));

    // uTLS / fragments from a pasted QUIC config would break the dial: dropped.
    let mut h = hy2("hy2.example.com");
    h.singbox_extra.insert(
        "tls.utls".into(),
        json!({ "enabled": true, "fingerprint": "chrome" }),
    );
    h.singbox_extra
        .insert("tls.record_fragment".into(), json!(true));
    h.singbox_extra
        .insert("disable_chrome_parrot".into(), json!(true));
    let o = out(&h, &EmitPolicy::default());
    assert_eq!(o["tls"], json!({ "enabled": true }));
    assert_eq!(o["disable_chrome_parrot"], true);
    // naive accepts no TLS knob beyond the typed ones.
    let mut n = naive("n.example.com");
    n.singbox_extra
        .insert("tls".into(), json!({ "insecure": true, "alpn": ["h2"] }));
    assert_eq!(
        out(&n, &EmitPolicy::default())["tls"],
        json!({ "enabled": true, "server_name": "front.example.com" })
    );
}

/// sing-box refusals surfaced as typed errors before the engine would fail at start.
#[test]
fn impossible_tls_combinations_are_refused() {
    let mut p = vless("v.example.com");
    p.tls = Some(Tls {
        reality: Some(reality()),
        ech: Some(Ech::default()),
        ..tls("www.example.com")
    });
    assert_eq!(
        emit_singbox(&p, "x", &EmitPolicy::default()),
        Err(EmitError::RealityWithEch)
    );
    p.tls = Some(Tls {
        reality: Some(reality()),
        ..tls("www.example.com")
    });
    p.transport = Some(Transport::Quic);
    assert_eq!(
        emit_singbox(&p, "x", &EmitPolicy::default()),
        Err(EmitError::RealityOverQuic)
    );
    p.transport = None;
    p.tls = Some(Tls {
        spki_pin_sha256: vec!["AAAA".into()],
        certificate_pem: Some("-----BEGIN CERTIFICATE-----".into()),
        ..tls("v.example.com")
    });
    assert_eq!(
        emit_singbox(&p, "x", &EmitPolicy::default()),
        Err(EmitError::PinWithCertificate)
    );
    // Reality never carries `disable_sni` / `insecure` (an error / meaningless there).
    p.tls = Some(Tls {
        reality: Some(reality()),
        disable_sni: true,
        insecure: true,
        ..tls("www.example.com")
    });
    let o = out(&p, &EmitPolicy::default());
    assert!(o["tls"].get("disable_sni").is_none() && o["tls"].get("insecure").is_none());

    let mut h = hy2("h.example");
    h.kind = Kind::Hysteria2 {
        password: "p".into(),
        obfs: Some(Hy2Obfs {
            kind: "wechat-video".into(),
            password: "o".into(),
        }),
        ports: Vec::new(),
        hop_interval_s: None,
        hop_interval_max_s: None,
        up_mbps: None,
        down_mbps: None,
        bbr_profile: None,
    };
    assert_eq!(
        emit_singbox(&h, "x", &EmitPolicy::default()),
        Err(EmitError::Hy2Obfs("wechat-video".into()))
    );
}

/// profiles §7 "golden emit tests": exact text (keys and their order) for one profile per
/// protocol; `check.rs` runs the same shapes through `sing-box check`.
#[test]
fn golden_shapes() {
    let android = EmitPolicy {
        device: Some(ClientDevice::Android),
        tls_compat: true,
        ..EmitPolicy::default()
    };
    let pc_stealth = EmitPolicy {
        device: Some(ClientDevice::Pc),
        tls_compat: true,
        ..EmitPolicy::default()
    };
    let mut vision = vless("reality.example.com");
    vision.kind = Kind::Vless {
        uuid: UUID.into(),
        flow: Some("xtls-rprx-vision".into()),
        packet_encoding: None,
        encryption: None,
    };
    vision.tls = Some(Tls {
        reality: Some(reality()),
        ..tls("www.example.com")
    });
    let mut ws_vmess = vmess("m.example.com");
    ws_vmess.tls = Some(tls("m.example.com"));
    ws_vmess.transport = Some(Transport::Ws {
        path: "/ws".into(),
        host: Some("cdn.example.com".into()),
        max_early_data: None,
        early_data_header: None,
    });
    let mut grpc_trojan = trojan("t.example.com");
    grpc_trojan.tls = Some(tls("t.example.com"));
    grpc_trojan.transport = Some(Transport::Grpc {
        service_name: "TunService".into(),
        multi_mode: None,
    });
    let mut ss2022 = ss("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==");
    if let Kind::Shadowsocks { uot, .. } = &mut ss2022.kind {
        *uot = Some(2);
    }
    let mut hop = hy2("hy2.example.com");
    hop.kind = Kind::Hysteria2 {
        password: "secret".into(),
        obfs: Some(Hy2Obfs {
            kind: "salamander".into(),
            password: "pepper".into(),
        }),
        ports: vec![(20000, 30000)],
        hop_interval_s: Some(30),
        hop_interval_max_s: None,
        up_mbps: Some(50),
        down_mbps: Some(100),
        bbr_profile: None,
    };
    hop.tls = Some(tls("s.example.com"));
    let mut http_tls = profile(
        "proxy.example.com",
        443,
        Kind::Http {
            username: Some("u".into()),
            password: Some("p".into()),
        },
    );
    http_tls.tls = Some(tls("proxy.example.com"));
    let utls = |fp: &str| json!({ "enabled": true, "fingerprint": fp });
    let cases = [
        (
            vision,
            android.clone(),
            json!({
            "type": "vless", "tag": "proxy-out", "server": "reality.example.com", "server_port": 443,
            "uuid": UUID, "flow": "xtls-rprx-vision",
            // REALITY on an Android device still says chrome (servers refuse `android`).
            "tls": { "enabled": true, "server_name": "www.example.com", "utls": utls("chrome"),
                     "reality": { "enabled": true, "public_key": PBK, "short_id": "1234" } } }),
        ),
        (
            ws_vmess,
            EmitPolicy::default(),
            json!({
            "type": "vmess", "tag": "proxy-out", "server": "m.example.com", "server_port": 443,
            "uuid": UUID, "security": "auto",
            "tls": { "enabled": true, "server_name": "m.example.com", "utls": utls("chrome") },
            "transport": { "type": "ws", "path": "/ws", "headers": { "Host": "cdn.example.com" } } }),
        ),
        (
            grpc_trojan,
            pc_stealth,
            json!({
            "type": "trojan", "tag": "proxy-out", "server": "t.example.com", "server_port": 443, "password": "SYNTHETIC",
            "tls": { "enabled": true, "server_name": "t.example.com", "record_fragment": true, "utls": utls("chrome") },
            "transport": { "type": "grpc", "service_name": "TunService" } }),
        ),
        (
            ss2022,
            android.clone(),
            json!({
            "type": "shadowsocks", "tag": "proxy-out", "server": "ss.example.com", "server_port": 8388,
            "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA==",
            "udp_over_tcp": { "enabled": true, "version": 2 } }),
        ),
        (
            hop,
            android.clone(),
            json!({
            "type": "hysteria2", "tag": "proxy-out", "server": "hy2.example.com", "server_ports": ["20000:30000"],
            "hop_interval": "30s", "up_mbps": 50, "down_mbps": 100,
            "obfs": { "type": "salamander", "password": "pepper" }, "password": "secret",
            "tls": { "enabled": true, "server_name": "s.example.com" } }),
        ),
        (
            tuic("tuic.example.com"),
            android.clone(),
            json!({
            "type": "tuic", "tag": "proxy-out", "server": "tuic.example.com", "server_port": 443,
            "uuid": "550e8400-e29b-41d4-a716-446655440000", "password": "secret",
            "congestion_control": "bbr", "udp_relay_mode": "native", "tls": { "enabled": true, "alpn": ["h3"] } }),
        ),
        (
            naive("naive.example.com"),
            android.clone(),
            json!({
            "type": "naive", "tag": "proxy-out", "server": "naive.example.com", "server_port": 443,
            "username": "user", "password": "pass", "tls": { "enabled": true, "server_name": "front.example.com" } }),
        ),
        (
            anytls("any.example.com"),
            EmitPolicy::default(),
            json!({
            "type": "anytls", "tag": "proxy-out", "server": "any.example.com", "server_port": 443, "password": "secret",
            "tls": { "enabled": true, "utls": utls("chrome") } }),
        ),
        (
            http_tls,
            android,
            json!({
            "type": "http", "tag": "proxy-out", "server": "proxy.example.com", "server_port": 443,
            "username": "u", "password": "p",
            "tls": { "enabled": true, "server_name": "proxy.example.com", "record_fragment": true, "utls": utls("android") } }),
        ),
    ];
    for (p, policy, expected) in cases {
        assert_eq!(
            out(&p, &policy).to_string(),
            expected.to_string(),
            "{}",
            p.kind.label()
        );
    }
}
