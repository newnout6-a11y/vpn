//! Export tests: link formats, round trips through the importer's reading rules, share fallback.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::{Map, json};

use super::*;
use crate::model::{
    DialPrefs, Ech, Host, Hy2Obfs, Mux, NativeEntry, NativeXray, Note, Reality, ShadowTlsLayer,
    SsPlugin, Tls, Transport, WgPeer, WireGuard,
};

fn profile(name: &str, host: &str, port: u16, kind: Kind) -> Profile {
    let server = match host.parse::<IpAddr>() {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(host.into()),
    };
    Profile {
        name: name.into(),
        description: None,
        server,
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

fn sni(name: &str) -> Option<Tls> {
    Some(Tls {
        server_name: Some(name.into()),
        ..Tls::default()
    })
}

fn vless_kind(uuid: &str) -> Kind {
    Kind::Vless {
        uuid: uuid.into(),
        flow: None,
        packet_encoding: None,
        encryption: None,
    }
}

fn ws(path: &str, host: Option<&str>) -> Option<Transport> {
    Some(Transport::Ws {
        path: path.into(),
        host: host.map(Into::into),
        max_early_data: None,
        early_data_header: None,
    })
}

fn hy2_kind(obfs: Option<Hy2Obfs>, ports: Vec<(u16, u16)>) -> Kind {
    Kind::Hysteria2 {
        password: "secret".into(),
        obfs,
        ports,
        hop_interval_s: None,
        hop_interval_max_s: None,
        up_mbps: None,
        down_mbps: None,
        bbr_profile: None,
    }
}

fn ss_kind(method: &str, password: &str, plugin: Option<SsPlugin>) -> Kind {
    Kind::Shadowsocks {
        method: method.into(),
        password: password.into(),
        plugin,
        shadowtls: None,
        uot: None,
    }
}

fn wg_kind(private_key: &str, host: Host, port: u16, peer: impl FnOnce(&mut WgPeer)) -> Kind {
    let mut wg_peer = WgPeer {
        host,
        port,
        public_key: "peerKey".into(),
        pre_shared_key: None,
        allowed_ips: Vec::new(),
        keepalive_s: None,
        reserved: None,
    };
    peer(&mut wg_peer);
    Kind::Wireguard(WireGuard {
        private_key: private_key.into(),
        local_address: vec!["10.0.0.2/32".parse().unwrap()],
        mtu: None,
        dns: Vec::new(),
        peers: vec![wg_peer],
    })
}

/// Profiles shaped as the importer reads the spec's link vectors, with the link they export to.
fn golden() -> Vec<(Profile, &'static str)> {
    let mut v = Vec::new();

    let tuic = Kind::Tuic {
        uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
        password: "secret".into(),
        congestion: Some("bbr".into()),
        udp_relay_mode: Some("native".into()),
        zero_rtt: false,
        heartbeat_s: None,
    };
    let mut p = profile("TUIC", "tuic.example.com", 443, tuic);
    p.tls = sni("front.example.com");
    v.push((p, "tuic://550e8400-e29b-41d4-a716-446655440000:secret@tuic.example.com:443?sni=front.example.com&congestion_control=bbr&udp_relay_mode=native#TUIC"));

    let naive = Kind::Naive {
        username: "user".into(),
        password: "pass".into(),
        quic: false,
        extra_headers: vec![],
        insecure_concurrency: None,
    };
    let mut p = profile("Naive ECH", "naive.example.com", 443, naive);
    let ech = Ech {
        config_lines: vec!["abc".into(), "def".into()],
        query_server_name: Some("cloudflare-ech.com".into()),
    };
    p.tls = Some(Tls {
        server_name: Some("front.example.com".into()),
        ech: Some(ech),
        ..Tls::default()
    });
    v.push((p, "naive+https://user:pass@naive.example.com:443?sni=front.example.com&ech=1&echConfig=abc%2Cdef&echQueryServerName=cloudflare-ech.com#Naive%20ECH"));

    let wg = wg_kind(
        "privateKey",
        Host::Domain("wg.example.com".into()),
        51820,
        |peer| {
            peer.pre_shared_key = Some("sharedKey".into());
        },
    );
    let mut p = profile("WG", "wg.example.com", 51820, wg);
    if let Kind::Wireguard(wg) = &mut p.kind {
        wg.mtu = Some(1420);
        wg.dns = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
    }
    v.push((p, "wireguard://privateKey@wg.example.com:51820?publicKey=peerKey&psk=sharedKey&address=10.0.0.2%2F32&dns=1.1.1.1&mtu=1420#WG"));

    let obfs = Hy2Obfs {
        kind: "salamander".into(),
        password: "pepper".into(),
    };
    let mut p = profile(
        "HY2",
        "hy2.example.com",
        443,
        hy2_kind(Some(obfs), vec![(8443, 8450)]),
    );
    if let Kind::Hysteria2 {
        hop_interval_s,
        up_mbps,
        down_mbps,
        ..
    } = &mut p.kind
    {
        (*hop_interval_s, *up_mbps, *down_mbps) = (Some(30), Some(80), Some(200));
    }
    p.tls = sni("front.example.com");
    v.push((p, "hysteria2://secret@hy2.example.com:443?sni=front.example.com&obfs=salamander&obfs-password=pepper&mport=8443-8450&hop_interval=30s&upmbps=80&downmbps=200#HY2"));

    let ports = vec![(8443, 8450), (9443, 9443), (10443, 10445)];
    let mut p = profile("HY2", "hy2.example.com", 443, hy2_kind(None, ports));
    p.tls = Some(Tls::default());
    v.push((
        p,
        "hysteria2://secret@hy2.example.com:443?mport=8443-8450%2C9443%2C10443-10445#HY2",
    ));

    let mut p = profile(
        "t",
        "h.example",
        443,
        Kind::Trojan {
            password: "p".into(),
        },
    );
    p.transport = ws("/ws", None);
    v.push((
        p,
        "trojan://p@h.example:443?security=none&type=ws&path=%2Fws#t",
    ));

    let plugin = SsPlugin {
        name: "obfs-local".into(),
        opts: "obfs=http;obfs-host=example.com".into(),
    };
    let p = profile(
        "n",
        "1.2.3.4",
        8388,
        ss_kind("aes-256-gcm", "pass", Some(plugin)),
    );
    v.push((p, "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#n"));
    let p = profile(
        "n",
        "h.example",
        8388,
        ss_kind("aes-256-gcm", "p%41ss", None),
    );
    v.push((p, "ss://YWVzLTI1Ni1nY206cCU0MXNz@h.example:8388#n"));
    let p = profile(
        "n",
        "h.example",
        8388,
        ss_kind("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==", None),
    );
    v.push((
        p,
        "ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA%3D%3D@h.example:8388#n",
    ));

    let reality = Reality {
        public_key: "PBK-synthetic_key".into(),
        short_id: "1234".into(),
        spider_x: Some("/test-path".into()),
        ..Reality::default()
    };
    let mut p = profile(
        "Reality",
        "reality.example.com",
        443,
        vless_kind("00000000-0000-4000-8000-000000000000"),
    );
    p.tls = Some(Tls {
        reality: Some(reality),
        ..Tls::default()
    });
    v.push((p, "vless://00000000-0000-4000-8000-000000000000@reality.example.com:443?encryption=none&security=reality&pbk=PBK-synthetic_key&sid=1234&spx=%2Ftest-path#Reality"));

    let v6 = Host::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    let wg = wg_kind("key", v6, 10803, |peer| {
        peer.public_key = "PUB".into();
        peer.reserved = Some([1, 22, 33]);
    });
    let mut p = profile("title", "2001:db8::1", 10803, wg);
    if let Kind::Wireguard(wg) = &mut p.kind {
        wg.mtu = Some(1500);
    }
    p.description = Some("Happ the best".into());
    v.push((p, "wireguard://key@[2001:db8::1]:10803?publicKey=PUB&address=10.0.0.2%2F32&mtu=1500&reserved=1%2C22%2C33#title%3FserverDescription%3DSGFwcCB0aGUgYmVzdA%3D%3D"));

    let mut p = profile(
        "gRPC",
        "h.example",
        443,
        vless_kind("00000000-0000-4000-8000-000000000001"),
    );
    p.tls = sni("front.example.com");
    p.transport = Some(Transport::Grpc {
        service_name: "service-name".into(),
        multi_mode: Some(false),
    });
    v.push((p, "vless://00000000-0000-4000-8000-000000000001@h.example:443?encryption=none&security=tls&sni=front.example.com&type=grpc&serviceName=service-name&mode=gun#gRPC"));

    let socks = Kind::Socks {
        username: Some("user".into()),
        password: Some("pass".into()),
    };
    v.push((
        profile("S", "1.2.3.4", 1080, socks),
        "socks://user:pass@1.2.3.4:1080#S",
    ));

    let naive = Kind::Naive {
        username: "user".into(),
        password: "pass".into(),
        quic: true,
        extra_headers: vec![],
        insecure_concurrency: None,
    };
    let mut p = profile("N", "h.example", 443, naive);
    p.tls = Some(Tls::default());
    v.push((p, "naive+quic://user:pass@h.example:443#N"));

    let anytls = Kind::Anytls {
        password: "secret".into(),
        idle_check_s: Some(30),
        idle_timeout_s: Some(60),
        min_idle: Some(2),
    };
    let mut p = profile("AnyTLS", "any.example.com", 443, anytls);
    p.tls = sni("front.example.com");
    v.push((p, "anytls://secret@any.example.com:443?security=tls&sni=front.example.com&idle_session_check_interval=30s&idle_session_timeout=60s&min_idle_session=2#AnyTLS"));

    v
}

/// Export formats (profiles §2.14 / §3.10; §7.1 tuic / ECH / WG / HY2 round trips; §7.3 P-08,
/// P-09, P-12, P-37; AT-04-004): every spec vector exports to the link it was imported from.
#[test]
fn links_match_the_spec_vectors() {
    for (p, link) in golden() {
        assert_eq!(export_uri(&p).as_deref(), Some(link), "{}", p.name);
    }
}

/// P-08: `+` and `=` of base64 keys are encoded, never left for a `+`-as-space reader.
#[test]
fn base64_values_are_percent_encoded() {
    let wg = wg_kind(
        "k+y/=",
        Host::Domain("wg.example.com".into()),
        51820,
        |peer| peer.public_key = "ab+cd+ef=".into(),
    );
    let link = export_uri(&profile("W", "wg.example.com", 51820, wg)).unwrap();
    assert!(
        link.starts_with("wireguard://k%2By%2F%3D@wg.example.com:51820?publicKey=ab%2Bcd%2Bef%3D&"),
        "{link}"
    );
}

/// XHTTP round trip (AT-04-001/002/006): a literal `%` in the path and the `extra` JSON survive
/// exactly one decode on import.
#[test]
fn xhttp_values_are_encoded_once() {
    let extra =
        json!({"noSSEHeader": true, "custom": {"escaped": "%2F&=%25", "array": [true, 0, "text"]}});
    let mut p = profile(
        "X",
        "192.0.2.1",
        443,
        vless_kind("11111111-2222-4333-8444-555555555555"),
    );
    p.tls = sni("front.example.com");
    p.transport = Some(Transport::Xhttp {
        host: "front.example.com".into(),
        path: "/a%2Fb".into(),
        mode: Some("packet-up".into()),
        extra: extra.as_object().cloned(),
    });
    let link = export_uri(&p).unwrap();
    assert!(
        link.contains("&type=xhttp&host=front.example.com&path=%2Fa%252Fb&mode=packet-up&extra="),
        "{link}"
    );
    let raw = link
        .split("extra=")
        .nth(1)
        .and_then(|rest| rest.split('#').next())
        .unwrap();
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&decoded).unwrap(), extra);
}

fn vmess_json(link: &str) -> Value {
    use base64::Engine as _;
    let payload = link.strip_prefix("vmess://").unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn vmess(name: &str) -> Profile {
    let kind = Kind::Vmess {
        uuid: "00000000-0000-4000-8000-000000000001".into(),
        security: "auto".into(),
        global_padding: false,
        authenticated_length: false,
    };
    profile(name, "h.example", 443, kind)
}

/// VMess is shared in the v2rayN base64 JSON form (profiles §2.14; §7.1 "no tcp-only" and §7.2
/// XHTTP vectors).
#[test]
fn vmess_exports_v2rayn_json() {
    let mut p = vmess("VMess");
    p.tls = Some(Tls::default());
    let expected = json!({"v": "2", "ps": "VMess", "add": "h.example", "port": 443, "id": "00000000-0000-4000-8000-000000000001",
        "aid": 0, "scy": "auto", "net": "tcp", "type": "none", "tls": "tls"});
    assert_eq!(vmess_json(&export_uri(&p).unwrap()), expected);

    let mut p = vmess("VM");
    p.tls = Some(Tls {
        server_name: Some("front.example.com".into()),
        alpn: vec!["h2".into(), "http/1.1".into()],
        insecure: true,
        ..Tls::default()
    });
    p.transport = ws("/ws", Some("cdn.example"));
    let doc = vmess_json(&export_uri(&p).unwrap());
    for (key, value) in [
        ("net", json!("ws")),
        ("host", json!("cdn.example")),
        ("path", json!("/ws")),
        ("sni", json!("front.example.com")),
        ("alpn", json!("h2,http/1.1")),
        ("allowInsecure", json!(true)),
    ] {
        assert_eq!(doc[key], value, "{key}");
    }

    let mut p = vmess("X");
    let extra = json!({"noSSEHeader": true});
    p.transport = Some(Transport::Xhttp {
        host: String::new(),
        path: "/a%2Fb".into(),
        mode: Some("packet-up".into()),
        extra: extra.as_object().cloned(),
    });
    let doc = vmess_json(&export_uri(&p).unwrap());
    assert_eq!(
        (&doc["net"], &doc["path"], &doc["mode"], &doc["extra"]),
        (
            &json!("xhttp"),
            &json!("/a%2Fb"),
            &json!("packet-up"),
            &extra
        )
    );
    assert_eq!(doc["tls"], json!(""));
}

/// One change applied to a profile.
type Edit = Box<dyn Fn(&mut Profile)>;

/// The base of the lossy cases: a VLESS ws+tls key that does export.
fn base() -> Profile {
    let mut p = profile(
        "Base",
        "h.example",
        443,
        vless_kind("00000000-0000-4000-8000-000000000001"),
    );
    p.tls = sni("front.example.com");
    p.transport = ws("/ws", Some("cdn.example"));
    p
}

/// K16 / §3.10: a link is never handed out when it cannot carry the whole profile.
#[test]
fn lossy_profiles_have_no_link() {
    assert!(export_uri(&base()).is_some());
    let graph = NativeXray {
        version: 1,
        selected_tag: "proxy".into(),
        entry: NativeEntry {
            outbound_tag: Some("proxy".into()),
            balancer_tag: None,
        },
        outbounds: vec![json!({"tag": "proxy", "protocol": "vless"})],
        routing: None,
        observatory: None,
        burst_observatory: None,
        policy: None,
    };
    let edits: Vec<(&str, Edit)> = vec![
        (
            "mux",
            Box::new(|p| {
                p.mux = Some(Mux {
                    enabled: true,
                    ..Mux::default()
                })
            }),
        ),
        ("dial", Box::new(|p| p.dial.tcp_fast_open = true)),
        (
            "singbox_extra",
            Box::new(|p| _ = p.singbox_extra.insert("tls.fragment".into(), json!(true))),
        ),
        (
            "native graph",
            Box::new(move |p| p.native_xray = Some(graph.clone())),
        ),
        (
            "quic transport",
            Box::new(|p| p.transport = Some(Transport::Quic)),
        ),
        (
            "spki pin",
            Box::new(|p| p.tls.as_mut().unwrap().spki_pin_sha256 = vec!["pin".into()]),
        ),
        (
            "certificate",
            Box::new(|p| p.tls.as_mut().unwrap().certificate_pem = Some("PEM".into())),
        ),
        (
            "host would become SNI",
            Box::new(|p| p.tls.as_mut().unwrap().server_name = None),
        ),
        (
            "encryption none",
            Box::new(|p| {
                p.kind = Kind::Vless {
                    uuid: "u".into(),
                    flow: None,
                    packet_encoding: None,
                    encryption: Some("none".into()),
                }
            }),
        ),
        ("empty uuid", Box::new(|p| p.kind = vless_kind(""))),
        ("relative path", Box::new(|p| p.transport = ws("ws", None))),
        (
            "empty ws host",
            Box::new(|p| p.transport = ws("/", Some(""))),
        ),
        (
            "xhttp mode",
            Box::new(|p| {
                p.transport = Some(Transport::Xhttp {
                    host: String::new(),
                    path: "/".into(),
                    mode: Some("bogus".into()),
                    extra: None,
                })
            }),
        ),
        ("port 0", Box::new(|p| p.port = 0)),
        (
            "bad host",
            Box::new(|p| p.server = Host::Domain("bad host".into())),
        ),
        (
            "IP spelled as a name",
            Box::new(|p| p.server = Host::Domain("10.0.0.1".into())),
        ),
    ];
    for (case, edit) in edits {
        let mut p = base();
        edit(&mut p);
        assert_eq!(export_uri(&p), None, "{case}");
    }
}

#[test]
fn protocol_fields_without_a_link_form_have_no_link() {
    let golden = golden();
    let tuic = golden[0].0.clone();
    let wg = golden[2].0.clone();
    let hy2 = golden[3].0.clone();
    let ss = golden[7].0.clone();
    let mut cases: Vec<(&str, Profile)> = Vec::new();
    let mut p = tuic.clone();
    if let Kind::Tuic { congestion, .. } = &mut p.kind {
        *congestion = Some("new-reno".into());
    }
    cases.push(("tuic new-reno spelling", p));
    let mut p = hy2.clone();
    p.tls = None;
    cases.push(("hy2 without TLS", p));
    let mut p = hy2.clone();
    if let Kind::Hysteria2 {
        hop_interval_max_s, ..
    } = &mut p.kind
    {
        *hop_interval_max_s = Some(60);
    }
    cases.push(("hy2 hop range", p));
    let mut p = wg.clone();
    if let Kind::Wireguard(config) = &mut p.kind {
        let second = config.peers[0].clone();
        config.peers.push(second);
    }
    cases.push(("two WireGuard peers", p));
    let mut p = wg;
    if let Kind::Wireguard(config) = &mut p.kind {
        config.peers[0].port = 2408;
    }
    cases.push(("peer elsewhere", p));
    let mut p = ss.clone();
    if let Kind::Shadowsocks { shadowtls, .. } = &mut p.kind {
        *shadowtls = Some(ShadowTlsLayer {
            version: 3,
            password: "p".into(),
            server_name: "s.example".into(),
        });
    }
    cases.push(("shadowtls chain", p));
    let mut p = ss;
    if let Kind::Shadowsocks { method, .. } = &mut p.kind {
        *method = "AES-256-GCM".into();
    }
    cases.push(("upper-case cipher", p));
    let mut p = vmess("V");
    p.tls = Some(Tls {
        ech: Some(Ech::default()),
        ..Tls::default()
    });
    cases.push(("vmess ECH", p));
    let mut p = profile(
        "S",
        "1.2.3.4",
        1080,
        Kind::Socks {
            username: Some(String::new()),
            password: Some("p".into()),
        },
    );
    cases.push(("empty socks user", p.clone()));
    p.kind = Kind::Socks {
        username: None,
        password: None,
    };
    p.tls = Some(Tls::default());
    cases.push(("socks over TLS", p));
    for (case, p) in cases {
        assert_eq!(export_uri(&p), None, "{case}");
    }
}

/// `exportOutboundForSharing` (profiles §2.14 / §3.10): a lossless key is shared as its link.
#[test]
fn share_prefers_the_link() {
    let p = base();
    let link = export_uri(&p).unwrap();
    assert_eq!(export_share(&p), Some(Shared::Uri(link.clone())));
    assert_eq!(Shared::Uri(link.clone()).text(), link);
}

/// A key without a lossless link is shared as the emitted sing-box JSON wrapped as
/// `{"remarks", "outbounds"|"endpoints"}` (outbound, WireGuard endpoint, ShadowTLS chain).
#[test]
fn share_falls_back_to_singbox_json() {
    use crate::emit_singbox::{EmitPolicy, emit_singbox};
    let emitted = |p: &Profile| emit_singbox(p, "proxy", &EmitPolicy::default()).unwrap();

    let mut p = base();
    p.mux = Some(Mux {
        enabled: true,
        padding: true,
        ..Mux::default()
    });
    assert_eq!(export_uri(&p), None);
    let outbound = emitted(&p).outbounds()[0].clone();
    assert_eq!(outbound["tag"], "proxy");
    let shared = export_share(&p).unwrap();
    assert_eq!(
        shared,
        Shared::Json(json!({"remarks": "Base", "outbounds": [outbound]}))
    );
    assert!(
        shared
            .text()
            .starts_with(r#"{"remarks":"Base","outbounds":[{"#)
    );

    let mut wg = profile(
        "Two peers",
        "203.0.113.7",
        51820,
        wg_kind(
            "PRIV-FAKE",
            Host::Ip([203, 0, 113, 7].into()),
            51820,
            |peer| {
                peer.allowed_ips = vec!["0.0.0.0/0".parse().unwrap()];
            },
        ),
    );
    if let Kind::Wireguard(w) = &mut wg.kind {
        let mut second = w.peers[0].clone();
        second.host = Host::Ip([203, 0, 113, 8].into());
        second.allowed_ips = vec!["::/0".parse().unwrap()];
        w.peers.push(second);
    }
    assert_eq!(export_uri(&wg), None);
    let endpoint = emitted(&wg).endpoints()[0].clone();
    assert_eq!(
        export_share(&wg),
        Some(Shared::Json(
            json!({"remarks": "Two peers", "endpoints": [endpoint]})
        ))
    );

    let mut chain = profile(
        "Chain",
        "ss.example.com",
        443,
        ss_kind("aes-128-gcm", "pw", None),
    );
    if let Kind::Shadowsocks { shadowtls, .. } = &mut chain.kind {
        *shadowtls = Some(ShadowTlsLayer {
            version: 3,
            password: "layer-pw".into(),
            server_name: "cover.example".into(),
        });
    }
    let outbounds = emitted(&chain).outbounds().to_vec();
    assert_eq!(outbounds.len(), 2);
    assert_eq!(
        export_share(&chain),
        Some(Shared::Json(
            json!({"remarks": "Chain", "outbounds": outbounds})
        ))
    );

    // No link (dial options) and no sing-box form (XHTTP is Xray-only): nothing to share.
    let mut xhttp = base();
    xhttp.transport = Some(Transport::Xhttp {
        host: "cdn.example".into(),
        path: "/x".into(),
        mode: None,
        extra: None,
    });
    xhttp.dial.tcp_fast_open = true;
    assert_eq!(export_share(&xhttp), None);
}

/// A provider graph is shared as its Xray document, never as a link.
#[test]
fn share_of_a_native_graph_is_its_xray_document() {
    let mut p = base();
    p.native_xray = Some(NativeXray {
        version: 1,
        selected_tag: "proxy".into(),
        entry: NativeEntry {
            outbound_tag: Some("proxy".into()),
            balancer_tag: None,
        },
        outbounds: vec![json!({"tag": "proxy", "protocol": "vless", "settings": {
            "vnext": [{"address": "203.0.113.9", "port": 443,
                       "users": [{"id": "00000000-0000-4000-8000-000000000000", "encryption": "none"}]}]}})],
        routing: None,
        observatory: None,
        burst_observatory: None,
        policy: None,
    });
    let document =
        crate::xray_native::export_document(p.native_xray.as_ref().unwrap(), "Base").unwrap();
    assert_eq!(export_share(&p), Some(Shared::Json(document)));
}

/// Proxy-list lines (profiles §7.1 "proxy lines", servers §7 export vectors).
#[test]
fn proxy_lines() {
    let http = Kind::Http {
        username: Some("user".into()),
        password: Some("pa:ss".into()),
    };
    let line = export_proxy_line(&profile("H", "proxy.example.com", 8080, http));
    assert_eq!(
        line.as_deref(),
        Some("http://user:pa%3Ass@proxy.example.com:8080")
    );
    let http = Kind::Http {
        username: Some("u".into()),
        password: Some("p@ss".into()),
    };
    assert_eq!(
        export_proxy_line(&profile("H", "1.2.3.4", 8080, http)).as_deref(),
        Some("http://u:p%40ss@1.2.3.4:8080")
    );
    let socks = Kind::Socks {
        username: None,
        password: None,
    };
    let line = export_proxy_line(&profile("S", "2001:db8::1", 1080, socks.clone()));
    assert_eq!(line.as_deref(), Some("socks5://[2001:db8::1]:1080"));
    let naive = &golden()[1].0;
    assert_eq!(
        export_proxy_line(naive).as_deref(),
        Some("https://user:pass@naive.example.com:443")
    );
    assert_eq!(export_proxy_line(&base()), None);
    // TLS around SOCKS, a transport or REALITY has no place in a line (the login would leak).
    let mut wrapped = profile("S", "1.2.3.4", 1080, socks.clone());
    wrapped.tls = Some(Tls::default());
    assert_eq!(export_proxy_line(&wrapped), None);
    let mut wrapped = profile(
        "H",
        "1.2.3.4",
        8080,
        Kind::Http {
            username: None,
            password: None,
        },
    );
    wrapped.tls = Some(Tls::default());
    assert_eq!(
        export_proxy_line(&wrapped).as_deref(),
        Some("https://1.2.3.4:8080")
    );
    wrapped.tls.as_mut().unwrap().reality = Some(Reality::default());
    assert_eq!(export_proxy_line(&wrapped), None);
    wrapped.tls = None;
    wrapped.transport = ws("/", None);
    assert_eq!(export_proxy_line(&wrapped), None);
    assert_eq!(
        export_proxy_line(&profile("S", "bad host", 1080, socks.clone())),
        None
    );
    assert_eq!(export_proxy_line(&profile("S", "1.2.3.4", 0, socks)), None);
    let quic = &golden()[13].0;
    assert!(matches!(quic.kind, Kind::Naive { quic: true, .. }));
    assert_eq!(export_proxy_line(quic), None);
}

/// The imported line is handed back byte for byte only while it still reads as the profile.
#[test]
fn faithful_line_is_kept() {
    let line = "vless://00000000-0000-4000-8000-000000000001@h.example:443?security=tls&sni=front.example.com&fragment=1,40-60,30-50#Node";
    let mut p = base();
    p.source = Source::Uri(line.into());
    assert_eq!(faithful_line(&p, |_| Some(p.clone())), Some(line));
    let renamed = Profile {
        name: "Renamed".into(),
        ..p.clone()
    };
    assert_eq!(faithful_line(&p, |_| Some(renamed)), None);
    assert_eq!(faithful_line(&p, |_| None), None);
    // Notes describe the reading, not the key: a note added later keeps the provider's line.
    let noted = Profile {
        notes: vec![Note::CertPinNotEnforced],
        ..p.clone()
    };
    assert_eq!(faithful_line(&noted, |_| Some(p.clone())), Some(line));
    let pasted_json = Profile {
        source: Source::Json,
        ..p
    };
    assert_eq!(faithful_line(&pasted_json, |_| panic!("not a link")), None);
}

/// Profiles beyond the spec vectors that the round trip covers too.
fn more_linkable() -> Vec<Profile> {
    let xhttp = Transport::Xhttp {
        host: "front.example.com".into(),
        path: "/a%2Fb".into(),
        mode: Some("packet-up".into()),
        extra: json!({"noSSEHeader": true, "custom": {"escaped": "%2F&=%25", "array": [true, 0, "text"]}}).as_object().cloned(),
    };
    let mut out = vec![base()];
    for kind in [
        vless_kind("11111111-2222-4333-8444-555555555555"),
        Kind::Trojan {
            password: "SYNTHETIC_PASSWORD".into(),
        },
        vmess("x").kind,
    ] {
        let mut p = profile("XHTTP node", "192.0.2.1", 443, kind);
        p.tls = sni("front.example.com");
        p.transport = Some(xhttp.clone());
        out.push(p);
    }
    let mut p = vmess("VMess ws");
    p.tls = Some(Tls {
        server_name: Some("front.example.com".into()),
        alpn: vec!["h2".into()],
        fingerprint: Some("firefox".into()),
        ..Tls::default()
    });
    p.transport = ws("/ws", Some("cdn.example"));
    p.description = Some("Описание".into());
    out.push(p);
    let mut p = profile(
        "Узел 1",
        "h.example",
        443,
        Kind::Http {
            username: Some("user".into()),
            password: Some("p:ss word".into()),
        },
    );
    p.tls = Some(Tls {
        server_name: Some("front.example.com".into()),
        insecure: true,
        ..Tls::default()
    });
    out.push(p);
    let headers = vec![
        ("X-Token".to_owned(), "a b".to_owned()),
        ("Via".to_owned(), "1.1".to_owned()),
    ];
    let naive = Kind::Naive {
        username: "u:1".into(),
        password: "p@ss+".into(),
        quic: false,
        extra_headers: headers,
        insecure_concurrency: Some(2),
    };
    let mut p = profile("Naive", "h.example", 8443, naive);
    p.tls = Some(Tls {
        server_name: Some("front.example.com".into()),
        insecure: true,
        ..Tls::default()
    });
    out.push(p);
    let mut p = profile("Pinned", "h.example", 443, hy2_kind(None, vec![]));
    p.tls = Some(Tls {
        alpn: vec!["h3".into()],
        cert_pin_sha256: Some("ab".repeat(32)),
        insecure: true,
        ..Tls::default()
    });
    out.push(p);
    let mut p = profile(
        "Pinned VLESS",
        "h.example",
        443,
        vless_kind("00000000-0000-4000-8000-000000000004"),
    );
    p.tls = Some(Tls {
        server_name: Some("front.example.com".into()),
        cert_pin_sha256: Some("cd".repeat(32)),
        insecure: true,
        ..Tls::default()
    });
    out.push(p);
    let uuid = "00000000-0000-4000-8000-000000000003";
    let reality = Reality {
        public_key: "PBK".into(),
        short_id: "d34db33f".into(),
        spider_x: None,
        ..Reality::default()
    };
    let reality_tls = Tls {
        server_name: Some("www.example.com".into()),
        fingerprint: Some("chrome".into()),
        reality: Some(reality),
        ..Tls::default()
    };
    let vision = Kind::Vless {
        uuid: uuid.into(),
        flow: Some("xtls-rprx-vision".into()),
        packet_encoding: Some("xudp".into()),
        encryption: None,
    };
    let mut p = profile("Vision", "203.0.113.7", 443, vision);
    p.tls = Some(reality_tls.clone());
    out.push(p);
    let mut p = profile("gRPC multi", "h.example", 443, vless_kind(uuid));
    p.tls = Some(reality_tls.clone());
    p.transport = Some(Transport::Grpc {
        service_name: "svc".into(),
        multi_mode: Some(true),
    });
    out.push(p);
    let encrypted = Kind::Vless {
        uuid: uuid.into(),
        flow: None,
        packet_encoding: None,
        encryption: Some("mlkem768x25519plus.native.0rtt.SYNTHETIC".into()),
    };
    let mut p = profile("Encrypted", "h.example", 80, encrypted);
    p.transport = Some(Transport::TcpHttpHeader {
        host: vec!["a.example".into(), "b.example".into()],
        path: vec!["/x".into()],
    });
    out.push(p);
    let mut p = profile("h2", "h.example", 443, vless_kind(uuid));
    p.tls = Some(Tls {
        server_name: Some("front.example.com".into()),
        alpn: vec!["h2".into()],
        ..Tls::default()
    });
    p.transport = Some(Transport::Http {
        hosts: vec!["a.example".into(), "b.example".into()],
        path: "/h2".into(),
    });
    out.push(p);
    let mut p = profile(
        "Upgrade",
        "h.example",
        443,
        Kind::Trojan {
            password: "p+w/d=".into(),
        },
    );
    p.tls = sni("front.example.com");
    p.transport = Some(Transport::HttpUpgrade {
        host: "cdn.example".into(),
        path: "/up?ed=2048".into(),
    });
    out.push(p);
    let tuic = Kind::Tuic {
        uuid: uuid.into(),
        password: "secret".into(),
        congestion: Some("new_reno".into()),
        udp_relay_mode: Some("quic".into()),
        zero_rtt: true,
        heartbeat_s: Some(10),
    };
    let mut p = profile("TUIC opts", "h.example", 443, tuic);
    p.tls = Some(Tls {
        disable_sni: true,
        insecure: true,
        alpn: vec!["h3".into()],
        ..Tls::default()
    });
    out.push(p);
    let anytls = Kind::Anytls {
        password: "secret".into(),
        idle_check_s: None,
        idle_timeout_s: None,
        min_idle: Some(0),
    };
    let mut p = profile("AnyTLS REALITY", "h.example", 443, anytls);
    p.tls = Some(reality_tls);
    out.push(p);
    out
}

fn comparable(p: Profile) -> Profile {
    Profile {
        source: Source::Json,
        notes: Vec::new(),
        ..p
    }
}

/// Round trip through the real importer (AT-04-001, AT-04-006): every exported link reads back
/// as the same profile.
#[test]
fn links_read_back_as_the_same_profile() {
    let profiles = golden().into_iter().map(|(p, _)| p).chain(more_linkable());
    for p in profiles {
        let link = export_uri(&p).unwrap_or_else(|| panic!("no link for {}", p.name));
        let back = crate::uri::parse_uri(&link).unwrap_or_else(|e| panic!("{link}: {e:?}"));
        assert_eq!(comparable(back), comparable(p), "{link}");
    }
}

/// A V2Ray-family link carries the certificate pin as Xray's `pcs` (an Xray client would drop
/// `pinSHA256` and, next to `allowInsecure`, dial unverified); Hysteria2 keeps `pinSHA256`.
#[test]
fn certificate_pins_use_the_scheme_s_parameter() {
    let links: Vec<String> = more_linkable()
        .iter()
        .filter(|p| p.name.starts_with("Pinned"))
        .filter_map(export_uri)
        .collect();
    assert_eq!(links.len(), 2, "{links:?}");
    assert!(links[0].starts_with("hysteria2://") && links[0].contains("pinSHA256="));
    assert!(
        links[1].starts_with("vless://") && links[1].contains(&format!("pcs={}", "cd".repeat(32)))
    );
    assert!(!links[1].contains("pinSHA256"));
}

/// The provider's line comes back byte for byte, unmodelled parameters included, until the
/// profile changes.
#[test]
fn imported_lines_are_returned_unchanged() {
    let lines = [
        "vless://00000000-0000-4000-8000-000000000001@h.example:443?security=tls&sni=front.example.com&fragment=1,40-60,30-50#Node",
        "hy2://secret@hy2.example.com:443?sni=front.example.com&obfs=salamander&obfs-password=pepper&mport=8443-8450&hop_interval=30s&upmbps=80&downmbps=200#HY2",
        "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388/#n",
    ];
    for line in lines {
        let p = crate::uri::parse_uri(line).unwrap();
        assert_eq!(export_uri(&p).as_deref(), Some(line));
        let renamed = Profile {
            name: "Renamed".into(),
            ..p
        };
        let rebuilt = export_uri(&renamed).unwrap();
        assert!(rebuilt.ends_with("#Renamed"), "{rebuilt}");
        // A rebuilt link keeps the key's TLS tricks (review a2).
        let again = crate::uri::parse_uri(&rebuilt).unwrap();
        assert_eq!(again.tls, renamed.tls, "{rebuilt}");
    }
}

/// Item 18: a rebuilt link writes the key's tricks back as `fragment=` in Xray's order, and
/// link -> profile -> link -> profile keeps them; schemes whose reader has no `fragment=`
/// are refused (the JSON form keeps them).
#[test]
fn tls_tricks_round_trip_through_links() {
    let base = "vless://00000000-0000-4000-8000-000000000001@h.example:443?security=tls&sni=front.example.com";
    let cases = [
        ("tlshello,100-200,10-20", "tlshello,100-200,10-20"),
        ("tlshello,100-200,0", "tlshello,100-200,0"),
        ("tlshello,10-20,0", "tlshello,10-20,0"),
        ("1-3,40-60,30-50", "1,40-60,30-50"),
        ("100-200,10-20,tlshello", "tlshello,100-200,10-20"),
    ];
    for (given, written) in cases {
        let line = format!("{base}&fragment={given}#N");
        let p = crate::uri::parse_uri(&line).unwrap();
        let renamed = Profile {
            name: "R".into(),
            ..p.clone()
        };
        let rebuilt = export_uri(&renamed).unwrap();
        let expected = format!("fragment={}", written.replace(',', "%2C"));
        assert!(rebuilt.contains(&expected), "{given}: {rebuilt}");
        let again = crate::uri::parse_uri(&rebuilt).unwrap();
        assert_eq!(again.tls, p.tls, "{given}: {rebuilt}");
    }
    let mut anytls =
        crate::uri::parse_uri("anytls://pass@h.example:443?sni=front.example.com#A").unwrap();
    anytls.tls.as_mut().unwrap().tricks = Some(crate::model::TlsTricks::STRONG);
    assert_eq!(export_uri(&anytls), None);
}

/// A key stored before item 18 read `fragment=` as a note only; Copy key still hands out the
/// provider's exact line (review a2).
#[test]
fn keys_stored_before_tricks_keep_their_line() {
    let line = "vless://00000000-0000-4000-8000-000000000001@h.example:443?security=tls&sni=front.example.com&fragment=tlshello,100-200,10-20&noises=SYNTH#Old";
    let mut stored = crate::uri::parse_uri(line).unwrap();
    stored.tls.as_mut().unwrap().tricks = None;
    stored.notes = vec![
        Note::UnsupportedField("fragment".into()),
        Note::UnsupportedField("noises".into()),
    ];
    assert_eq!(export_uri(&stored).as_deref(), Some(line));
}

/// A JSON share carries the localized "shared as JSON" notice; a link carries none.
#[test]
fn json_share_carries_a_localized_notice() {
    let notice = Shared::Json(json!({})).notice().unwrap();
    crate::test_locales::assert_localized(&notice.key);
    assert_eq!(Shared::Uri("vless://…".into()).notice(), None);
}

/// `Debug` never prints the key (CONTRACT §4.9), only the scheme.
#[test]
fn shared_debug_hides_the_key() {
    let link = Shared::Uri("vless://SECRET-ID@h.example:443#n".into());
    assert_eq!(format!("{link:?}"), "Uri(vless://<hidden>)");
    let doc = Shared::Json(json!({"password": "SECRET"}));
    assert_eq!(format!("{doc:?}"), "Json(<hidden>)");
}
