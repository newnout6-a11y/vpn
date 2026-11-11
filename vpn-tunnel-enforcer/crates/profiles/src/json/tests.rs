//! Vectors from profiles spec §7 (sing-box / Xray JSON import) plus the allow-list rules.
use serde_json::{Value, json};

use super::parse_json;
use crate::model::{Host, Kind, Note, ParseReport, SkipReason, Source, Transport};

const UUID: &str = "00000000-0000-4000-8000-000000000001";

fn parse(v: Value) -> ParseReport {
    parse_json(&v)
}

fn names(r: &ParseReport) -> Vec<&str> {
    r.profiles.iter().map(|p| p.name.as_str()).collect()
}

/// Xray VLESS outbound in the classic `vnext` shape.
fn xray_vless(tag: &str, address: &str, port: u16, users: Value) -> Value {
    json!({
        "tag": tag, "protocol": "vless",
        "settings": { "vnext": [{ "address": address, "port": port, "users": users }] },
        "streamSettings": { "network": "tcp", "security": "reality",
            "realitySettings": { "serverName": "front.example.com", "publicKey": "PBK-FAKE", "shortId": "1234",
                                 "fingerprint": "firefox", "spiderX": "/test-path" } }
    })
}

/// AT-04-006 / spec §7.3 "§2.7 endpoints": a WireGuard endpoint next to a `direct` outbound imports
/// with its real protocol; a lone peer defaults to the full tunnel.
#[test]
fn singbox_wireguard_endpoint_is_a_profile() {
    let r = parse(json!({
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "endpoints": [{ "type": "wireguard", "tag": "wg", "address": ["10.0.0.2/32"], "private_key": "PRIV-FAKE",
                        "peers": [{ "address": "wg.example", "port": 51820, "public_key": "PUB-FAKE" }] }]
    }));
    assert_eq!(r.profiles.len(), 1, "{r:?}");
    let p = &r.profiles[0];
    assert_eq!(p.name, "wg");
    assert_eq!(
        (p.server.clone(), p.port),
        (Host::Domain("wg.example".into()), 51820)
    );
    let Kind::Wireguard(wg) = &p.kind else {
        panic!("not wireguard: {:?}", p.kind)
    };
    assert_eq!(wg.local_address[0].to_string(), "10.0.0.2/32");
    let allowed: Vec<String> = wg.peers[0]
        .allowed_ips
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(allowed, ["0.0.0.0/0", "::/0"]);
    assert_eq!(p.source, Source::Json);
    assert!(p.notes.is_empty(), "{:?}", p.notes);
}

/// Several peers must say which routes each carries.
#[test]
fn wireguard_multi_peer_needs_allowed_ips() {
    let peer = |h: &str| json!({ "address": h, "port": 51820, "public_key": "PUB-FAKE" });
    let r = parse(
        json!({ "endpoints": [{ "type": "wireguard", "address": "10.0.0.2", "private_key": "K",
                                          "peers": [peer("a.example"), peer("b.example")] }] }),
    );
    assert!(r.profiles.is_empty());
    assert!(
        matches!(r.skipped[0].reason, SkipReason::Invalid { .. }),
        "{r:?}"
    );
}

/// REALITY next to ECH or on Hysteria2 can never connect (the emitter refuses both): skipped.
#[test]
fn reality_with_ech_or_on_quic_is_skipped() {
    let reality = json!({ "enabled": true, "public_key": "PBK-FAKE", "short_id": "ab" });
    let r = parse(json!({ "outbounds": [
        { "type": "vless", "tag": "e", "server": "r.example", "server_port": 443,
          "uuid": "00000000-0000-4000-8000-000000000001",
          "tls": { "enabled": true, "server_name": "www.example.com", "reality": reality,
                   "ech": { "enabled": true, "config": ["AEr+"] } } },
        { "type": "hysteria2", "tag": "q", "server": "h.example", "server_port": 443,
          "password": "fake", "tls": { "enabled": true, "reality": reality } }
    ] }));
    assert!(r.profiles.is_empty(), "{r:?}");
    let detail = |i: usize| match &r.skipped[i].reason {
        SkipReason::Invalid { detail, .. } => detail.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        [detail(0), detail(1)],
        [
            "REALITY cannot be combined with ECH",
            "REALITY cannot run over QUIC"
        ],
        "{r:?}"
    );
}

/// Spec §7.2 "Xray docs with remarks": three documents, each named by its remarks.
#[test]
fn xray_documents_are_named_by_remarks() {
    let doc = |remarks: &str, host: &str, port: u16, id: &str| {
        json!({ "remarks": remarks, "outbounds": [
            xray_vless("proxy", host, port, json!([{ "id": id, "flow": "xtls-rprx-vision" }])),
            { "tag": "direct", "protocol": "freedom" } ] })
    };
    let r = parse(json!([
        doc(
            "Norway",
            "bridge1.example.net",
            443,
            "00000000-0000-4000-8000-000000000001"
        ),
        doc(
            "Sweden",
            "bridge1.example.net",
            443,
            "00000000-0000-4000-8000-000000000002"
        ),
        doc(
            "Finland",
            "bridge2.example.net",
            8443,
            "00000000-0000-4000-8000-000000000003"
        ),
    ]));
    assert_eq!(names(&r), ["Norway", "Sweden", "Finland"]);
    assert_eq!(
        r.profiles[2].server,
        Host::Domain("bridge2.example.net".into())
    );
    assert_eq!(r.profiles[2].port, 8443);
    assert!(r.profiles.iter().all(|p| p.kind.label() == "vless"));
    let tls = r.profiles[0].tls.as_ref().expect("reality");
    assert_eq!(tls.fingerprint.as_deref(), Some("firefox"));
    assert_eq!(
        tls.reality.as_ref().and_then(|x| x.spider_x.as_deref()),
        Some("/test-path")
    );
}

/// Spec §7.2 "direct outbound array" and "non-generic tag".
#[test]
fn xray_outbound_arrays_use_remarks_then_tags() {
    let mut a = xray_vless("proxy", "a.example", 443, json!([{ "id": UUID }]));
    a["remarks"] = json!("Direct Node 1");
    let mut b = xray_vless("proxy", "b.example", 443, json!([{ "id": UUID }]));
    b["remarks"] = json!("Direct Node 2");
    assert_eq!(
        names(&parse(json!([a, b]))),
        ["Direct Node 1", "Direct Node 2"]
    );
    let tagged = xray_vless(
        "🇭🇰 HK-Special-01",
        "hk.example",
        443,
        json!([{ "id": UUID }]),
    );
    assert_eq!(names(&parse(json!([tagged]))), ["🇭🇰 HK-Special-01"]);
}

/// Spec §7.2 "multi-user": two users in the first node plus a second node give three profiles.
#[test]
fn xray_multi_user_splits_per_credential() {
    let out = json!({ "tag": "Multi", "protocol": "vless", "settings": { "vnext": [
        { "address": "one.example", "port": 443, "users": [{ "id": UUID }, { "id": "00000000-0000-4000-8000-000000000002" }] },
        { "address": "two.example", "port": 443, "users": [{ "id": "00000000-0000-4000-8000-000000000003" }] } ] } });
    let r = parse(json!({ "outbounds": [out] }));
    assert_eq!(names(&r), ["Multi #1", "Multi #2", "Multi"]);
    let Kind::Vless { uuid, .. } = &r.profiles[1].kind else {
        panic!()
    };
    assert_eq!(uuid, "00000000-0000-4000-8000-000000000002");
}

/// P-04 class: one outbound with thousands of users is linear (each per-user graph used to start
/// from a copy of the whole user list).
#[test]
fn many_users_stay_linear() {
    let users: Vec<Value> = (0..5000)
        .map(|i| json!({ "id": format!("00000000-0000-4000-8000-{i:012}") }))
        .collect();
    let started = std::time::Instant::now();
    let r =
        parse(json!({ "outbounds": [xray_vless("Big", "b.example", 443, Value::Array(users))] }));
    assert_eq!(r.profiles.len(), 5000);
    assert_eq!(r.profiles[4999].name, "Big #5000");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

/// Spec §7.2 "independent outbounds": 100 plain outbounds are 100 profiles.
#[test]
fn hundred_independent_outbounds() {
    let outs: Vec<Value> = (0..100)
        .map(|i| {
            xray_vless(
                &format!("node-{i}"),
                &format!("n{i}.example"),
                443,
                json!([{ "id": UUID }]),
            )
        })
        .collect();
    let r = parse(json!({ "outbounds": outs }));
    assert_eq!(r.profiles.len(), 100);
    assert_eq!(r.profiles[99].name, "node-99");
}

/// AT-04-006: allow-listed sing-box keys survive verbatim, the rest become Notes (none silently lost).
#[test]
fn singbox_keys_are_kept_or_noted() {
    let r = parse(json!({ "outbounds": [{
        "type": "vless", "tag": "de-1", "server": "de.example", "server_port": 443, "uuid": UUID,
        "flow": "xtls-rprx-vision", "network": "tcp", "remarks": "Germany", "sourceUri": "vless://x",
        "bind_interface": "eth0", "foo": 1, "tcp_fast_open": true, "connect_timeout": "5s",
        "domain_resolver": { "server": "dns-remote", "strategy": "ipv4_only" },
        "tls": { "enabled": true, "server_name": "front.example", "fragment": true, "record_fragment": true,
                 "certificate_path": "C:/cert.pem", "utls": { "enabled": true, "fingerprint": "firefox" },
                 "alpn": ["http/1.1"], "engine": "apple", "kernel_tx": true },
        "multiplex": { "enabled": true, "protocol": "h2mux", "max_connections": 4, "min_streams": 2, "padding": true }
    }] }));
    assert_eq!(r.profiles.len(), 1, "{r:?}");
    let p = &r.profiles[0];
    assert_eq!(p.name, "Germany");
    let mut extra: Vec<&str> = p.singbox_extra.keys().map(String::as_str).collect();
    extra.sort_unstable();
    assert_eq!(
        extra,
        [
            "multiplex.min_streams",
            "network",
            "tls.fragment",
            "tls.record_fragment"
        ]
    );
    assert_eq!(p.singbox_extra["multiplex.min_streams"], json!(2));
    assert!(
        p.notes
            .contains(&Note::DialFieldDropped("bind_interface".into())),
        "{:?}",
        p.notes
    );
    assert!(p.notes.contains(&Note::UnsupportedField("foo".into())));
    assert!(
        p.notes
            .contains(&Note::FileReferenceDropped("tls.certificate_path".into()))
    );
    // Platform-bound TLS knobs would make sing-box refuse the whole config on Windows.
    for key in ["tls.engine", "tls.kernel_tx"] {
        assert!(
            p.notes.contains(&Note::UnsupportedField(key.into())),
            "{key}"
        );
    }
    assert_eq!(
        p.notes.len(),
        5,
        "annotations (remarks, sourceUri) are not notes: {:?}",
        p.notes
    );
    // The provider's fingerprint and ALPN are kept as given (AT-04-006, K3).
    let tls = p.tls.as_ref().expect("tls");
    assert_eq!(
        (tls.fingerprint.as_deref(), tls.alpn.as_slice()),
        (Some("firefox"), &["http/1.1".to_owned()][..])
    );
    assert_eq!(p.dial.dns_strategy.as_deref(), Some("ipv4_only"));
    assert_eq!(p.dial.connect_timeout_s, Some(5));
    assert!(p.dial.tcp_fast_open);
    let mux = p.mux.as_ref().expect("mux");
    assert_eq!(
        (mux.protocol.as_deref(), mux.max_connections, mux.padding),
        (Some("h2mux"), Some(4), true)
    );
}

/// Spec §7.3 P-04 tail: a bare trojan outbound object is one profile.
#[test]
fn bare_outbound_object() {
    let r = parse(
        json!({ "type": "trojan", "server": "192.0.2.1", "server_port": 443, "password": "p" }),
    );
    assert_eq!(r.profiles.len(), 1);
    assert_eq!(
        r.profiles[0].server,
        Host::Ip("192.0.2.1".parse().expect("ip"))
    );
    assert_eq!(r.profiles[0].name, "Trojan");
}

/// P-11: Shadowsocks over ShadowTLS is one chained profile; a ShadowTLS outbound alone is skipped.
#[test]
fn shadowtls_chain_and_standalone() {
    let r = parse(json!({ "outbounds": [
        { "type": "shadowsocks", "tag": "ss", "method": "2022-blake3-aes-128-gcm", "password": "SS-FAKE", "detour": "stls" },
        { "type": "shadowtls", "tag": "stls", "server": "st.example", "server_port": 443, "version": 3,
          "password": "ST-FAKE", "tls": { "enabled": true, "server_name": "www.microsoft.com" } },
        { "type": "shadowtls", "tag": "lonely", "server": "x.example", "server_port": 443, "version": 3, "password": "P" }
    ] }));
    assert_eq!(r.profiles.len(), 1, "{r:?}");
    let p = &r.profiles[0];
    assert_eq!(
        (p.server.clone(), p.port),
        (Host::Domain("st.example".into()), 443)
    );
    let Kind::Shadowsocks {
        shadowtls: Some(layer),
        ..
    } = &p.kind
    else {
        panic!("{:?}", p.kind)
    };
    assert_eq!(
        (layer.version, layer.server_name.as_str()),
        (3, "www.microsoft.com")
    );
    assert!(
        p.notes.is_empty(),
        "detour of the chain is not a dropped field: {:?}",
        p.notes
    );
    assert_eq!(r.skipped.len(), 1);
    assert_eq!(r.skipped[0].reason, SkipReason::ShadowTlsNeedsInner);
}

/// Hysteria2 from sing-box JSON: ranges, durations, obfs; the legacy `network: "tcp"` is dropped.
#[test]
fn singbox_hysteria2() {
    let r = parse(
        json!({ "type": "hysteria2", "tag": "hy", "server": "hy.example", "server_ports": ["20000:30000", "443"],
        "hop_interval": "30s", "up_mbps": 50, "down_mbps": 200, "password": "PW-FAKE", "network": "tcp",
        "obfs": { "type": "salamander", "password": "OB-FAKE", "min_packet_size": 512 },
        "tls": { "enabled": true, "server_name": "front.example", "alpn": ["h3"] } }),
    );
    let p = &r.profiles[0];
    assert_eq!(
        p.port, 20000,
        "server_port falls back to the first hopping port"
    );
    let Kind::Hysteria2 {
        ports,
        hop_interval_s,
        up_mbps,
        obfs,
        ..
    } = &p.kind
    else {
        panic!()
    };
    assert_eq!(ports, &[(20000, 30000), (443, 443)]);
    assert_eq!((*hop_interval_s, *up_mbps), (Some(30), Some(50)));
    assert_eq!(obfs.as_ref().map(|o| o.kind.as_str()), Some("salamander"));
    assert_eq!(
        p.singbox_extra.get("obfs.min_packet_size"),
        Some(&json!(512))
    );
    assert!(!p.singbox_extra.contains_key("network"));
    assert!(p.notes.is_empty(), "{:?}", p.notes);
    // An obfuscation the core cannot run (no password, unknown type) refuses the entry at import
    // instead of failing at connect.
    for obfs in [
        json!({ "type": "salamander" }),
        json!({ "type": "brutal", "password": "x" }),
    ] {
        let r = parse(
            json!({ "type": "hysteria2", "server": "hy.example", "server_port": 443, "password": "PW", "obfs": obfs }),
        );
        assert!(
            r.profiles.is_empty() && matches!(r.skipped[0].reason, SkipReason::Invalid { .. }),
            "{r:?}"
        );
    }
}

/// AT-04-002: a non-zero VMess alter_id is normalised with a visible Note.
#[test]
fn vmess_alter_id_note() {
    let r = parse(
        json!({ "type": "vmess", "server": "vm.example", "server_port": 443, "uuid": UUID, "alter_id": 64 }),
    );
    assert_eq!(r.profiles[0].notes, [Note::AlterIdNormalized(64)]);
}

/// Unencrypted and naive-insecure facts are Notes; unsupported plugins / transports are skipped.
#[test]
fn notes_and_typed_refusals() {
    let r = parse(json!({ "outbounds": [
        { "type": "socks", "tag": "s", "server": "127.0.0.1", "server_port": 1080 },
        { "type": "naive", "tag": "n", "server": "n.example", "server_port": 443, "username": "u", "password": "p",
          "tls": { "enabled": true, "server_name": "n.example", "insecure": true } },
        { "type": "shadowsocks", "tag": "kcp", "server": "s.example", "server_port": 8388, "method": "aes-256-gcm",
          "password": "p", "plugin": "kcptun" },
        { "type": "vless", "tag": "x", "server": "v.example", "server_port": 443, "uuid": UUID,
          "transport": { "type": "mkcp" } },
        { "type": "trojan", "tag": "t", "server": "t.example", "server_port": 443, "password": "" }
    ] }));
    assert_eq!(r.profiles[0].notes, [Note::Unencrypted]);
    assert_eq!(r.profiles[1].notes, [Note::NaiveInsecureIgnored]);
    assert!(
        r.profiles[1].tls.as_ref().is_some_and(|t| t.insecure),
        "stored, not applied"
    );
    let reasons: Vec<&SkipReason> = r.skipped.iter().map(|s| &s.reason).collect();
    assert_eq!(
        reasons,
        [
            &SkipReason::UnsupportedPlugin("kcptun".into()),
            &SkipReason::UnsupportedTransport("mkcp".into()),
            &SkipReason::MissingCredential,
        ]
    );
    assert!(
        r.skipped
            .iter()
            .all(|s| !s.excerpt.contains("aes") && s.excerpt.chars().count() <= 80)
    );
}

/// AT-04-006: a block the type cannot carry is a Note, not a silent drop; a provider uTLS
/// fingerprint on a QUIC protocol is kept but flagged (sing-box cannot apply it).
#[test]
fn blocks_the_type_cannot_carry() {
    let r = parse(json!({ "outbounds": [
        { "type": "shadowsocks", "tag": "ss", "server": "s.example", "server_port": 8388, "method": "aes-256-gcm",
          "password": "p", "tls": { "enabled": true, "server_name": "s.example" }, "transport": { "type": "ws" } },
        { "type": "tuic", "tag": "tu", "server": "t.example", "server_port": 443, "uuid": UUID, "password": "p",
          "heartbeat": "10s", "tls": { "enabled": true, "server_name": "t.example", "utls": { "enabled": true, "fingerprint": "chrome" } } }
    ] }));
    let ss = &r.profiles[0];
    assert!(ss.tls.is_none() && ss.transport.is_none());
    assert_eq!(
        ss.notes,
        [
            Note::UnsupportedField("tls".into()),
            Note::UnsupportedField("transport".into())
        ]
    );
    let tuic = &r.profiles[1];
    assert_eq!(tuic.notes, [Note::ProviderFpDroppedOnQuic]);
    assert_eq!(
        tuic.tls.as_ref().and_then(|t| t.fingerprint.as_deref()),
        Some("chrome")
    );
    assert!(matches!(
        tuic.kind,
        Kind::Tuic {
            heartbeat_s: Some(10),
            ..
        }
    ));
}

/// Spec §7.2 XHTTP / gRPC vectors on the Xray side: Xray-only transports stay typed.
#[test]
fn xray_transports() {
    let stream = |s: Value| {
        json!({ "tag": "t", "protocol": "trojan",
        "settings": { "servers": [{ "address": "192.0.2.1", "port": 443, "password": "SYNTHETIC_PASSWORD" }] },
        "streamSettings": s })
    };
    let extra = json!({ "noSSEHeader": true, "custom": { "escaped": "%2F&=%25", "array": [true, 0, "text"] } });
    let r = parse(json!([
        stream(
            json!({ "network": "xhttp", "security": "tls", "tlsSettings": { "serverName": "front.example.com" },
            "xhttpSettings": { "path": "/a%2Fb", "host": "front.example.com", "mode": "packet-up", "extra": extra } })
        ),
        stream(
            json!({ "method": "grpc", "grpcSettings": { "serviceName": "service-name", "multiMode": true } })
        ),
        stream(json!({ "network": "xhttp", "xhttpSettings": { "mode": "not-a-mode" } })),
        stream(json!({ "network": "xhttp", "xhttpSettings": { "extra": [] } })),
        stream(json!({ "network": "kcp" })),
    ]));
    let Some(Transport::Xhttp {
        path,
        mode,
        extra: Some(kept),
        ..
    }) = &r.profiles[0].transport
    else {
        panic!("{r:?}")
    };
    assert_eq!(
        (path.as_str(), mode.as_deref()),
        ("/a%2Fb", Some("packet-up"))
    );
    assert_eq!(Value::Object(kept.clone()), extra);
    assert_eq!(
        r.profiles[1].transport,
        Some(Transport::Grpc {
            service_name: "service-name".into(),
            multi_mode: Some(true)
        })
    );
    // Without a preserved graph, kcp has nowhere to go; with one it is carried by the graph.
    let unusable = if cfg!(feature = "profiles-native") {
        2
    } else {
        3
    };
    assert_eq!(r.skipped.len(), unusable, "{:?}", r.skipped);
    assert!(matches!(r.skipped[0].reason, SkipReason::Invalid { .. }));
}

/// REALITY needs its public key; Xray's newer `password` name is accepted.
#[test]
fn xray_reality_key() {
    let mut no_key = xray_vless("a", "a.example", 443, json!([{ "id": UUID }]));
    no_key["streamSettings"]["realitySettings"] = json!({ "serverName": "x", "shortId": "1" });
    let mut renamed = xray_vless("b", "b.example", 443, json!([{ "id": UUID }]));
    renamed["streamSettings"]["realitySettings"] =
        json!({ "serverName": "x", "password": "PBK-NEW" });
    let r = parse(json!([no_key, renamed]));
    assert!(
        matches!(r.skipped[0].reason, SkipReason::Invalid { .. }),
        "{r:?}"
    );
    let reality = r.profiles[0]
        .tls
        .as_ref()
        .and_then(|t| t.reality.clone())
        .expect("reality");
    assert_eq!(reality.public_key, "PBK-NEW");
}

/// Xray 26 flat settings and the `hysteria` protocol (version 2, password in hysteriaSettings).
#[test]
fn xray_flat_settings_and_hysteria() {
    let r = parse(json!({ "outbounds": [
        { "tag": "flat", "protocol": "vless", "settings": { "address": "f.example", "port": 443, "id": UUID, "encryption": "none" } },
        { "tag": "hy", "protocol": "hysteria", "settings": { "version": 2, "address": "h.example", "port": 8443 },
          "streamSettings": { "method": "hysteria", "hysteriaSettings": { "version": 2, "auth": "HY-FAKE" },
                              "security": "tls", "tlsSettings": { "serverName": "h.example", "alpn": ["h3"],
                              "pinnedPeerCertSha256": "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89" } } }
    ] }));
    assert_eq!(names(&r), ["flat", "hy"]);
    let Kind::Vless { encryption, .. } = &r.profiles[0].kind else {
        panic!()
    };
    assert_eq!(encryption, &None);
    let hy = &r.profiles[1];
    assert!(matches!(&hy.kind, Kind::Hysteria2 { password, .. } if password == "HY-FAKE"));
    assert_eq!(
        hy.tls.as_ref().and_then(|t| t.cert_pin_sha256.as_deref()),
        Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    );
    assert_eq!(hy.notes, [Note::CertPinNotEnforced]);
}

/// Xray 26 Hysteria `finalmask`: Salamander / Gecko and `udpHop` reach the typed profile; masks
/// sing-box cannot run are Notes (the old reading dropped the obfuscation silently).
#[test]
fn xray_hysteria_finalmask() {
    let hy = |mask: Value| {
        let doc = json!({ "tag": "hy", "protocol": "hysteria", "settings": { "version": 2, "address": "h.example", "port": 443 },
            "streamSettings": { "method": "hysteria", "hysteriaSettings": { "version": 2, "auth": "HY-FAKE" }, "finalmask": mask } });
        parse(doc).profiles.remove(0)
    };
    let p = hy(
        json!({ "udp": [{ "type": "salamander", "settings": { "password": "OBFS-FAKE" } }],
        "quicParams": { "udpHop": { "ports": "20000-30000,443", "interval": "5-10" }, "bbrProfile": "aggressive" } }),
    );
    let Kind::Hysteria2 {
        obfs,
        ports,
        hop_interval_s,
        hop_interval_max_s,
        bbr_profile,
        ..
    } = &p.kind
    else {
        panic!()
    };
    let obfs = obfs.as_ref().expect("obfs");
    assert_eq!(
        (obfs.kind.as_str(), obfs.password.as_str()),
        ("salamander", "OBFS-FAKE")
    );
    assert_eq!(ports, &[(20000, 30000), (443, 443)]);
    assert_eq!((*hop_interval_s, *hop_interval_max_s), (Some(5), Some(10)));
    assert_eq!(bbr_profile.as_deref(), Some("aggressive"));
    assert!(p.notes.is_empty() && p.singbox_extra.is_empty(), "{p:?}");

    let p = hy(
        json!({ "udp": [{ "type": "salamander", "settings": { "password": "O", "packetSize": "512-1200" } },
            { "type": "noise", "settings": {} }],
        "quicParams": { "udpHop": { "interval": 30 }, "brutalDisableLossCompensation": true } }),
    );
    let Kind::Hysteria2 {
        obfs,
        hop_interval_s,
        hop_interval_max_s,
        ..
    } = &p.kind
    else {
        panic!()
    };
    assert_eq!(obfs.as_ref().map(|o| o.kind.as_str()), Some("gecko"));
    assert_eq!((*hop_interval_s, *hop_interval_max_s), (Some(30), None));
    assert_eq!(
        (
            p.singbox_extra.get("obfs.min_packet_size"),
            p.singbox_extra.get("obfs.max_packet_size")
        ),
        (Some(&json!(512)), Some(&json!(1200)))
    );
    assert_eq!(
        p.notes,
        [
            Note::UnsupportedField("finalmask.udp.noise".into()),
            Note::UnsupportedField("finalmask.quicParams.brutalDisableLossCompensation".into())
        ]
    );
}

/// Xray Hysteria Brutal rates become sing-box `up_mbps` / `down_mbps` the way Xray's client
/// uses them: the upload only under the default / `brutal` / `force-brutal` congestion, the
/// announced download always; units are bits with binary multiples, case-insensitive.
#[test]
fn xray_hysteria_brutal_rates() {
    let rates = |quic: Value| {
        let doc = json!({ "tag": "hy", "protocol": "hysteria", "settings": { "version": 2, "address": "h.example", "port": 443 },
            "streamSettings": { "network": "hysteria", "hysteriaSettings": { "version": 2, "auth": "HY-FAKE" },
                                "finalmask": { "quicParams": quic } } });
        let p = parse(doc).profiles.remove(0);
        let Kind::Hysteria2 {
            up_mbps, down_mbps, ..
        } = p.kind
        else {
            panic!()
        };
        (up_mbps, down_mbps, p.notes)
    };
    // 100 * 2^20 bit/s = 104.9 Mbit/s; 1 Gbps = 1073.7 Mbit/s.
    assert_eq!(
        rates(json!({ "brutalUp": "100 mbps", "brutalDown": "1 Gbps" })),
        (Some(105), Some(1074), vec![])
    );
    assert_eq!(
        rates(json!({ "congestion": "force-brutal", "brutalUp": "50MBPS" })),
        (Some(52), None, vec![])
    );
    assert_eq!(
        rates(json!({ "congestion": "bbr", "brutalUp": "50 mbps", "brutalDown": "200 mbps" })),
        (None, Some(210), vec![])
    );
    assert_eq!(
        rates(json!({ "congestion": "reno", "brutalUp": "lots", "brutalDown": "0" })),
        (
            None,
            None,
            vec![
                Note::UnsupportedField("finalmask.quicParams.congestion".into()),
                Note::UnsupportedField("finalmask.quicParams.brutalUp".into()),
                Note::UnsupportedField("finalmask.quicParams.brutalDown".into())
            ]
        )
    );
}
#[test]
fn wrappers_and_strings() {
    use base64::Engine as _;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let doc = json!({ "outbounds": [{ "type": "trojan", "tag": "wrapped", "server": "w.example", "server_port": 443, "password": "p" }] });
    let text = doc.to_string();
    for input in [
        json!({ "ok": true, "data": { "config": doc.clone() } }),
        json!({ "result": text.clone() }),
        json!({ "subscription": b64(&text) }),
        json!({ "anything": b64(&b64(&text)) }),
    ] {
        assert_eq!(names(&parse(input.clone())), ["wrapped"], "{input}");
    }
    assert!(
        parse(json!({ "x": b64(&b64(&b64(&text))) }))
            .profiles
            .is_empty(),
        "three base64 layers are too many"
    );
}

/// AT-04-001: nesting beyond depth 6 is not searched and never panics.
#[test]
fn depth_limit() {
    let mut v =
        json!({ "type": "trojan", "server": "d.example", "server_port": 443, "password": "p" });
    for _ in 0..6 {
        v = json!({ "data": v });
    }
    assert_eq!(parse(v.clone()).profiles.len(), 1);
    assert!(parse(json!({ "data": v })).profiles.is_empty());
}

/// A server config's inbounds never become profiles, wherever they sit.
#[test]
fn inbounds_are_ignored() {
    let inbound = json!({ "type": "vless", "tag": "in", "listen": "::", "listen_port": 443, "users": [{ "uuid": UUID }] });
    let r = parse(json!({ "inbounds": [inbound.clone()], "extra": [inbound] }));
    assert_eq!((r.profiles.len(), r.skipped.len()), (0, 0));
}

/// Provider Xray graphs (need the `profiles-native` package, which owns graph validation).
#[cfg(feature = "profiles-native")]
mod native {
    use super::*;

    /// A Happ/Remnawave-style document: a balancer over two REALITY hops, entered by the last rule.
    fn provider_doc(remarks: &str, host: &str) -> Value {
        let hop = |tag: &str, h: &str| {
            let mut o = xray_vless(
                tag,
                h,
                443,
                json!([{ "id": UUID, "flow": "xtls-rprx-vision" }]),
            );
            o["mux"] = json!({ "enabled": true, "concurrency": 6, "xudpConcurrency": 4, "xudpProxyUDP443": "reject" });
            o
        };
        json!({ "remarks": remarks,
            "outbounds": [hop("proxy-1", host), hop("proxy-2", &format!("b.{host}")),
                          { "tag": "direct", "protocol": "freedom" }, { "tag": "block", "protocol": "blackhole" }],
            "routing": { "balancers": [{ "tag": "l1", "selector": ["proxy-"], "strategy": { "type": "leastPing" } }],
                         "rules": [{ "type": "field", "domain": ["geosite:private"], "outboundTag": "direct" },
                                   { "type": "field", "network": "tcp,udp", "balancerTag": "l1" }] },
            "observatory": { "subjectSelector": ["proxy-"], "probeUrl": "https://www.google.com/generate_204" } })
    }

    /// Spec §7.2 "provider documents": one profile per document, graph entered at the balancer,
    /// the provider's `firefox` fingerprint kept.
    #[test]
    fn one_profile_per_provider_document() {
        let r = parse(json!([
            provider_doc("Norway", "no.example"),
            provider_doc("Sweden", "se.example")
        ]));
        assert_eq!(names(&r), ["Norway", "Sweden"], "{r:?}");
        let p = &r.profiles[0];
        let graph = p.native_xray.as_ref().expect("graph");
        assert_eq!(graph.entry.balancer_tag.as_deref(), Some("l1"));
        assert!(graph.outbounds.len() >= 2, "both balancer hops are kept");
        assert_eq!(
            p.tls.as_ref().and_then(|t| t.fingerprint.as_deref()),
            Some("firefox")
        );
        assert_eq!(p.server, Host::Domain("no.example".into()));
    }

    /// Spec §7.2 "unsafe graph" + §7.3 P-14 isolation: a balancer falling back to `freedom` and a
    /// local certificate file reject only their own document.
    #[test]
    fn unsafe_graph_rejects_only_its_document() {
        let mut fallback = provider_doc("Unsafe", "u.example");
        fallback["routing"]["balancers"][0]["fallbackTag"] = json!("direct");
        let mut file_ref = provider_doc("FileRef", "f.example");
        file_ref["outbounds"][0]["streamSettings"]["realitySettings"]["certificateFile"] =
            json!("C:/cert.pem");
        let r = parse(json!([
            provider_doc("Norway", "no.example"),
            fallback,
            file_ref
        ]));
        assert_eq!(names(&r), ["Norway"]);
        assert_eq!(r.skipped.len(), 2, "{:?}", r.skipped);
        assert!(
            r.skipped
                .iter()
                .all(|s| matches!(s.reason, SkipReason::NativeGraphRejected(_)))
        );
    }

    /// Spec §7.2 "independent outbounds" / "multi-user": every graph holds only its own outbound,
    /// narrowed to one node and one user (no quadratic credential copies).
    #[test]
    fn graphs_hold_only_their_own_outbound() {
        let outs: Vec<Value> = (0..100)
            .map(|i| {
                xray_vless(
                    &format!("node-{i}"),
                    &format!("n{i}.example"),
                    443,
                    json!([{ "id": UUID }]),
                )
            })
            .collect();
        let r = parse(json!({ "outbounds": outs }));
        assert!(r.profiles.iter().all(|p| {
            p.native_xray
                .as_ref()
                .is_some_and(|g| g.outbounds.len() == 1)
        }));
        let multi = json!({ "tag": "Multi", "protocol": "vless", "settings": { "vnext": [
            { "address": "one.example", "port": 443, "users": [{ "id": UUID }, { "id": "00000000-0000-4000-8000-000000000002" }] },
            { "address": "two.example", "port": 443, "users": [{ "id": "00000000-0000-4000-8000-000000000003" }] } ] } });
        let r = parse(json!({ "outbounds": [multi] }));
        assert_eq!(r.profiles.len(), 3);
        for p in &r.profiles {
            let graph = p.native_xray.as_ref().expect("graph");
            let vnext = graph.outbounds[0]
                .pointer("/settings/vnext")
                .and_then(Value::as_array)
                .expect("vnext");
            assert_eq!(vnext.len(), 1);
            assert_eq!(vnext[0]["users"].as_array().map(Vec::len), Some(1));
        }
    }
}

/// Share links and Clash text inside JSON strings (need the `profiles-uri` / `profiles-clash` packages).
#[cfg(feature = "profiles-uri")]
mod strings_with_links {
    use super::*;

    const VLESS: &str = "vless://00000000-0000-4000-8000-000000000001@one.example.com:443?security=tls&sni=front.example.com#One";
    const TROJAN: &str = "trojan://secret@two.example.com:443?sni=front.example.com#Two";

    /// Spec §7.2 smoke: `{"ok":true,"links":[vless, trojan]}` gives 2 profiles; a feed URL in the
    /// same document is not a key.
    #[test]
    fn links_inside_json() {
        let r = parse(
            json!({ "ok": true, "url": "https://sub.example.com/abc", "links": [VLESS, TROJAN] }),
        );
        assert_eq!(names(&r), ["One", "Two"], "{r:?}");
        assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    }

    /// Spec §3.4 "parse_text-like": a string holding prose, a JSON document and a link yields both
    /// keys (the document's span is not scanned for links again); a link inside a sentence counts.
    #[test]
    fn every_format_of_one_string() {
        let doc = r#"{"type":"trojan","tag":"Doc","server":"d.example","server_port":443,"password":"p"}"#;
        let r = parse(json!({ "message": format!("Your keys: {doc}\nand {VLESS}.") }));
        assert_eq!(names(&r), ["Doc", "One"], "{r:?}");
        assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    }

    /// Spec §7.2 "doc + URI": a provider document and a share link side by side in one array.
    #[cfg(feature = "profiles-native")]
    #[test]
    fn document_next_to_a_link() {
        let doc = json!({ "remarks": "Norway", "outbounds": [xray_vless("proxy", "no.example", 443, json!([{ "id": UUID }]))],
            "routing": { "rules": [{ "type": "field", "network": "tcp,udp", "outboundTag": "proxy" }] } });
        let simple =
            "vless://00000000-0000-4000-8000-000000000001@s.example:443?security=tls#Simple";
        assert_eq!(names(&parse(json!([doc, simple]))), ["Norway", "Simple"]);
    }

    /// A Clash list stored as a JSON string goes to the Clash importer.
    #[cfg(feature = "profiles-clash")]
    #[test]
    fn clash_inside_json() {
        let yaml = "proxies:\n- name: c0\n  type: trojan\n  server: t.example\n  port: 443\n  password: p\n";
        let r = parse(json!({ "data": yaml }));
        assert_eq!(names(&r), ["c0"], "{r:?}");
    }
}
