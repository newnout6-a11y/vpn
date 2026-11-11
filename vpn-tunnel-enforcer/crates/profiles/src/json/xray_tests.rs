//! Xray-format import decisions (engine audit 2026-11-11): SOCKS / HTTP / WireGuard outbounds,
//! unknown proxy protocols, plain outbounds as typed profiles, transports Xray 26 removed. What
//! comes out typed is emitted and piped through the bundled `sing-box check` when it exists.
use serde_json::{Value, json};

use super::parse_json;
use crate::emit_singbox::check::{check, sing_box};
use crate::emit_singbox::{EmitPolicy, emit_singbox};
use crate::model::{Host, Kind, Note, ParseReport, Profile, SkipReason, Transport};

const UUID: &str = "00000000-0000-4000-8000-000000000001";
/// Well-formed fake WireGuard keys (sing-box parses keys when it builds the endpoint).
const WG_PRIVATE: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
const WG_PUBLIC: &str = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=";
const WG_PSK: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A=";

fn parse(v: Value) -> ParseReport {
    parse_json(&v)
}

/// Every profile emits and passes `sing-box check` (skipped quietly without the binary).
fn assert_sing_box_runs(profiles: &[Profile]) {
    let exe = sing_box();
    for p in profiles {
        let fragment = emit_singbox(p, "proxy-out", &EmitPolicy::default())
            .unwrap_or_else(|e| panic!("{}: {e}", p.name));
        if let Some(exe) = &exe {
            check(exe, &fragment).unwrap_or_else(|e| panic!("{}: {e}", p.name));
        }
    }
}

fn wireguard_outbound(peers: Value) -> Value {
    json!({ "tag": "wg-nl", "protocol": "wireguard", "settings": {
        "secretKey": WG_PRIVATE, "address": ["172.16.0.2/32", "2606:4700:110:8a36::2/128"],
        "peers": peers, "mtu": 1280, "reserved": [1, 2, 3], "remoteDNS": ["1.1.1.1"],
        "noKernelTun": true, "workers": 2 } })
}

/// Engine audit: Xray SOCKS, HTTP and WireGuard outbounds used to vanish from an import; they
/// are typed profiles now, in the Xray 26 flat shape and the older `servers[].users[]` one.
#[test]
fn xray_socks_http_wireguard_are_typed() {
    let r = parse(json!({ "outbounds": [
        { "tag": "socks-flat", "protocol": "socks",
          "settings": { "address": "192.0.2.10", "port": 1080, "user": "u1", "pass": "p1" } },
        { "tag": "socks-old", "protocol": "socks", "settings": { "servers": [
            { "address": "s.example", "port": 1080, "users": [{ "user": "u2", "pass": "p2" }] } ] } },
        { "tag": "http-tls", "protocol": "http",
          "settings": { "address": "h.example", "port": 443, "user": "u3", "pass": "p3",
                        "headers": { "User-Agent": "x" } },
          "streamSettings": { "security": "tls", "tlsSettings": { "serverName": "h.example" } } },
        wireguard_outbound(json!([{ "endpoint": "wg.example:2408", "publicKey": WG_PUBLIC,
                                    "preSharedKey": WG_PSK, "keepAlive": 25 }])),
        { "tag": "direct", "protocol": "freedom", "settings": {} },
        { "tag": "dns-out", "protocol": "dns", "settings": { "address": "1.1.1.1" } }
    ] }));
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    let names: Vec<&str> = r.profiles.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["socks-flat", "socks-old", "http-tls", "wg-nl"]);
    let [socks_flat, socks_old, http, wg] = &r.profiles[..] else {
        unreachable!()
    };
    assert!(
        matches!(&socks_flat.kind, Kind::Socks { username: Some(u), password: Some(p) } if u == "u1" && p == "p1")
    );
    assert_eq!(socks_flat.notes, [Note::Unencrypted]);
    assert!(matches!(&socks_old.kind, Kind::Socks { username: Some(u), .. } if u == "u2"));
    assert_eq!(socks_old.server, Host::Domain("s.example".into()));
    assert!(matches!(&http.kind, Kind::Http { password: Some(p), .. } if p == "p3"));
    assert!(http.tls.is_some());
    assert_eq!(
        http.notes,
        [Note::UnsupportedField("settings.headers".into())]
    );
    let Kind::Wireguard(tunnel) = &wg.kind else {
        panic!("{:?}", wg.kind.label())
    };
    assert_eq!(
        (&wg.server, wg.port),
        (&Host::Domain("wg.example".into()), 2408)
    );
    assert_eq!(tunnel.local_address.len(), 2);
    assert_eq!(tunnel.mtu, Some(1280));
    let peer = &tunnel.peers[0];
    assert_eq!(peer.allowed_ips.len(), 2, "a lone peer carries everything");
    assert_eq!(
        (
            peer.reserved,
            peer.keepalive_s,
            peer.pre_shared_key.as_deref()
        ),
        (Some([1, 2, 3]), Some(25), Some(WG_PSK))
    );
    assert_eq!(
        wg.notes,
        [Note::UnsupportedField("settings.workers".into())]
    );
    assert!(r.profiles.iter().all(|p| p.native_xray.is_none()));
    assert_sing_box_runs(&r.profiles);
}

/// What cannot become a profile says why: SOCKS over TLS or a transport, a chain the typed key
/// cannot follow, WireGuard without peers or with unrouted peers, an unknown proxy protocol, a
/// server-less outbound. Routing helpers and stray inbounds stay silent.
#[test]
fn unusable_xray_outbounds_are_skipped_with_a_reason() {
    let peer = |endpoint: &str| json!({ "endpoint": endpoint, "publicKey": WG_PUBLIC });
    let r = parse(json!({ "outbounds": [
        { "tag": "a", "protocol": "socks", "settings": { "address": "192.0.2.1", "port": 1080 },
          "streamSettings": { "security": "tls" } },
        { "tag": "b", "protocol": "http", "settings": { "address": "192.0.2.2", "port": 80 },
          "streamSettings": { "network": "ws" } },
        { "tag": "c", "protocol": "socks", "settings": { "address": "192.0.2.3", "port": 1080 },
          "proxySettings": { "tag": "a" } },
        wireguard_outbound(json!([])),
        wireguard_outbound(json!([peer("192.0.2.4:51820"), peer("192.0.2.5:51820")])),
        { "tag": "d", "protocol": "mtproto", "settings": { "servers": [{ "address": "192.0.2.6", "port": 443 }] } },
        { "tag": "e", "protocol": "vless", "settings": {} },
        { "tag": "f", "protocol": "blackhole", "settings": { "response": { "type": "http" } } },
        { "tag": "g", "protocol": "loopback", "settings": { "inboundTag": "x" } },
        { "tag": "in", "protocol": "vless", "port": 443, "settings": { "clients": [{ "id": UUID }] } }
    ] }));
    assert!(
        r.profiles.is_empty(),
        "{:?}",
        r.profiles.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
    let reasons: Vec<&SkipReason> = r.skipped.iter().map(|s| &s.reason).collect();
    assert_eq!(reasons.len(), 7, "{reasons:?}");
    assert!(matches!(reasons[0], SkipReason::Invalid { detail, .. } if detail.contains("TLS")));
    assert_eq!(reasons[1], &SkipReason::UnsupportedTransport("ws".into()));
    assert!(
        matches!(reasons[2], SkipReason::Invalid { detail, .. } if detail.contains("another outbound"))
    );
    assert!(matches!(reasons[3], SkipReason::Invalid { detail, .. } if detail == "no peers"));
    assert!(
        matches!(reasons[4], SkipReason::Invalid { detail, .. } if detail.contains("allowedIPs"))
    );
    assert_eq!(reasons[5], &SkipReason::UnknownScheme("mtproto".into()));
    assert!(
        matches!(reasons[6], SkipReason::Invalid { detail, .. } if detail == "no server address")
    );
    assert!(
        r.skipped[0].excerpt.contains("192.0.2.1"),
        "{}",
        r.skipped[0].excerpt
    );
    assert!(
        r.skipped[3].excerpt.starts_with("wireguard wg-nl"),
        "{}",
        r.skipped[3].excerpt
    );
}

/// 32 bytes of 0x01, base64url: a well-formed but obviously fake REALITY public key.
const PBK: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn vless(tag: &str, stream: Value) -> Value {
    json!({ "tag": tag, "protocol": "vless",
        "settings": { "vnext": [{ "address": "v.example", "port": 443,
                                  "users": [{ "id": UUID, "encryption": "none", "flow": "", "level": 0 }] }] },
        "streamSettings": stream })
}

fn reality_stream() -> Value {
    json!({ "network": "tcp", "security": "reality", "tcpSettings": { "header": { "type": "none" } },
            "realitySettings": { "serverName": "front.example.com", "publicKey": PBK, "shortId": "1234",
                                 "fingerprint": "firefox", "spiderX": "/", "show": false } })
}

/// Engine audit: a lone outbound the model carries in full is a typed profile (either engine
/// runs it, «только sing-box» included); a provider document around one such outbound too.
/// Anything Xray-only keeps the native graph.
#[test]
fn plain_outbounds_are_typed_xray_only_ones_keep_the_graph() {
    let mut vision = vless("vision", reality_stream());
    vision["settings"]["vnext"][0]["users"][0]["flow"] = json!("xtls-rprx-vision");
    vision["mux"] = json!({ "enabled": false, "concurrency": -1 });
    let ws = json!({ "tag": "ws", "protocol": "vmess",
        "settings": { "vnext": [{ "address": "m.example", "port": 443, "users": [{ "id": UUID, "security": "auto" }] }] },
        "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": { "serverName": "m.example", "alpn": ["http/1.1"] },
                            "wsSettings": { "path": "/ws", "headers": { "Host": "m.example" } } } });
    let ss = json!({ "tag": "ss", "protocol": "shadowsocks", "settings": {
        "address": "192.0.2.7", "port": 8388, "method": "2022-blake3-aes-128-gcm", "password": "AAAAAAAAAAAAAAAAAAAAAA==" } });
    let doc = json!({ "remarks": "Provider doc", "dns": { "servers": ["1.1.1.1"] },
        "inbounds": [{ "tag": "socks-in", "port": 10808, "listen": "127.0.0.1", "protocol": "socks" }],
        "policy": { "levels": { "0": { "handshake": 4 } } },
        "outbounds": [vless("proxy", reality_stream()), { "tag": "direct", "protocol": "freedom" },
                      { "tag": "block", "protocol": "blackhole" }],
        "routing": { "rules": [{ "type": "field", "domain": ["example.org"], "outboundTag": "direct" },
                               { "type": "field", "network": "tcp,udp", "outboundTag": "proxy" }] } });
    let mut typed = Vec::new();
    for input in [json!([vision, ws, ss]), doc] {
        let r = parse(input);
        assert!(r.skipped.is_empty(), "{:?}", r.skipped);
        typed.extend(r.profiles);
    }
    let names: Vec<&str> = typed.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["vision", "ws", "ss", "Provider doc"]);
    for p in &typed {
        assert!(p.native_xray.is_none(), "{}", p.name);
        assert!(p.notes.is_empty(), "{}: {:?}", p.name, p.notes);
    }
    assert!(
        matches!(&typed[1].transport, Some(Transport::Ws { host: Some(h), .. }) if h == "m.example")
    );
    assert_sing_box_runs(&typed);

    // Named by the JSON pointer of the Xray-only field each one adds.
    let with = |pointer: &str, value: Value| {
        let mut o = vless(pointer, reality_stream());
        let (parent, leaf) = pointer.rsplit_once('/').unwrap();
        o.pointer_mut(parent).unwrap()[leaf] = value;
        o
    };
    let graphs = [
        with("/mux", json!({ "enabled": true, "concurrency": 8 })),
        with("/streamSettings/sockopt", json!({ "tcpFastOpen": true })),
        with(
            "/streamSettings/finalmask",
            json!({ "tcp": [{ "type": "fragment" }] }),
        ),
        with("/sendThrough", json!("192.0.2.99")),
        with(
            "/streamSettings/realitySettings/mldsa65Verify",
            json!("FAKE"),
        ),
        with(
            "/streamSettings/tcpSettings/header",
            json!({ "type": "http", "request": { "path": ["/"] } }),
        ),
        vless(
            "kcp",
            json!({ "network": "kcp", "kcpSettings": { "mtu": 1350 } }),
        ),
    ];
    let r = parse(json!(graphs));
    assert_eq!(r.profiles.len(), graphs.len(), "{:?}", r.skipped);
    for p in &r.profiles {
        assert!(p.native_xray.is_some(), "{} lost its graph", p.name);
    }
    // Several pins: the model keeps one, Xray accepts any. One pin with the CA check off: only
    // Xray verifies it (sing-box refuses the key), so the graph that runs on Xray stays.
    let pins = format!("{},{}", "ab".repeat(32), "cd".repeat(32));
    let pinned = |tag: &str, tls: Value| {
        vless(
            tag,
            json!({ "network": "tcp", "security": "tls", "tlsSettings": tls }),
        )
    };
    let r = parse(json!([
        pinned(
            "pins",
            json!({ "serverName": "v.example", "pinnedPeerCertSha256": pins })
        ),
        pinned(
            "insecure",
            json!({ "serverName": "v.example", "allowInsecure": true,
                                   "pinnedPeerCertSha256": "ab".repeat(32) })
        ),
        pinned(
            "one-pin",
            json!({ "serverName": "v.example", "pinnedPeerCertSha256": "ab".repeat(32) })
        ),
    ]));
    let graphs: Vec<bool> = r.profiles.iter().map(|p| p.native_xray.is_some()).collect();
    assert_eq!(graphs, [true, true, false], "{:?}", r.skipped);
    assert_eq!(r.profiles[2].notes, [Note::CertPinNotEnforced]);
}

/// Engine audit (broken): Xray 26 removed HTTP/2 and QUIC, so these graphs could never start and
/// «только sing-box» refused them. The selected outbound becomes a typed sing-box profile with a
/// Note and one Note per dropped Xray-only field; what neither engine can run is skipped.
#[test]
fn removed_transports_become_sing_box_profiles() {
    let tls = json!({ "serverName": "front.example.com" });
    let mut h2 = vless(
        "h2",
        json!({ "network": "h2", "security": "tls", "tlsSettings": tls,
        "httpSettings": { "host": ["front.example.com"], "path": "/h2", "method": "PUT" } }),
    );
    h2["mux"] = json!({ "enabled": true });
    let quic = json!({ "tag": "quic", "protocol": "trojan",
        "settings": { "servers": [{ "address": "192.0.2.8", "port": 443, "password": "SYNTHETIC" }] },
        "streamSettings": { "network": "quic", "security": "tls", "tlsSettings": tls,
                            "quicSettings": { "security": "none", "header": { "type": "none" } } } });
    let r = parse(json!([h2, quic]));
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    let removed = Note::Other(Note::XRAY_TRANSPORT_REMOVED.into());
    let [h2, quic] = &r.profiles[..] else {
        panic!("{:?}", r.profiles.len())
    };
    assert!(h2.native_xray.is_none() && quic.native_xray.is_none());
    assert_eq!(
        h2.transport,
        Some(Transport::Http {
            hosts: vec!["front.example.com".into()],
            path: "/h2".into()
        })
    );
    assert_eq!(
        h2.notes,
        [
            removed.clone(),
            Note::UnsupportedField("streamSettings.httpSettings.method".into()),
            Note::UnsupportedField("mux".into())
        ]
    );
    assert_eq!(
        (&quic.transport, &quic.notes[..]),
        (&Some(Transport::Quic), &[removed.clone()][..])
    );
    assert_sing_box_runs(&r.profiles);

    // A balancer over HTTP/2 hops: one typed profile from the hop the document selects.
    let doc = json!({ "remarks": "H2 doc",
        "outbounds": [vless("hop-1", json!({ "network": "http", "security": "tls", "tlsSettings": tls })),
                      vless("hop-2", json!({ "network": "http", "security": "tls", "tlsSettings": tls }))],
        "routing": { "balancers": [{ "tag": "b", "selector": ["hop-"] }],
                     "rules": [{ "type": "field", "network": "tcp,udp", "balancerTag": "b" }] } });
    let r = parse(doc);
    assert_eq!(r.profiles.len(), 1, "{:?}", r.skipped);
    assert!(r.profiles[0].native_xray.is_none() && r.profiles[0].notes.contains(&removed));

    let mut chained = vless(
        "chained",
        json!({ "network": "h2", "security": "tls", "tlsSettings": tls,
        "sockopt": { "dialerProxy": "bridge" } }),
    );
    chained["settings"]["vnext"][0]["address"] = json!("c.example");
    let keyed = json!({ "tag": "keyed", "protocol": "vmess",
        "settings": { "vnext": [{ "address": "k.example", "port": 443, "users": [{ "id": UUID }] }] },
        "streamSettings": { "network": "quic", "quicSettings": { "security": "aes-128-gcm", "key": "k" } } });
    let h3 = vless(
        "h3",
        json!({ "network": "h3", "security": "tls", "tlsSettings": tls }),
    );
    let bridge_doc = json!({ "remarks": "Bridge", "outbounds": [
            vless("entry", { let mut s = reality_stream(); s["sockopt"] = json!({ "dialerProxy": "hop" }); s }),
            vless("hop", json!({ "network": "quic", "security": "tls", "tlsSettings": tls }))],
        "routing": { "rules": [{ "type": "field", "network": "tcp,udp", "outboundTag": "entry" }] } });
    let r = parse(json!([chained, keyed, h3]));
    let rejected = |r: &ParseReport| {
        r.skipped
            .iter()
            .map(|s| s.reason.clone())
            .collect::<Vec<_>>()
    };
    assert!(r.profiles.is_empty());
    let reasons = rejected(&r);
    assert!(
        matches!(&reasons[0], SkipReason::NativeGraphRejected(m) if m.contains("removed")),
        "{reasons:?}"
    );
    assert!(
        matches!(&reasons[1], SkipReason::Invalid { scheme, .. } if scheme == "quic"),
        "{reasons:?}"
    );
    assert_eq!(reasons[2], SkipReason::UnsupportedTransport("h3".into()));
    let r = parse(bridge_doc);
    assert!(r.profiles.is_empty());
    assert!(
        matches!(&rejected(&r)[..], [SkipReason::NativeGraphRejected(m)] if m.contains("removed"))
    );
}
