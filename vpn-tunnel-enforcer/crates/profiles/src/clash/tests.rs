//! Clash importer tests; vectors from spec profiles.md §7 (P-06, P-23, smoke and verifier rows).
use super::*;
use crate::model::{Ech, Hy2Obfs, Reality, ShadowTlsLayer, SsPlugin, Transport};

fn report(yaml: &str) -> ParseReport {
    parse_clash(yaml).expect("a Clash document")
}

fn one(yaml: &str) -> Profile {
    let r = report(yaml);
    assert!(r.skipped.is_empty(), "skipped: {:?}", r.skipped);
    assert_eq!(r.profiles.len(), 1, "profiles: {:?}", r.profiles);
    r.profiles.into_iter().next().expect("one profile")
}

fn tls(p: &Profile) -> &Tls {
    p.tls.as_ref().expect("TLS on")
}

/// P-23 (verifier): column-0 list items are the usual mihomo style and must import (old: 0).
#[test]
fn column_zero_items_import() {
    let p = one(
        "proxies:\n- name: c0\n  type: trojan\n  server: t.example\n  port: 443\n  password: p\n",
    );
    assert_eq!(p.name, "c0");
    assert_eq!(p.server, Host::Domain("t.example".into()));
    assert_eq!(p.port, 443);
    assert_eq!(
        p.kind,
        Kind::Trojan {
            password: "p".into()
        }
    );
    assert_eq!(tls(&p).server_name.as_deref(), Some("t.example"));
    assert_eq!(p.source, Source::Clash);
    assert!(p.notes.is_empty(), "{:?}", p.notes);
}

/// P-23 (verifier): mihomo always-TLS types get TLS without `sni`/`tls`; `servername` alone does not
/// turn TLS on for VLESS.
#[test]
fn always_tls_types_and_servername_without_tls() {
    let r = report(concat!(
        "proxies:\n",
        "  - name: h\n    type: hysteria2\n    server: h.example\n    port: 443\n    password: pw\n",
        "  - name: t\n    type: trojan\n    server: t.example\n    port: 443\n    password: pw\n",
        "  - name: v\n    type: vless\n    server: v.example\n    port: 443\n    uuid: 00000000-0000-4000-8000-000000000001\n",
        "    tls: false\n    servername: x\n",
    ));
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    let [h, t, v] = r.profiles.as_slice() else {
        panic!("{:?}", r.profiles)
    };
    assert_eq!(tls(h).server_name.as_deref(), Some("h.example"));
    assert_eq!(tls(t).server_name.as_deref(), Some("t.example"));
    assert!(v.tls.is_none());
    assert!(
        v.notes.is_empty(),
        "TLS keys of a TLS-less entry are not 'unsupported': {:?}",
        v.notes
    );
}

/// P-23: scalars keep their text (`0012345`, `0123`), block-sequence ALPN, certificate pin in
/// `fingerprint` (not uTLS), hopping ports and `"30 Mbps"`. P-03: the pin is stored with a Note.
#[test]
fn scalars_lists_pins_ports_and_bandwidth() {
    let pin = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
    let yaml = format!(
        "proxies:\n  - name: hy\n    type: hysteria2\n    server: hy.example\n    port: 443\n    password: 0012345\n    alpn:\n      - h3\n    fingerprint: {pin}\n    ports: 443,20000-30000\n    up: \"30 Mbps\"\n    down: 200\n    skip-cert-verify: true\n"
    );
    let p = one(&yaml);
    let Kind::Hysteria2 {
        password,
        ports,
        up_mbps,
        down_mbps,
        ..
    } = &p.kind
    else {
        panic!("{:?}", p.kind)
    };
    assert_eq!(password, "0012345");
    assert_eq!(ports, &[(443, 443), (20000, 30000)]);
    assert_eq!((*up_mbps, *down_mbps), (Some(30), Some(200)));
    let t = tls(&p);
    assert_eq!(t.alpn, ["h3"]);
    assert_eq!(t.fingerprint, None, "a pin is never a uTLS name");
    assert_eq!(
        t.cert_pin_sha256.as_deref(),
        Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    );
    assert!(t.insecure, "insecure is kept as the provider set it");
    assert_eq!(p.notes, [Note::CertPinNotEnforced]);
}

/// Smoke vector: a Clash VLESS REALITY block; `short-id` keeps its leading zero (P-23).
#[test]
fn vless_reality_block() {
    let p = one(concat!(
        "proxies:\n",
        "  - name: \"Reality NL\"\n    type: vless\n    server: 192.0.2.10\n    port: 443\n",
        "    uuid: 00000000-0000-4000-8000-000000000002\n    network: tcp\n    flow: xtls-rprx-vision\n",
        "    tls: true\n    udp: true\n    servername: www.example.com\n    client-fingerprint: chrome\n",
        "    reality-opts:\n      public-key: SYNTHETIC-PUBLIC-KEY\n      short-id: 0123\n",
    ));
    assert_eq!(p.server, Host::Ip("192.0.2.10".parse().unwrap()));
    let Kind::Vless {
        uuid,
        flow,
        encryption,
        ..
    } = &p.kind
    else {
        panic!("{:?}", p.kind)
    };
    assert_eq!(uuid, "00000000-0000-4000-8000-000000000002");
    assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
    assert_eq!(encryption, &None);
    let t = tls(&p);
    assert_eq!(t.server_name.as_deref(), Some("www.example.com"));
    assert_eq!(t.fingerprint.as_deref(), Some("chrome"));
    let reality = Reality {
        public_key: "SYNTHETIC-PUBLIC-KEY".into(),
        short_id: "0123".into(),
        spider_x: None,
    };
    assert_eq!(t.reality, Some(reality));
    assert!(p.transport.is_none());
    assert!(p.notes.is_empty(), "{:?}", p.notes);
}

/// P-06: `udp` and VLESS `encryption: none` never reach the profile (sing-box rejects unknown keys).
#[test]
fn udp_and_encryption_none_are_dropped() {
    let r = report(concat!(
        "proxies:\n",
        "  - {name: h, type: hysteria2, server: h.example, port: 443, password: pw, udp: true}\n",
        "  - {name: v, type: vless, server: v.example, port: 443, uuid: u-1, network: ws, encryption: none, udp: true}\n",
    ));
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    for p in &r.profiles {
        assert!(p.singbox_extra.is_empty(), "{:?}", p.singbox_extra);
        assert!(p.notes.is_empty(), "{:?}", p.notes);
    }
    let Kind::Vless { encryption, .. } = &r.profiles[1].kind else {
        panic!()
    };
    assert_eq!(encryption, &None);
    let ws = Transport::Ws {
        path: "/".into(),
        host: None,
        max_early_data: None,
        early_data_header: None,
    };
    assert_eq!(r.profiles[1].transport, Some(ws));
}

/// Packet encodings: mihomo's `packet` alias and `packet-addr` / `xudp` switches map to the two
/// values sing-box accepts; an unknown one is noted and dropped (it would stop the engine).
#[test]
fn packet_encodings_are_normalised() {
    let r = report(concat!(
        "proxies:\n",
        "- {name: a, type: vless, server: v.example, port: 443, uuid: u, packet-encoding: Packet}\n",
        "- {name: b, type: vless, server: v.example, port: 443, uuid: u, packet-addr: true}\n",
        "- {name: c, type: vless, server: v.example, port: 443, uuid: u, packet-addr: true, xudp: true}\n",
        "- {name: d, type: vless, server: v.example, port: 443, uuid: u, packet-encoding: bogus}\n",
        "- {name: e, type: vmess, server: v.example, port: 443, uuid: u, cipher: auto, packet-encoding: bogus}\n",
    ));
    let encoding = |p: &Profile| match &p.kind {
        Kind::Vless {
            packet_encoding, ..
        } => packet_encoding.clone(),
        _ => p
            .singbox_extra
            .get("packet_encoding")
            .and_then(Value::as_str)
            .map(str::to_owned),
    };
    let got: Vec<Option<String>> = r.profiles.iter().map(encoding).collect();
    let packet = Some("packetaddr".to_owned());
    assert_eq!(
        got,
        [packet.clone(), packet, Some("xudp".into()), None, None]
    );
    let note = [Note::UnsupportedField("packet-encoding".into())];
    assert_eq!(
        (&r.profiles[3].notes[..], &r.profiles[4].notes[..]),
        (&note[..], &note[..])
    );
}

/// `reality-opts` without a public key is skipped with a reason, not downgraded to plain TLS (§3.5).
#[test]
fn reality_without_public_key_is_skipped() {
    let r = report(
        "proxies:\n- {name: r, type: vless, server: r.example, port: 443, uuid: u, reality-opts: {short-id: ab}}\n",
    );
    assert!(r.profiles.is_empty());
    assert_eq!(r.skipped.len(), 1);
    assert_eq!(r.skipped[0].excerpt, "r (vless)");
    assert!(
        matches!(&r.skipped[0].reason, SkipReason::Invalid { detail, .. } if detail.contains("public-key"))
    );
}

/// REALITY on a QUIC type or next to ECH can never connect (the emitter refuses both): such
/// entries are skipped at import, the others of the list stay.
#[test]
fn reality_on_quic_or_with_ech_is_skipped() {
    let r = report(concat!(
        "proxies:\n",
        "- {name: q, type: hysteria2, server: h.example, port: 443, password: p, reality-opts: {public-key: k}}\n",
        "- {name: t, type: tuic, server: h.example, port: 443, uuid: u, password: p, reality-opts: {public-key: k}}\n",
        "- {name: e, type: vless, server: r.example, port: 443, uuid: u, reality-opts: {public-key: k}, ech-opts: {enable: true, config: AEr+}}\n",
        "- {name: ok, type: vless, server: r.example, port: 443, uuid: u, reality-opts: {public-key: k}}\n",
    ));
    assert_eq!(r.profiles.len(), 1, "{:?}", r.skipped);
    let details: Vec<String> = r
        .skipped
        .iter()
        .map(|s| match &s.reason {
            SkipReason::Invalid { detail, .. } => detail.clone(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        details,
        [
            "hysteria2: REALITY cannot run over QUIC",
            "tuic: REALITY cannot run over QUIC",
            "vless: REALITY cannot be combined with ECH"
        ]
    );
}

/// Shadowsocks plugins: `obfs` -> sing-box `obfs-local`, `v2ray-plugin` opts with mihomo's
/// defaults (host `bing.com`, mux on), `shadow-tls` -> a ShadowTLS layer whose TLS carries the
/// provider uTLS name (P-09 for Clash); UoT versions as mihomo reads them.
#[test]
fn shadowsocks_plugins() {
    let r = report(concat!(
        "proxies:\n",
        "- {name: o, type: ss, server: s.example, port: 8388, cipher: AES-256-GCM, password: pw,\n",
        "   plugin: obfs, plugin-opts: {mode: tls, host: cdn.example}}\n",
        "- {name: v, type: ss, server: s.example, port: 443, cipher: aes-128-gcm, password: pw,\n",
        "   plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, host: cdn.example, path: /ws}}\n",
        "- {name: st, type: ss, server: s.example, port: 443, cipher: 2022-blake3-aes-128-gcm, password: pw,\n",
        "   client-fingerprint: Chrome, plugin: shadow-tls, plugin-opts: {host: www.example.com, password: stpw, version: 3}}\n",
        "- {name: k, type: ss, server: s.example, port: 443, cipher: aes-128-gcm, password: pw, plugin: kcptun}\n",
        "- {name: u, type: ss, server: s.example, port: 443, cipher: aes-128-gcm, password: pw, udp-over-tcp: true}\n",
        "- {name: o2, type: ss, server: s.example, port: 8388, cipher: aes-128-gcm, password: pw, plugin: obfs}\n",
        "- {name: v2, type: ss, server: s.example, port: 443, cipher: aes-128-gcm, password: pw,\n",
        "   plugin: v2ray-plugin, plugin-opts: {mode: websocket, mux: false}}\n",
        "- {name: u2, type: ss, server: s.example, port: 443, cipher: aes-128-gcm, password: pw,\n",
        "   udp-over-tcp: true, udp-over-tcp-version: 2}\n",
        "- {name: ob, type: ss, server: s.example, port: 443, cipher: aes-128-gcm, password: pw,\n",
        "   plugin: obfs, plugin-opts: {mode: websocket}}\n",
        "- {name: u3, type: ss, server: s.example, port: 443, cipher: aes-128-gcm, password: pw,\n",
        "   udp-over-tcp: true, udp-over-tcp-version: 3}\n",
    ));
    let plugin_of = |p: &Profile| match &p.kind {
        Kind::Shadowsocks {
            plugin,
            shadowtls,
            uot,
            method,
            ..
        } => (plugin.clone(), shadowtls.clone(), *uot, method.clone()),
        other => panic!("{other:?}"),
    };
    let (obfs, _, _, method) = plugin_of(&r.profiles[0]);
    assert_eq!(method, "aes-256-gcm");
    assert_eq!(
        obfs,
        Some(SsPlugin {
            name: "obfs-local".into(),
            opts: "obfs=tls;obfs-host=cdn.example".into()
        })
    );
    let (v2ray, ..) = plugin_of(&r.profiles[1]);
    let opts = "mode=websocket;tls;host=cdn.example;path=/ws;mux=1";
    assert_eq!(
        v2ray,
        Some(SsPlugin {
            name: "v2ray-plugin".into(),
            opts: opts.into()
        })
    );
    let (none, layer, ..) = plugin_of(&r.profiles[2]);
    assert_eq!(none, None);
    let layer_expected = ShadowTlsLayer {
        version: 3,
        password: "stpw".into(),
        server_name: "www.example.com".into(),
    };
    assert_eq!(layer, Some(layer_expected));
    assert_eq!(tls(&r.profiles[2]).fingerprint.as_deref(), Some("chrome"));
    assert!(r.profiles[2].notes.is_empty(), "{:?}", r.profiles[2].notes);
    let (_, _, uot, _) = plugin_of(&r.profiles[3]);
    assert_eq!(uot, Some(1), "mihomo's default UoT version is 1");
    let opts_of = |i: usize| plugin_of(&r.profiles[i]).0.map(|p| p.opts);
    assert_eq!(opts_of(4).as_deref(), Some("obfs=http;obfs-host=bing.com"));
    assert_eq!(
        opts_of(5).as_deref(),
        Some("mode=websocket;host=bing.com;mux=0")
    );
    assert_eq!(plugin_of(&r.profiles[6]).2, Some(2));
    let reasons: Vec<&SkipReason> = r.skipped.iter().map(|s| &s.reason).collect();
    assert_eq!(reasons.len(), 3, "{reasons:?}");
    assert_eq!(reasons[0], &SkipReason::UnsupportedPlugin("kcptun".into()));
    assert_eq!(
        reasons[1],
        &SkipReason::UnsupportedPlugin("obfs (websocket)".into())
    );
    assert!(
        matches!(reasons[2], SkipReason::Invalid { detail, .. } if detail.contains("udp-over-tcp-version"))
    );
}

/// AT-04-002: VMess `alterId` is normalised to 0 with a warning; cipher and switches are kept.
#[test]
fn vmess_alter_id_and_options() {
    let p = one(concat!(
        "proxies:\n",
        "- name: vm\n  type: vmess\n  server: vm.example\n  port: 443\n  uuid: 00000000-0000-4000-8000-000000000003\n",
        "  alterId: 64\n  cipher: Auto\n  global-padding: true\n  authenticated-length: yes\n  packet-encoding: xudp\n",
        "  tls: true\n  servername: front.example\n  network: grpc\n  grpc-opts:\n    grpc-service-name: svc\n",
    ));
    let expected = Kind::Vmess {
        uuid: "00000000-0000-4000-8000-000000000003".into(),
        security: "auto".into(),
        global_padding: true,
        authenticated_length: true,
    };
    assert_eq!(p.kind, expected);
    assert_eq!(p.notes, [Note::AlterIdNormalized(64)]);
    assert_eq!(
        p.singbox_extra.get("packet_encoding"),
        Some(&Value::from("xudp"))
    );
    assert_eq!(
        p.transport,
        Some(Transport::Grpc {
            service_name: "svc".into(),
            multi_mode: None
        })
    );
    assert_eq!(tls(&p).server_name.as_deref(), Some("front.example"));
}

/// TUIC v5: heartbeat in ms -> whole seconds, `new-reno` normalised, `disable-sni`, `ip` override;
/// v4 (`token`) is skipped. A provider uTLS name is dropped on QUIC with a Note.
#[test]
fn tuic_mapping() {
    let r = report(concat!(
        "proxies:\n",
        "- {name: t5, type: tuic, server: tuic.example, port: 10443, uuid: 00000000-0000-4000-8000-000000000004,\n",
        "   password: pw, ip: 192.0.2.7, heartbeat-interval: 10500, congestion-controller: new-reno,\n",
        "   udp-relay-mode: QUIC, reduce-rtt: true, disable-sni: true, alpn: [h3], client-fingerprint: chrome}\n",
        "- {name: t4, type: tuic, server: tuic.example, port: 10443, token: TOKEN}\n",
    ));
    let p = &r.profiles[0];
    let expected = Kind::Tuic {
        uuid: "00000000-0000-4000-8000-000000000004".into(),
        password: "pw".into(),
        congestion: Some("new_reno".into()),
        udp_relay_mode: Some("quic".into()),
        zero_rtt: true,
        heartbeat_s: Some(11),
    };
    assert_eq!(p.kind, expected);
    assert_eq!(p.server, Host::Ip("192.0.2.7".parse().unwrap()));
    let t = tls(p);
    assert_eq!(
        t.server_name.as_deref(),
        Some("tuic.example"),
        "the SNI stays the configured name"
    );
    assert!(t.disable_sni);
    assert_eq!(t.alpn, ["h3"]);
    assert_eq!(t.fingerprint, None);
    assert_eq!(p.notes, [Note::ProviderFpDroppedOnQuic]);
    assert_eq!(r.skipped.len(), 1);
    assert!(
        matches!(&r.skipped[0].reason, SkipReason::Invalid { detail, .. } if detail.contains("token"))
    );
}

/// AnyTLS idle settings (seconds) and the always-on TLS with the provider fingerprint.
#[test]
fn anytls_mapping() {
    let p = one(concat!(
        "proxies:\n",
        "- {name: a, type: anytls, server: 1.2.3.4, port: 443, password: pw, client-fingerprint: firefox,\n",
        "   idle-session-check-interval: 30, idle-session-timeout: 60s, min-idle-session: 2, sni: front.example}\n",
    ));
    let expected = Kind::Anytls {
        password: "pw".into(),
        idle_check_s: Some(30),
        idle_timeout_s: Some(60),
        min_idle: Some(2),
    };
    assert_eq!(p.kind, expected);
    assert_eq!(tls(&p).fingerprint.as_deref(), Some("firefox"));
    assert_eq!(tls(&p).server_name.as_deref(), Some("front.example"));
}

/// SOCKS5 / HTTP proxies: credentials kept, plaintext flagged, SOCKS over TLS refused.
#[test]
fn socks_and_http() {
    let r = report(concat!(
        "proxies:\n",
        "- {name: s, type: socks5, server: 2001:db8::1, port: 1080, username: u, password: p}\n",
        "- {name: h, type: http, server: h.example, port: 443, username: u, password: p, tls: true, sni: x.example}\n",
        "- {name: st, type: socks5, server: s.example, port: 1080, tls: true}\n",
    ));
    let s = &r.profiles[0];
    assert_eq!(s.server, Host::Ip("2001:db8::1".parse().unwrap()));
    assert_eq!(
        s.kind,
        Kind::Socks {
            username: Some("u".into()),
            password: Some("p".into())
        }
    );
    assert_eq!(s.notes, [Note::Unencrypted]);
    let h = &r.profiles[1];
    assert_eq!(
        h.kind,
        Kind::Http {
            username: Some("u".into()),
            password: Some("p".into())
        }
    );
    assert_eq!(tls(h).server_name.as_deref(), Some("x.example"));
    assert!(h.notes.is_empty(), "{:?}", h.notes);
    assert_eq!(
        r.skipped[0].reason,
        SkipReason::UnsupportedTransport("socks5+tls".into())
    );
}

const PRIV: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const PUB: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

fn vless_with(lines: &str) -> String {
    format!(
        "proxies:\n- name: n\n  type: vless\n  server: v.example\n  port: 443\n  uuid: u-1\n  tls: true\n{lines}"
    )
}

/// Transports: ws (Host header, early data), ws with `v2ray-http-upgrade`, h2, TCP HTTP header mask,
/// XHTTP with translated extras; an unknown network skips the entry.
#[test]
fn transports() {
    let ws = one(&vless_with(
        "  network: ws\n  ws-opts:\n    path: /ray\n    headers:\n      Host: cdn.example\n    max-early-data: 2048\n    early-data-header-name: Sec-WebSocket-Protocol\n",
    ));
    let expected = Transport::Ws {
        path: "/ray".into(),
        host: Some("cdn.example".into()),
        max_early_data: Some(2048),
        early_data_header: Some("Sec-WebSocket-Protocol".into()),
    };
    assert_eq!(ws.transport, Some(expected));
    let up = one(&vless_with(
        "  network: ws\n  ws-opts: {path: /up, headers: {host: h.example}, v2ray-http-upgrade: true}\n",
    ));
    assert_eq!(
        up.transport,
        Some(Transport::HttpUpgrade {
            host: "h.example".into(),
            path: "/up".into()
        })
    );
    let h2 = one(&vless_with(
        "  network: h2\n  h2-opts: {host: [a.example, b.example], path: /h2}\n",
    ));
    assert_eq!(
        h2.transport,
        Some(Transport::Http {
            hosts: vec!["a.example".into(), "b.example".into()],
            path: "/h2".into()
        })
    );
    let http = one(&vless_with(
        "  network: http\n  http-opts: {method: GET, path: [/, /video], headers: {Host: [m.example]}}\n",
    ));
    let mask = Transport::TcpHttpHeader {
        host: vec!["m.example".into()],
        path: vec!["/".into(), "/video".into()],
    };
    assert_eq!(http.transport, Some(mask));
    let x = report(&vless_with(
        "  network: xhttp\n  xhttp-opts:\n    path: /x\n    host: x.example\n    mode: packet-up\n    no-grpc-header: true\n    x-padding-bytes: 100-1000\n    sc-max-each-post-bytes: lots\n    reuse-settings: {max-concurrency: 16-32, h-keep-alive-period: 0, max-connections: 9-3}\n    session-placement: path\n",
    ));
    let p = &x.profiles[0];
    let Some(Transport::Xhttp {
        host,
        path,
        mode,
        extra,
    }) = &p.transport
    else {
        panic!("{:?}", p.transport)
    };
    assert_eq!(
        (host.as_str(), path.as_str(), mode.as_deref()),
        ("x.example", "/x", Some("packet-up"))
    );
    let extra = Value::Object(extra.clone().expect("extra"));
    let want = serde_json::json!({"noGRPCHeader": true, "xPaddingBytes": "100-1000", "xmux": {"maxConcurrency": "16-32", "hKeepAlivePeriod": 0}});
    assert_eq!(extra, want);
    // Values Xray would refuse (it rejects the whole config) are noted and dropped.
    let noted = |field: &str| Note::UnsupportedField(field.into());
    assert_eq!(
        p.notes,
        [
            noted("xhttp-opts.sc-max-each-post-bytes"),
            noted("xhttp-opts.reuse-settings.max-connections"),
            noted("xhttp-opts.session-placement"),
        ]
    );
    let bad_mode = report(&vless_with(
        "  network: xhttp\n  xhttp-opts: {mode: warp-speed}\n",
    ));
    assert!(bad_mode.profiles.is_empty() && bad_mode.skipped.len() == 1);
    let kcp = report(&vless_with("  network: mkcp\n"));
    assert_eq!(
        kcp.skipped[0].reason,
        SkipReason::UnsupportedTransport("mkcp".into())
    );
}

/// K15: mihomo `smux` (sing-mux) becomes `multiplex` with padding and brutal; stream limits go to
/// the allow-listed extras.
#[test]
fn smux_becomes_multiplex() {
    let p = one(&vless_with(
        "  smux:\n    enabled: true\n    protocol: H2MUX\n    max-connections: 4\n    min-streams: 4\n    padding: true\n    brutal-opts: {enabled: true, up: 50, down: \"100 Mbps\"}\n",
    ));
    let mux = Mux {
        enabled: true,
        protocol: Some("h2mux".into()),
        max_connections: Some(4),
        padding: true,
        brutal: Some((50, 100)),
    };
    assert_eq!(p.mux, Some(mux));
    assert_eq!(
        p.singbox_extra.get("multiplex.min_streams"),
        Some(&Value::from(4))
    );
    assert_eq!(
        one(&vless_with("  smux: {enabled: false, padding: true}\n")).mux,
        None
    );
    // sing-box cannot multiplex QUIC protocols: the key is noted, not stored for a failing start.
    let hy2 = one(
        "proxies:\n- {name: h, type: hysteria2, server: h.example, port: 443, password: pw, smux: {enabled: true}}\n",
    );
    assert_eq!(
        (hy2.mux, hy2.notes),
        (None, vec![Note::UnsupportedField("smux".into())])
    );
}

/// AT-04-006: dial knobs map to dial prefs; what cannot be reproduced is a Note, never silent.
#[test]
fn dial_fields_and_unknown_keys_are_reported() {
    let p = one(&vless_with(
        "  ip-version: ipv4-prefer\n  tfo: true\n  mptcp: true\n  dialer-proxy: other\n  interface-name: eth0\n  name-cert-verify: x.example\n  ip-version-extra: 1\n",
    ));
    assert_eq!(p.dial.dns_strategy.as_deref(), Some("prefer_ipv4"));
    assert!(p.dial.tcp_fast_open && p.dial.tcp_multi_path);
    let expected = [
        Note::DialFieldDropped("interface-name".into()),
        Note::DialFieldDropped("dialer-proxy".into()),
        Note::UnsupportedField("name-cert-verify".into()),
        Note::UnsupportedField("ip-version-extra".into()),
    ];
    assert_eq!(p.notes, expected);
}

/// WireGuard in Clash: single-peer form and the `peers` list (no top-level server needed),
/// WARP `reserved`, AmneziaWG options as a Note. As in mihomo, the single-peer form ignores
/// `allowed-ips` (empty: the emitter routes everything, K21) and listed peers keep theirs.
#[test]
fn wireguard_entries() {
    let single = one(&format!(
        "proxies:\n- {{name: w, type: wireguard, server: 2001:db8::5, port: 2408, ip: 172.16.0.2, ipv6: fd01::2,\n   private-key: {PRIV}, public-key: {PUB}, reserved: [209, 98, 59], mtu: 1280, dns: [1.1.1.1, dns.example],\n   allowed-ips: ['0.0.0.0/0'], persistent-keepalive: 25, udp: true, remote-dns-resolve: true}}\n"
    ));
    let Kind::Wireguard(wg) = &single.kind else {
        panic!("{:?}", single.kind)
    };
    assert_eq!(single.server, Host::Ip("2001:db8::5".parse().unwrap()));
    assert_eq!(single.port, 2408);
    assert_eq!(wg.private_key, PRIV);
    let addresses: Vec<String> = wg.local_address.iter().map(ToString::to_string).collect();
    assert_eq!(addresses, ["172.16.0.2/32", "fd01::2/128"]);
    assert_eq!((wg.mtu, wg.dns.len()), (Some(1280), 1));
    let peer = &wg.peers[0];
    assert_eq!(
        (peer.public_key.as_str(), peer.reserved, peer.keepalive_s),
        (PUB, Some([209, 98, 59]), Some(25))
    );
    assert!(peer.allowed_ips.is_empty());
    assert!(single.notes.is_empty(), "{:?}", single.notes);

    let multi = one(&format!(
        "proxies:\n- name: m\n  type: wireguard\n  ip: 10.0.0.2/32\n  private-key: {PRIV}\n  amnezia-wg-option: {{jc: 4, jmin: 40, jmax: 70, version: 3, header-protection-key: k, random-trailers: false}}\n  peers:\n    - server: wg.example\n      port: 51820\n      public-key: {PUB}\n      allowed-ips: ['0.0.0.0/0']\n      reserved: U4An\n"
    ));
    assert_eq!(
        (multi.server.clone(), multi.port),
        (Host::Domain("wg.example".into()), 51820)
    );
    let Kind::Wireguard(wg) = &multi.kind else {
        panic!()
    };
    assert_eq!(wg.peers[0].reserved, Some([0x53, 0x80, 0x27]));
    assert_eq!(wg.peers[0].allowed_ips[0].to_string(), "0.0.0.0/0");
    assert_eq!(
        multi.notes,
        [
            Note::Other("profiles.wgIni.amneziaJunkDropped".into()),
            Note::UnsupportedField("amnezia-wg-option.header-protection-key".into())
        ]
    );

    let bad = report(&format!(
        "proxies:\n- {{name: b, type: wireguard, server: w.example, port: 1, ip: 10.0.0.2, private-key: short, public-key: {PUB}}}\n"
    ));
    assert!(
        matches!(&bad.skipped[0].reason, SkipReason::Invalid { detail, .. } if detail.contains("32 bytes"))
    );

    // Several listed peers must each name their routes (mihomo refuses the entry at load).
    let unrouted = report(&format!(
        "proxies:\n- name: u\n  type: wireguard\n  ip: 10.0.0.2/32\n  private-key: {PRIV}\n  peers:\n    - {{server: a.example, port: 51820, public-key: {PUB}, allowed-ips: ['0.0.0.0/0']}}\n    - {{server: b.example, port: 51820, public-key: {PUB}}}\n"
    ));
    assert!(unrouted.profiles.is_empty());
    assert!(
        matches!(&unrouted.skipped[0].reason, SkipReason::Invalid { detail, .. } if detail.contains("allowed-ips")),
        "{:?}",
        unrouted.skipped
    );
}

/// Not a Clash document: no root `proxies:` line, a `proxies` mapping, broken YAML before the list.
#[test]
fn non_clash_text_is_none() {
    assert_eq!(
        parse_clash("vless://u@h.example:443?security=tls#n\n"),
        None
    );
    assert_eq!(parse_clash("{\"outbounds\": []}"), None);
    assert_eq!(parse_clash("my proxies: are great\n"), None);
    assert_eq!(parse_clash("proxies:\n  a: b\n"), None);
    assert_eq!(parse_clash("x: [unclosed\nproxies:\n- {name: a}\n"), None);
    assert_eq!(
        parse_clash("proxies:\n"),
        Some(ParseReport::default()),
        "an empty list is still Clash"
    );
}

/// A broken or unknown entry is reported and never stops the others (§3.5).
#[test]
fn broken_entries_do_not_stop_the_list() {
    let r = report(concat!(
        "proxies:\n",
        "- {name: a, type: ssr, server: s.example, port: 1}\n",
        "- just a string\n",
        "- {name: b, type: trojan, server: t.example, port: 99999, password: p}\n",
        "- {name: c, type: trojan, server: t.example, port: 443}\n",
        "- {type: vmess, port: 443, uuid: u}\n",
        "- {name: ok, type: trojan, server: t.example, port: 443, password: p}\n",
    ));
    assert_eq!(r.profiles.len(), 1);
    assert_eq!(r.profiles[0].name, "ok");
    let reasons: Vec<&SkipReason> = r.skipped.iter().map(|s| &s.reason).collect();
    assert_eq!(reasons[0], &SkipReason::UnknownScheme("ssr".into()));
    assert!(
        matches!(reasons[1], SkipReason::Invalid { detail, .. } if detail.contains("not a mapping"))
    );
    assert!(
        matches!(reasons[2], SkipReason::Invalid { detail, .. } if detail.contains("invalid port"))
    );
    assert_eq!(reasons[3], &SkipReason::MissingCredential);
    assert!(
        matches!(reasons[4], SkipReason::Invalid { detail, .. } if detail.contains("missing server"))
    );
    let excerpts: Vec<&str> = r.skipped.iter().map(|s| s.excerpt.as_str()).collect();
    assert_eq!(
        excerpts,
        [
            "a (ssr)",
            "#2 (?)",
            "b (trojan)",
            "c (trojan)",
            "#5 (vmess)"
        ]
    );
}

/// Anchors defined in a skipped section, aliases and YAML merge keys (`<<`) as mihomo resolves them.
#[test]
fn anchors_aliases_and_merge_keys() {
    let r = report(concat!(
        "x-base: &base {type: trojan, server: t.example, port: 443, password: p}\n",
        "rules:\n  - DOMAIN,example.com,DIRECT\n  - MATCH,PROXY\n",
        "proxies:\n",
        "  - <<: *base\n    name: one\n",
        "  - <<: [*base]\n    name: two\n    port: 8443\n",
        "  - &third {name: three, type: trojan, server: t3.example, port: 443, password: q}\n",
        "proxy-groups: [{name: PROXY, proxies: [one, two]}]\n",
    ));
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    let summary: Vec<(&str, u16)> = r
        .profiles
        .iter()
        .map(|p| (p.name.as_str(), p.port))
        .collect();
    assert_eq!(summary, [("one", 443), ("two", 8443), ("three", 443)]);
}

/// AT-04-001: alias bombs and nesting bombs stop with a reported error, quickly and without panics.
#[test]
fn alias_and_nesting_bombs_are_bounded() {
    let mut anchors = String::from("  a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
    for i in 1..10 {
        let prev = format!("*a{}", i - 1);
        anchors.push_str(&format!(
            "  a{i}: &a{i} [{}]\n",
            [prev.as_str(); 10].join(", ")
        ));
    }
    let started = std::time::Instant::now();
    // Inside an entry: that entry is lost, the error is reported.
    let r = report(&format!(
        "proxies:\n- name: n\n  type: trojan\n{anchors}  x: *a9\n"
    ));
    assert!(r.profiles.is_empty());
    let too_large = |r: &ParseReport| matches!(&r.skipped[0].reason, SkipReason::Invalid { detail, .. } if detail.contains("too large"));
    assert!(too_large(&r), "{:?}", r.skipped);
    // One long scalar aliased many times: few nodes, but gigabytes once copied.
    let long = format!(
        "proxies:\n- name: s\n  x: &s \"{}\"\n  y: [{}]\n",
        "a".repeat(1 << 20),
        ["*s"; 100_000].join(",")
    );
    let r = report(&long);
    assert!(too_large(&r), "{:?}", r.skipped);
    // Before the list: the document is unreadable, so it is not taken as Clash at all.
    let before = format!(
        "x:\n{anchors}proxies:\n- {{name: n, type: trojan, server: t.example, port: 443, password: p}}\n"
    );
    assert_eq!(parse_clash(&before), None);
    let deep = format!(
        "proxies:\n- {{name: d, type: trojan, x: {}{}}}\n",
        "[".repeat(40),
        "]".repeat(40)
    );
    let r = report(&deep);
    assert!(
        matches!(&r.skipped[0].reason, SkipReason::Invalid { detail, .. } if detail.contains("deeper"))
    );
    // A merge key over a map with many keys stays linear.
    let keys: Vec<String> = (0..50_000).map(|i| format!("k{i}: v")).collect();
    let merged = format!(
        "x: &m {{{}}}\nproxies:\n- {{<<: *m, name: n, type: trojan, server: t.example, port: 443, password: p}}\n",
        keys.join(", ")
    );
    assert_eq!(report(&merged).profiles.len(), 1);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

/// Entries read before a YAML error are kept and the error is reported; text after the list is
/// never parsed, so its errors do not matter.
#[test]
fn errors_inside_and_after_the_list() {
    let r = report(
        "proxies:\n- {name: a, type: trojan, server: t.example, port: 443, password: p}\n- {name: b, type: [\n",
    );
    assert_eq!(r.profiles.len(), 1);
    assert_eq!(r.skipped.len(), 1);
    assert_eq!(r.skipped[0].excerpt, "proxies");
    let r = report(
        "proxies:\n- {name: a, type: trojan, server: t.example, port: 443, password: p}\nrules: [unclosed\n",
    );
    assert_eq!((r.profiles.len(), r.skipped.len()), (1, 0));
}

/// Names: control characters become spaces, empty names get the protocol default, 256 chars max.
#[test]
fn names_are_cleaned() {
    let r = report(&format!(
        "proxies:\n- {{name: \"a\\tb\\u0007\", type: trojan, server: t.example, port: 443, password: p}}\n- {{type: hy2, server: h.example, port: 443, password: p}}\n- {{name: {}, type: trojan, server: t.example, port: 443, password: p}}\n",
        "x".repeat(300)
    ));
    let names: Vec<usize> = r.profiles.iter().map(|p| p.name.chars().count()).collect();
    assert_eq!(r.profiles[0].name, "a b");
    assert_eq!(r.profiles[1].name, "Hysteria2");
    assert_eq!(names[2], 256);
}

/// mihomo bandwidth strings: bare numbers are Mbps, `b` bits, `B` bytes, K/M/G/T binary prefixes.
#[test]
fn bandwidth_units() {
    let cases = [
        ("30", Some(30)),
        ("30 Mbps", Some(30)),
        ("30Mbps", Some(30)),
        ("10 MBps", Some(80)),
        ("1 Gbps", Some(1024)),
    ];
    for (raw, want) in cases {
        assert_eq!(parse_mbps(raw), want, "{raw}");
    }
    for (raw, want) in [
        ("512 Kbps", Some(1)),
        ("100 kbps", Some(1)),
        ("0", None),
        ("fast", None),
        ("30 Mbit", None),
    ] {
        assert_eq!(parse_mbps(raw), want, "{raw}");
    }
}

/// Hysteria2 obfs (gecko packet sizes go to the allow-listed extras), hop range, BBR profile, and
/// ECH options; a bad optional knob is a Note, not a lost server.
#[test]
fn hysteria2_obfs_hopping_and_ech() {
    let p = one(concat!(
        "proxies:\n",
        "- name: hy\n  type: hy2\n  server: hy.example\n  ports: 20000-20010/30000\n  hop-interval: 15-30\n  password: pw\n",
        "  obfs: Gecko\n  obfs-password: op\n  obfs-min-packet-size: 512\n  obfs-max-packet-size: 1200\n  bbr-profile: aggressive\n",
        "  up: lots\n  ech-opts:\n    enable: true\n    config: AEn+DQBFKwAgACABWIHUGj4u\n    query-server-name: ech.example\n",
    ));
    assert_eq!(
        p.port, 20000,
        "without `port` the first hopping port is dialed"
    );
    let expected = Kind::Hysteria2 {
        password: "pw".into(),
        obfs: Some(Hy2Obfs {
            kind: "gecko".into(),
            password: "op".into(),
        }),
        ports: vec![(20000, 20010), (30000, 30000)],
        hop_interval_s: Some(15),
        hop_interval_max_s: Some(30),
        up_mbps: None,
        down_mbps: None,
        bbr_profile: Some("aggressive".into()),
    };
    assert_eq!(p.kind, expected);
    assert_eq!(
        p.singbox_extra.get("obfs.min_packet_size"),
        Some(&Value::from(512))
    );
    assert_eq!(
        p.singbox_extra.get("obfs.max_packet_size"),
        Some(&Value::from(1200))
    );
    let ech = Ech {
        config_lines: vec!["AEn+DQBFKwAgACABWIHUGj4u".into()],
        query_server_name: Some("ech.example".into()),
    };
    assert_eq!(tls(&p).ech, Some(ech));
    assert_eq!(p.notes, [Note::UnsupportedField("up".into())]);
    let bad = report(concat!(
        "proxies:\n",
        "- {name: b, type: hysteria2, server: h.example, port: 443, password: pw, obfs: wireguard}\n",
        "- {name: c, type: hysteria2, server: h.example, port: 443, password: pw, obfs: salamander}\n",
    ));
    let details: Vec<&str> = bad
        .skipped
        .iter()
        .filter_map(|s| match &s.reason {
            SkipReason::Invalid { detail, .. } => Some(detail.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        details,
        [
            "hysteria2: unknown obfs wireguard",
            "hysteria2: obfs without a password"
        ]
    );
}

/// Ciphers no engine of ours implements are refused at import; Xray spellings are normalised.
#[test]
fn shadowsocks_ciphers() {
    let r = report(concat!(
        "proxies:\n",
        "- {name: a, type: ss, server: s.example, port: 1, cipher: aes-128-ccm, password: pw}\n",
        "- {name: b, type: ss, server: s.example, port: 1, cipher: chacha20-poly1305, password: pw}\n",
        "- {name: c, type: ss, server: s.example, port: 1, cipher: none}\n",
    ));
    assert!(
        matches!(&r.skipped[0].reason, SkipReason::Invalid { detail, .. } if detail.contains("aes-128-ccm"))
    );
    let methods: Vec<(&str, &str)> = r
        .profiles
        .iter()
        .map(|p| match &p.kind {
            Kind::Shadowsocks {
                method, password, ..
            } => (method.as_str(), password.as_str()),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(methods, [("chacha20-ietf-poly1305", "pw"), ("none", "")]);
    assert_eq!(r.profiles[1].notes, [Note::Unencrypted]);
}

/// At most 5000 entries per document; the cut is reported, not silent.
#[test]
fn entry_cap_is_reported() {
    let mut yaml = String::from("proxies:\n");
    for i in 0..=MAX_PROXIES {
        yaml.push_str(&format!(
            "- {{name: n{i}, type: trojan, server: t.example, port: 443, password: p}}\n"
        ));
    }
    let r = report(&yaml);
    assert_eq!(r.profiles.len(), MAX_PROXIES);
    assert_eq!(r.skipped.len(), 1);
    assert!(
        matches!(&r.skipped[0].reason, SkipReason::Invalid { detail, .. } if detail.contains("5000"))
    );
}

/// Quoted scalars keep their exact text (a credential may begin with a space); `"null"` quoted is
/// text, plain `null` / `~` is absent.
#[test]
fn quoted_scalars_are_verbatim() {
    let p = one(
        "proxies:\n- {name: q, type: trojan, server: t.example, port: \"443\", password: \" p w \", sni: ~}\n",
    );
    assert_eq!(
        p.kind,
        Kind::Trojan {
            password: " p w ".into()
        }
    );
    assert_eq!(tls(&p).server_name.as_deref(), Some("t.example"));
    let p = one(
        "proxies:\n- {name: q, type: trojan, server: t.example, port: 443, password: \"null\"}\n",
    );
    assert_eq!(
        p.kind,
        Kind::Trojan {
            password: "null".into()
        }
    );
    let r = report(
        "proxies:\n- {name: q, type: trojan, server: t.example, port: 443, password: null}\n",
    );
    assert_eq!(r.skipped[0].reason, SkipReason::MissingCredential);
}

/// Sub-keys of the transport's `*-opts` map and of `reality-opts` that are not read become
/// `UnsupportedField("<map>.<key>")` instead of vanishing; early data under HTTPUpgrade too.
#[test]
fn unread_option_sub_keys_are_noted() {
    let grpc = one(
        "proxies:\n- {name: g, type: vless, server: r.example, port: 443, uuid: u, network: grpc, grpc-opts: {grpc-service-name: s, ping-interval: 30}, reality-opts: {public-key: k, short-id: ab, support-x25519mlkem768: true}}\n",
    );
    assert_eq!(
        grpc.notes,
        [
            Note::UnsupportedField("reality-opts.support-x25519mlkem768".into()),
            Note::UnsupportedField("grpc-opts.ping-interval".into())
        ]
    );
    let upgrade = one(
        "proxies:\n- {name: u, type: vmess, server: v.example, port: 80, uuid: u, alterId: 0, cipher: auto, network: ws, ws-opts: {path: /u, v2ray-http-upgrade: true, max-early-data: 2048}}\n",
    );
    assert!(matches!(upgrade.transport, Some(Transport::HttpUpgrade { .. })));
    assert_eq!(
        upgrade.notes,
        [Note::UnsupportedField("ws-opts.max-early-data".into())]
    );
}
