//! Imported shapes through the emitter and the real `sing-box check` (AT-04-002): the emitter's
//! own matrix starts from typed profiles, this one from what the Clash and WireGuard INI
//! importers actually produce from provider text. Credentials are obvious fakes; WireGuard and
//! REALITY keys are well-formed because sing-box parses them at construction.
use super::parse_clash;
use crate::emit_singbox::check::{check, sing_box};
use crate::emit_singbox::{EmitPolicy, emit_singbox};
use crate::model::Profile;
use crate::wg_ini::parse_wg_ini;

/// The mihomo shapes providers publish that sing-box runs (flow and block style mixed).
const CLASH: &str = r#"proxies:
  - {name: vless-reality, type: vless, server: r.example.com, port: 443, uuid: 00000000-0000-4000-8000-000000000001, flow: xtls-rprx-vision, network: tcp, tls: true, udp: true, servername: www.example.com, client-fingerprint: chrome, reality-opts: {public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0, short-id: 0123abcd}}
  - {name: vless-grpc-reality, type: vless, server: r.example.com, port: 443, uuid: 00000000-0000-4000-8000-000000000002, network: grpc, tls: true, servername: www.example.com, grpc-opts: {grpc-service-name: TunService}, reality-opts: {public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0, short-id: ab}}
  - name: vless-ws-tls
    type: vless
    server: cdn.example.com
    port: 443
    uuid: 00000000-0000-4000-8000-000000000003
    network: ws
    tls: true
    servername: cdn.example.com
    alpn: [h2, http/1.1]
    ws-opts: {path: /ws?ed=2048, headers: {Host: cdn.example.com}}
  - {name: vmess-ws-mux, type: vmess, server: v.example.com, port: 80, uuid: 00000000-0000-4000-8000-000000000004, alterId: 0, cipher: auto, network: ws, ws-opts: {path: /v}, smux: {enabled: true, protocol: h2mux, max-connections: 4, padding: true}}
  - {name: vmess-h2, type: vmess, server: v.example.com, port: 443, uuid: 00000000-0000-4000-8000-000000000005, alterId: 0, cipher: aes-128-gcm, tls: true, network: h2, h2-opts: {host: [h2.example.com], path: /h2}}
  - {name: trojan-grpc, type: trojan, server: t.example.com, port: 443, password: fake-pass, sni: t.example.com, network: grpc, grpc-opts: {grpc-service-name: tg}}
  - {name: trojan-insecure, type: trojan, server: 192.0.2.10, port: 8443, password: fake-pass, skip-cert-verify: true}
  - {name: ss-aead, type: ss, server: s.example.com, port: 8388, cipher: aes-256-gcm, password: fake-pass, udp: true}
  - {name: ss-2022, type: ss, server: s.example.com, port: 8389, cipher: 2022-blake3-aes-128-gcm, password: AAECAwQFBgcICQoLDA0ODw==}
  - {name: ss-v2ray-plugin, type: ss, server: s.example.com, port: 443, cipher: chacha20-ietf-poly1305, password: fake-pass, plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, host: cdn.example.com, path: /ss}}
  - {name: ss-obfs, type: ss, server: s.example.com, port: 8390, cipher: aes-128-gcm, password: fake-pass, plugin: obfs, plugin-opts: {mode: http, host: bing.com}}
  - {name: ss-shadowtls, type: ss, server: s.example.com, port: 443, cipher: 2022-blake3-aes-128-gcm, password: AAECAwQFBgcICQoLDA0ODw==, plugin: shadow-tls, client-fingerprint: chrome, plugin-opts: {host: cover.example.com, password: fake-layer, version: 3}}
  - {name: hy2-hop, type: hysteria2, server: h.example.com, port: 443, ports: 20000-30000, password: fake-pass, sni: h.example.com, obfs: salamander, obfs-password: fake-obfs, up: 50 Mbps, down: 100 Mbps}
  - {name: tuic, type: tuic, server: q.example.com, port: 443, uuid: 00000000-0000-4000-8000-000000000006, password: fake-pass, sni: q.example.com, alpn: [h3], congestion-controller: bbr, udp-relay-mode: native}
  - {name: anytls, type: anytls, server: a.example.com, port: 443, password: fake-pass, sni: a.example.com, client-fingerprint: firefox}
  - {name: wg-single, type: wireguard, server: wg.example.com, port: 51820, ip: 10.0.0.2/32, ipv6: fd00::2/128, private-key: AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=, public-key: ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=, pre-shared-key: QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A=, reserved: [1, 2, 3], mtu: 1280, udp: true}
  - name: wg-peers
    type: wireguard
    ip: 10.0.0.3/32
    private-key: AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
    persistent-keepalive: 25
    peers:
      - {server: wg1.example.com, port: 51820, public-key: ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=, allowed-ips: [0.0.0.0/0]}
      - {server: 192.0.2.20, port: 51821, public-key: QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A=, allowed-ips: [10.10.0.0/16]}
  - {name: socks, type: socks5, server: p.example.com, port: 1080, username: fake-user, password: fake-pass}
  - {name: http-tls, type: http, server: p.example.com, port: 8443, username: fake-user, password: fake-pass, tls: true, sni: p.example.com}
"#;

/// A WireGuard client file as VPN providers hand it out.
const INI: &str = "[Interface]\nPrivateKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\n\
Address = 10.8.0.2/32, fd00::2/128\nDNS = 1.1.1.1\nMTU = 1280\n\n[Peer]\n\
PublicKey = ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=\n\
PresharedKey = QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A=\n\
AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = wg.example.com:51820\nPersistentKeepalive = 25\n";

fn imported() -> Vec<Profile> {
    let report = parse_clash(CLASH).expect("a Clash document");
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.profiles.len(), 19);
    let wg = parse_wg_ini(INI).expect("an INI file").expect("imported");
    report.profiles.into_iter().chain([wg]).collect()
}

/// AT-04-002: every profile the Clash and INI importers produce from the shapes above is
/// emitted under the default and the stealth policy, and each fragment passes the bundled
/// sing-box 1.14 `check` (skipped quietly when the binary is not on this machine).
#[test]
fn imported_profiles_pass_sing_box_check() {
    let policies = [
        EmitPolicy::default(),
        EmitPolicy {
            tls_compat: true,
            domain_resolver: Some("dns-bootstrap".into()),
            ..EmitPolicy::default()
        },
    ];
    let exe = sing_box();
    let mut failures = Vec::new();
    for p in imported() {
        for policy in &policies {
            let fragment = emit_singbox(&p, "proxy-out", policy)
                .unwrap_or_else(|e| panic!("{}: {e}", p.name));
            if let Some(exe) = &exe
                && let Err(e) = check(exe, &fragment)
            {
                failures.push(format!("{}: {e}", p.name));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
