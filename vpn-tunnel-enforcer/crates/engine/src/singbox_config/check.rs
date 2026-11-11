//! Every variant of the generated config through the bundled sing-box 1.14 `check` (decodes
//! with DisallowUnknownFields and builds inbounds, outbounds, DNS and rules without starting
//! them, so the TUN is not created). Skipped quietly when the binary is absent.
use std::net::Ipv4Addr;

use serde_json::json;
use vpnte_base::types::ProxyKind;
use vpnte_core::net::HostPort;

use super::tests::*;
use super::*;
use crate::tags::{DIRECT_OUT, PROXY_OUT};
use crate::test_support::{resources, singbox_check};

/// The Smart RU fragments with the bundled rule sets (forward slashes, as routing emits them).
fn smart_ru() -> RoutingParts {
    smart_ru_parts(&resources().to_string_lossy().replace('\\', "/"))
}

fn variants() -> Vec<(&'static str, ConfigInputs)> {
    let mut v = Vec::new();
    v.push((
        "vless ip, ipv4 tun",
        inputs(native(&vless("1.2.3.4", None))),
    ));

    let mut i = inputs(native(&reality("sub.example.com")));
    i.tun = tun(true, false);
    i.tun.stack = TunStack::Gvisor;
    i.phys_dns = vec![Ipv4Addr::new(192, 168, 1, 1)];
    v.push(("reality hostname, dual stack, native dns, gvisor", i));

    let mut i = inputs(Upstream::Native {
        fragment: native_fragment(&reality("1.2.3.4")),
        udp: UdpPolicy {
            udp: false,
            block_quic: true,
        },
    });
    i.tun = tun(true, true);
    v.push(("tcp-only upstream, dual stack, hijack", i));

    v.push(("hysteria2", inputs(native(&hysteria2("1.2.3.4")))));
    let mut i = inputs(native(&shadowsocks("2001:db8::7")));
    i.tun = tun(true, false);
    v.push(("shadowsocks ipv6 endpoint excluded, dual stack", i));

    let mut i = inputs(native(&wireguard("wg.example.com")));
    i.tun = tun(true, false);
    v.push(("wireguard hostname peer, dual stack", i));

    let mut i = inputs(native(&wireguard("203.0.113.5")));
    i.routing.dns_servers = vec![json!({
        "type": "https", "tag": "dns-remote", "server": "custom-dns.example.com",
        "path": "/dns-query", "detour": "proxy-out",
        "tls": { "server_name": "custom-dns.example.com" },
    })];
    v.push(("wireguard, hostname DoH", i));

    let mut i = inputs(Upstream::LocalProxy {
        addr: HostPort::parse("127.0.0.1:10808").unwrap(),
        kind: ProxyKind::Socks5,
        creds: Some(creds("local")),
    });
    i.listeners.probe = None;
    i.routing.process_rules = vec![json!({
        "process_path_regex": [
            r"(?i)(?:^|\\)Happ\.exe$", r"(?i)(?:^|\\)xray\.exe$", r"(?i)(?:^|\\)FlClash\.exe$",
        ],
        "outbound": DIRECT_OUT,
    })];
    v.push(("local socks, third-party cores direct", i));

    let mut i = inputs(Upstream::LocalProxy {
        addr: HostPort::parse("proxy.home.arpa:10809").unwrap(),
        kind: ProxyKind::Http,
        creds: None,
    });
    i.listeners.probe = None;
    v.push(("local http by name", i));

    let mut i = inputs(slots(UdpPolicy {
        udp: true,
        block_quic: true,
    }));
    i.listeners.dns_bootstrap = Some(25556);
    i.tun = tun(true, false);
    i.routing = smart_ru();
    i.routing.process_rules = vec![
        json!({
            "process_path_regex": [r"(?i)^C:\\Program Files \(x86\)\\App\+1\\app\.exe$"],
            "outbound": DIRECT_OUT,
        }),
        json!({ "process_path_regex": [r"(?i)^C:\\Apps\\chat\.exe$"], "outbound": PROXY_OUT }),
    ];
    i.routing.domain_rules.insert(
        0,
        json!({ "domain_keyword": ["telegram"], "action": "reject", "method": "default", "no_drop": true }),
    );
    i.routing.dns_rules.insert(
        0,
        json!({ "domain_keyword": ["telegram"], "action": "reject", "method": "default", "no_drop": true }),
    );
    v.push(("xray slots, bootstrap-in, smart ru, user rules", i));

    let mut i = inputs(native(&vless("sub.example.com", Some("xudp"))));
    i.routing = smart_ru();
    i.routing.dns_servers = vec![
        json!({ "type": "tls", "tag": "dns-remote", "server": "8.8.8.8", "server_port": 853, "detour": "proxy-out", "tls": { "server_name": "dns.google" } }),
        json!({ "type": "dhcp", "tag": "dns-direct" }),
    ];
    v.push(("vless hostname, DoT remote, dhcp direct", i));
    v
}

/// AT-02-002 / AT-04-002 / AT-07-012: every generated variant passes `sing-box check`.
#[test]
fn every_variant_passes_sing_box_check() {
    if crate::test_support::singbox_exe().is_none() {
        return;
    }
    let mut failures = Vec::new();
    for (name, inputs) in variants() {
        let config = build(&inputs).unwrap_or_else(|e| panic!("{name}: {e}"));
        if let Err(e) = singbox_check(&config) {
            failures.push(format!("{name}: {e}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// The check is meaningful: it refuses removed TUN fields and unknown rule keys.
#[test]
fn check_refuses_broken_configs() {
    let mut config = build(&inputs(native(&vless("1.2.3.4", None)))).unwrap();
    if singbox_check(&config) == Ok(false) {
        return;
    }
    assert_eq!(singbox_check(&config), Ok(true));
    config["inbounds"][0]["gso"] = json!(true);
    assert!(singbox_check(&config).is_err());
    let mut config = build(&inputs(native(&vless("1.2.3.4", None)))).unwrap();
    config["route"]["rules"][0]["no_such_field"] = json!(1);
    assert!(singbox_check(&config).is_err());
}
