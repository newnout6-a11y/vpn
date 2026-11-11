//! Proxy capture (NOADMIN.md §2): the config without a TUN, for an unelevated engine.
use serde_json::{Value, json};

use super::tests::*;
use super::*;
use crate::tags::*;

/// The proxy-capture port of the fixtures (distinct from every listener in `inputs`).
pub(super) const PROXY_PORT: u16 = 25560;

/// `i` with the loopback proxy instead of the TUN.
pub(super) fn proxied(mut i: ConfigInputs) -> ConfigInputs {
    i.capture = Capture::Proxy { port: PROXY_PORT };
    i
}

fn has_rule(config: &Value, rule: &Value) -> bool {
    index_of(config, rule).is_some()
}

fn quic_reject() -> Value {
    json!({ "network": "udp", "port": 443, "action": "reject", "method": "default", "no_drop": true })
}

/// The first inbound is an unauthenticated loopback mixed listener; the authenticated loopback
/// inbounds stay, and nothing asks sing-box to touch the system proxy.
#[test]
fn proxy_inbound_replaces_the_tun() {
    let c = build(&proxied(inputs(native(&vless("1.2.3.4", None))))).unwrap();
    let inbounds = c["inbounds"].as_array().unwrap();
    assert_eq!(
        inbounds[0],
        json!({ "type": "mixed", "tag": PROXY_IN, "listen": "127.0.0.1", "listen_port": PROXY_PORT })
    );
    assert!(inbounds.iter().all(|i| i["type"] != "tun"));
    let tags: Vec<&str> = inbounds.iter().filter_map(|i| i["tag"].as_str()).collect();
    assert_eq!(tags, [PROXY_IN, DIRECT_IN, PROBE_IN]);
    assert!(inbounds[1..].iter().all(|i| i["users"].is_array()));
    let text = c.to_string();
    for absent in [
        "set_system_proxy",
        "auto_route",
        "strict_route",
        "route_exclude_address",
        "auto_detect_interface",
        TUN_IN,
    ] {
        assert!(!text.contains(absent), "{absent} in {c:#}");
    }
}

/// The TUN DNS hijack goes; loopback rules, sniffing, the IPv6 / QUIC policy, private direct,
/// the STUN pin, routing's fragments, the DNS section and the Clash API stay.
#[test]
fn proxy_form_keeps_everything_but_the_tun() {
    let mut i = proxied(inputs(native(&vless("sub.example.com", None))));
    i.routing = smart_ru_parts("C:/rt");
    let process =
        json!({ "process_path_regex": [r"(?i)^C:\\Apps\\chat\.exe$"], "outbound": DIRECT_OUT });
    i.routing.process_rules = vec![process.clone()];
    let c = build(&i).unwrap();
    assert!(!has_rule(
        &c,
        &json!({ "protocol": "dns", "action": "hijack-dns" })
    ));
    let order = [
        json!({ "inbound": DIRECT_IN, "outbound": DIRECT_OUT }),
        json!({ "inbound": PROBE_IN, "outbound": PROXY_OUT }),
        process,
        quic_reject(),
        ipv6_reject_rule(),
        json!({ "action": "sniff" }),
        json!({ "ip_is_private": true, "outbound": DIRECT_OUT }),
        json!({ "network": "udp", "port": [19302, 3478], "outbound": PROXY_OUT }),
        i.routing.domain_rules[0].clone(),
    ];
    let at: Vec<usize> = order.iter().map(|r| index_of(&c, r).unwrap()).collect();
    assert!(at.windows(2).all(|w| w[0] + 1 == w[1]), "{at:?} in {c:#}");
    assert_eq!(c["route"]["rule_set"], json!(i.routing.rule_sets));
    assert_eq!(c["route"]["final"], PROXY_OUT);
    assert_eq!(c["route"]["default_domain_resolver"], DNS_REMOTE);
    assert!(dns_server(&c, DNS_DIRECT).is_some());
    assert!(dns_server(&c, DNS_BOOTSTRAP).is_some());
    assert_eq!(c["dns"]["rules"], json!(i.routing.dns_rules));
    assert_eq!(c["dns"]["strategy"], "ipv4_only");
    let clash = &c["experimental"]["clash_api"];
    assert_eq!(clash["external_controller"], "127.0.0.1:25553");
    // The same profile over a TUN differs only in the capture parts.
    let mut t = i.clone();
    t.capture = Capture::Tun(tun(false, true));
    let t = build(&t).unwrap();
    assert_eq!(t["dns"], c["dns"]);
    assert_eq!(t["outbounds"], c["outbounds"]);
    assert_eq!(t["experimental"], c["experimental"]);
}

/// The UDP policy of the upstream is kept: QUIC reject before sniff, the all-UDP drop.
#[test]
fn proxy_form_keeps_the_udp_policy() {
    let c = build(&proxied(inputs(local_socks()))).unwrap();
    assert!(index_of(&c, &quic_reject()).unwrap() < index_of(&c, &ipv6_reject_rule()).unwrap());
    let tcp_only = slots(UdpPolicy {
        udp: false,
        block_quic: true,
    });
    let c = build(&proxied(inputs(tcp_only))).unwrap();
    assert!(has_rule(
        &c,
        &json!({ "network": "udp", "action": "reject", "method": "drop" })
    ));
    assert_eq!(c["outbounds"][0]["type"], "selector");
}

/// The proxy port is an app-owned port: non-zero and distinct from every other listener.
#[test]
fn proxy_port_is_checked() {
    let collide: [fn(&mut ConfigInputs) -> u16; 5] = [
        |_| 0,
        |i| i.listeners.clash_port,
        |i| i.listeners.direct.port,
        |i| i.listeners.probe.as_ref().unwrap().port,
        |i| {
            i.listeners.dns_bootstrap = Some(26000);
            26000
        },
    ];
    for f in collide {
        let mut i = inputs(native(&vless("1.2.3.4", None)));
        let port = f(&mut i);
        i.capture = Capture::Proxy { port };
        assert!(
            matches!(build(&i), Err(ConfigError::InvalidListeners(_))),
            "{port}"
        );
    }
    let mut i = inputs(slots(UdpPolicy {
        udp: true,
        block_quic: true,
    }));
    i.capture = Capture::Proxy { port: 25551 };
    assert!(matches!(build(&i), Err(ConfigError::InvalidListeners(_))));
}

/// AT-02-011: the capture is part of the key, the proxy port too (the system proxy points at
/// it); listener ports and secrets are not.
#[test]
fn proxy_capture_compat_key() {
    let up = || {
        slots(UdpPolicy {
            udp: true,
            block_quic: true,
        })
    };
    let base = proxied(inputs(up()));
    let key = compat_key(&base);
    assert_ne!(key, compat_key(&inputs(up())));
    let mut same = base.clone();
    same.listeners.clash_port = 30000;
    same.listeners.clash_secret = "ffffffffffffffffffffffffffffffff".into();
    assert_eq!(compat_key(&same), key);
    let mut other = base.clone();
    other.capture = Capture::Proxy { port: 25561 };
    assert_ne!(compat_key(&other), key);
}
