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

fn outbound(config: &Value, tag: &str) -> Value {
    let outs = config["outbounds"].as_array().unwrap().iter();
    outs.into_iter().find(|o| o["tag"] == tag).cloned().unwrap()
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
        stun_pins()[0].clone(),
        stun_pins()[1].clone(),
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
    // The same profile over a TUN differs only in the capture parts, the TUN's in-memory
    // optimistic DNS (speed3 S3-13 (a)) and the resolver of `direct-out`: a proxy client hands
    // over a name, resolved on `dns-direct` when it leaves directly (appsplit-b3).
    let mut t = i.clone();
    t.capture = Capture::Tun(tun(false, true));
    let t = build(&t).unwrap();
    let mut tun_dns = t["dns"].clone();
    assert!(
        tun_dns
            .as_object_mut()
            .and_then(|d| d.remove("optimistic"))
            .is_some()
    );
    assert_eq!(tun_dns, c["dns"]);
    let (direct, others) = (outbound(&c, DIRECT_OUT), outbound(&t, DIRECT_OUT));
    assert_eq!(direct["domain_resolver"], DNS_DIRECT);
    assert!(others.get("domain_resolver").is_none());
    let rest = |c: &Value| -> Vec<Value> {
        let outs = c["outbounds"].as_array().unwrap().iter();
        outs.filter(|o| o["tag"] != DIRECT_OUT).cloned().collect()
    };
    assert_eq!(rest(&t), rest(&c));
    assert_eq!(t["experimental"], c["experimental"]);
    // Without `dns-direct` (no Smart RU, no direct rule, no scope) nothing changes.
    let bare = build(&proxied(inputs(native(&vless("1.2.3.4", None))))).unwrap();
    assert!(outbound(&bare, DIRECT_OUT).get("domain_resolver").is_none());
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

/// fixlists-b3: under proxy capture the user's «Не через прокси» entries leave directly for
/// every program, before every app's rule, and their names resolve on the network's resolver
/// (an intranet name), which is added when routing defines none; a TUN ignores them. sing-box
/// accepts both.
#[test]
fn the_users_bypass_entries_leave_directly_under_proxy_capture() {
    let entries = crate::routing::bypass::parse_list("corp.example 203.0.113.*").unwrap();
    let bypass = crate::routing::bypass::route_rules(&entries);
    let mut i = proxied(inputs(native(&vless("1.2.3.4", None))));
    let process =
        json!({ "process_path_regex": [r"(?i)^C:\\Apps\\vpn\.exe$"], "outbound": PROXY_OUT });
    i.routing.process_rules = vec![process.clone()];
    i.routing.proxy_bypass = bypass.clone();
    i.phys_dns = vec![std::net::Ipv4Addr::new(192, 168, 1, 1)];
    let c = build(&i).unwrap();
    let at: Vec<usize> = [&bypass[0], &bypass[1], &process]
        .iter()
        .map(|r| index_of(&c, r).unwrap())
        .collect();
    assert!(at.windows(2).all(|w| w[0] + 1 == w[1]), "{at:?} in {c:#}");
    let server = dns_server(&c, DNS_DIRECT).expect("dns-direct");
    assert_eq!(server["server"], "192.168.1.1");
    assert_eq!(outbound(&c, DIRECT_OUT)["domain_resolver"], DNS_DIRECT);
    assert_eq!(crate::test_support::singbox_check(&c).map(|_| ()), Ok(()));

    let mut t = i.clone();
    t.capture = Capture::Tun(tun(false, true));
    let t = build(&t).unwrap();
    assert!(index_of(&t, &bypass[0]).is_none() && dns_server(&t, DNS_DIRECT).is_none());
    assert_eq!(crate::test_support::singbox_check(&t).map(|_| ()), Ok(()));
}

/// speed3 S3-13 (a): a Tunnel config answers expired names from memory for at most an hour
/// (never `true`: three days); the proxy form has no such cache, and neither keeps anything on
/// disk (`cache_file` would also restore the last session's selector choice).
#[test]
fn optimistic_dns_only_in_the_tunnel_and_only_in_memory() {
    let up = || {
        slots(UdpPolicy {
            udp: true,
            block_quic: true,
        })
    };
    let tun = build(&inputs(up())).expect("tun");
    assert_eq!(
        tun["dns"]["optimistic"],
        json!({ "enabled": true, "timeout": "1h" })
    );
    let proxy = build(&proxied(inputs(up()))).expect("proxy");
    assert!(proxy["dns"].get("optimistic").is_none(), "{}", proxy["dns"]);
    for config in [&tun, &proxy] {
        assert!(config["experimental"].get("cache_file").is_none());
    }
}
