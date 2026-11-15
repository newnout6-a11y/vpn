//! Lab live-11 L11-2: the server addresses an Xray slot dials, on a provider graph imported and
//! compiled the way the app does it, and in the TUN config built from them.
use std::collections::HashMap;
use std::net::IpAddr;

use serde_json::{Value, json};
use vpnte_base::types::ClientDevice;
use vpnte_profiles::json::parse_json;
use vpnte_profiles::xray_native::CompiledGraph;

use super::tests::{inputs, slots, tun};
use super::*;
use crate::xray_config::{ProxyGraph, proxy_graph};

const UUID: &str = "11111111-2222-4333-8444-555555555555";
const PBK: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn ip(text: &str) -> IpAddr {
    text.parse().expect("IP")
}

fn vless(tag: &str, address: &str, dialer: Option<&str>) -> Value {
    let mut stream = json!({
        "network": "tcp", "security": "reality",
        "realitySettings": {"serverName": "front.example.com", "publicKey": PBK, "fingerprint": "chrome"}
    });
    if let Some(dialer) = dialer {
        stream["sockopt"] = json!({ "dialerProxy": dialer });
    }
    json!({
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{"address": address, "port": 443, "users": [{"id": UUID, "encryption": "none"}]}]},
        "streamSettings": stream
    })
}

/// A provider document as subscriptions ship it: a balancer over three members (one by name),
/// a fallback that dials through a member, an observatory probing the members.
fn provider() -> Value {
    json!({
        "remarks": "Provider",
        "outbounds": [
            vless("fi-1", "fi1.example.net", None),
            vless("fi-2", "203.0.113.12", None),
            vless("fi-3", "203.0.113.13", None),
            vless("chain", "203.0.113.15", Some("fi-2")),
            {"tag": "direct", "protocol": "freedom"}
        ],
        "routing": {
            "balancers": [{"tag": "auto", "selector": ["fi-"], "strategy": {"type": "leastPing"}, "fallbackTag": "chain"}],
            "rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "auto"}]
        },
        "observatory": {"subjectSelector": ["fi-"], "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "1m"}
    })
}

/// The provider graph as a start plans it: compiled, its names resolved and substituted.
fn planned() -> ProxyGraph {
    let mut report = parse_json(&provider());
    assert_eq!(report.profiles.len(), 1, "{:?}", report.skipped);
    let profile = report.profiles.remove(0);
    let mut graph = proxy_graph(&profile, ClientDevice::Pc).expect("compiles");
    assert_eq!(graph.hosts(), ["fi1.example.net"]);
    let resolved = HashMap::from([("fi1.example.net".to_owned(), ip("203.0.113.11"))]);
    graph.substitute(&resolved);
    graph
}

/// Every member of the balancer (the observatory dials the same members), the resolved name
/// included; the fallback that dials through a member is reached inside it and stays routed.
#[test]
fn a_provider_graph_names_every_member_it_dials() {
    let found = xray_servers(&planned());
    let mut sorted = found.clone();
    sorted.sort();
    let members = ["203.0.113.11", "203.0.113.12", "203.0.113.13"].map(ip);
    assert_eq!(sorted, members, "{found:?}");
    assert!(
        !found.contains(&ip("203.0.113.15")),
        "a chained hop is not dialled by Xray itself"
    );
}

/// The TUN config of an Xray-slot start keeps those servers out of its routes, and the real
/// sing-box accepts it.
#[test]
fn the_tun_routes_leave_out_the_slots_servers() {
    let servers = xray_servers(&planned());
    let mut i = inputs(slots(UdpPolicy {
        udp: true,
        block_quic: true,
    }));
    i.capture = Capture::Tun(tun(true, false));
    let config = build_with_servers(&i, &servers).expect("builds");
    let excluded = &config["inbounds"][0]["route_exclude_address"];
    for server in &servers {
        assert!(
            excluded
                .as_array()
                .is_some_and(|l| l.contains(&json!(format!("{server}/32"))))
        );
    }
    if crate::test_support::singbox_exe().is_some() {
        assert_eq!(crate::test_support::singbox_check(&config), Ok(true));
    }
}

fn compiled(outbounds: Vec<Value>) -> ProxyGraph {
    ProxyGraph::Native(Box::new(CompiledGraph {
        outbounds,
        rules: Vec::new(),
        balancers: Vec::new(),
        entry: json!({"outboundTag": "proxy"}),
        observatory: None,
        burst_observatory: None,
        policy: None,
    }))
}

/// The list is bounded and keeps the selected outbound (`proxy`, compiled first) at its head.
#[test]
fn a_large_graph_keeps_the_selected_server_within_the_bound() {
    let mut outbounds = vec![vless("proxy", "198.51.100.1", None)];
    outbounds.extend((2..=40).map(|n| vless(&format!("m{n}"), &format!("198.51.100.{n}"), None)));
    let found = xray_servers(&compiled(outbounds));
    assert_eq!(found.len(), MAX_XRAY_SERVERS);
    assert_eq!(found[0], ip("198.51.100.1"));
}

/// An XHTTP split download and WireGuard peers are dials of their own; a `dns` outbound's
/// resolver, a name left unresolved and a repeated address are not added.
#[test]
fn downloads_and_peers_count_resolvers_and_names_do_not() {
    let mut split = vless("proxy", "198.51.100.1", None);
    split["streamSettings"] = json!({
        "network": "xhttp", "security": "tls",
        "xhttpSettings": {"path": "/x", "extra": {"downloadSettings": {"address": "198.51.100.2", "port": 443}}}
    });
    let wireguard = json!({
        "tag": "wg", "protocol": "wireguard",
        "settings": {"secretKey": "x", "address": ["10.0.0.2/32"],
                     "peers": [{"endpoint": "[2001:db8::7]:51820"}, {"endpoint": "198.51.100.1:51820"}]}
    });
    let resolver = json!({"tag": "dns-out", "protocol": "dns", "settings": {"address": "1.1.1.1"}});
    let named = vless("named", "unresolved.example.net", None);
    let found = xray_servers(&compiled(vec![split, wireguard, resolver, named]));
    assert_eq!(
        found,
        ["198.51.100.1", "198.51.100.2", "2001:db8::7"].map(ip)
    );
    let lone = json!({"protocol": "dns", "settings": {"address": "8.8.8.8"}});
    assert!(xray_servers(&ProxyGraph::Translated(lone)).is_empty());
}
