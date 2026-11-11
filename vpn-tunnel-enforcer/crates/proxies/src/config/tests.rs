//! Spec external-proxy §7.3 (engine config, pinning) and §7.7 (one listener per slot).
use std::net::IpAddr;

use serde_json::{Map, Value, json};
use vpnte_base::types::Creds;
use vpnte_profiles::emit_singbox::{EmitPolicy, SingBoxFragment, emit_singbox};
use vpnte_profiles::model::{
    DialPrefs, Host, Kind, Profile, ShadowTlsLayer, Source, WgPeer, WireGuard,
};

use super::*;

/// The old fixture outbound (fake UUID), as emitted with the slot tag.
pub(super) fn sample() -> SingBoxFragment {
    SingBoxFragment::Outbound(json!({
        "type": "vless", "tag": "proxy-out", "server": "203.0.113.10", "server_port": 443,
        "uuid": "00000000-0000-4000-8000-000000000000", "tls": { "enabled": true },
    }))
}

/// A hostname endpoint with extra keys merged in (placeholders only).
pub(super) fn hostname(extra: Value) -> SingBoxFragment {
    let mut o = json!({
        "type": "vless", "tag": "proxy-out", "server": "vpn.example.test", "server_port": 443,
        "uuid": "00000000-0000-4000-8000-000000000000", "domain_strategy": "prefer_ipv4",
    });
    if let (Some(o), Some(extra)) = (o.as_object_mut(), extra.as_object()) {
        o.extend(extra.clone());
    }
    SingBoxFragment::Outbound(o)
}

pub(super) fn profile(server: Host, port: u16, kind: Kind) -> Profile {
    Profile {
        name: "test".into(),
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

/// WireGuard with fake all-zero keys.
pub(super) fn wireguard(peer: Host) -> SingBoxFragment {
    let zero_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();
    let wg = WireGuard {
        private_key: zero_key.clone(),
        local_address: vec!["10.66.0.2/32".parse().unwrap()],
        mtu: None,
        dns: Vec::new(),
        peers: vec![WgPeer {
            host: peer,
            port: 51820,
            public_key: zero_key,
            pre_shared_key: None,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            keepalive_s: None,
            reserved: None,
        }],
    };
    let p = profile(
        Host::Ip("203.0.113.20".parse().unwrap()),
        51820,
        Kind::Wireguard(wg),
    );
    emit_singbox(&p, PROXY_OUT_TAG, &EmitPolicy::default()).unwrap()
}

/// Shadowsocks over ShadowTLS (a chain) with a hostname server.
pub(super) fn shadowtls_chain() -> SingBoxFragment {
    let kind = Kind::Shadowsocks {
        method: "aes-128-gcm".into(),
        password: "fake-password".into(),
        plugin: None,
        shadowtls: Some(ShadowTlsLayer {
            version: 3,
            password: "fake-password".into(),
            server_name: "cdn.example.test".into(),
        }),
        uot: None,
    };
    let p = profile(Host::Domain("vpn.example.test".into()), 443, kind);
    emit_singbox(&p, PROXY_OUT_TAG, &EmitPolicy::default()).unwrap()
}

fn rules(config: &Value) -> &Vec<Value> {
    config["route"]["rules"].as_array().unwrap()
}

/// Spec §7.3 + B-2: sniffing is a route action, every public request goes to `proxy-out`,
/// anything else is rejected, and there is no `block` outbound or `final`.
#[test]
fn uses_sniff_actions_and_fails_closed() {
    let config = build(&sample(), 17990).unwrap();
    assert_eq!(
        config["inbounds"][0],
        json!({ "type": "mixed", "tag": "external-mixed-in", "listen": "127.0.0.1", "listen_port": 17990 })
    );
    let rules = rules(&config);
    assert_eq!(rules[0], json!({ "action": "sniff" }));
    for rule in [
        json!({ "domain": ["localhost"], "outbound": "direct-out" }),
        json!({ "domain_suffix": ["localhost"], "outbound": "direct-out" }),
        json!({ "ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "direct-out" }),
        json!({ "ip_is_private": true, "outbound": "direct-out" }),
        json!({ "inbound": "external-mixed-in", "outbound": "proxy-out" }),
    ] {
        assert!(rules.contains(&rule), "{rule}");
    }
    assert_eq!(rules.last(), Some(&json!({ "action": "reject" })));
    assert_eq!(config["outbounds"][0]["tag"], "proxy-out");
    let types: Vec<&str> = config["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|o| o["type"].as_str())
        .collect();
    assert_eq!(types, ["vless", "direct"]);
    assert!(config["route"].get("final").is_none());
    assert_eq!(config["route"]["auto_detect_interface"], false);
    assert!(config.get("dns").is_none() && config.get("endpoints").is_none());
}

/// Spec §7.3 (Rust form of "bootstraps hostname endpoints"): with the resolver stubbed to
/// 203.0.113.5 the server is pinned, the provider SNI survives, nothing DNS-related remains and
/// the input is untouched.
#[test]
fn pins_hostname_endpoints_without_dns() {
    let input = hostname(json!({ "tls": { "enabled": true, "server_name": "cdn.example.test" } }));
    assert_eq!(hostnames(&input), ["vpn.example.test"]);
    let mut pinned = input.clone();
    pin(
        &mut pinned,
        "VPN.example.test",
        "203.0.113.5".parse().unwrap(),
    );
    let config = build(&pinned, 17990).unwrap();
    let out = &config["outbounds"][0];
    assert_eq!(out["server"], "203.0.113.5");
    assert_eq!(out["tls"]["server_name"], "cdn.example.test");
    assert!(out.get("domain_strategy").is_none() && out.get("domain_resolver").is_none());
    assert!(config.get("dns").is_none());
    assert!(config["route"].get("default_domain_resolver").is_none());
    assert_eq!(input.outbounds()[0]["server"], "vpn.example.test");
    assert!(hostnames(&pinned).is_empty());
}

/// Spec §7.3 extra cases + B-4: the name stays where the server reads it.
#[test]
fn pinning_keeps_the_server_name() {
    let ip: IpAddr = "203.0.113.5".parse().unwrap();
    let pinned = |extra: Value| {
        let mut f = hostname(extra);
        pin(&mut f, "vpn.example.test", ip);
        f.outbounds()[0].clone()
    };
    let o = pinned(json!({ "tls": { "enabled": true } }));
    assert_eq!(o["tls"]["server_name"], "vpn.example.test");
    let o = pinned(json!({ "transport": { "type": "ws", "path": "/x" } }));
    assert_eq!(o["transport"]["headers"]["Host"], "vpn.example.test");
    let o = pinned(
        json!({ "transport": { "type": "ws", "headers": { "host": "front.example.test" } } }),
    );
    assert_eq!(
        o["transport"]["headers"],
        json!({ "host": "front.example.test" })
    );
    let o = pinned(json!({ "transport": { "type": "httpupgrade" } }));
    assert_eq!(o["transport"]["host"], "vpn.example.test");
    let o = pinned(json!({ "transport": { "type": "http" } }));
    assert_eq!(o["transport"]["host"], json!(["vpn.example.test"]));
    let o = pinned(json!({ "tls": { "enabled": true }, "transport": { "type": "http" } }));
    assert!(
        o["transport"].get("host").is_none(),
        "h2 sends its own default host"
    );
    let o = pinned(json!({ "tls": { "enabled": false } }));
    assert!(o["tls"].get("server_name").is_none());
    let o = pinned(
        json!({ "tls": { "enabled": true, "reality": { "enabled": true }, "server_name": "www.example.com" } }),
    );
    assert_eq!(o["tls"]["server_name"], "www.example.com");
    // Spec §7.3: the resolver answered [2001:db8::1, 203.0.113.7] -> IPv4 is pinned.
    let answer: Vec<IpAddr> = vec![
        "2001:db8::1".parse().unwrap(),
        "203.0.113.7".parse().unwrap(),
    ];
    assert_eq!(
        preferred_address(&answer),
        Some("203.0.113.7".parse().unwrap())
    );
    assert_eq!(preferred_address(&answer[..1]), Some(answer[0]));
    assert_eq!(preferred_address(&[]), None);
}

/// Spec §7.3 "no DNS bootstrap for IP endpoints": nothing to resolve, nothing DNS-related.
#[test]
fn ip_endpoints_need_no_resolution() {
    assert!(hostnames(&sample()).is_empty());
    let config = build(&sample(), 17990).unwrap();
    assert!(config.get("dns").is_none());
    assert!(config["route"].get("default_domain_resolver").is_none());
    assert!(config["outbounds"][0].get("domain_resolver").is_none());
}

/// B-28: WireGuard is an endpoint tagged `proxy-out`, never an outbound; peer host names are
/// pinned like servers.
#[test]
fn wireguard_runs_as_an_endpoint() {
    let config = build(&wireguard(Host::Ip("203.0.113.20".parse().unwrap())), 17990).unwrap();
    assert_eq!(config["endpoints"][0]["tag"], "proxy-out");
    assert_eq!(config["endpoints"][0]["type"], "wireguard");
    let outbounds = config["outbounds"].as_array().unwrap();
    assert!(outbounds.iter().all(|o| o["type"] != "wireguard"));
    let mut named = wireguard(Host::Domain("wg.example.test".into()));
    assert_eq!(hostnames(&named), ["wg.example.test"]);
    pin(
        &mut named,
        "wg.example.test",
        "203.0.113.21".parse().unwrap(),
    );
    assert_eq!(named.endpoints()[0]["peers"][0]["address"], "203.0.113.21");
}

/// A ShadowTLS chain resolves only the member that dials; its camouflage SNI is kept.
#[test]
fn chains_pin_the_dialing_member() {
    let mut chain = shadowtls_chain();
    assert_eq!(hostnames(&chain), ["vpn.example.test"]);
    pin(
        &mut chain,
        "vpn.example.test",
        "203.0.113.30".parse().unwrap(),
    );
    let dialer = chain
        .outbounds()
        .iter()
        .find(|o| o.get("detour").is_none())
        .unwrap();
    assert_eq!(dialer["server"], "203.0.113.30");
    assert_eq!(dialer["tls"]["server_name"], "cdn.example.test");
    let config = build(&chain, 17990).unwrap();
    assert_eq!(config["outbounds"][0]["tag"], "proxy-out");
}

/// B-27: an Xray profile runs behind a SOCKS5 bridge to the slot's xray child.
#[test]
fn xray_profiles_run_through_a_socks_bridge() {
    let creds = Creds {
        user: "fake-user".into(),
        pass: "fake-pass".into(),
    };
    let config = build(&xray_bridge(41234, &creds).unwrap(), 17991).unwrap();
    assert_eq!(
        config["outbounds"][0],
        json!({ "type": "socks", "tag": "proxy-out", "server": "127.0.0.1", "server_port": 41234,
                "version": "5", "username": "fake-user", "password": "fake-pass", "udp_fragment": true })
    );
    assert_eq!(rules(&config).last(), Some(&json!({ "action": "reject" })));
}

/// Spec §7.7: every slot listens on its own port; the upstream must carry the slot tag.
#[test]
fn each_slot_gets_its_own_listener() {
    for (slot, port) in [(1, 17990), (2, 17991)] {
        let port_of = crate::slot::Slot::new(slot).unwrap().default_port();
        assert_eq!(port_of, port);
        let config = build(&sample(), port_of).unwrap();
        assert_eq!(config["inbounds"][0]["tag"], "external-mixed-in");
        assert_eq!(config["inbounds"][0]["listen_port"], port);
    }
    let foreign = SingBoxFragment::Outbound(json!({ "type": "direct", "tag": "original-tag" }));
    assert_eq!(build(&foreign, 17990).unwrap_err().http_status(), 500);
    assert_eq!(build(&sample(), 0).unwrap_err().detail(), "invalid port");
    let empty = SingBoxFragment::Chain(Vec::new());
    assert!(build(&empty, 17990).is_err());
}
