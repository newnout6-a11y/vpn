//! Pre-resolution vectors, pure part (xray-engine spec §7 "Endpoint plan": host collection and
//! substitution; the resolver itself — timeouts, concurrency, cancellation — is the caller's).
use std::collections::HashMap;
use std::net::IpAddr;

use serde_json::{Value, json};
use vpnte_base::types::ClientDevice;
use vpnte_profiles::model::Profile;
use vpnte_profiles::xray_native::CompiledGraph;

use super::*;
use crate::xray_config::{ProxyGraph, proxy_graph};

fn map(pairs: &[(&str, &str)]) -> HashMap<String, IpAddr> {
    pairs
        .iter()
        .map(|(h, ip)| ((*h).to_owned(), ip.parse().expect("IP")))
        .collect()
}

fn graph(outbounds: Vec<Value>) -> ProxyGraph {
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

fn outbounds(g: &ProxyGraph) -> &[Value] {
    match g {
        ProxyGraph::Native(c) => &c.outbounds,
        ProxyGraph::Translated(o) => std::slice::from_ref(o),
    }
}

fn vless(tag: &str, address: &str, stream: Value) -> Value {
    json!({"tag": tag, "protocol": "vless", "streamSettings": stream,
           "settings": {"vnext": [{"address": address, "port": 443, "users": [{"id": UUID, "encryption": "none"}]}]}})
}

/// Repeated hosts are listed once, literals never; every node gets its IP; explicit names stay.
#[test]
fn hosts_and_substitution() {
    let tls = json!({"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "front.example.com"}});
    let mut g = graph(vec![
        vless("proxy", "one.example.com", tls.clone()),
        vless("vpnte-source:b", "one.example.com", tls.clone()),
        vless("vpnte-source:c", "two.example.com", tls.clone()),
        json!({"tag": "vpnte-source:h", "protocol": "hysteria", "settings": {"address": "three.example.com", "port": 443, "version": 2}}),
        vless("vpnte-source:d", "192.0.2.1", tls.clone()),
        vless("vpnte-source:e", "[2001:db8::1]", tls),
    ]);
    assert_eq!(
        g.hosts(),
        ["one.example.com", "two.example.com", "three.example.com"]
    );
    let before = g.clone();
    g.substitute(&map(&[
        ("one.example.com", "192.0.2.44"),
        ("two.example.com", "192.0.2.44"),
        ("three.example.com", "192.0.2.44"),
    ]));
    let o = outbounds(&g);
    for node in &o[..3] {
        assert_eq!(node["settings"]["vnext"][0]["address"], "192.0.2.44");
        assert_eq!(
            node["streamSettings"]["tlsSettings"]["serverName"],
            "front.example.com"
        );
    }
    assert_eq!(o[3]["settings"]["address"], "192.0.2.44");
    assert_eq!(o[4], outbounds(&before)[4]);
    assert!(g.hosts().is_empty());
    // A host without an answer stays a name (the caller fails the start instead).
    let mut partial = before;
    partial.substitute(&map(&[("two.example.com", "192.0.2.45")]));
    assert_eq!(partial.hosts(), ["one.example.com", "three.example.com"]);
}

/// Only the named node of a list changes.
#[test]
fn mixed_literal_and_named_nodes() {
    let mut node = vless("proxy", "192.0.2.1", json!({"security": "none"}));
    node["settings"]["vnext"] = json!([
        {"address": "192.0.2.1", "port": 443, "users": []},
        {"address": "2001:db8::1", "port": 443, "users": []},
        {"address": "leaf.example.com", "port": 443, "users": []}
    ]);
    let mut g = graph(vec![node]);
    assert_eq!(g.hosts(), ["leaf.example.com"]);
    g.substitute(&map(&[("leaf.example.com", "2001:db8::2")]));
    let addresses: Vec<&str> = outbounds(&g)[0]["settings"]["vnext"]
        .as_array()
        .expect("vnext")
        .iter()
        .filter_map(|n| n["address"].as_str())
        .collect();
    assert_eq!(addresses, ["192.0.2.1", "2001:db8::1", "2001:db8::2"]);
}

/// B7: names Xray would derive from a host-name address are pinned before it becomes an IP;
/// a provider's explicit name (the REALITY camouflage) is never changed.
#[test]
fn derived_names_are_pinned() {
    let mut g = graph(vec![
        vless(
            "proxy",
            "h.example",
            json!({"network": "tcp", "security": "tls", "tlsSettings": {"serverName": ""}}),
        ),
        vless(
            "vpnte-source:r",
            "h.example",
            json!({"network": "tcp", "security": "reality",
            "realitySettings": {"publicKey": PBK, "fingerprint": "chrome"}}),
        ),
        vless(
            "vpnte-source:k",
            "h.example",
            json!({"network": "tcp", "security": "reality",
            "realitySettings": {"serverName": "camouflage.example", "publicKey": PBK}}),
        ),
        vless(
            "vpnte-source:w",
            "h.example",
            json!({"network": "ws", "security": "none"}),
        ),
        vless(
            "vpnte-source:x",
            "h.example",
            json!({"network": "ws", "security": "none",
            "wsSettings": {"headers": {"Host": "front.example"}}}),
        ),
        vless(
            "vpnte-source:g",
            "h.example",
            json!({"method": "grpc", "security": "none"}),
        ),
        vless("vpnte-source:t", "h.example", json!({"security": "tls"})),
    ]);
    g.substitute(&map(&[("h.example", "203.0.113.7")]));
    let o = outbounds(&g);
    assert_eq!(
        o[0]["streamSettings"]["tlsSettings"]["serverName"],
        "h.example"
    );
    assert_eq!(
        o[1]["streamSettings"]["realitySettings"]["serverName"],
        "h.example"
    );
    assert_eq!(
        o[2]["streamSettings"]["realitySettings"]["serverName"],
        "camouflage.example"
    );
    assert_eq!(o[3]["streamSettings"]["wsSettings"]["host"], "h.example");
    assert!(o[4]["streamSettings"]["wsSettings"].get("host").is_none());
    assert_eq!(
        o[5]["streamSettings"]["grpcSettings"]["authority"],
        "h.example"
    );
    assert_eq!(
        o[6]["streamSettings"]["tlsSettings"]["serverName"],
        "h.example"
    );
    assert!(
        o.iter()
            .all(|n| n["settings"]["vnext"][0]["address"] == "203.0.113.7")
    );
}

/// B8: the XHTTP split-download address is resolved and substituted too, with its own names.
#[test]
fn xhttp_download_address() {
    let stream = json!({"network": "xhttp", "security": "tls", "tlsSettings": {"serverName": "up.example"},
        "xhttpSettings": {"path": "/x", "extra": {"downloadSettings": {"address": "dl.example", "port": 443,
            "network": "xhttp", "security": "tls", "xhttpSettings": {"path": "/x"}}}}});
    let mut g = graph(vec![vless("proxy", "up.example", stream)]);
    assert_eq!(g.hosts(), ["up.example", "dl.example"]);
    g.substitute(&map(&[
        ("up.example", "192.0.2.10"),
        ("dl.example", "192.0.2.11"),
    ]));
    let s = &outbounds(&g)[0]["streamSettings"];
    let download = &s["xhttpSettings"]["extra"]["downloadSettings"];
    assert_eq!(download["address"], "192.0.2.11");
    assert_eq!(download["tlsSettings"]["serverName"], "dl.example");
    assert_eq!(s["tlsSettings"]["serverName"], "up.example");
}

/// A translated profile already carries its names; substitution only swaps the address, and
/// the result still passes the real Xray check.
#[test]
fn translated_profile_substitution() {
    let p = Profile {
        tls: tls("front.example"),
        ..profile(trojan())
    };
    let mut g = proxy_graph(&p, ClientDevice::Pc).expect("translates");
    assert_eq!(g.hosts(), ["nl.example"]);
    g.substitute(&map(&[("nl.example", "198.51.100.20")]));
    let ProxyGraph::Translated(o) = &g else {
        unreachable!("typed profile")
    };
    assert_eq!(o["settings"]["servers"][0]["address"], "198.51.100.20");
    assert_eq!(
        o["streamSettings"]["tlsSettings"]["serverName"],
        "front.example"
    );
    let config = crate::xray_config::build_config(&g, &super::config::endpoint(20007));
    assert!(crate::test_support::xray_check(&config).is_ok());
}
