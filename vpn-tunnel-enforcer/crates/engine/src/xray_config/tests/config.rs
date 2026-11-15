//! Config vectors (xray-engine spec §7 "Config" and "Native graph"; old xrayEngine.test.ts,
//! xraySlots.test.ts, nativeXrayCompatibility.test.ts; AT-02-008 / AT-06-001 / AT-04-002).
use serde_json::{Value, json};
use vpnte_base::types::{ClientDevice, Creds};
use vpnte_profiles::json::parse_json;
use vpnte_profiles::model::Profile;
use vpnte_profiles::xray_native::NativeError;

use super::*;
use crate::slot::SlotEndpoint;
use crate::xray_config::{ProxyGraph, XrayConfigError, build_config, proxy_graph};

pub(super) fn endpoint(port: u16) -> SlotEndpoint {
    SlotEndpoint::new(
        port,
        Creds {
            user: "slot-user".into(),
            pass: "slot-password".into(),
        },
    )
    .expect("valid endpoint")
}

fn freedom() -> ProxyGraph {
    ProxyGraph::Translated(json!({"tag": "proxy", "protocol": "freedom"}))
}

/// AT-02-008 / AT-06-001: authenticated loopback SOCKS with route-only sniffing, private ranges
/// direct, everything else to `proxy`; the log goes to stdout at Info, access log off.
#[test]
fn translated_config() {
    let c = build_config(&freedom(), &endpoint(19999));
    assert_eq!(
        c["log"],
        json!({"loglevel": "info", "access": "none", "error": ""})
    );
    let inbounds = c["inbounds"].as_array().expect("inbounds");
    assert_eq!(inbounds.len(), 1);
    let inbound = &inbounds[0];
    assert_eq!(inbound["tag"], "in");
    assert_eq!(inbound["protocol"], "socks");
    assert_eq!(inbound["listen"], "127.0.0.1");
    assert_eq!(inbound["port"], 19999);
    assert_eq!(
        inbound["settings"],
        json!({"udp": true, "auth": "password",
               "accounts": [{"user": "slot-user", "pass": "slot-password"}]})
    );
    assert_eq!(
        inbound["sniffing"],
        json!({"enabled": true, "destOverride": ["tls", "http", "quic"], "routeOnly": true})
    );
    let tags: Vec<&str> = c["outbounds"]
        .as_array()
        .expect("outbounds")
        .iter()
        .filter_map(|o| o["tag"].as_str())
        .collect();
    assert_eq!(tags, ["proxy", "direct", "block"]);
    let rules = c["routing"]["rules"].as_array().expect("rules");
    assert!(
        rules[0]["ip"]
            .as_array()
            .is_some_and(|ips| ips.contains(&json!("10.0.0.0/8")))
    );
    assert_eq!(rules[0]["outboundTag"], "direct");
    assert_eq!(
        rules[1],
        json!({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})
    );
    for key in ["dns", "api", "stats", "policy", "observatory"] {
        assert!(c.get(key).is_none(), "{key}");
    }
}

fn vless_node(tag: &str, address: &str, dialer: Option<&str>) -> Value {
    let mut stream = json!({
        "network": "tcp", "security": "reality",
        "realitySettings": {"serverName": "front.example.com", "publicKey": PBK, "fingerprint": "firefox"}
    });
    if let Some(dialer) = dialer {
        stream["sockopt"] = json!({ "dialerProxy": dialer });
    }
    json!({
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{"address": address, "port": 443, "users": [{"id": UUID, "encryption": "none"}]}]},
        "mux": {"enabled": true, "concurrency": 6, "xudpConcurrency": 4, "xudpProxyUDP443": "reject"},
        "streamSettings": stream
    })
}

/// Provider document (spec §7 "Native graph"): balancer entry `l1`, a hysteria leg, a bridge
/// through a loopback, plus listeners / API / DNS / log and a global rule that must all go.
pub(super) fn norway() -> Value {
    json!({
        "remarks": "Norway",
        "inbounds": [{"listen": "0.0.0.0", "protocol": "socks", "port": 12345, "tag": "untrusted-listener"}],
        "api": {"services": ["HandlerService"]}, "dns": {"servers": ["untrusted.example.com"]},
        "log": {"error": "C:/untrusted/location.log"},
        "policy": {"levels": {"0": {"handshake": 7, "connIdle": 300}}},
        "outbounds": [
            vless_node("norwayvless1", "192.0.2.1", None),
            {"tag": "norwayhysteria1", "protocol": "hysteria", "settings": {"address": "192.0.2.2", "port": 443, "version": 2},
             "streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "auth": "SYNTHETIC_AUTH"},
                                "security": "tls", "tlsSettings": {"serverName": "front.example.com"}}},
            vless_node("bridgenorwayvless1", "192.0.2.1", Some("LOOP-L1")),
            vless_node("l1bridgevless1", "192.0.2.3", None),
            {"tag": "LOOP-L2", "protocol": "loopback", "settings": {"inboundTag": "L2-REROUTE"}},
            {"tag": "LOOP-L1", "protocol": "loopback", "settings": {"inboundTag": "L1-REROUTE"}},
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "unused", "protocol": "freedom"}
        ],
        "routing": {
            "balancers": [
                {"tag": "l1", "selector": ["norwayvless"], "strategy": {"type": "leastLoad", "settings": {"expected": 1}}, "fallbackTag": "LOOP-L2"},
                {"tag": "l2", "selector": ["norwayhysteria"], "strategy": {"type": "leastLoad"}, "fallbackTag": "bridgenorwayvless1"},
                {"tag": "bridge", "selector": ["l1bridge"], "strategy": {"type": "leastLoad"}, "fallbackTag": "direct"}
            ],
            "rules": [
                {"type": "field", "domain": ["untrusted.example.com"], "outboundTag": "direct"},
                {"type": "field", "inboundTag": ["L2-REROUTE"], "balancerTag": "l2"},
                {"type": "field", "inboundTag": ["L1-REROUTE"], "balancerTag": "bridge"},
                {"type": "field", "network": "tcp,udp", "balancerTag": "l1"}
            ]
        },
        "burstObservatory": {"subjectSelector": ["norway", "l1bridge"],
                             "pingConfig": {"destination": "https://example.com/", "interval": "1m", "sampling": 1, "timeout": "5s"}}
    })
}

/// The document imported the way the app imports pasted JSON: one profile with its graph.
pub(super) fn imported(doc: &Value) -> Profile {
    let mut report = parse_json(doc);
    assert_eq!(report.profiles.len(), 1, "{:?}", report.skipped);
    report.profiles.remove(0)
}

fn by_tag<'a>(list: &'a Value, tag: &str) -> &'a Value {
    list.as_array()
        .and_then(|l| l.iter().find(|o| o["tag"] == tag))
        .unwrap_or_else(|| panic!("no {tag}"))
}

/// AT-04-002 / AT-02-002: the compiled provider graph keeps its failover and bridge, loses
/// everything the app owns, and ends fail-closed.
#[test]
fn native_graph_config() {
    let doc = norway();
    let p = imported(&doc);
    assert_eq!(p.name, "Norway");
    let graph = proxy_graph(&p, ClientDevice::Pc).expect("compiles");
    assert!(matches!(graph, ProxyGraph::Native(_)));
    assert!(!format!("{graph:?}").contains(UUID));
    let c = build_config(&graph, &endpoint(20001));
    assert_eq!(doc, norway(), "source document unchanged");
    let text = c.to_string();
    assert!(!text.contains("untrusted"), "{text}");
    assert_eq!(c["inbounds"].as_array().map(Vec::len), Some(1));
    assert!(c.get("api").is_none() && c.get("dns").is_none());
    assert_eq!(c["policy"], doc["policy"]);

    let rules = c["routing"]["rules"].as_array().expect("rules");
    assert_eq!(rules[0]["inboundTag"], json!(["in"]));
    assert_eq!(rules[0]["outboundTag"], "direct");
    assert_eq!(
        rules.last(),
        Some(&json!({"type": "field", "network": "tcp,udp", "outboundTag": "block"}))
    );
    assert!(rules.contains(
        &json!({"type": "field", "inboundTag": ["in"], "network": "tcp,udp",
                                   "balancerTag": "vpnte-balancer:l1"})
    ));
    assert!(rules.contains(
        &json!({"type": "field", "inboundTag": ["vpnte-loop:L1-REROUTE"],
                                   "balancerTag": "vpnte-balancer:bridge"})
    ));

    let balancers = &c["routing"]["balancers"];
    let l1 = by_tag(balancers, "vpnte-balancer:l1");
    assert_eq!(l1["fallbackTag"], "vpnte-source:LOOP-L2");
    assert_eq!(l1["selector"], json!(["proxy"]));
    let l2 = by_tag(balancers, "vpnte-balancer:l2");
    assert_eq!(l2["fallbackTag"], "vpnte-source:bridgenorwayvless1");

    let outbounds = &c["outbounds"];
    let bridge = by_tag(outbounds, "vpnte-source:bridgenorwayvless1");
    assert_eq!(
        bridge["streamSettings"]["sockopt"]["dialerProxy"],
        "vpnte-source:LOOP-L1"
    );
    let loop_l1 = by_tag(outbounds, "vpnte-source:LOOP-L1");
    assert_eq!(loop_l1["settings"]["inboundTag"], "vpnte-loop:L1-REROUTE");
    let proxy = by_tag(outbounds, "proxy");
    let source = &doc["outbounds"][0];
    assert_eq!(proxy["streamSettings"], source["streamSettings"]);
    assert_eq!(proxy["mux"], source["mux"]);
    let tags: Vec<&str> = outbounds
        .as_array()
        .expect("outbounds")
        .iter()
        .filter_map(|o| o["tag"].as_str())
        .collect();
    assert_eq!(tags.first(), Some(&"proxy"));
    assert_eq!(&tags[tags.len() - 2..], ["direct", "block"]);
    assert!(!tags.iter().any(|t| t.ends_with(":unused")));
    let subjects = c["burstObservatory"]["subjectSelector"]
        .as_array()
        .expect("subjects");
    assert!(subjects.contains(&json!("proxy")));
    assert!(subjects.contains(&json!("vpnte-source:l1bridgevless1")));
}

/// A stored graph of an unknown version is refused when the config is built
/// (`Invalid preserved Xray profile`), whatever the selection said.
#[test]
fn invalid_native_graph() {
    let mut p = imported(&norway());
    if let Some(graph) = p.native_xray.as_mut() {
        graph.version = 2;
    }
    let err = proxy_graph(&p, ClientDevice::Pc).expect_err("refused");
    assert_eq!(err, XrayConfigError::Native(NativeError::InvalidProfile));
    assert_eq!(err.to_string(), "Invalid preserved Xray profile");
    let graph = super::select::native(1);
    let p = Profile {
        native_xray: Some(graph),
        ..profile(vless())
    };
    assert_eq!(
        proxy_graph(&p, ClientDevice::Pc),
        Err(XrayConfigError::Native(NativeError::MissingSelected))
    );
}

/// A provider XHTTP outbound runs through its graph untouched (nativeXrayCompatibility.test.ts:
/// 252-271): the compiled `proxy` keeps the provider's `streamSettings` byte for byte. The
/// `sockopt` the model has no field for keeps it a graph (a plain lone outbound imports typed).
#[test]
fn native_xhttp_passes_through() {
    let stream = json!({"network": "xhttp", "security": "tls",
        "tlsSettings": {"serverName": "front.example.com", "fingerprint": "firefox"},
        "xhttpSettings": {"mode": "packet-up", "path": "/path", "host": "front.example.com",
                          "extra": {"noSSEHeader": true}},
        "sockopt": {"tcpKeepAliveIdle": 30}});
    let doc = json!({"outbounds": [{"tag": "proxy", "protocol": "vless",
        "settings": {"vnext": [{"address": "192.0.2.10", "port": 443,
                                "users": [{"id": UUID, "encryption": "none"}]}]},
        "streamSettings": stream}]});
    let p = imported(&doc);
    assert!(p.native_xray.is_some());
    let c = build_config(
        &proxy_graph(&p, ClientDevice::Pc).expect("compiles"),
        &endpoint(20006),
    );
    assert_eq!(by_tag(&c["outbounds"], "proxy")["streamSettings"], stream);
}
