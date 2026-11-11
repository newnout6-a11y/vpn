//! Native graph vectors (xray-engine spec §7 "Native graph"; old nativeXrayCompatibility.test.ts).
use serde_json::{Value, json};

use super::*;
use crate::model::{NativeEntry, NativeRouting};

/// 32 bytes of 0x01, base64url: a well-formed but obviously fake REALITY public key.
const PUBLIC_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const UUID: &str = "11111111-2222-4333-8444-555555555555";

fn vless(tag: &str, address: &str, dialer: Option<&str>) -> Value {
    let mut stream = json!({
        "network": "tcp", "tcpSettings": {"header": {"type": "none"}}, "security": "reality",
        "realitySettings": {"serverName": "front.example.com", "publicKey": PUBLIC_KEY, "fingerprint": "firefox"}
    });
    if let Some(dialer) = dialer {
        stream["sockopt"] = json!({"dialerProxy": dialer});
    }
    json!({
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{"address": address, "port": 443, "users": [{"id": UUID, "encryption": "none", "flow": ""}]}]},
        "mux": {"enabled": true, "concurrency": 6, "xudpConcurrency": 4, "xudpProxyUDP443": "reject"},
        "streamSettings": stream
    })
}

/// Trojan over TLS with extra `tlsSettings` keys.
fn trojan(tag: &str, tls_extra: Value) -> Value {
    let mut o = json!({"tag": tag, "protocol": "trojan",
        "settings": {"servers": [{"address": "192.0.2.1", "port": 443, "password": "SYNTHETIC"}]},
        "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "front.example.com"}}});
    o["streamSettings"]["tlsSettings"]
        .as_object_mut()
        .unwrap()
        .extend(tls_extra.as_object().unwrap().clone());
    o
}

/// Provider document: balancer entry `l1`, a hysteria leg, a bridge through a loopback, provider
/// listeners/API/DNS/log and a global direct rule that must all be dropped.
fn document() -> Value {
    json!({
        "remarks": "Norway",
        "inbounds": [{"listen": "0.0.0.0", "protocol": "socks", "port": 12345, "tag": "untrusted-listener"}],
        "api": {"services": ["HandlerService"]}, "dns": {"servers": ["untrusted.example.com"]},
        "log": {"error": "C:/untrusted/location.log"},
        "policy": {"levels": {"0": {"handshake": 7, "connIdle": 300}}},
        "outbounds": [
            vless("norwayvless1", "192.0.2.1", None),
            {"tag": "norwayhysteria1", "protocol": "hysteria", "settings": {"address": "192.0.2.2", "port": 443, "version": 2},
             "streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "auth": "SYNTHETIC_AUTH"},
                                "security": "tls", "tlsSettings": {"serverName": "front.example.com"}}},
            vless("bridgenorwayvless1", "192.0.2.1", Some("LOOP-L1")),
            vless("l1bridgevless1", "192.0.2.3", None),
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

/// Document import as the JSON importer does it: one profile per document with an entry.
fn import(doc: &Value) -> Result<NativeXray, NativeError> {
    let entry = document_entry(doc).expect("document has an entry");
    let selected = document_selected(doc, &entry).expect("document has a selectable outbound");
    preserve(selected, Some(doc), Some(entry))
}

fn compiled(graph: &NativeXray) -> CompiledGraph {
    compile(graph, selected_outbound(graph).expect("selected")).expect("compiles")
}

fn by_tag<'a>(list: &'a [Value], tag: &str) -> &'a Value {
    list.iter()
        .find(|o| o["tag"] == tag)
        .unwrap_or_else(|| panic!("no {tag}"))
}

fn tags(list: &[Value]) -> Vec<&str> {
    list.iter().filter_map(|o| o["tag"].as_str()).collect()
}

/// AT-04-002 / AT-04-006: one provider document is one profile with its automatic failover;
/// only the reachable graph is kept.
#[test]
fn document_is_one_profile_with_its_balancer_entry() {
    let doc = document();
    let entry = document_entry(&doc).unwrap();
    assert_eq!(
        entry,
        NativeEntry {
            outbound_tag: None,
            balancer_tag: Some("l1".into())
        }
    );
    assert_eq!(
        document_selected(&doc, &entry).unwrap()["tag"],
        "norwayvless1"
    );
    let mut sweden = document();
    sweden["remarks"] = json!("Sweden");
    assert_eq!(document_entry(&sweden), Some(entry));

    let graph = import(&doc).unwrap();
    assert_eq!(graph.version, 1);
    assert_eq!(graph.selected_tag, "norwayvless1");
    assert_eq!(
        tags(&graph.outbounds),
        [
            "norwayvless1",
            "norwayhysteria1",
            "bridgenorwayvless1",
            "l1bridgevless1",
            "LOOP-L2",
            "LOOP-L1",
            "direct"
        ]
    );
    let routing = graph.routing.as_ref().unwrap();
    // Only loopback routes survive; the global "untrusted → direct" rule and the entry rule do not.
    assert_eq!(
        routing.rules,
        doc["routing"]["rules"].as_array().unwrap()[1..3]
    );
    assert_eq!(routing.balancers.len(), 3);
    assert_eq!(graph.policy.as_ref(), doc.get("policy"));
    assert_eq!(
        graph.burst_observatory.as_ref(),
        doc.get("burstObservatory")
    );
    assert!(!serde_json::to_string(&graph).unwrap().contains("untrusted"));
}

/// AT-04-002 / AT-02-002: bridge, loopback and balancer dependencies are compiled without tag
/// collisions; provider listeners, API, DNS, log paths and global direct rules are not inherited.
#[test]
fn compiled_graph_keeps_the_provider_semantics() {
    let doc = document();
    let before = doc.clone();
    let compiled = compiled(&import(&doc).unwrap());
    assert_eq!(doc, before, "source document unchanged");

    assert_eq!(compiled.entry, json!({"balancerTag": "vpnte-balancer:l1"}));
    let l1 = by_tag(&compiled.balancers, "vpnte-balancer:l1");
    assert_eq!(l1["fallbackTag"], "vpnte-source:LOOP-L2");
    assert_eq!(l1["selector"], json!(["proxy"]));
    assert_eq!(l1["strategy"], doc["routing"]["balancers"][0]["strategy"]);
    assert_eq!(
        by_tag(&compiled.balancers, "vpnte-balancer:l2")["fallbackTag"],
        "vpnte-source:bridgenorwayvless1"
    );

    let out = &compiled.outbounds;
    assert_eq!(out[0]["tag"], "proxy");
    assert_eq!(
        by_tag(out, "vpnte-source:bridgenorwayvless1")["streamSettings"]["sockopt"]["dialerProxy"],
        "vpnte-source:LOOP-L1"
    );
    assert_eq!(
        by_tag(out, "vpnte-source:LOOP-L1")["settings"]["inboundTag"],
        "vpnte-loop:L1-REROUTE"
    );
    assert!(compiled.rules.contains(&json!({"type": "field", "inboundTag": ["vpnte-loop:L1-REROUTE"], "balancerTag": "vpnte-balancer:bridge"})));
    assert!(!tags(out).iter().any(|t| t.ends_with(":unused")));

    // AT-04-006: fingerprint, mux and stream settings of the provider survive untouched.
    assert_eq!(
        out[0]["streamSettings"],
        doc["outbounds"][0]["streamSettings"]
    );
    assert_eq!(out[0]["mux"], doc["outbounds"][0]["mux"]);
    assert_eq!(compiled.policy.as_ref(), doc.get("policy"));
    let subjects = compiled.burst_observatory.as_ref().unwrap()["subjectSelector"]
        .as_array()
        .unwrap()
        .clone();
    assert!(
        subjects.contains(&json!("proxy"))
            && subjects.contains(&json!("vpnte-source:l1bridgevless1"))
    );
    assert!(compiled.observatory.is_none());

    let guard = compiled.rules.last().unwrap();
    assert_eq!(guard["outboundTag"], "block");
    let all = serde_json::to_string(&(&compiled.outbounds, &compiled.rules, &compiled.balancers))
        .unwrap();
    assert!(!all.contains("untrusted"));
}

/// AT-02-008 / AT-04-006 / AT-06-001: loopback routes stay ahead of the fail-closed guards
/// across repeated export → import rounds, and the export is stable (source tags, B15).
#[test]
fn loopback_routes_stay_ahead_of_guards_across_export_rounds() {
    let mut graph = import(&document()).unwrap();
    let mut previous_export: Option<Value> = None;
    for round in 0..3 {
        let compiled = compiled(&graph);
        let loops: Vec<&str> = compiled
            .outbounds
            .iter()
            .filter(|o| o["protocol"] == "loopback")
            .map(|o| o["settings"]["inboundTag"].as_str().unwrap())
            .collect();
        assert_eq!(loops.len(), 2, "round {round}");
        for inbound in &loops {
            let matching: Vec<&Value> = compiled
                .rules
                .iter()
                .filter(|r| {
                    r["inboundTag"]
                        .as_array()
                        .is_some_and(|t| t.contains(&json!(inbound)))
                })
                .collect();
            assert!(
                matching[0]["balancerTag"].is_string(),
                "round {round}: fallback shadowed by a blackhole"
            );
            assert!(matching[0].get("outboundTag").is_none());
            let guard = *matching.last().unwrap();
            assert_eq!(guard["type"], "field");
            assert_eq!(guard["outboundTag"], "block");
            assert!(
                loops
                    .iter()
                    .all(|l| guard["inboundTag"].as_array().unwrap().contains(&json!(l)))
            );
        }
        let exported = export_document(&graph, "Norway").unwrap();
        assert!(
            !exported.to_string().contains("vpnte-source:"),
            "export keeps the provider's tags"
        );
        if let Some(previous) = &previous_export {
            assert_eq!(
                &exported, previous,
                "round {round}: export grows or changes"
            );
        }
        graph = import(&exported).unwrap();
        previous_export = Some(exported);
    }
}

/// AT-04-002: the export is a complete Xray document without provider listeners, API, DNS,
/// log paths or the app's own field, and it imports back to the same connection.
#[test]
fn export_is_a_clean_document_that_imports_back() {
    let graph = import(&document()).unwrap();
    let exported = export_document(&graph, "Norway").unwrap();
    for key in ["inbounds", "api", "dns", "log"] {
        assert!(exported.get(key).is_none(), "{key}");
    }
    let text = exported.to_string();
    assert!(!text.contains(FIELD) && !text.contains("untrusted"));
    assert_eq!(exported["remarks"], "Norway");
    assert_eq!(
        exported["routing"]["rules"]
            .as_array()
            .unwrap()
            .last()
            .unwrap(),
        &json!({"type": "field", "network": "tcp,udp", "balancerTag": "l1"})
    );
    assert_eq!(
        by_tag(exported["outbounds"].as_array().unwrap(), EXPORT_BLOCK_TAG)["protocol"],
        "blackhole"
    );

    let restored = import(&exported).unwrap();
    let (before, after) = (compiled(&graph), compiled(&restored));
    assert_eq!(after.balancers.len(), before.balancers.len());
    let mux = |c: &CompiledGraph| -> Vec<Value> {
        c.outbounds
            .iter()
            .filter(|o| o["protocol"] == "vless")
            .map(|o| o["mux"].clone())
            .collect()
    };
    assert_eq!(mux(&after), mux(&before));
    assert!(
        after
            .outbounds
            .iter()
            .any(|o| o.pointer("/streamSettings/sockopt/dialerProxy").is_some())
    );
}

/// A single outbound without a document exports as a one-outbound document and keeps its mux.
#[test]
fn single_outbound_round_trips() {
    let graph = preserve(&vless("single", "192.0.2.1", None), None, None).unwrap();
    assert_eq!(
        graph.entry,
        NativeEntry {
            outbound_tag: Some("single".into()),
            balancer_tag: None
        }
    );
    assert!(graph.routing.is_none());
    let exported = export_document(&graph, "Single").unwrap();
    assert_eq!(tags(exported["outbounds"].as_array().unwrap()), ["single"]);
    let restored = import(&exported).unwrap();
    assert_eq!(
        compiled(&restored).outbounds[0]["mux"],
        compiled(&graph).outbounds[0]["mux"]
    );
}

/// AT-04-001: independent outbounds of one subscription never copy each other's credentials.
#[test]
fn independent_outbounds_keep_only_themselves() {
    let doc = json!({"outbounds": (0..100).map(|i| vless(&format!("node-{i}"), "192.0.2.1", None)).collect::<Vec<_>>()});
    assert!(document_entry(&doc).is_none());
    for outbound in doc["outbounds"].as_array().unwrap() {
        let graph = preserve(outbound, Some(&doc), None).unwrap();
        assert_eq!(graph.outbounds.len(), 1);
        assert_eq!(graph.outbounds[0]["tag"], outbound["tag"]);
    }
}

/// An untagged outbound becomes `proxy`.
#[test]
fn untagged_selected_outbound_is_named_proxy() {
    let mut raw = vless("x", "192.0.2.1", None);
    raw.as_object_mut().unwrap().remove("tag");
    let graph = preserve(&raw, Some(&json!({"outbounds": [raw.clone()]})), None).unwrap();
    assert_eq!(graph.selected_tag, "proxy");
    assert_eq!(tags(&graph.outbounds), ["proxy"]);
}

/// Missing and cyclic dependencies and a provider fallback that sends application traffic
/// directly are refused; the import then yields no profile.
#[test]
fn rejects_missing_cyclic_and_bypassing_graphs() {
    let raw = vless("selected", "192.0.2.1", Some("missing"));
    let err = preserve(&raw, None, None).unwrap_err();
    assert_eq!(err, NativeError::MissingDependency);
    assert!(
        regex::Regex::new("Missing.*dependency")
            .unwrap()
            .is_match(&err.to_string())
    );

    let mut selected = raw.clone();
    selected["streamSettings"] = json!({"sockopt": {"dialerProxy": "loop"}});
    let graph = NativeXray {
        version: 1,
        selected_tag: "selected".into(),
        entry: NativeEntry {
            outbound_tag: Some("selected".into()),
            balancer_tag: None,
        },
        outbounds: vec![
            selected.clone(),
            json!({"tag": "loop", "protocol": "loopback", "settings": {"inboundTag": "again"}}),
        ],
        routing: Some(NativeRouting {
            rules: vec![
                json!({"type": "field", "inboundTag": ["again"], "outboundTag": "selected"}),
            ],
            balancers: vec![],
        }),
        observatory: None,
        burst_observatory: None,
        policy: None,
    };
    let err = compile(&graph, &selected).unwrap_err();
    assert_eq!(err, NativeError::Cyclic);
    assert!(err.to_string().contains("Cyclic"));

    let mut doc = document();
    doc["routing"]["balancers"][0]["fallbackTag"] = json!("direct");
    let entry = NativeEntry {
        outbound_tag: None,
        balancer_tag: Some("l1".into()),
    };
    let err = preserve(&doc["outbounds"][0], Some(&doc), Some(entry)).unwrap_err();
    assert_eq!(err, NativeError::ApplicationBypass);
    assert!(err.to_string().contains("bypass VPN protection"));
    assert_eq!(import(&doc), Err(NativeError::ApplicationBypass));
    // One unsafe document does not affect another one (P-14 isolation).
    assert!(import(&document()).is_ok());
}

/// Local file references anywhere in a reachable outbound are refused before any engine runs;
/// `masterKeyLog` included (B14: the elevated engine would write TLS key logs to that path).
#[test]
fn rejects_local_file_references() {
    let mut doc = document();
    doc["outbounds"][0]["streamSettings"]["realitySettings"]["certificateFile"] =
        json!("C:/fake/cert.pem");
    assert_eq!(import(&doc), Err(NativeError::LocalFileReference));
    assert!(
        NativeError::LocalFileReference
            .to_string()
            .contains("external local file")
    );

    let mut doc = document();
    doc["outbounds"][1]["streamSettings"]["tlsSettings"]["MasterKeyLog"] =
        json!("C:/fake/keys.log");
    assert_eq!(import(&doc), Err(NativeError::LocalFileReference));

    let mut doc = document();
    doc["outbounds"][0]["streamSettings"] = json!({"network": "xhttp", "security": "tls",
        "xhttpSettings": {"path": "/x", "extra": {"downloadSettings": {"tlsSettings": {"masterKeyLog": "C:/fake/keys.log"}}}}});
    assert_eq!(import(&doc), Err(NativeError::LocalFileReference));

    // An empty value is not a reference; an unreachable outbound is not checked.
    let mut doc = document();
    doc["outbounds"][0]["streamSettings"]["realitySettings"]["certificateFile"] = json!("");
    doc["outbounds"][7]["streamSettings"] = json!({"tlsSettings": {"keyFile": "C:/fake/key.pem"}});
    assert!(import(&doc).is_ok());
}

/// A copied loop rule that matches by geo data is refused at import: the bundled Xray has no
/// `geoip.dat` / `geosite.dat` and fails at start ("failed to open geoip.dat", checked with
/// 26.11.9); `ext:` would also make it read a file. Dropped provider rules are not checked.
#[test]
fn rejects_loop_rules_that_need_geo_data() {
    for matcher in [
        json!({"ip": ["geoip:private"]}),
        json!({"domain": ["domain:example.com", "geosite:category-ads"]}),
        json!({"domain": "ext:custom.dat:ads"}),
        json!({"source": ["ext-ip:custom.dat:x"]}),
        json!({"domain": ["ext-domain:custom.dat:x"]}),
    ] {
        let mut doc = document();
        let rule = doc["routing"]["rules"][1].as_object_mut().expect("rule");
        rule.extend(matcher.as_object().expect("matcher").clone());
        assert_eq!(import(&doc), Err(NativeError::GeoData), "{matcher}");
    }
    assert!(NativeError::GeoData.to_string().contains("geo data"));

    // Case matters in Xray (`GEOSITE:x` is a plain domain), tags are names, and the dropped
    // global rule is never copied into the running config.
    let mut doc = document();
    doc["routing"]["rules"][1]["domain"] = json!(["GEOSITE:ads", "keyword:geosite:x"]);
    doc["routing"]["rules"][0]["domain"] = json!(["geosite:category-ads"]);
    assert!(import(&doc).is_ok());
}

/// New import-time checks: what the bundled Xray would refuse only at start.
#[test]
fn rejects_what_xray_refuses_to_build() {
    let mut multi_user = vless("multi", "192.0.2.1", None);
    multi_user["settings"]["vnext"][0]["users"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": UUID, "encryption": "none"}));
    assert_eq!(
        preserve(&multi_user, None, None),
        Err(NativeError::MultipleEndpoints)
    );
    let mut multi_node = vless("multi", "192.0.2.1", None);
    let node = multi_node["settings"]["vnext"][0].clone();
    multi_node["settings"]["vnext"]
        .as_array_mut()
        .unwrap()
        .push(node);
    assert_eq!(
        preserve(&multi_node, None, None),
        Err(NativeError::MultipleEndpoints)
    );
    let servers = json!({"tag": "t", "protocol": "trojan", "settings": {"servers": [
        {"address": "192.0.2.1", "port": 443, "password": "SYNTHETIC"}, {"address": "192.0.2.2", "port": 443, "password": "SYNTHETIC"}]}});
    assert_eq!(
        preserve(&servers, None, None),
        Err(NativeError::MultipleEndpoints)
    );
    // Xray wants exactly one: an empty list or a node without users is refused as well.
    let mut no_servers = trojan("t", json!({}));
    no_servers["settings"]["servers"] = json!([]);
    let mut no_users = vless("v", "192.0.2.1", None);
    no_users["settings"]["vnext"][0]
        .as_object_mut()
        .unwrap()
        .remove("users");
    let mut no_nodes = vless("v", "192.0.2.1", None);
    no_nodes["settings"]["vnext"] = json!([]);
    for outbound in [no_servers, no_users, no_nodes] {
        assert_eq!(
            preserve(&outbound, None, None),
            Err(NativeError::MultipleEndpoints),
            "{outbound}"
        );
    }

    let tls = |extra: Value| preserve(&trojan("t", extra), None, None);
    assert_eq!(
        tls(json!({"allowInsecure": true})),
        Err(NativeError::InsecureWithoutPin)
    );
    assert!(tls(json!({"allowInsecure": true, "pinnedPeerCertSha256": "ab".repeat(32)})).is_ok());
    assert!(tls(json!({"allowInsecure": false})).is_ok());

    let reserved = json!({"tag": EXPORT_BLOCK_TAG, "protocol": "freedom"});
    let mut entry = vless("entry", "192.0.2.1", Some(EXPORT_BLOCK_TAG));
    entry["mux"] = json!({"enabled": false});
    let doc = json!({"outbounds": [entry.clone(), reserved]});
    assert_eq!(
        preserve(&entry, Some(&doc), None),
        Err(NativeError::ReservedTag)
    );
}

/// Untrusted chains are walked recursively: an absurd depth is refused, not a stack overflow.
#[test]
fn refuses_absurdly_deep_chains() {
    let n = 200;
    let outbounds: Vec<Value> = (0..n)
        .map(|i| {
            let dialer = (i + 1 < n).then(|| format!("hop-{}", i + 1));
            vless(&format!("hop-{i}"), "192.0.2.1", dialer.as_deref())
        })
        .collect();
    let doc = json!({"outbounds": outbounds});
    assert_eq!(
        preserve(&doc["outbounds"][0], Some(&doc), None),
        Err(NativeError::TooDeep)
    );
}

/// Stored graphs are read like the old reader (engine-selection vectors: version 2 → error).
#[test]
fn decode_validates_like_the_old_reader() {
    let minimal = json!({"version": 1, "selectedTag": "entry", "entry": {"outboundTag": "entry"}, "outbounds": []});
    let graph = decode(&minimal).unwrap();
    assert_eq!(selected_outbound(&graph), Err(NativeError::MissingSelected));
    assert_eq!(
        compile(&graph, &json!({})),
        Err(NativeError::MissingDependency)
    );
    for broken in [
        json!({"version": 2, "selectedTag": "entry", "entry": {"outboundTag": "entry"}, "outbounds": []}),
        json!({"version": 1, "selectedTag": "", "entry": {"outboundTag": "entry"}, "outbounds": []}),
        json!({"version": 1, "entry": {"outboundTag": "entry"}, "outbounds": []}),
        json!({"version": 1, "selectedTag": "entry", "outbounds": []}),
        json!({"version": 1, "selectedTag": "entry", "entry": {}, "outbounds": {}}),
        json!(null),
    ] {
        assert_eq!(
            decode(&broken),
            Err(NativeError::InvalidProfile),
            "{broken}"
        );
    }
    assert!(
        NativeError::InvalidProfile
            .to_string()
            .contains("Invalid preserved Xray profile")
    );
}

/// The stored JSON keeps the Electron shape (camelCase, absent optionals) and round-trips.
#[test]
fn stored_shape_round_trips() {
    let graph = import(&document()).unwrap();
    let stored = serde_json::to_value(&graph).unwrap();
    let keys: Vec<&str> = stored
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "version",
            "selectedTag",
            "entry",
            "outbounds",
            "routing",
            "burstObservatory",
            "policy"
        ]
    );
    assert_eq!(stored["entry"]["balancerTag"], "l1");
    assert_eq!(decode(&stored).unwrap(), graph);
}

/// Only an unconditional last rule describes a whole document.
#[test]
fn document_entry_accepts_only_an_unconditional_last_rule() {
    let with_last = |rule: Value| {
        document_entry(
            &json!({"routing": {"rules": [{"type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "x"}, rule]}}),
        )
    };
    let out = |t: &str| {
        Some(NativeEntry {
            outbound_tag: Some(t.into()),
            balancer_tag: None,
        })
    };
    assert_eq!(
        with_last(json!({"type": "field", "outboundTag": "proxy"})),
        out("proxy")
    );
    assert_eq!(
        with_last(json!({"type": "field", "network": "udp,tcp", "outboundTag": "proxy"})),
        out("proxy")
    );
    assert_eq!(
        with_last(
            json!({"type": "field", "network": "tcp,udp", "ruleTag": "all", "outboundTag": "proxy"})
        ),
        out("proxy")
    );
    assert_eq!(
        with_last(json!({"type": "field", "network": "tcp", "outboundTag": "proxy"})),
        None
    );
    assert_eq!(
        with_last(json!({"type": "field", "domain": ["example.com"], "outboundTag": "proxy"})),
        None
    );
    assert_eq!(
        with_last(json!({"type": "field", "network": "tcp,udp"})),
        None
    );
    assert_eq!(document_entry(&json!({"outbounds": []})), None);
}

/// Every error key exists in both languages and `profiles.xrayNative` holds nothing else.
#[test]
fn locale_fragments_cover_every_message() {
    let native = [
        NativeError::InvalidProfile,
        NativeError::MissingSelected,
        NativeError::DuplicateTag,
        NativeError::BadBalancerTag,
        NativeError::MissingBalancer,
        NativeError::EmptyBalancer,
        NativeError::MissingDependency,
        NativeError::ApplicationBypass,
        NativeError::Cyclic,
        NativeError::MissingLoopbackRoute,
        NativeError::LoopbackRouteNoDestination,
        NativeError::UnsupportedProtocol,
        NativeError::NoEntry,
        NativeError::SelectedOutsideGraph,
        NativeError::LocalFileReference,
        NativeError::MultipleEndpoints,
        NativeError::InsecureWithoutPin,
        NativeError::ReservedTag,
        NativeError::TooDeep,
        NativeError::GeoData,
    ];
    let used: std::collections::BTreeSet<String> =
        native.iter().map(|e| e.msg().key.into_owned()).collect();
    for key in &used {
        crate::test_locales::assert_localized(key);
    }
    let own: std::collections::BTreeSet<String> =
        crate::test_locales::package_keys("profiles-native")
            .into_iter()
            .filter(|k| k.starts_with("profiles.xrayNative."))
            .collect();
    assert_eq!(used, own, "unused locale keys");
}

/// Runs `xray run -test` on `config` (over stdin, as the engine does) when the bundled binary
/// exists; `None` = binary absent, test skipped.
fn xray_check(config: &Value) -> Option<Result<(), String>> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let exe = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../resources/xray.exe"
    ));
    if !exe.exists() {
        return None;
    }
    let mut cmd = Command::new(exe);
    cmd.args(["run", "-test", "-config", "stdin:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().expect("spawn xray");
    let readers: Vec<_> = [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    .map(|mut pipe| {
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = pipe.read_to_string(&mut text);
            text
        })
    })
    .collect();
    let mut stdin = child.stdin.take().expect("stdin");
    stdin
        .write_all(config.to_string().as_bytes())
        .expect("write config");
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait xray") {
            break Some(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let output: String = readers
        .into_iter()
        .map(|r| r.join().unwrap_or_default())
        .collect();
    Some(match status {
        Some(status) if status.success() => Ok(()),
        Some(_) => Err(output),
        None => Err(format!("timeout: {output}")),
    })
}

/// The compiled graph inside a minimal runtime config shaped like the engine's.
fn runtime_config(c: &CompiledGraph) -> Value {
    let mut entry_rule = json!({"type": "field", "inboundTag": ["in"]});
    entry_rule
        .as_object_mut()
        .unwrap()
        .extend(c.entry.as_object().unwrap().clone());
    let mut outbounds = c.outbounds.clone();
    outbounds.push(json!({"tag": "direct", "protocol": "freedom"}));
    outbounds.push(json!({"tag": "block", "protocol": "blackhole"}));
    let mut rules = vec![entry_rule];
    rules.extend(c.rules.iter().cloned());
    rules.push(json!({"type": "field", "network": "tcp,udp", "outboundTag": "block"}));
    let mut config = json!({
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": 50123, "protocol": "socks", "settings": {"udp": true}}],
        "outbounds": outbounds,
        "routing": {"rules": rules, "balancers": c.balancers}
    });
    if let Some(observatory) = &c.observatory {
        config["observatory"] = observatory.clone();
    }
    if let Some(burst) = &c.burst_observatory {
        config["burstObservatory"] = burst.clone();
    }
    if let Some(policy) = &c.policy {
        config["policy"] = policy.clone();
    }
    config
}

/// AT-04-002 (real binary): the full synthetic VLESS/Hysteria/bridge graph, its re-import and
/// the exported document itself pass the bundled Xray's config check.
#[test]
fn bundled_xray_accepts_compiled_and_exported_graphs() {
    let graph = import(&document()).unwrap();
    let exported = export_document(&graph, "Norway").unwrap();
    let restored = import(&exported).unwrap();
    for (what, config) in [
        ("compiled", runtime_config(&compiled(&graph))),
        ("re-imported", runtime_config(&compiled(&restored))),
        ("exported", exported),
    ] {
        match xray_check(&config) {
            None => return,
            Some(result) => assert_eq!(result, Ok(()), "{what}: {config}"),
        }
    }
    // The check is live: a config Xray cannot build is refused.
    let broken = json!({"outbounds": [{"tag": "x", "protocol": "no-such-protocol"}]});
    assert!(xray_check(&broken).is_some_and(|r| r.is_err()));
}

/// Review regression: the bundled Xray refuses `allowInsecure: true` even next to a pin, so
/// the compiled graph keeps only the pin (any depth); the source graph is not changed.
#[test]
fn pinned_insecure_tls_compiles_to_the_pin_alone() {
    let pin = "ab".repeat(32);
    let mut outbound = trojan(
        "t",
        json!({"allowInsecure": true, "pinnedPeerCertSha256": pin}),
    );
    let graph = preserve(&outbound, None, None).unwrap();
    let c = compiled(&graph);
    let tls = &c.outbounds[0]["streamSettings"]["tlsSettings"];
    assert!(tls.get("allowInsecure").is_none());
    assert_eq!(tls["pinnedPeerCertSha256"], json!(pin));
    assert_eq!(
        graph.outbounds[0], outbound,
        "stored graph keeps the source"
    );
    if let Some(result) = xray_check(&runtime_config(&c)) {
        assert_eq!(result, Ok(()));
    }

    outbound["streamSettings"]["xhttpSettings"] = json!({"extra": {"downloadSettings":
        {"tlsSettings": {"allowInsecure": true, "pinnedPeerCertSha256": pin}}}});
    let c = compiled(&preserve(&outbound, None, None).unwrap());
    assert!(
        !serde_json::to_string(&c.outbounds)
            .unwrap()
            .contains("allowInsecure")
    );
}

/// Review regression: a balancer whose prefixes match nothing still falls back (Xray refuses an
/// empty selector list), and an observatory a balancer depends on survives even when it watches
/// nothing reachable (Xray: "not all dependencies are resolved").
#[test]
fn balancers_keep_what_xray_needs_to_start() {
    let doc = json!({
        "outbounds": [vless("backup", "192.0.2.1", None), vless("global", "192.0.2.2", None)],
        "routing": {
            "balancers": [{"tag": "b", "selector": ["missing-"], "fallbackTag": "backup"}],
            "rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "b"}]
        },
        "observatory": {"subjectSelector": ["global"], "probeUrl": "https://example.com/", "probeInterval": "1m"}
    });
    let entry = document_entry(&doc).unwrap();
    let graph = preserve(&doc["outbounds"][0], Some(&doc), Some(entry)).unwrap();
    let c = compiled(&graph);
    assert_eq!(c.balancers[0]["selector"], json!(["vpnte-balancer:b"]));
    assert_eq!(c.balancers[0]["fallbackTag"], "proxy");
    assert_eq!(
        c.observatory.as_ref().unwrap()["subjectSelector"],
        json!([])
    );
    let exported = export_document(&graph, "Backup").unwrap();
    assert_eq!(exported["observatory"], doc["observatory"]);
    for config in [runtime_config(&c), exported] {
        if let Some(result) = xray_check(&config) {
            assert_eq!(result, Ok(()), "{config}");
        }
    }

    // Without balancers an observatory that watches nothing reachable is still dropped.
    let single = preserve(&doc["outbounds"][0], Some(&doc), None).unwrap();
    assert!(single.observatory.is_some() && compiled(&single).observatory.is_none());
    assert!(
        export_document(&single, "Backup")
            .unwrap()
            .get("observatory")
            .is_none()
    );
}

/// Review regression: a selector prefix that also matches the export's blackhole (`vpn` →
/// `vpnte-block`) is exported as the exact tags it selects, so another client's Xray never
/// balances onto the guard; later rounds keep the document unchanged.
#[test]
fn export_selectors_never_pick_the_guard_blackhole() {
    let doc = json!({
        "outbounds": [vless("vpn-de-1", "192.0.2.1", None), vless("vpn-nl-2", "192.0.2.2", None),
                      {"tag": "LOOP", "protocol": "loopback", "settings": {"inboundTag": "L"}}],
        "routing": {
            "balancers": [{"tag": "b", "selector": ["vpn"], "fallbackTag": "LOOP"}],
            "rules": [{"type": "field", "inboundTag": ["L"], "outboundTag": "vpn-nl-2"},
                      {"type": "field", "network": "tcp,udp", "balancerTag": "b"}]
        },
        "burstObservatory": {"subjectSelector": ["vpn"],
                             "pingConfig": {"destination": "https://example.com/", "interval": "1m", "sampling": 1, "timeout": "5s"}}
    });
    let exported = export_document(&import(&doc).unwrap(), "VPN").unwrap();
    assert_eq!(
        exported["routing"]["balancers"][0]["selector"],
        json!(["vpn-de-1", "vpn-nl-2"])
    );
    let again = export_document(&import(&exported).unwrap(), "VPN").unwrap();
    assert_eq!(again, exported);
    if let Some(result) = xray_check(&exported) {
        assert_eq!(result, Ok(()));
    }
}

/// QUIC policy through a native graph (old tunControllerConfig.test.ts:366-402): the provider's
/// mux decides whether UDP/443 must be refused.
#[test]
fn mux_policy_decides_udp443() {
    let with_mux = |muxes: &[Value]| {
        let outbounds = muxes
            .iter()
            .enumerate()
            .map(|(i, mux)| {
                let mut o = vless(&format!("n{i}"), "192.0.2.1", None);
                o["mux"] = mux.clone();
                o
            })
            .collect();
        mux_rejects_udp443(&NativeXray {
            version: 1,
            selected_tag: "n0".into(),
            entry: NativeEntry {
                outbound_tag: Some("n0".into()),
                balancer_tag: None,
            },
            outbounds,
            routing: None,
            observatory: None,
            burst_observatory: None,
            policy: None,
        })
    };
    assert!(with_mux(&[json!({"enabled": true})]));
    assert!(with_mux(&[
        json!({"enabled": true, "xudpProxyUDP443": "reject"})
    ]));
    assert!(with_mux(&[
        json!({"enabled": true, "xudpConcurrency": -1, "xudpProxyUDP443": "reject"})
    ]));
    assert!(!with_mux(&[
        json!({"enabled": true, "xudpProxyUDP443": "allow"})
    ]));
    assert!(!with_mux(&[
        json!({"enabled": true, "xudpProxyUDP443": "skip"})
    ]));
    assert!(!with_mux(&[
        json!({"enabled": false, "xudpProxyUDP443": "reject"})
    ]));
    assert!(with_mux(&[
        json!({"enabled": true, "xudpProxyUDP443": "allow"}),
        json!({"enabled": true})
    ]));
}

/// `{:?}` of a compiled graph never shows credentials.
#[test]
fn compiled_debug_hides_credentials() {
    let shown = format!("{:?}", compiled(&import(&document()).unwrap()));
    assert!(
        !shown.contains(UUID) && !shown.contains(PUBLIC_KEY) && !shown.contains("SYNTHETIC_AUTH"),
        "{shown}"
    );
}
