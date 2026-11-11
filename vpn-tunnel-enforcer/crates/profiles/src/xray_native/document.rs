//! Provider documents in and out: the entry of a whole document, keeping an outbound with what
//! it reaches, and the standalone export with the provider's own tags.
use std::collections::HashSet;

use serde_json::{Map, Value, json};

use super::compile::observed;
use super::reach::{DEPENDENCY_POINTERS, reach};
use super::{EXPORT_BLOCK_TAG, NativeError, PROXY_TAG, SELECTABLE_PROTOCOLS};
use super::{
    keep_inbounds, list_of, non_empty, non_empty_str, selected_outbound, strings, tag, truthy,
};
use crate::model::{NativeEntry, NativeRouting, NativeXray};

/// Entry of a whole provider document: only an unconditional terminal rule (the last one, with
/// keys ⊆ `type, network, outboundTag, balancerTag, ruleTag` and network absent or TCP+UDP) can
/// describe the complete connection.
pub fn document_entry(doc: &Value) -> Option<NativeEntry> {
    let rule = doc
        .pointer("/routing/rules")?
        .as_array()?
        .last()?
        .as_object()?;
    let allowed = ["type", "network", "outboundTag", "balancerTag", "ruleTag"];
    if rule.keys().any(|key| !allowed.contains(&key.as_str())) {
        return None;
    }
    if rule.get("network").is_some_and(truthy)
        && !matches!(
            rule.get("network").and_then(Value::as_str),
            Some("tcp,udp" | "udp,tcp")
        )
    {
        return None;
    }
    if let Some(out) = non_empty(rule.get("outboundTag")) {
        return Some(NativeEntry {
            outbound_tag: Some(out.to_owned()),
            balancer_tag: None,
        });
    }
    non_empty(rule.get("balancerTag")).map(|bal| NativeEntry {
        outbound_tag: None,
        balancer_tag: Some(bal.to_owned()),
    })
}

/// The outbound a document import presents as the profile: the first VLESS/VMess/Trojan/SS
/// outbound that is the entry outbound or matched by the entry balancer's selector.
pub fn document_selected<'a>(doc: &'a Value, entry: &NativeEntry) -> Option<&'a Value> {
    let entry_outbound = entry.outbound_tag.as_deref().filter(|t| !t.is_empty());
    let selector: Vec<&str> = entry
        .balancer_tag
        .as_deref()
        .and_then(|bal| {
            doc.pointer("/routing/balancers")?
                .as_array()?
                .iter()
                .find(|b| tag(b) == Some(bal))
        })
        .map(|b| strings(b.get("selector")))
        .unwrap_or_default();
    doc.get("outbounds")?.as_array()?.iter().find(|o| {
        let protocol_ok = o
            .get("protocol")
            .and_then(Value::as_str)
            .is_some_and(|p| SELECTABLE_PROTOCOLS.contains(&p));
        let own = tag(o).unwrap_or("");
        protocol_ok && (entry_outbound == Some(own) || selector.iter().any(|p| own.starts_with(p)))
    })
}

/// Keeps a provider outbound as a graph: the outbound itself plus, when the entry or its own
/// dialers need them, the document's outbounds, routes and balancers. Only what the entry can
/// reach is kept, so independent outbounds of one subscription never copy each other's
/// credentials. `entry` defaults to the selected outbound itself.
pub fn preserve(
    selected: &Value,
    doc: Option<&Value>,
    entry: Option<NativeEntry>,
) -> Result<NativeXray, NativeError> {
    let selected_tag = tag(selected);
    let raw_tag = selected_tag.unwrap_or(PROXY_TAG).to_owned();
    let mut raw = selected.clone();
    raw.as_object_mut()
        .ok_or(NativeError::InvalidProfile)?
        .insert("tag".into(), Value::String(raw_tag.clone()));
    let entry = entry.unwrap_or_else(|| NativeEntry {
        outbound_tag: Some(raw_tag.clone()),
        balancer_tag: None,
    });
    let needs_graph = non_empty_str(entry.balancer_tag.as_deref()).is_some()
        || non_empty_str(entry.outbound_tag.as_deref()).is_some_and(|t| t != raw_tag)
        || DEPENDENCY_POINTERS
            .iter()
            .any(|p| non_empty(raw.pointer(p)).is_some());
    let doc_outbounds = doc
        .and_then(|d| d.get("outbounds"))
        .and_then(Value::as_array);
    let outbounds = match doc_outbounds.filter(|_| needs_graph) {
        Some(list) => list
            .iter()
            .map(|o| {
                let is_selected = std::ptr::eq(o, selected)
                    || tag(o) == Some(raw_tag.as_str())
                    || (selected_tag.is_none() && (list.len() == 1 || o == selected));
                if is_selected { raw.clone() } else { o.clone() }
            })
            .collect(),
        None => vec![raw.clone()],
    };
    let doc_field = |key: &str| doc.and_then(|d| d.get(key)).filter(|v| truthy(v)).cloned();
    let doc_routing = doc.and_then(|d| d.get("routing")).filter(|v| truthy(v));
    let mut graph = NativeXray {
        version: 1,
        selected_tag: raw_tag,
        entry,
        outbounds,
        routing: doc_routing.map(|r| NativeRouting {
            rules: list_of(r, "rules"),
            balancers: list_of(r, "balancers"),
        }),
        observatory: doc_field("observatory"),
        burst_observatory: doc_field("burstObservatory"),
        policy: doc_field("policy"),
    };

    let (keep, loops, balancers) = {
        let reach = reach(&graph, &raw)?;
        let keep: HashSet<String> = reach
            .visited
            .iter()
            .map(|&i| reach.outbounds[i].0.to_owned())
            .collect();
        let loops: Vec<String> = reach
            .loop_inbounds()
            .into_iter()
            .map(str::to_owned)
            .collect();
        let balancers: HashSet<String> = reach
            .used_balancers
            .iter()
            .map(|&b| reach.balancers[b].0.to_owned())
            .collect();
        (keep, loops, balancers)
    };
    graph
        .outbounds
        .retain(|o| tag(o).is_some_and(|t| keep.contains(t)));
    if let Some(routing) = &mut graph.routing {
        routing.rules.retain(|r| {
            strings(r.get("inboundTag"))
                .iter()
                .any(|t| loops.iter().any(|l| l == t))
        });
        routing
            .balancers
            .retain(|b| tag(b).is_some_and(|t| balancers.contains(t)));
    }
    Ok(graph)
}

/// The validated graph as a standalone Xray document for sharing: the provider's own tags (so
/// repeated export → import rounds stay stable), only what the entry reaches, never provider
/// listeners, API, DNS, log paths or the app's own fields.
pub fn export_document(graph: &NativeXray, name: &str) -> Result<Value, NativeError> {
    let primary = selected_outbound(graph)?;
    let reach = reach(graph, primary)?;
    let selected = graph.selected_tag.as_str();
    let mut outbounds = vec![primary.clone()];
    for (i, &(t, outbound)) in reach.outbounds.iter().enumerate() {
        if reach.seen[i] && t != selected {
            outbounds.push(outbound.clone());
        }
    }

    let loops = reach.loop_inbounds();
    let mut rules: Vec<Value> = Vec::new();
    for (k, rule) in reach.rules.iter().enumerate() {
        if reach.loop_rules[k] {
            let mut copy = rule.clone();
            keep_inbounds(&mut copy, &loops, str::to_owned);
            rules.push(copy);
        }
    }
    if !loops.is_empty() {
        let guard = json!({"type": "field", "inboundTag": loops, "outboundTag": EXPORT_BLOCK_TAG});
        // A re-imported export already carries the guard; do not stack another one per round.
        if rules.last() != Some(&guard) {
            rules.push(guard);
        }
        if !reach.is_visited(EXPORT_BLOCK_TAG) {
            outbounds.push(json!({"tag": EXPORT_BLOCK_TAG, "protocol": "blackhole"}));
        }
    }
    let mut entry_rule = json!({"type": "field", "network": "tcp,udp"});
    match non_empty_str(graph.entry.outbound_tag.as_deref()) {
        Some(out) => entry_rule["outboundTag"] = json!(out),
        None => {
            entry_rule["balancerTag"] =
                json!(graph.entry.balancer_tag.as_deref().unwrap_or_default())
        }
    }
    rules.push(entry_rule);

    let mut routing = Map::new();
    routing.insert("rules".into(), Value::Array(rules));
    // In another client's Xray a prefix such as `vpn` would also pick the guard's blackhole:
    // such a selector is written as the exact tags it selects here.
    let guarded = outbounds.iter().any(|o| tag(o) == Some(EXPORT_BLOCK_TAG));
    let balancers: Vec<Value> = (0..reach.balancers.len())
        .filter(|b| reach.used_balancers.contains(b))
        .map(|b| {
            let source = reach.balancers[b].1;
            let exact: Vec<&str> = reach
                .candidates(source)
                .into_iter()
                .map(|i| reach.outbounds[i].0)
                .collect();
            let mut copy = source.clone();
            if guarded
                && !exact.is_empty()
                && strings(source.get("selector"))
                    .iter()
                    .any(|p| EXPORT_BLOCK_TAG.starts_with(p))
                && let Some(map) = copy.as_object_mut()
            {
                map.insert("selector".into(), json!(exact));
            }
            copy
        })
        .collect();
    if !balancers.is_empty() {
        routing.insert("balancers".into(), Value::Array(balancers));
    }
    let mut doc = Map::new();
    doc.insert("remarks".into(), json!(name));
    doc.insert("outbounds".into(), Value::Array(outbounds));
    doc.insert("routing".into(), Value::Object(routing));
    for (key, value) in [
        ("observatory", &graph.observatory),
        ("burstObservatory", &graph.burst_observatory),
    ] {
        if let Some(value) = value.as_ref().filter(|v| observed(&reach, v).is_some()) {
            doc.insert(key.into(), value.clone());
        }
    }
    if let Some(policy) = &graph.policy {
        doc.insert("policy".into(), policy.clone());
    }
    Ok(Value::Object(doc))
}
