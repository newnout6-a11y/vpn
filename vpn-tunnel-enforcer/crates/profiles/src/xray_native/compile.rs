//! Compiling a validated graph for the engine: namespaced tags, loopback routes, the fail-closed
//! guard.
use serde_json::{Value, json};

use super::reach::{DEPENDENCY_POINTERS, Reach, reach};
use super::{
    BALANCER_PREFIX, ENGINE_BLOCK_TAG, LOOP_PREFIX, NativeError, PROXY_TAG, SOURCE_PREFIX,
};
use super::{keep_inbounds, non_empty_str, protocol, retag, strings, tag, truthy};
use crate::model::NativeXray;

/// The graph reachable from the entry, with namespaced tags, ready for the engine config:
/// selected outbound → `proxy`, other outbound `T` → `vpnte-source:T`, balancer `B` →
/// `vpnte-balancer:B`, loopback inbound `L` → `vpnte-loop:L`.
#[derive(Clone, PartialEq)]
pub struct CompiledGraph {
    /// `proxy` first, then the other reachable outbounds in dependency (post) order.
    pub outbounds: Vec<Value>,
    /// Loopback routes in the provider's source order, then the fail-closed guard to `block`.
    pub rules: Vec<Value>,
    pub balancers: Vec<Value>,
    /// `{"outboundTag": …}` or `{"balancerTag": …}` (compiled name) for the app's entry rule.
    pub entry: Value,
    pub observatory: Option<Value>,
    pub burst_observatory: Option<Value>,
    pub policy: Option<Value>,
}

/// Outbounds carry credentials and probe URLs: `{:?}` shows only the shape.
impl std::fmt::Debug for CompiledGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledGraph")
            .field("outbounds", &self.outbounds.len())
            .field("rules", &self.rules.len())
            .field("balancers", &self.balancers.len())
            .field("entry", &self.entry)
            .finish_non_exhaustive()
    }
}

/// Validates the graph and compiles the part reachable from its entry with namespaced tags.
/// `primary` replaces the stored selected outbound (the engine passes it with a resolved address).
pub fn compile(graph: &NativeXray, primary: &Value) -> Result<CompiledGraph, NativeError> {
    let reach = reach(graph, primary)?;
    let selected = graph.selected_tag.as_str();
    let mapped = |t: &str| {
        if t == selected {
            PROXY_TAG.to_owned()
        } else {
            format!("{SOURCE_PREFIX}{t}")
        }
    };
    let mapped_balancer = |t: &str| format!("{BALANCER_PREFIX}{t}");
    let mapped_loop = |t: &str| format!("{LOOP_PREFIX}{t}");

    let mut outbounds = Vec::with_capacity(reach.visited.len());
    for &i in &reach.visited {
        let (t, source) = reach.outbounds[i];
        let mut outbound = if t == selected {
            primary.clone()
        } else {
            source.clone()
        };
        outbound
            .as_object_mut()
            .ok_or(NativeError::InvalidProfile)?
            .insert("tag".into(), Value::String(mapped(t)));
        if protocol(&outbound) == "loopback" {
            retag(&mut outbound, "/settings/inboundTag", mapped_loop);
        }
        for pointer in DEPENDENCY_POINTERS {
            retag(&mut outbound, pointer, mapped);
        }
        drop_allow_insecure(&mut outbound);
        outbounds.push(outbound);
    }
    if let Some(pos) = outbounds.iter().position(|o| tag(o) == Some(PROXY_TAG)) {
        let proxy = outbounds.remove(pos);
        outbounds.insert(0, proxy);
    }

    // Routing priority stays the provider's source order, including guards restored by an import.
    let loops = reach.loop_inbounds();
    let mut rules = Vec::new();
    for (k, rule) in reach.rules.iter().enumerate() {
        if !reach.loop_rules[k] {
            continue;
        }
        let mut copy = rule.clone();
        keep_inbounds(&mut copy, &loops, mapped_loop);
        retag(&mut copy, "/outboundTag", mapped);
        retag(&mut copy, "/balancerTag", mapped_balancer);
        rules.push(copy);
    }
    // Conditional loopback routes must fail closed instead of falling into the primary.
    if !loops.is_empty() {
        let inbounds: Vec<String> = loops.iter().map(|t| mapped_loop(t)).collect();
        rules.push(
            json!({"type": "field", "inboundTag": inbounds, "outboundTag": ENGINE_BLOCK_TAG}),
        );
    }

    let balancers = reach
        .used_balancers
        .iter()
        .map(|&b| {
            let (t, source) = reach.balancers[b];
            // Exact expanded tags keep the selector's meaning despite the namespacing. Xray refuses
            // an empty list: the balancer's own compiled name matches no outbound, so a balancer
            // whose prefixes match nothing keeps falling back as it did at the provider.
            let mut selector: Vec<Value> = reach
                .candidates(source)
                .into_iter()
                .filter(|&i| reach.seen[i])
                .map(|i| Value::String(mapped(reach.outbounds[i].0)))
                .collect();
            if selector.is_empty() {
                selector.push(Value::String(mapped_balancer(t)));
            }
            let mut copy = source.clone();
            if let Some(map) = copy.as_object_mut() {
                map.insert("tag".into(), Value::String(mapped_balancer(t)));
                map.insert("selector".into(), Value::Array(selector));
            }
            retag(&mut copy, "/fallbackTag", mapped);
            copy
        })
        .collect();

    let entry = match non_empty_str(graph.entry.outbound_tag.as_deref()) {
        Some(out) => json!({"outboundTag": mapped(out)}),
        None => {
            json!({"balancerTag": mapped_balancer(graph.entry.balancer_tag.as_deref().unwrap_or_default())})
        }
    };
    let observe = |source: Option<&Value>| {
        let source = source?;
        let subjects = observed(&reach, source)?
            .into_iter()
            .map(|t| Value::String(mapped(t)))
            .collect();
        let mut copy = source.clone();
        copy.as_object_mut()?
            .insert("subjectSelector".into(), Value::Array(subjects));
        Some(copy)
    };
    Ok(CompiledGraph {
        outbounds,
        rules,
        balancers,
        entry,
        observatory: observe(graph.observatory.as_ref()),
        burst_observatory: observe(graph.burst_observatory.as_ref()),
        policy: graph.policy.clone(),
    })
}

/// Reachable outbounds an observatory watches (its `subjectSelector` prefixes), in visit order;
/// `None` when it has nothing to do in this graph. A graph with balancers keeps it even when it
/// watches nothing reachable: Xray refuses to start a balancer with a fallback or a `least*`
/// strategy without an observatory.
pub(super) fn observed<'g>(reach: &Reach<'g>, observatory: &Value) -> Option<Vec<&'g str>> {
    if !truthy(observatory) {
        return None;
    }
    let prefixes = strings(observatory.get("subjectSelector"));
    let subjects: Vec<&str> = reach
        .visited
        .iter()
        .map(|&i| reach.outbounds[i].0)
        .filter(|t| prefixes.iter().any(|p| t.starts_with(p)))
        .collect();
    (!subjects.is_empty() || !reach.used_balancers.is_empty()).then_some(subjects)
}

/// The bundled Xray refuses `allowInsecure: true` even next to a pin. Import accepted it only
/// with `pinnedPeerCertSha256` (replaces the CA check on its own) or `verifyPeerCertByName`
/// (keeps the CA check against those names), so the flag is dropped.
fn drop_allow_insecure(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(Value::Object(tls)) = map.get_mut("tlsSettings")
                && tls.get("allowInsecure") == Some(&Value::Bool(true))
            {
                tls.remove("allowInsecure");
            }
            map.values_mut().for_each(drop_allow_insecure);
        }
        Value::Array(items) => items.iter_mut().for_each(drop_allow_insecure),
        _ => {}
    }
}
