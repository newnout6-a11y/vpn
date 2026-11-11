//! Walking a graph from its entry: reachability, dependency order, cycles and the import-time
//! safety checks of every reachable outbound.
use std::collections::{HashMap, HashSet};

use serde_json::Value;

use super::{BYPASS_PROTOCOLS, EXPORT_BLOCK_TAG, GRAPH_PROTOCOLS, NativeError};
use super::{non_empty, non_empty_str, protocol, routes_inbound, strings, tag, truthy};
use crate::model::NativeXray;

/// Fields that name another outbound the hop dials through (split XHTTP downloads included:
/// an unmapped tag there would point at nothing once the graph is namespaced).
pub(super) const DEPENDENCY_POINTERS: [&str; 4] = [
    "/streamSettings/sockopt/dialerProxy",
    "/proxySettings/tag",
    "/streamSettings/xhttpSettings/downloadSettings/sockopt/dialerProxy",
    "/streamSettings/xhttpSettings/extra/downloadSettings/sockopt/dialerProxy",
];

/// Deeper chains are refused (see [`NativeError::TooDeep`]).
const MAX_DEPTH: usize = 64;

/// The part of a graph reachable from its entry, in source tags.
pub(super) struct Reach<'g> {
    /// Outbounds in source order with their tags.
    pub(super) outbounds: Vec<(&'g str, &'g Value)>,
    by_tag: HashMap<&'g str, usize>,
    pub(super) balancers: Vec<(&'g str, &'g Value)>,
    pub(super) rules: &'g [Value],
    /// Outbound indices in post order (dependencies first).
    pub(super) visited: Vec<usize>,
    pub(super) seen: Vec<bool>,
    app_seen: Vec<bool>,
    active: Vec<bool>,
    /// Balancer indices in first-use order.
    pub(super) used_balancers: Vec<usize>,
    /// Per rule: the rule routes a reachable loopback inbound.
    pub(super) loop_rules: Vec<bool>,
    depth: usize,
}

impl<'g> Reach<'g> {
    fn new(graph: &'g NativeXray) -> Result<Self, NativeError> {
        let mut outbounds = Vec::with_capacity(graph.outbounds.len());
        let mut by_tag = HashMap::with_capacity(graph.outbounds.len());
        for outbound in &graph.outbounds {
            let t = tag(outbound).ok_or(NativeError::DuplicateTag)?;
            if by_tag.insert(t, outbounds.len()).is_some() {
                return Err(NativeError::DuplicateTag);
            }
            outbounds.push((t, outbound));
        }
        let (rules, raw_balancers) = match &graph.routing {
            Some(routing) => (routing.rules.as_slice(), routing.balancers.as_slice()),
            None => (&[][..], &[][..]),
        };
        let mut balancers = Vec::with_capacity(raw_balancers.len());
        let mut balancer_tags = HashSet::new();
        for balancer in raw_balancers {
            let t = tag(balancer).ok_or(NativeError::BadBalancerTag)?;
            if !balancer_tags.insert(t) {
                return Err(NativeError::BadBalancerTag);
            }
            balancers.push((t, balancer));
        }
        let n = outbounds.len();
        Ok(Self {
            outbounds,
            by_tag,
            balancers,
            rules,
            visited: Vec::new(),
            seen: vec![false; n],
            app_seen: vec![false; n],
            active: vec![false; n],
            used_balancers: Vec::new(),
            loop_rules: vec![false; rules.len()],
            depth: 0,
        })
    }

    fn index(&self, t: &str) -> Option<usize> {
        self.by_tag.get(t).copied()
    }

    /// Outbounds a balancer selects (Xray prefix semantics), in source order. The blackhole an
    /// export adds is never a candidate, so a re-imported export keeps the provider's balancing.
    pub(super) fn candidates(&self, balancer: &Value) -> Vec<usize> {
        let prefixes = strings(balancer.get("selector"));
        (0..self.outbounds.len())
            .filter(|&i| {
                let t = self.outbounds[i].0;
                t != EXPORT_BLOCK_TAG && prefixes.iter().any(|p| t.starts_with(p))
            })
            .collect()
    }

    fn enter(&mut self) -> Result<(), NativeError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(NativeError::TooDeep);
        }
        Ok(())
    }

    fn visit_balancer(&mut self, t: &str, app: bool) -> Result<(), NativeError> {
        self.enter()?;
        let b = self
            .balancers
            .iter()
            .position(|(own, _)| *own == t)
            .ok_or(NativeError::MissingBalancer)?;
        let balancer = self.balancers[b].1;
        let mut targets: Vec<&str> = self
            .candidates(balancer)
            .into_iter()
            .map(|i| self.outbounds[i].0)
            .collect();
        if let Some(fallback) = non_empty(balancer.get("fallbackTag")) {
            targets.push(fallback);
        }
        if targets.is_empty() {
            return Err(NativeError::EmptyBalancer);
        }
        if !self.used_balancers.contains(&b) {
            self.used_balancers.push(b);
        }
        let mut done = HashSet::new();
        for target in targets {
            if done.insert(target) {
                self.visit_outbound(target, app)?;
            }
        }
        self.depth -= 1;
        Ok(())
    }

    fn visit_outbound(&mut self, t: &str, app: bool) -> Result<(), NativeError> {
        self.enter()?;
        let i = self.index(t).ok_or(NativeError::MissingDependency)?;
        let outbound = self.outbounds[i].1;
        let protocol = protocol(outbound);
        // A provider fallback must never turn into plain application egress; freedom stays
        // allowed as the dialer of an encrypted hop.
        if app && BYPASS_PROTOCOLS.contains(&protocol) {
            return Err(NativeError::ApplicationBypass);
        }
        if self.active[i] {
            return Err(NativeError::Cyclic);
        }
        // A node first reached as a dialer is walked again as an application route.
        if self.seen[i] && (!app || self.app_seen[i]) {
            self.depth -= 1;
            return Ok(());
        }
        self.active[i] = true;
        if protocol == "loopback" {
            let inbound = non_empty(outbound.pointer("/settings/inboundTag"))
                .ok_or(NativeError::MissingLoopbackRoute)?;
            let rules = self.rules;
            let matching: Vec<usize> = (0..rules.len())
                .filter(|&k| routes_inbound(&rules[k], inbound))
                .collect();
            if matching.is_empty() {
                return Err(NativeError::MissingLoopbackRoute);
            }
            for k in matching {
                let rule = &rules[k];
                if let Some(out) = non_empty(rule.get("outboundTag")) {
                    self.visit_outbound(out, app)?;
                } else if let Some(bal) = non_empty(rule.get("balancerTag")) {
                    self.visit_balancer(bal, app)?;
                } else {
                    return Err(NativeError::LoopbackRouteNoDestination);
                }
                self.loop_rules[k] = true;
            }
        } else {
            if !GRAPH_PROTOCOLS.contains(&protocol) {
                return Err(NativeError::UnsupportedProtocol);
            }
            for pointer in DEPENDENCY_POINTERS {
                if let Some(dialer) = non_empty(outbound.pointer(pointer)) {
                    self.visit_outbound(dialer, false)?;
                }
            }
        }
        self.active[i] = false;
        if !self.seen[i] {
            self.seen[i] = true;
            self.visited.push(i);
        }
        self.app_seen[i] |= app;
        self.depth -= 1;
        Ok(())
    }

    /// Inbound tags of the reachable loopbacks, in visit order, without repeats.
    pub(super) fn loop_inbounds(&self) -> Vec<&'g str> {
        let mut out: Vec<&'g str> = Vec::new();
        for &i in &self.visited {
            let outbound = self.outbounds[i].1;
            if protocol(outbound) == "loopback"
                && let Some(inbound) = non_empty(outbound.pointer("/settings/inboundTag"))
                && !out.contains(&inbound)
            {
                out.push(inbound);
            }
        }
        out
    }

    pub(super) fn is_visited(&self, t: &str) -> bool {
        self.index(t).is_some_and(|i| self.seen[i])
    }
}

/// Walks the graph from its entry and checks every reachable outbound (`primary` stands in for
/// the selected one, as at start where the engine passes it with a resolved address).
pub(super) fn reach<'g>(graph: &'g NativeXray, primary: &Value) -> Result<Reach<'g>, NativeError> {
    let mut reach = Reach::new(graph)?;
    if let Some(out) = non_empty_str(graph.entry.outbound_tag.as_deref()) {
        reach.visit_outbound(out, true)?;
    } else if let Some(bal) = non_empty_str(graph.entry.balancer_tag.as_deref()) {
        reach.visit_balancer(bal, true)?;
    } else {
        return Err(NativeError::NoEntry);
    }
    if !reach.is_visited(&graph.selected_tag) {
        return Err(NativeError::SelectedOutsideGraph);
    }
    for &i in &reach.visited {
        let (t, source) = reach.outbounds[i];
        let outbound = if t == graph.selected_tag {
            primary
        } else {
            source
        };
        if t == EXPORT_BLOCK_TAG && protocol(outbound) != "blackhole" {
            return Err(NativeError::ReservedTag);
        }
        check_outbound(outbound)?;
    }
    // Only the loop rules are copied into the running config; other provider rules are dropped.
    let copied = reach.rules.iter().zip(&reach.loop_rules);
    if copied
        .filter(|(_, copied)| **copied)
        .any(|(rule, _)| uses_geo_data(rule))
    {
        return Err(NativeError::GeoData);
    }
    Ok(reach)
}

/// A matcher value that loads `geoip.dat`, `geosite.dat` or a named `.dat` file (prefixes are
/// case-sensitive in Xray: `GEOSITE:x` is a plain domain). Tag fields are names, not matchers.
fn uses_geo_data(rule: &Value) -> bool {
    const PREFIXES: [&str; 5] = ["geoip:", "geosite:", "ext:", "ext-ip:", "ext-domain:"];
    let geo = |s: &str| PREFIXES.iter().any(|p| s.starts_with(p));
    rule.as_object().is_some_and(|fields| {
        fields.iter().any(|(key, value)| {
            !key.ends_with("Tag")
                && match value {
                    Value::String(s) => geo(s),
                    Value::Array(items) => items.iter().filter_map(Value::as_str).any(geo),
                    _ => false,
                }
        })
    })
}

/// Refusals the bundled Xray (or plain safety) would otherwise produce only at start.
fn check_outbound(outbound: &Value) -> Result<(), NativeError> {
    // Xray wants exactly one member in `vnext` (and one user in it) or `servers`; an empty list
    // or a node without `users` is refused like several. The flat `settings.address` form has none.
    let len = |list: Option<&Value>| list.and_then(Value::as_array).map(Vec::len);
    let settings = outbound.get("settings");
    let vnext = settings.and_then(|s| s.get("vnext"));
    let nodes = vnext
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    if [vnext, settings.and_then(|s| s.get("servers"))]
        .into_iter()
        .any(|list| len(list).is_some_and(|n| n != 1))
        || nodes.iter().any(|node| len(node.get("users")) != Some(1))
    {
        return Err(NativeError::MultipleEndpoints);
    }
    walk_values(outbound)
}

/// Rejects local file paths anywhere (the elevated engine would read or, for `masterKeyLog`,
/// write them) and `tlsSettings` that disable certificate checks without a pin.
fn walk_values(value: &Value) -> Result<(), NativeError> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if is_file_key(key) && truthy(child) {
                    return Err(NativeError::LocalFileReference);
                }
                if key == "tlsSettings" && insecure_without_pin(child) {
                    return Err(NativeError::InsecureWithoutPin);
                }
                walk_values(child)?;
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(walk_values),
        _ => Ok(()),
    }
}

fn is_file_key(key: &str) -> bool {
    [
        "certificateFile",
        "keyFile",
        "echConfigListFile",
        "sessionTicketKeyFile",
        "masterKeyLog",
    ]
    .iter()
    .any(|k| k.eq_ignore_ascii_case(key))
}

fn insecure_without_pin(tls: &Value) -> bool {
    tls.get("allowInsecure").and_then(Value::as_bool) == Some(true)
        && non_empty(tls.get("pinnedPeerCertSha256")).is_none()
}
