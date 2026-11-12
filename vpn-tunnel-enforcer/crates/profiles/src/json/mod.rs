//! JSON importer: sing-box and Xray documents (outbounds, endpoints, wrappers) -> profiles.
//!
//! Traversal (profiles spec §3.4): a document's `outbounds` + `endpoints` first, then the value
//! itself as one outbound, then wrapper keys (`config`, `data`, …) down to depth 6. The first
//! place that yields profiles or skipped entries wins; arrays collect every item.
mod outbounds;
mod parts;
pub(crate) mod scan;
pub(crate) mod singbox;
mod strings;
#[cfg(test)]
mod tests;
mod values;
mod wireguard;
mod xray;
mod xray_hysteria;
mod xray_plain;
mod xray_proxy;
mod xray_stream;
#[cfg(test)]
mod xray_tests;

use serde_json::{Map, Value};

use crate::common::fields::reality_conflict;
use crate::model::{ParseReport, Profile, SkipReason, Skipped};
use outbounds::candidates;

use values::text;

/// Wrappers nested deeper than this are not searched.
const MAX_DEPTH: usize = 6;
/// Skipped-entry excerpts are cut to this many characters.
const EXCERPT_CHARS: usize = 80;

/// Keys providers wrap configs in, searched first and in this order (the old app's order).
const PREFERRED: &[&str] = &[
    "xrayFullConfig",
    "fullConfig",
    "full_config",
    "rawConfig",
    "raw_config",
    "config",
    "configs",
    "configuration",
    "outbound",
    "outbounds",
    "profile",
    "profiles",
    "server",
    "servers",
    "node",
    "nodes",
    "data",
    "result",
    "subscription",
];

/// Sections of a full sing-box / Xray config that never hold client outbounds. A server config's
/// `inbounds[]` used to become bogus profiles when the generic walk reached it first.
const NEVER_PROFILES: &[&str] = &[
    "inbounds",
    "log",
    "dns",
    "route",
    "routing",
    "experimental",
    "ntp",
    "api",
    "policy",
    "stats",
    "observatory",
    "burstObservatory",
    "fakedns",
    "metrics",
    "reverse",
    "services",
    "certificate",
];

/// Profiles found in one parsed JSON value. Never fails: unusable entries come back as `skipped`.
pub fn parse_json(value: &Value) -> ParseReport {
    // An AmneziaVPN server description (a decoded `vpn://` key) names its containers itself.
    if let Some(report) = crate::amnezia::parse_document(value) {
        return report;
    }
    let mut out = Out::default();
    walk(value, 0, None, &mut out);
    ParseReport {
        profiles: out.profiles,
        skipped: out.skipped,
        meta: Default::default(),
    }
}

/// Results collected so far.
#[derive(Default)]
pub(crate) struct Out {
    profiles: Vec<Profile>,
    skipped: Vec<Skipped>,
}

impl Out {
    fn len(&self) -> usize {
        self.profiles.len() + self.skipped.len()
    }

    fn push(&mut self, result: Result<Profile, SkipReason>, excerpt: impl FnOnce() -> String) {
        let result = result.and_then(|p| match reality_conflict(&p) {
            Some(detail) => Err(SkipReason::Invalid {
                scheme: p.kind.label().to_owned(),
                detail: detail.to_owned(),
            }),
            None => Ok(p),
        });
        match result {
            Ok(profile) => self.profiles.push(profile),
            Err(reason) => self.skipped.push(Skipped {
                excerpt: excerpt(),
                reason,
            }),
        }
    }

    /// Takes over what the Clash importer reported for a Clash list inside a JSON string.
    fn extend(&mut self, report: ParseReport) {
        self.profiles.extend(report.profiles);
        self.skipped.extend(report.skipped);
    }
}

/// Imports what `v` holds; true when anything (profile or skipped entry) came out of it.
fn walk(v: &Value, depth: usize, remarks: Option<&str>, out: &mut Out) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    let before = out.len();
    match v {
        Value::String(s) => {
            strings::import(s, depth, out);
        }
        Value::Array(items) => {
            let all: Vec<&Value> = items.iter().collect();
            if !candidates(&all, remarks, None, out) {
                for item in items {
                    walk(item, depth + 1, remarks, out);
                }
            }
        }
        Value::Object(o) => {
            object(o, v, depth, remarks, out);
        }
        _ => {}
    }
    out.len() > before
}

fn object(
    o: &Map<String, Value>,
    v: &Value,
    depth: usize,
    inherited: Option<&str>,
    out: &mut Out,
) -> bool {
    let remarks = text(o, &["remarks", "ps", "name"]).or(inherited);
    let lists: Vec<&Value> = ["outbounds", "endpoints"]
        .iter()
        .filter_map(|k| o.get(*k)?.as_array())
        .flatten()
        .collect();
    if !lists.is_empty() && candidates(&lists, remarks, Some(v), out) {
        return true;
    }
    if candidates(&[v], remarks, None, out) {
        return true;
    }
    for key in PREFERRED {
        if let Some(child) = o.get(*key)
            && walk(child, depth + 1, remarks, out)
        {
            return true;
        }
    }
    o.iter()
        .filter(|(k, _)| !PREFERRED.contains(&k.as_str()) && !NEVER_PROFILES.contains(&k.as_str()))
        .filter(|(_, child)| matches!(child, Value::Object(_) | Value::Array(_) | Value::String(_)))
        .any(|(_, child)| walk(child, depth + 1, remarks, out))
}
