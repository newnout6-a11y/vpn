//! One-time import from the Electron stores (`domain-routing.json`, `dns-profiles.json`,
//! `split-tunnel.json`; each argument is the whole store object). Every entry goes through the
//! same validation as the UI; what does not parse is dropped and counted in the warnings.
use std::collections::HashSet;

use serde_json::Value;
use uuid::Uuid;
use vpnte_base::Msg;

use super::{RulesDoc, profile_name};
use crate::routing::dns::{BUILTIN_PREFIX, DnsAddr, DnsProfile, find_profile};
use crate::routing::domain::{DomainAction, DomainPattern, DomainRule, MAX_RULES};
use crate::routing::process::{AppPath, ProcessName, SplitApp, SplitTarget};

impl RulesDoc {
    /// Builds the document from the old stores; returns it with the import warnings.
    pub fn from_legacy(
        domain: Option<&Value>,
        dns: Option<&Value>,
        split: Option<&Value>,
    ) -> (RulesDoc, Vec<Msg>) {
        let mut doc = RulesDoc::default();
        let mut warnings = Vec::new();
        let mut report = |key: &'static str, n: usize| {
            if n > 0 {
                warnings.push(Msg::new(key).arg("count", n));
            }
        };
        report(
            "engine.routing.legacy.domainDropped",
            doc.legacy_domain(domain),
        );
        report("engine.routing.legacy.dnsDropped", doc.legacy_dns(dns));
        report(
            "engine.routing.legacy.splitDropped",
            doc.legacy_split(split),
        );
        (doc, warnings)
    }

    /// `domainRules[]` sorted by `priority` (stable); dotless patterns become `~keyword`.
    fn legacy_domain(&mut self, store: Option<&Value>) -> usize {
        let mut rows: Vec<&Value> = list(store, "domainRules").collect();
        // Stored uncoerced by the old app: the string "5" sorted as 5 there.
        let priority = |r: &Value| {
            match r.get("priority") {
                Some(Value::String(s)) => s.trim().parse().ok(),
                v => v.and_then(Value::as_f64),
            }
            .unwrap_or(f64::MAX)
        };
        rows.sort_by(|a, b| priority(a).total_cmp(&priority(b)));
        let mut dropped = 0;
        let (mut patterns, mut ids) = (HashSet::new(), HashSet::new());
        for r in rows {
            let pattern = r
                .get("pattern")
                .and_then(Value::as_str)
                .map(DomainPattern::parse_legacy);
            let action = r
                .get("action")
                .cloned()
                .map(serde_json::from_value::<DomainAction>);
            let (Some(Ok(pattern)), Some(Ok(action))) = (pattern, action) else {
                dropped += 1;
                continue;
            };
            if self.domain_rules.len() >= MAX_RULES || !patterns.insert(pattern.clone()) {
                dropped += 1;
                continue;
            }
            let id = legacy_id(r)
                .filter(|id| ids.insert(*id))
                .unwrap_or_else(Uuid::new_v4);
            self.domain_rules.push(DomainRule {
                id,
                pattern,
                action,
            });
        }
        dropped
    }

    /// `customProfiles[]` + `activeProfileId` (kept only if it resolves; else automatic).
    fn legacy_dns(&mut self, store: Option<&Value>) -> usize {
        let mut dropped = 0;
        for p in list(store, "customProfiles") {
            let text = |k: &str| {
                p.get(k)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .unwrap_or_default()
            };
            let id = text("id");
            let name = profile_name(text("name"));
            let primary = text("primary").parse::<DnsAddr>();
            let unique = !self.dns.custom.iter().any(|c| c.id == id);
            match (name, primary) {
                (Ok(name), Ok(primary))
                    if !id.is_empty()
                        && id.len() <= 200
                        && !id.starts_with(BUILTIN_PREFIX)
                        && unique =>
                {
                    let secondary = text("secondary").parse().ok();
                    self.dns.custom.push(DnsProfile {
                        id: id.to_owned(),
                        name,
                        primary,
                        secondary,
                    });
                }
                _ => dropped += 1,
            }
        }
        let active = store
            .and_then(|s| s.get("activeProfileId"))
            .and_then(Value::as_str);
        self.dns.active_id = active
            .filter(|id| find_profile(&self.dns.custom, id).is_some())
            .map(str::to_owned);
        dropped
    }

    /// `splitTunnelApps[]` (`kind` absent = app, `path` = target) + `splitTunnelRemovedPaths`.
    fn legacy_split(&mut self, store: Option<&Value>) -> usize {
        let mut dropped = 0;
        for a in list(store, "splitTunnelApps") {
            let path = a.get("path").and_then(Value::as_str).unwrap_or_default();
            let target = match a.get("kind").and_then(Value::as_str) {
                Some("process") => ProcessName::parse(path).map(SplitTarget::Command),
                _ => AppPath::parse(path).map(SplitTarget::App),
            };
            let Ok(target) = target else {
                dropped += 1;
                continue;
            };
            if self.find_target(&target).is_some() {
                dropped += 1;
                continue;
            }
            let rule = a
                .get("rule")
                .cloned()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();
            // App names get the display-name hygiene the old app applied on every read.
            let raw = a
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            let name = match &target {
                SplitTarget::App(p) => crate::apps::sanitize_name(raw, p.as_str()),
                SplitTarget::Command(n) if raw.is_empty() => n.to_string(),
                SplitTarget::Command(_) => raw.to_owned(),
            };
            let id = legacy_id(a).filter(|id| !self.split_tunnel.apps.iter().any(|x| x.id == *id));
            self.split_tunnel.apps.push(SplitApp {
                id: id.unwrap_or_else(Uuid::new_v4),
                name,
                target,
                rule,
            });
        }
        self.split_tunnel.removed_paths = list(store, "splitTunnelRemovedPaths")
            .filter_map(Value::as_str)
            .map(str::to_lowercase)
            .collect();
        dropped
    }
}

fn list<'a>(store: Option<&'a Value>, key: &str) -> impl Iterator<Item = &'a Value> {
    store
        .and_then(|s| s.get(key))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn legacy_id(entry: &Value) -> Option<Uuid> {
    entry
        .get("id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}
