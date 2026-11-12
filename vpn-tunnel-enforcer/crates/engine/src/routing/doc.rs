//! The persisted rules document `rules.json`: split-tunnel apps, DNS profiles and the active
//! choice, domain rules and their hit counters. Every mutation is a method here, called inside
//! `Store::update`; the tunnel watches the store and regenerates the fragments.
use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::store::Document;

use super::dns::{
    BUILTIN_PREFIX, DnsAddr, DnsProfile, MAX_NAME_LEN, builtin_profiles, find_profile,
};
use super::domain::{DomainAction, DomainPattern, DomainRule, MAX_RULES};
use super::process::{
    AppPath, AppRule, Probe, ProcessName, ResolvedSplit, SplitApp, SplitTarget, resolve_split,
};

/// Hit counters kept before entries of deleted rules are pruned.
pub const MAX_HIT_ENTRIES: usize = 10_000;

/// `rules.json`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RulesDoc {
    pub split_tunnel: SplitTunnel,
    pub dns: DnsSettings,
    /// In priority order: the first matching rule wins.
    #[serde(deserialize_with = "lenient")]
    pub domain_rules: Vec<DomainRule>,
    /// Connections whose host matched a rule, by rule id; they survive the rule's deletion.
    pub rule_hits: BTreeMap<Uuid, u64>,
    /// Keys written by a newer version, kept.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Document for RulesDoc {
    const FILE: &'static str = "rules.json";
    const VERSION: u32 = 1;
}

/// Split-tunnel entries and the paths the user removed (so a re-scan does not bring them back).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SplitTunnel {
    #[serde(deserialize_with = "lenient")]
    pub apps: Vec<SplitApp>,
    /// Lower-cased paths.
    pub removed_paths: BTreeSet<String>,
}

/// Custom DNS profiles and the active choice (`None` = automatic DoH through the tunnel).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DnsSettings {
    #[serde(deserialize_with = "lenient")]
    pub custom: Vec<DnsProfile>,
    pub active_id: Option<String>,
}

/// Entries that no longer parse (hand edits, older bugs) are dropped instead of making the
/// whole document unreadable; the next write removes them for good.
fn lenient<'de, D: Deserializer<'de>, T: DeserializeOwned>(d: D) -> Result<Vec<T>, D::Error> {
    let raw = Vec::<Value>::deserialize(d)?;
    Ok(raw
        .into_iter()
        .filter_map(|v| match serde_json::from_value(v) {
            Ok(item) => Some(item),
            Err(err) => {
                tracing::warn!(%err, "invalid entry in rules.json dropped");
                None
            }
        })
        .collect())
}

fn invalid(key: &'static str) -> AppError {
    AppError::validation(Msg::new(key))
}

/// Outcome of a domain-list import.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub added: usize,
    /// Already present (in the document or earlier in the list).
    pub duplicates: usize,
    /// Not added because the document holds [`MAX_RULES`] rules.
    pub over_limit: usize,
}

impl RulesDoc {
    /// Appends a rule (lowest priority). A pattern that already has a rule is refused.
    pub fn add_domain_rule(
        &mut self,
        pattern: DomainPattern,
        action: DomainAction,
    ) -> AppResult<Uuid> {
        if self.domain_rules.iter().any(|r| r.pattern == pattern) {
            return Err(invalid("engine.routing.domain.duplicate"));
        }
        if self.domain_rules.len() >= MAX_RULES {
            return Err(AppError::validation(
                Msg::new("engine.routing.domain.limit").arg("max", MAX_RULES),
            ));
        }
        let rule = DomainRule::new(pattern, action);
        let id = rule.id;
        self.domain_rules.push(rule);
        Ok(id)
    }

    /// Changes a rule's pattern and / or action in place.
    pub fn update_domain_rule(
        &mut self,
        id: Uuid,
        pattern: Option<DomainPattern>,
        action: Option<DomainAction>,
    ) -> AppResult<()> {
        if let Some(p) = &pattern
            && self
                .domain_rules
                .iter()
                .any(|r| r.id != id && r.pattern == *p)
        {
            return Err(invalid("engine.routing.domain.duplicate"));
        }
        let rule = self
            .domain_rules
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| invalid("engine.routing.domain.notFound"))?;
        if let Some(p) = pattern {
            rule.pattern = p;
        }
        if let Some(a) = action {
            rule.action = a;
        }
        Ok(())
    }

    /// Removes a rule; an unknown id is a no-op (`false`). Its hit counter stays.
    pub fn delete_domain_rule(&mut self, id: Uuid) -> bool {
        let before = self.domain_rules.len();
        self.domain_rules.retain(|r| r.id != id);
        before != self.domain_rules.len()
    }

    /// New priority order: the listed ids first (repeats and unknown ids ignored), then the
    /// unlisted rules in their current order.
    pub fn reorder_domain_rules(&mut self, ids: &[Uuid]) {
        let mut rest = std::mem::take(&mut self.domain_rules);
        for id in ids {
            if let Some(i) = rest.iter().position(|r| r.id == *id) {
                self.domain_rules.push(rest.remove(i));
            }
        }
        self.domain_rules.extend(rest);
    }

    /// Appends imported patterns with one action, skipping duplicates, up to [`MAX_RULES`].
    pub fn import_domains(
        &mut self,
        patterns: &[DomainPattern],
        action: DomainAction,
    ) -> ImportReport {
        let mut report = ImportReport::default();
        // Runs inside `Store::update` with up to 10 000 rules and a ~300 000-line list.
        let mut known: HashSet<DomainPattern> = self
            .domain_rules
            .iter()
            .map(|r| r.pattern.clone())
            .collect();
        for p in patterns {
            if known.contains(p) {
                report.duplicates += 1;
            } else if self.domain_rules.len() >= MAX_RULES {
                report.over_limit += 1;
            } else {
                known.insert(p.clone());
                self.domain_rules.push(DomainRule::new(p.clone(), action));
                report.added += 1;
            }
        }
        report
    }

    /// Matched connections of a rule so far.
    pub fn hit_count(&self, id: Uuid) -> u64 {
        self.rule_hits.get(&id).copied().unwrap_or(0)
    }

    /// Adds a batch of counted hits (flushed by the caller at most every 30 s). Past
    /// [`MAX_HIT_ENTRIES`] the counters of rules that no longer exist are dropped.
    pub fn add_hits(&mut self, hits: &BTreeMap<Uuid, u64>) {
        for (id, n) in hits {
            *self.rule_hits.entry(*id).or_default() += n;
        }
        if self.rule_hits.len() > MAX_HIT_ENTRIES {
            let live: BTreeSet<Uuid> = self.domain_rules.iter().map(|r| r.id).collect();
            self.rule_hits.retain(|id, _| live.contains(id));
        }
    }
}

/// DNS profiles. Changes apply at the next connect (the UI says so).
impl RulesDoc {
    /// Built-ins first, then the custom profiles.
    pub fn dns_profiles(&self) -> Vec<DnsProfile> {
        builtin_profiles()
            .into_iter()
            .chain(self.dns.custom.iter().cloned())
            .collect()
    }

    /// The active profile; a dangling id reads as automatic (`None`).
    pub fn active_dns(&self) -> Option<DnsProfile> {
        find_profile(&self.dns.custom, self.dns.active_id.as_deref()?)
    }

    /// Selects a profile, or automatic with `None`.
    pub fn select_dns(&mut self, id: Option<&str>) -> AppResult<()> {
        if let Some(id) = id
            && find_profile(&self.dns.custom, id).is_none()
        {
            return Err(invalid("engine.routing.dns.notFound"));
        }
        self.dns.active_id = id.map(str::to_owned);
        Ok(())
    }

    /// Creates a custom profile and returns its id (`dns-<ms>-<7 random chars>`).
    pub fn add_dns_profile(
        &mut self,
        name: &str,
        primary: DnsAddr,
        secondary: Option<DnsAddr>,
    ) -> AppResult<String> {
        let name = profile_name(name)?;
        let rand = Uuid::new_v4().simple().to_string();
        let id = format!("dns-{}-{}", now_ms(), &rand[..7]);
        self.dns.custom.push(DnsProfile {
            id: id.clone(),
            name,
            primary,
            secondary,
        });
        Ok(id)
    }

    /// Edits a custom profile; `secondary: Some(None)` clears it. Built-ins are read-only.
    pub fn update_dns_profile(
        &mut self,
        id: &str,
        name: Option<&str>,
        primary: Option<DnsAddr>,
        secondary: Option<Option<DnsAddr>>,
    ) -> AppResult<()> {
        if id.starts_with(BUILTIN_PREFIX) {
            return Err(invalid("engine.routing.dns.builtinReadOnly"));
        }
        let name = name.map(profile_name).transpose()?;
        let p = self
            .dns
            .custom
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| invalid("engine.routing.dns.notFound"))?;
        if let Some(n) = name {
            p.name = n;
        }
        if let Some(a) = primary {
            p.primary = a;
        }
        if let Some(s) = secondary {
            p.secondary = s;
        }
        Ok(())
    }

    /// Deletes a custom profile (`false` if unknown); deleting the active one selects automatic.
    pub fn delete_dns_profile(&mut self, id: &str) -> AppResult<bool> {
        if id.starts_with(BUILTIN_PREFIX) {
            return Err(invalid("engine.routing.dns.builtinReadOnly"));
        }
        let before = self.dns.custom.len();
        self.dns.custom.retain(|p| p.id != id);
        if self.dns.active_id.as_deref() == Some(id) {
            self.dns.active_id = None;
        }
        Ok(before != self.dns.custom.len())
    }
}

fn profile_name(raw: &str) -> AppResult<String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(invalid("engine.routing.dns.nameEmpty"));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(AppError::validation(
            Msg::new("engine.routing.dns.nameTooLong").arg("max", MAX_NAME_LEN),
        ));
    }
    Ok(name.to_owned())
}

/// Split tunnelling. Edits apply at once (the tunnel restarts when the fragments change).
impl RulesDoc {
    /// Adds an app by path (the caller checked that the file exists) with rule `none`; an
    /// app already listed is returned unchanged. A manual add clears the path's tombstone.
    pub fn add_app(&mut self, path: AppPath, name: &str) -> Uuid {
        self.split_tunnel
            .removed_paths
            .remove(&path.as_str().to_lowercase());
        if let Some(a) = self.find_target(&SplitTarget::App(path.clone())) {
            return a.id;
        }
        let name = match name.trim() {
            "" => crate::apps::fallback_name(path.as_str()),
            n => n.to_owned(),
        };
        self.push_app(name, SplitTarget::App(path), AppRule::None)
    }

    /// Adds a command name as a direct bypass; an existing entry for the name is re-armed to
    /// `direct` (adding a command has no other purpose).
    pub fn add_command(&mut self, name: ProcessName) -> Uuid {
        let target = SplitTarget::Command(name);
        if let Some(id) = self.find_target(&target).map(|a| a.id) {
            self.set_app_rule(id, AppRule::Direct);
            return id;
        }
        let display = match &target {
            SplitTarget::Command(n) => n.to_string(),
            SplitTarget::App(p) => p.to_string(),
        };
        self.push_app(display, target, AppRule::Direct)
    }

    /// Removes an entry (`false` if unknown); an app path is remembered so a re-scan does
    /// not bring it back.
    pub fn remove_app(&mut self, id: Uuid) -> bool {
        let Some(i) = self.split_tunnel.apps.iter().position(|a| a.id == id) else {
            return false;
        };
        let app = self.split_tunnel.apps.remove(i);
        if let SplitTarget::App(p) = app.target {
            self.split_tunnel
                .removed_paths
                .insert(p.as_str().to_lowercase());
        }
        true
    }

    /// Sets an entry's rule; `false` for an unknown id.
    pub fn set_app_rule(&mut self, id: Uuid, rule: AppRule) -> bool {
        match self.split_tunnel.apps.iter_mut().find(|a| a.id == id) {
            Some(a) => {
                a.rule = rule;
                true
            }
            None => false,
        }
    }

    /// Appends discovered apps whose paths are new and not removed by the user (rule `none`);
    /// returns how many were added.
    pub fn merge_discovered(&mut self, found: &[crate::apps::InstalledApp]) -> usize {
        let mut added = 0;
        for app in found {
            let removed = self
                .split_tunnel
                .removed_paths
                .contains(&app.path.as_str().to_lowercase());
            if !removed
                && self
                    .find_target(&SplitTarget::App(app.path.clone()))
                    .is_none()
            {
                self.push_app(
                    app.name.clone(),
                    SplitTarget::App(app.path.clone()),
                    AppRule::None,
                );
                added += 1;
            }
        }
        added
    }

    /// The entries resolved for an engine start (see [`resolve_split`]).
    pub fn resolve_split(&self, probe: impl Fn(&AppPath) -> Probe) -> ResolvedSplit {
        resolve_split(&self.split_tunnel.apps, probe)
    }

    fn find_target(&self, target: &SplitTarget) -> Option<&SplitApp> {
        self.split_tunnel.apps.iter().find(|a| a.target == *target)
    }

    fn push_app(&mut self, name: String, target: SplitTarget, rule: AppRule) -> Uuid {
        let id = Uuid::new_v4();
        self.split_tunnel.apps.push(SplitApp {
            id,
            name,
            target,
            rule,
        });
        id
    }
}

mod legacy;

#[cfg(test)]
#[path = "doc_tests.rs"]
mod tests;
