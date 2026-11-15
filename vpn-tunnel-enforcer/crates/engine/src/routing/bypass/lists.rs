//! Smart RU's name lists as the engine holds them, read back from the active rule-set files with
//! `sing-box rule-set decompile`: the binary format is sing-box's own, and the engine is the one
//! reader that cannot drift from it. Only the gov list (D4) and the blocked-in-Russia names are
//! read; the address sets cannot match a bypassed name (proxy clients hand over names and the
//! engine has no `resolve` action, so in Soft mode a name meets the domain lists only).
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::path::Path;

use serde_json::{Map, Value};

use super::BypassEntry;
use crate::routing::rulesets::decompile;
use crate::routing::smart_ru::{GOV_RU, RU_BLOCKED_SITES, RULE_SETS};

/// The gov entries and the blocked names, ready for [`super::automatic`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmartLists {
    gov: Vec<BypassEntry>,
    blocked: Names,
}

/// Names as hashes: every name, and every zone with a name below it, so "the same site or one
/// under the other" is a few lookups. Some 2 MB for the 74 000 blocked names of the November
/// 2026 list instead of 6 MB of strings; a collision can only drop an entry, never add one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Names {
    names: HashSet<u64>,
    zones: HashSet<u64>,
    /// A keyword, regex or inverted rule: it could match a host under any name.
    any: bool,
}

impl Names {
    /// Adds `name` (a leading dot is dropped: a subdomains-only name is treated as the site).
    pub(super) fn insert(&mut self, name: &str) {
        let name = name.trim_matches('.').to_ascii_lowercase();
        self.names.insert(hash(&name));
        for zone in ancestry(&name).skip(1) {
            self.zones.insert(hash(zone));
        }
    }

    /// `name` is a held name or lies under one (a keyword, regex or inverted rule is not
    /// counted: it says nothing certain about one name).
    fn covers(&self, name: &str) -> bool {
        ancestry(name).any(|a| self.names.contains(&hash(a)))
    }

    /// A held name is `name`, lies under it, or `name` lies under one.
    pub(super) fn near(&self, name: &str) -> bool {
        self.any
            || self.zones.contains(&hash(name))
            || ancestry(name).any(|a| self.names.contains(&hash(a)))
    }
}

impl SmartLists {
    /// From the decompiled JSON of the gov and the blocked rule sets.
    pub fn parse(gov: &str, blocked: &str) -> Result<Self, serde_json::Error> {
        let gov_rules = rules(gov)?;
        let mut lists = SmartLists::default();
        for rule in &gov_rules {
            lists.gov.extend(gov_entries(rule));
        }
        for rule in &rules(blocked)? {
            lists.blocked.add(rule);
        }
        Ok(lists)
    }

    /// The gov list's sites (`x` = the site and its subdomains, `.x` = the subdomains).
    pub fn gov(&self) -> &[BypassEntry] {
        &self.gov
    }

    /// A blocked name is `name`, lies under it, or `name` lies under one.
    pub fn blocked_near(&self, name: &str) -> bool {
        self.blocked.near(name)
    }

    /// `name` is on the blocked-in-Russia list or lies under a name on it: Smart RU sends it
    /// through the VPN (step DB, right after the user's rules).
    pub fn blocked_covers(&self, name: &str) -> bool {
        self.blocked.covers(&name.to_ascii_lowercase())
    }
}

impl Names {
    /// Every name of `rule` (logical rules: of their parts), conservatively: any condition that
    /// is not a plain name list can match more than its names say.
    fn add(&mut self, rule: &Map<String, Value>) {
        if rule.get("invert").and_then(Value::as_bool) == Some(true)
            || ["domain_keyword", "domain_regex"]
                .iter()
                .any(|k| rule.get(*k).is_some_and(|v| v != &Value::Array(Vec::new())))
        {
            self.any = true;
        }
        for name in strings(rule, "domain").chain(strings(rule, "domain_suffix")) {
            self.insert(name);
        }
        for part in rule
            .get("rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            match part.as_object() {
                Some(part) => self.add(part),
                None => self.any = true,
            }
        }
    }
}

/// Reads the gov and blocked lists from `dir` (the active rule-set directory, all files
/// present) with the sing-box at `exe`.
pub async fn read_smart_lists(exe: &Path, dir: &Path) -> io::Result<SmartLists> {
    let gov = decompile(exe, &dir.join(file_of(GOV_RU))).await?;
    let blocked = decompile(exe, &dir.join(file_of(RU_BLOCKED_SITES))).await?;
    SmartLists::parse(&gov, &blocked).map_err(io::Error::other)
}

/// The file name of a rule set in a rule-set directory.
fn file_of(tag: &str) -> &'static str {
    RULE_SETS
        .iter()
        .find(|(t, _, _)| *t == tag)
        .map_or("", |(_, file, _)| file)
}

/// The `rules` of a decompiled rule set (`{"version": n, "rules": [...]}`).
fn rules(json: &str) -> Result<Vec<Map<String, Value>>, serde_json::Error> {
    #[derive(serde::Deserialize)]
    struct Source {
        rules: Vec<Map<String, Value>>,
    }
    serde_json::from_str::<Source>(json).map(|s| s.rules)
}

/// The sites of a gov rule made of name suffixes only; a rule with any other condition matches
/// less than its names say, and a `domain` item is one host where an entry covers a site.
fn gov_entries(rule: &Map<String, Value>) -> Vec<BypassEntry> {
    if rule.keys().any(|k| k != "domain_suffix") {
        return Vec::new();
    }
    strings(rule, "domain_suffix")
        .filter_map(|s| match s.strip_prefix('.') {
            Some(base) => BypassEntry::parse(&format!("*.{base}")).ok(),
            None => BypassEntry::parse(s).ok(),
        })
        .filter(|e| matches!(e, BypassEntry::Site(_) | BypassEntry::Subdomains(_)))
        .collect()
}

/// The strings of `key` (a list, or one string as sing-box also accepts).
fn strings<'a>(rule: &'a Map<String, Value>, key: &str) -> impl Iterator<Item = &'a str> {
    let value = rule.get(key);
    let one = value.and_then(Value::as_str);
    let many = value.and_then(Value::as_array).into_iter().flatten();
    one.into_iter().chain(many.filter_map(Value::as_str))
}

/// `name`, then each zone above it (`a.b.c`, `b.c`, `c`).
fn ancestry(name: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(name), |n| n.split_once('.').map(|(_, rest)| rest))
}

fn hash(name: &str) -> u64 {
    let mut h = DefaultHasher::new();
    name.hash(&mut h);
    h.finish()
}
