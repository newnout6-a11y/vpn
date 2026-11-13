//! Automatic entries: names the routing sends direct for certain, judged by the rule order of
//! `plan` (owner answer 4). An entry covers a site and its subdomains (or the subdomains), so it
//! is dropped when anything that could route a host under it elsewhere exists: a user Block or
//! VPN rule naming a related site (a keyword one could match a host under any entry, so it
//! drops them all) and, while Smart RU runs, a pin or a blocked-in-Russia name. Process rules
//! run before every domain rule: while any app goes through the VPN there are no automatic
//! entries at all, as the app's names would otherwise leave directly.
use std::collections::HashSet;

use super::BypassEntry;
use super::lists::{Names, SmartLists};
use crate::routing::domain::{DomainAction, DomainPattern, DomainRule};
use crate::routing::process::{AppRule, SplitApp};
use crate::routing::smart_ru::{
    GOOGLE_AND_GEMINI_PINNED_SUFFIXES, IP_CHECKER_SUFFIXES, MAPS_DOMAIN_SUFFIXES, SmartRu,
    VPN_PINNED_MEDIA_SUFFIXES,
};

/// What the automatic entries depend on.
#[derive(Debug, Clone, Copy)]
pub struct AutoInputs<'a> {
    /// The user's domain rules (`RulesDoc::domain_rules`).
    pub domain_rules: &'a [DomainRule],
    /// The split-tunnel apps (`RulesDoc::split_tunnel.apps`).
    pub apps: &'a [SplitApp],
    /// Smart RU as the engine runs it: `enabled` only with a rule-set directory, the same
    /// condition as `RoutingInputs::rule_set_dir` (without one the engine runs it off).
    pub smart: SmartRu,
    /// The active rule-set files read back; `None` = could not be read.
    pub lists: Option<&'a SmartLists>,
}

/// The user's Direct rules of kind Exact / Subdomains in their order, then Smart RU's
/// government and banks list (D4), minus everything the module doc rules out.
pub fn automatic(i: &AutoInputs) -> Vec<BypassEntry> {
    if i.apps.iter().any(|a| a.rule == AppRule::Vpn) {
        return Vec::new();
    }
    let lists = match (i.smart.enabled, i.lists) {
        (false, _) => None,
        (true, Some(lists)) => Some(lists),
        // Smart RU runs but its lists are unknown: no name can be shown clear of them.
        (true, None) => return Vec::new(),
    };
    // Up to 10 000 rules: hashed, so each entry costs a few lookups.
    let mut against = Names::default();
    for rule in i.domain_rules {
        match (&rule.pattern, rule.action) {
            (_, DomainAction::Direct) => {}
            (DomainPattern::Keyword(_), _) => return Vec::new(),
            (DomainPattern::Exact(h) | DomainPattern::Subdomains(h), _) => against.insert(h),
        }
    }
    let pins = lists
        .map(|_| pinned(i.smart.maps_direct))
        .unwrap_or_default();
    let user = i
        .domain_rules
        .iter()
        .filter_map(|r| match (&r.pattern, r.action) {
            (DomainPattern::Exact(h), DomainAction::Direct) => Some(BypassEntry::Site(h.clone())),
            (DomainPattern::Subdomains(b), DomainAction::Direct) => {
                Some(BypassEntry::Subdomains(b.clone()))
            }
            _ => None,
        });
    let gov = lists.map(|l| l.gov().to_vec()).unwrap_or_default();
    let mut seen = HashSet::new();
    user.chain(gov)
        .filter(|entry| {
            let Some(name) = name_of(entry) else {
                return false;
            };
            !against.near(name)
                && !pins.iter().any(|p| related(name, p))
                && !lists.is_some_and(|l| l.blocked_near(name))
        })
        .filter(|entry| seen.insert(entry.clone()))
        .collect()
}

/// The pinned suffixes without their leading dot (maps only while they are not direct).
fn pinned(maps_direct: bool) -> Vec<&'static str> {
    let mut lists = vec![
        IP_CHECKER_SUFFIXES,
        GOOGLE_AND_GEMINI_PINNED_SUFFIXES,
        VPN_PINNED_MEDIA_SUFFIXES,
    ];
    if !maps_direct {
        lists.push(MAPS_DOMAIN_SUFFIXES);
    }
    lists
        .into_iter()
        .flatten()
        .map(|s| s.trim_start_matches('.'))
        .collect()
}

fn name_of(entry: &BypassEntry) -> Option<&str> {
    match entry {
        BypassEntry::Site(h) | BypassEntry::Subdomains(h) => Some(h),
        _ => None,
    }
}

/// `a` and `b` are the same name or one lies under the other: then some host is covered by both.
fn related(a: &str, b: &str) -> bool {
    a == b || under(a, b) || under(b, a)
}

/// `host` is a strict subdomain of `base`.
fn under(host: &str, base: &str) -> bool {
    host.len() > base.len() + 1
        && host.ends_with(base)
        && host.as_bytes()[host.len() - base.len() - 1] == b'.'
}
