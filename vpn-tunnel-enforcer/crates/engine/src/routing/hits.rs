//! Domain-rule hit counters from the engine's connection list (Clash API `/connections`).
//!
//! A hit means "a connection of this session whose host matches the rule's pattern and that
//! the engine routed the way the rule says" — not "connections this rule routed": process and
//! private-address rules run first. sing-box's own rule strings are not used as keys: they are
//! truncated after three items and their format changes between versions.
use std::collections::{BTreeMap, HashSet};

use uuid::Uuid;

use super::domain::{DomainAction, DomainRule, first_match};
use crate::tags::{DIRECT_OUT, PROXY_OUT};

/// One connection of a `/connections` poll.
#[derive(Debug, Clone, Copy)]
pub struct ConnSample<'a> {
    /// Clash connection id.
    pub id: &'a str,
    /// `metadata.host` (sniffed or requested domain; may be empty).
    pub host: &'a str,
    /// `rule` (`final` when no rule matched).
    pub rule: &'a str,
    /// `chains`; the last element is the outbound the matching rule chose.
    pub chains: &'a [String],
}

/// The rule a connection is counted for: the first user rule matching its host, when the
/// engine's decision agrees with that rule's action.
pub fn attribute(rules: &[DomainRule], conn: &ConnSample) -> Option<Uuid> {
    if conn.rule == "final" {
        return None;
    }
    let rule = first_match(rules, conn.host)?;
    let outbound = conn.chains.last().map(String::as_str);
    let agrees = match rule.action {
        DomainAction::Direct => outbound == Some(DIRECT_OUT),
        DomainAction::Vpn => outbound == Some(PROXY_OUT),
        // A rejected connection is probably never listed; if it is, it has no outbound.
        DomainAction::Block => conn.rule.contains("reject"),
    };
    agrees.then_some(rule.id)
}

/// Counts each connection once across polls and accumulates hits until they are flushed
/// into the document (`RulesDoc::add_hits`, at most every 30 s and on exit).
#[derive(Debug, Default)]
pub struct HitTracker {
    seen: HashSet<String>,
    pending: BTreeMap<Uuid, u64>,
}

impl HitTracker {
    /// One poll: new connection ids are attributed; ids no longer listed are forgotten, so
    /// memory follows the live connection count. With no rules nothing is recorded.
    pub fn observe<'a>(
        &mut self,
        rules: &[DomainRule],
        poll: impl IntoIterator<Item = ConnSample<'a>>,
    ) {
        let mut live = HashSet::new();
        for conn in poll {
            live.insert(conn.id.to_owned());
            if self.seen.contains(conn.id) || rules.is_empty() {
                continue;
            }
            if let Some(id) = attribute(rules, &conn) {
                *self.pending.entry(id).or_default() += 1;
            }
        }
        self.seen = live;
    }

    /// The hits counted since the last call.
    pub fn take(&mut self) -> BTreeMap<Uuid, u64> {
        std::mem::take(&mut self.pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::domain::DomainPattern;

    fn rule(p: &str, action: DomainAction) -> DomainRule {
        DomainRule::new(DomainPattern::parse(p).unwrap(), action)
    }

    fn conn<'a>(id: &'a str, host: &'a str, chains: &'a [String]) -> ConnSample<'a> {
        ConnSample {
            id,
            host,
            rule: "domain=x => route(proxy-out)",
            chains,
        }
    }

    /// AT-06-003 / F-011 (domainRoutingHits.test.ts): first matching rule per host, each
    /// connection id counted once across polls.
    #[test]
    fn hits_vectors() {
        let proxy = vec!["vpnte-upstream-a".to_owned(), "proxy-out".to_owned()];
        let mut t = HitTracker::default();
        t.observe(&[], [conn("c0", "cdn.hits.example", &proxy)]);
        assert!(t.take().is_empty());
        let exact = rule("cdn.hits.example", DomainAction::Vpn);
        let wild = rule("*.hits.example", DomainAction::Vpn);
        let rules = [exact.clone(), wild.clone()];
        t.observe(
            &rules,
            [
                conn("c1", "cdn.hits.example", &proxy),
                conn("c2", "img.hits.example", &proxy),
                conn("c3", "img.hits.example", &proxy),
                conn("c4", "unrelated.example", &proxy),
            ],
        );
        assert_eq!(t.take(), BTreeMap::from([(exact.id, 1), (wild.id, 2)]));
        t.observe(&rules, [conn("c1", "cdn.hits.example", &proxy)]);
        t.observe(
            &rules,
            [
                conn("c1", "cdn.hits.example", &proxy),
                conn("c5", "cdn.hits.example", &proxy),
            ],
        );
        assert_eq!(t.take(), BTreeMap::from([(exact.id, 1)]));
    }

    /// B-DR-6: a connection another rule sent elsewhere, or `final`, is not counted.
    #[test]
    fn engine_decision_must_agree() {
        let direct = vec!["direct-out".to_owned()];
        let proxy = vec!["proxy-out".to_owned()];
        let r = rule("example.com", DomainAction::Direct);
        let rules = [r.clone()];
        assert_eq!(
            attribute(&rules, &conn("a", "www.example.com", &direct)),
            Some(r.id)
        );
        assert_eq!(
            attribute(&rules, &conn("a", "www.example.com", &proxy)),
            None
        );
        let fin = ConnSample {
            rule: "final",
            ..conn("a", "www.example.com", &direct)
        };
        assert_eq!(attribute(&rules, &fin), None);
        let blocked = rule("ads.example", DomainAction::Block);
        let rej = ConnSample {
            rule: "domain=ads.example => reject",
            ..conn("b", "ads.example", &[])
        };
        assert_eq!(
            attribute(std::slice::from_ref(&blocked), &rej),
            Some(blocked.id)
        );
    }
}
