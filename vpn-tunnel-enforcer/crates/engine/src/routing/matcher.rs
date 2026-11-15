//! One sing-box domain matcher (`domain` / `domain_suffix` / `domain_keyword`, OR'ed by the
//! engine) built from user patterns or Smart RU suffix lists; entries are deduplicated.
use std::collections::HashSet;

use serde_json::{Map, Value};

use super::domain::DomainPattern;

#[derive(Debug, Default, Clone)]
pub(crate) struct Matcher {
    domain: Vec<String>,
    suffix: Vec<String>,
    keyword: Vec<String>,
}

impl Matcher {
    /// Adds a user pattern: `x.com` = apex + `.x.com`, `*.x.com` = `.x.com`, `~k` = keyword.
    pub(crate) fn pattern(&mut self, p: &DomainPattern) {
        match p {
            DomainPattern::Exact(x) => {
                self.domain.push(x.clone());
                self.suffix.push(format!(".{x}"));
            }
            DomainPattern::Subdomains(b) => self.suffix.push(format!(".{b}")),
            DomainPattern::Keyword(k) => self.keyword.push(k.clone()),
        }
    }

    /// Adds a list suffix the way `suffixListToMatcher` did: the apex as `domain` AND the
    /// dotted form as `domain_suffix`. A dotted suffix alone missed the apex (`2ip.ru` went
    /// direct past the IP-checker pin and showed the real IP); a dotless suffix would also
    /// match `my2ip.ru`.
    pub(crate) fn suffix(&mut self, raw: &str) {
        let s = raw.trim();
        if s.is_empty() {
            return;
        }
        let dotted = if s.starts_with('.') {
            s.to_owned()
        } else {
            format!(".{s}")
        };
        if dotted.len() > 1 {
            self.domain.push(dotted[1..].to_owned());
        }
        self.suffix.push(dotted);
    }

    /// The matcher fields of a rule object, first occurrences only (a merged run of up to
    /// 10 000 user rules is deduplicated by hash); empty lists are left out.
    pub(crate) fn into_fields(self) -> Map<String, Value> {
        let mut m = Map::new();
        for (key, list) in [
            ("domain", self.domain),
            ("domain_suffix", self.suffix),
            ("domain_keyword", self.keyword),
        ] {
            let mut seen = HashSet::new();
            let list: Vec<String> = list
                .into_iter()
                .filter(|s| seen.insert(s.clone()))
                .collect();
            if !list.is_empty() {
                m.insert(key.to_owned(), Value::from(list));
            }
        }
        m
    }
}
