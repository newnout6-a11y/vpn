//! The user's «Не через прокси» entries as route rules (fixlists-b3): under proxy capture a
//! program that reaches the engine with one anyway still leaves directly. `NO_PROXY` readers
//! miss `*.x` and most ranges (their syntaxes differ), WinINet programs miss CIDR items.
use serde_json::{Value, json};

use super::{BypassEntry, cidr};
use crate::routing::domain::DomainPattern;
use crate::routing::matcher::Matcher;
use crate::tags::DIRECT_OUT;

/// `direct-out` rules for `entries`: one for the names (`x` = the site and its subdomains,
/// `*.x` = the subdomains, as in the user's domain rules), one for the addresses.
pub fn route_rules(entries: &[BypassEntry]) -> Vec<Value> {
    let mut names = Matcher::default();
    let mut nets = Vec::new();
    for entry in entries {
        match entry {
            BypassEntry::Site(x) => names.pattern(&DomainPattern::Exact(x.clone())),
            BypassEntry::Subdomains(x) => names.pattern(&DomainPattern::Subdomains(x.clone())),
            BypassEntry::Ipv4(ip) => nets.push(format!("{ip}/32")),
            BypassEntry::Ipv4Range(octets) => nets.push(cidr(octets)),
            BypassEntry::Ipv6(ip) => nets.push(format!("{ip}/128")),
        }
    }
    let mut rules = Vec::new();
    let mut names = names.into_fields();
    if !names.is_empty() {
        names.insert("outbound".into(), json!(DIRECT_OUT));
        rules.push(Value::Object(names));
    }
    if !nets.is_empty() {
        rules.push(json!({ "ip_cidr": nets, "outbound": DIRECT_OUT }));
    }
    rules
}
