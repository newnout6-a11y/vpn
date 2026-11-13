//! «Не через прокси»: what Soft mode's system proxy (WinINet `ProxyOverride`) and `NO_PROXY`
//! leave direct, beside the loopback and local names Soft always lists (RU-2026 item 14 a-b).
//!
//! A bypass entry acts before the engine sees the request, so only two kinds exist: the user's
//! own list (their rule, owner answer 4 holds by definition) and automatic entries whose direct
//! outcome the routing makes certain from the name alone ([`automatic`]). RU TLDs are never
//! added: Smart RU sends a `.ru` site direct only when its address is Russian, and a bypassed
//! name would also skip a user rule that sends it through the VPN or blocks it.
use std::collections::HashSet;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use vpnte_base::{AppError, Msg};

use super::domain::{DomainPattern, PatternError};

mod auto;
mod lists;

pub use auto::{AutoInputs, automatic};
pub use lists::{SmartLists, read_smart_lists};

/// Most entries the user's list keeps.
pub const MAX_ENTRIES: usize = 200;
/// Longest `ProxyOverride` text the user's list may take; the automatic entries fill the rest
/// of [`MAX_TEXT`].
pub const MAX_USER_TEXT: usize = 8 * 1024;
/// Longest `ProxyOverride` / `NO_PROXY` text the entries may take together: well inside the
/// tweak journal's 64 KiB value, which must hold the user's own setting as well.
pub const MAX_TEXT: usize = 16 * 1024;

/// One validated entry; its `Display` is the stored form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BypassEntry {
    /// `x.com`: the site and every subdomain, as in the user's domain rules.
    Site(String),
    /// `*.x.com`: subdomains only.
    Subdomains(String),
    Ipv4(Ipv4Addr),
    /// `10.*`, `192.168.*`: the leading octets (1 to 3) of an IPv4 range.
    Ipv4Range(Vec<u8>),
    Ipv6(Ipv6Addr),
}

/// Why the user's list was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BypassError {
    #[error("not a host, address or wildcard")]
    Invalid(String),
    #[error("more than {MAX_ENTRIES} entries")]
    TooMany,
    #[error("the list is too long for the system proxy")]
    TooLong,
}

impl BypassError {
    /// User-facing explanation.
    pub fn msg(&self) -> Msg {
        match self {
            BypassError::Invalid(entry) => {
                Msg::new("engine.routing.bypass.invalid").arg("entry", entry.clone())
            }
            BypassError::TooMany => {
                Msg::new("engine.routing.bypass.tooMany").arg("max", MAX_ENTRIES)
            }
            BypassError::TooLong => Msg::new("engine.routing.bypass.tooLong"),
        }
    }
}

impl From<BypassError> for AppError {
    fn from(err: BypassError) -> Self {
        AppError::validation(err.msg()).with_source(err)
    }
}

impl BypassEntry {
    /// Parses one entry: a host (a pasted URL gives its host, IDN becomes punycode), `*.host`,
    /// an IPv4 / IPv6 address or an IPv4 range with trailing `*` octets.
    pub fn parse(raw: &str) -> Result<Self, BypassError> {
        let t = raw.trim().to_lowercase();
        let invalid = || BypassError::Invalid(raw.trim().to_owned());
        if let Ok(ip) = t.parse::<Ipv4Addr>() {
            return Ok(BypassEntry::Ipv4(ip));
        }
        if let Ok(ip) = t
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<Ipv6Addr>()
        {
            return Ok(BypassEntry::Ipv6(ip));
        }
        if let Some(octets) = ipv4_range(&t) {
            return Ok(BypassEntry::Ipv4Range(octets));
        }
        match DomainPattern::parse(&t) {
            Ok(DomainPattern::Exact(host)) => Ok(BypassEntry::Site(host)),
            Ok(DomainPattern::Subdomains(base)) => Ok(BypassEntry::Subdomains(base)),
            // A dotless intranet name: the rule syntax wants a dot, `*.name` checks the label.
            Err(PatternError::NeedsDot) => match DomainPattern::parse(&format!("*.{t}")) {
                Ok(DomainPattern::Subdomains(name)) => Ok(BypassEntry::Site(name)),
                _ => Err(invalid()),
            },
            Ok(DomainPattern::Keyword(_)) | Err(_) => Err(invalid()),
        }
    }

    /// The `ProxyOverride` items (WinINet / Chromium syntax: `*` wildcards, exact otherwise).
    pub fn override_items(&self) -> Vec<String> {
        match self {
            BypassEntry::Site(h) => vec![h.clone(), format!("*.{h}")],
            BypassEntry::Ipv6(ip) => vec![format!("[{ip}]")],
            other => vec![other.to_string()],
        }
    }

    /// The `NO_PROXY` items. curl, Go and Python read a plain name as the name and its
    /// subdomains, Node's `proxy-from-env` as the name only and `.name` as the subdomains: both
    /// forms cover the site in all of them. `.name` alone also covers the bare name in curl and
    /// Python. Ranges become CIDR (curl and Go; others skip what they cannot read).
    pub fn no_proxy_items(&self) -> Vec<String> {
        match self {
            BypassEntry::Site(h) => vec![h.clone(), format!(".{h}")],
            BypassEntry::Subdomains(b) => vec![format!(".{b}")],
            BypassEntry::Ipv4(ip) => vec![ip.to_string()],
            BypassEntry::Ipv4Range(octets) => {
                let mut full = [0u8; 4];
                full[..octets.len()].copy_from_slice(octets);
                vec![format!("{}/{}", Ipv4Addr::from(full), octets.len() * 8)]
            }
            BypassEntry::Ipv6(ip) => vec![ip.to_string()],
        }
    }
}

impl fmt::Display for BypassEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BypassEntry::Site(h) => f.write_str(h),
            BypassEntry::Subdomains(b) => write!(f, "*.{b}"),
            BypassEntry::Ipv4(ip) => write!(f, "{ip}"),
            BypassEntry::Ipv4Range(octets) => {
                for o in octets {
                    write!(f, "{o}.")?;
                }
                f.write_str("*")
            }
            BypassEntry::Ipv6(ip) => write!(f, "{ip}"),
        }
    }
}

/// `10.*`, `192.168.*`, `172.16.*.*`: one to three decimal octets, then `*` labels.
fn ipv4_range(t: &str) -> Option<Vec<u8>> {
    let labels: Vec<&str> = t.split('.').collect();
    let stars = labels.iter().rev().take_while(|l| **l == "*").count();
    let octets = &labels[..labels.len() - stars];
    if labels.len() > 4 || stars == 0 || octets.is_empty() || octets.len() > 3 {
        return None;
    }
    octets
        .iter()
        .map(|o| {
            let digits = !o.is_empty() && o.len() <= 3 && o.bytes().all(|b| b.is_ascii_digit());
            digits.then(|| o.parse::<u8>().ok()).flatten()
        })
        .collect()
}

/// The user's list from the page text: entries split on new lines, `;`, `,` or spaces, so a
/// list copied from Windows' own setting pastes as it is. `<local>` and repeats are dropped
/// (Soft always lists local names); the user's order is kept.
pub fn parse_list(text: &str) -> Result<Vec<BypassEntry>, BypassError> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for token in text.split(|c: char| c == ';' || c == ',' || c.is_whitespace()) {
        if token.is_empty() || token.eq_ignore_ascii_case("<local>") {
            continue;
        }
        let entry = BypassEntry::parse(token)?;
        if seen.insert(entry.clone()) {
            out.push(entry);
        }
    }
    if out.len() > MAX_ENTRIES {
        return Err(BypassError::TooMany);
    }
    let items: Vec<String> = out.iter().flat_map(BypassEntry::override_items).collect();
    if text_len(&items) > MAX_USER_TEXT {
        return Err(BypassError::TooLong);
    }
    Ok(out)
}

/// The stored list (`Settings::proxy_bypass`) back as entries; one a hand-edited file broke is
/// skipped with a warning instead of failing the session.
pub fn from_stored(stored: &[String]) -> Vec<BypassEntry> {
    stored
        .iter()
        .filter_map(|raw| match BypassEntry::parse(raw) {
            Ok(entry) => Some(entry),
            Err(err) => {
                tracing::warn!(%err, "bypass: stored entry skipped");
                None
            }
        })
        .collect()
}

/// What Soft writes beside its own local entries, in each reader's syntax.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BypassLists {
    /// WinINet `ProxyOverride` items (joined with `;`).
    pub proxy_override: Vec<String>,
    /// `NO_PROXY` items (joined with `,`).
    pub no_proxy: Vec<String>,
}

/// The user's entries, then the automatic ones while both texts stay within [`MAX_TEXT`]. An
/// automatic `*.x` entry goes to `ProxyOverride` only: `.x` also covers the bare `x` in curl and
/// Python, and the routing may send that one through the VPN.
pub fn render(user: &[BypassEntry], auto: &[BypassEntry]) -> BypassLists {
    let mut out = BypassLists::default();
    let mut seen = (HashSet::new(), HashSet::new());
    for entry in user {
        add(&mut out.proxy_override, &mut seen.0, entry.override_items());
        add(&mut out.no_proxy, &mut seen.1, entry.no_proxy_items());
    }
    let mut left_out = 0usize;
    for entry in auto {
        let over = entry.override_items();
        let no_proxy = match entry {
            BypassEntry::Subdomains(_) => Vec::new(),
            _ => entry.no_proxy_items(),
        };
        let fits = |list: &[String], more: &[String]| text_len(list) + text_len(more) < MAX_TEXT;
        if !fits(&out.proxy_override, &over) || !fits(&out.no_proxy, &no_proxy) {
            left_out += 1;
            continue;
        }
        add(&mut out.proxy_override, &mut seen.0, over);
        add(&mut out.no_proxy, &mut seen.1, no_proxy);
    }
    if left_out > 0 {
        tracing::info!(
            left_out,
            "bypass: automatic entries over the size budget left out"
        );
    }
    out
}

fn add(list: &mut Vec<String>, seen: &mut HashSet<String>, items: Vec<String>) {
    list.extend(items.into_iter().filter(|i| seen.insert(i.clone())));
}

/// Length of the items joined with one separator each.
fn text_len(items: &[String]) -> usize {
    items.iter().map(|i| i.len() + 1).sum()
}

#[cfg(test)]
mod tests;
