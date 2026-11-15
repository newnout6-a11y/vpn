//! Domain history («История трафика»): the sites reached while protected, with connection and
//! lookup counts, bytes and first / last sight. Fed by two live sources:
//! 1. Clash `/connections` snapshots (authoritative: sniffed names and per-flow bytes);
//! 2. the engine's INFO DNS answer lines on its stdout / stderr pipe (lookups that never became a
//!    sniffed connection, and the IP → name map for flows whose `host` is empty).
//!
//! Keep the engine log level at `info`: `debug` floods the log, and the per-record answers the
//! observer reads are INFO lines in sing-box 1.14.
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vpnte_base::types::UnixMs;
use vpnte_core::store::Document;

mod history;
mod service;

pub use history::History;
pub use service::{HistoryService, NewConnectionHook};

/// Most-recent domains kept (by last sight).
pub const MAX_DOMAINS: usize = 2000;
/// A change reaches the disk at most this long after it happened.
pub const PERSIST_DELAY: Duration = Duration::from_secs(10);

/// Well-known DoH / DoT resolver hosts: sing-box dials them for its own DNS, they are never a
/// site the user visited.
pub const DOH_INFRA_HOSTS: &[&str] = &[
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "one.one.one.one",
    "dns.google",
    "dns.google.com",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "dns.adguard-dns.com",
    "unfiltered.adguard-dns.com",
    "family.adguard-dns.com",
    "doh.opendns.com",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
    "security.cloudflare-dns.com",
    "dns.controld.com",
    "freedns.controld.com",
];

/// One visited domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRecord {
    pub domain: String,
    pub first_seen: UnixMs,
    pub last_seen: UnixMs,
    /// Distinct tunnelled connections (Clash ids) seen for this domain.
    #[serde(default)]
    pub connections: u32,
    /// DNS exchanges that answered for this domain.
    #[serde(default)]
    pub lookups: u32,
    #[serde(default)]
    pub bytes_up: u64,
    #[serde(default)]
    pub bytes_down: u64,
    /// Outbound tag the route picked for the latest connection (`proxy-out`, `direct-out` …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
}

impl DomainRecord {
    fn new(domain: &str, now: UnixMs) -> Self {
        Self {
            domain: domain.to_owned(),
            first_seen: now,
            last_seen: now,
            connections: 0,
            lookups: 0,
            bytes_up: 0,
            bytes_down: 0,
            outbound: None,
        }
    }

    /// The count to show: connections when any were seen, else DNS lookups.
    pub fn visits(&self) -> u32 {
        if self.connections > 0 {
            self.connections
        } else {
            self.lookups
        }
    }
}

/// `history/traffic-domains.json`: domain → record, at most [`MAX_DOMAINS`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainsDoc {
    #[serde(default)]
    pub domains: BTreeMap<String, DomainRecord>,
}

impl Document for DomainsDoc {
    const FILE: &'static str = "history/traffic-domains.json";
    const VERSION: u32 = 1;
}

impl DomainsDoc {
    /// Converts the old `traffic-domains.json` (`{domains: {d: {domain, firstSeen, lastSeen,
    /// count, bytesUp, bytesDown}}}`): `count` becomes `connections`; records whose name would
    /// not be recorded today are skipped; the newest [`MAX_DOMAINS`] are kept.
    pub fn from_legacy(old: &Value) -> Self {
        let num = |v: &Value, key: &str| v.get(key).and_then(Value::as_f64).unwrap_or(0.0);
        let mut records: Vec<DomainRecord> = old
            .get("domains")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter_map(|(key, rec)| {
                let domain = should_record(key, &HashSet::new())?;
                let first_seen = num(rec, "firstSeen").max(0.0) as UnixMs;
                let last_seen = num(rec, "lastSeen").max(0.0) as UnixMs;
                Some(DomainRecord {
                    first_seen: first_seen.min(last_seen),
                    last_seen,
                    connections: num(rec, "count").max(0.0).min(u32::MAX as f64) as u32,
                    bytes_up: num(rec, "bytesUp").max(0.0) as u64,
                    bytes_down: num(rec, "bytesDown").max(0.0) as u64,
                    ..DomainRecord::new(&domain, 0)
                })
            })
            .collect();
        records.sort_by_key(|r| std::cmp::Reverse(r.last_seen));
        records.truncate(MAX_DOMAINS);
        Self {
            domains: records.into_iter().map(|r| (r.domain.clone(), r)).collect(),
        }
    }
}

/// Lowercases, unwraps `[v6]`, drops a trailing `:port` and trailing dots; `None` when empty.
pub fn normalize_host(raw: &str) -> Option<String> {
    let mut host = raw.trim().to_lowercase();
    if let Some(inner) = host.strip_prefix('[') {
        if let Some(close) = inner.find(']') {
            host = inner[..close].to_owned();
        }
    } else if host.parse::<IpAddr>().is_err()
        && let Some(colon) = host.rfind(':')
        && colon > 0
    {
        let port = &host[colon + 1..];
        if (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit()) {
            host.truncate(colon);
        }
    }
    let host = host.trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_owned())
}

static LOCAL_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^localhost$|\.local$|\.internal$|\.lan$|\.home$|\.arpa$").expect("valid regex")
});

/// The normalised host if it is a site worth recording; `None` for IP literals, single labels,
/// local / reverse / service-discovery names, DoH resolvers, `infra` (configured servers) and
/// text that is no host name at all (a sniffed HTTP `Host` header can carry anything).
pub fn should_record(raw: &str, infra: &HashSet<String>) -> Option<String> {
    let host = normalize_host(raw)?;
    let noise = host.len() > 253
        || !host
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '.' | '_'))
        || host.parse::<IpAddr>().is_ok()
        || !host.contains('.')
        || LOCAL_HOST.is_match(&host)
        || host.starts_with('_')
        || host.contains("._")
        || DOH_INFRA_HOSTS.contains(&host.as_str())
        || infra.contains(&host);
    (!noise).then_some(host)
}

#[cfg(test)]
mod tests;
