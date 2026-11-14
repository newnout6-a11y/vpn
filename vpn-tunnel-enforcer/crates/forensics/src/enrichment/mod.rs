//! Opt-in site names for the domain history («обогащение»): fetches the main document of
//! `https://<registrable domain>/` and keeps its site name, title, description, canonical URL and
//! icon. Off by default; queued only by the 15 s background tick, never by a UI read.
//!
//! SSRF guard: every hop's host is resolved first and refused when any address is not public;
//! on the direct route the request is pinned to the vetted addresses, so a rebinding answer cannot
//! redirect it (F-177). Through a proxy the proxy resolves the name, only the pre-check applies.
use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use vpnte_base::types::{ProxyKind, UnixMs};
use vpnte_core::net::{HostPort, Route};
use vpnte_core::store::Document;

use crate::domains::DomainRecord;

mod fetch;
mod page;
mod service;

pub use service::Enricher;

/// A site name stays fresh this long.
pub const READY_TTL_MS: i64 = 30 * 24 * 3600 * 1000;
/// A failed lookup is retried after this long.
pub const FAILURE_TTL_MS: i64 = 24 * 3600 * 1000;
/// Cache entries kept (newest by fetch time).
pub const MAX_ENTRIES: usize = 1000;
/// Lookups running at the same time.
pub const MAX_CONCURRENT: usize = 2;
/// Domains queued or running at most; the next tick refills.
pub const MAX_PENDING: usize = 8;
/// Deadline of one lookup, redirects and name checks included.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);
/// Background tick that queues the history's domains.
pub const TICK: Duration = Duration::from_secs(15);

/// Lookup state of one registrable domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnrichStatus {
    /// Queued or running (never stored).
    Pending,
    Ready,
    Unavailable,
}

/// What is known about a site. Text is display data from the site itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainEnrichment {
    pub status: EnrichStatus,
    pub site_name: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub canonical_url: Option<String>,
    pub favicon_url: Option<String>,
    pub fetched_at: UnixMs,
}

impl DomainEnrichment {
    fn empty(status: EnrichStatus, now: UnixMs) -> Self {
        Self {
            status,
            site_name: None,
            title: None,
            description: None,
            canonical_url: None,
            favicon_url: None,
            fetched_at: now,
        }
    }

    /// Still valid at `now` (ready: 30 days, unavailable: 24 hours).
    pub fn is_fresh(&self, now: UnixMs) -> bool {
        let ttl = match self.status {
            EnrichStatus::Ready => READY_TTL_MS,
            EnrichStatus::Unavailable | EnrichStatus::Pending => FAILURE_TTL_MS,
        };
        now - self.fetched_at < ttl
    }
}

/// `cache/domain-info.json`: registrable domain → result, at most [`MAX_ENTRIES`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichmentDoc {
    #[serde(default)]
    pub entries: BTreeMap<String, DomainEnrichment>,
}

impl Document for EnrichmentDoc {
    const FILE: &'static str = "cache/domain-info.json";
    const VERSION: u32 = 1;
}

impl EnrichmentDoc {
    /// Converts the old `domain-intelligence.json` (`{entries: {key: DomainEnrichment}}`): keeps
    /// ready / unavailable entries with a valid key, URLs re-checked, newest [`MAX_ENTRIES`].
    pub fn from_legacy(old: &Value) -> Self {
        let mut entries: Vec<(String, DomainEnrichment)> = old
            .get("entries")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter_map(|(key, entry)| {
                let key = registrable(key)?;
                let mut e: DomainEnrichment = serde_json::from_value(entry.clone()).ok()?;
                if e.status == EnrichStatus::Pending {
                    return None;
                }
                e.canonical_url = e.canonical_url.filter(|u| allowed_url_str(u));
                e.favicon_url = e.favicon_url.filter(|u| allowed_url_str(u));
                Some((key, e))
            })
            .collect();
        entries.sort_by_key(|(_, e)| std::cmp::Reverse(e.fetched_at));
        entries.truncate(MAX_ENTRIES);
        Self {
            entries: entries.into_iter().collect(),
        }
    }
}

/// A host worth looking up, lowercased (IDN as punycode); `None` for paths, user info, single
/// labels, IP literals and local names.
pub fn normalize_domain(input: &str) -> Option<String> {
    let raw = input.trim();
    let raw = raw.strip_suffix('.').unwrap_or(raw);
    if raw.is_empty() || raw.contains('/') || raw.contains('@') {
        return None;
    }
    let url = Url::parse(&format!("https://{raw}")).ok()?;
    let host = match url.host()? {
        url::Host::Domain(host) => host.to_ascii_lowercase(),
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => return None,
    };
    let local = host == "localhost"
        || [".local", ".internal", ".lan"]
            .iter()
            .any(|tld| host.ends_with(tld));
    (host.contains('.') && !local).then_some(host)
}

/// The registrable domain (public suffix + one label, private suffixes included) the cache is
/// keyed by: `contacts.google.com` → `google.com`.
pub fn registrable(host: &str) -> Option<String> {
    let host = normalize_domain(host)?;
    Some(psl::domain_str(&host).map_or_else(|| host.clone(), str::to_owned))
}

/// A URL a lookup may load or keep: https on the default port, no user info, a valid host.
pub fn allowed_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.host_str().and_then(normalize_domain).is_some()
}

fn allowed_url_str(url: &str) -> bool {
    Url::parse(url).is_ok_and(|u| allowed_url(&u))
}

/// Route through the local proxy at `addr` (`host:port`, or `<kind>://host:port`): the scheme
/// must match `kind`; credentials, paths, queries and fragments are refused.
pub fn proxy_route(addr: &str, kind: ProxyKind) -> Option<Route> {
    let addr = addr.trim();
    let scheme = match kind {
        ProxyKind::Socks5 => "socks5",
        ProxyKind::Http => "http",
    };
    let host_port = match addr.split_once("://") {
        None => HostPort::parse(addr).ok()?,
        Some(_) => {
            let url = Url::parse(addr).ok()?;
            let clean = url.scheme() == scheme
                && url.username().is_empty()
                && url.password().is_none()
                && matches!(url.path(), "" | "/")
                && url.query().is_none()
                && url.fragment().is_none();
            if !clean {
                return None;
            }
            HostPort::new(url.host_str()?, url.port()?).ok()?
        }
    };
    Some(Route::proxy(kind, &host_port, None))
}

/// A history row with its site info, as the history page and «Последние сайты» show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    #[serde(flatten)]
    pub record: DomainRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrichment: Option<DomainEnrichment>,
}

/// What the enrichment needs from settings and the connection state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnrichInputs {
    /// The `domain_enrichment` setting.
    pub enabled: bool,
    /// Egress for lookups: the active local proxy in local-proxy mode ([`proxy_route`]), direct
    /// while the tunnel runs (sockets ride the TUN), else `None` (no lookups, nothing attached).
    pub route: Option<Route>,
}

#[cfg(test)]
mod tests;
