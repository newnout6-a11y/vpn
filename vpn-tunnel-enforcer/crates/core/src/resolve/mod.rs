//! Name resolution for app-side lookups: the OS resolver, or DNS-over-HTTPS when the system DNS
//! is blocked or poisoned (the subscription fallback, profiles §3.7 / servers §2.5). Only the
//! addresses the caller's filter accepts come back: a poisoned `127.0.0.1` answer must never
//! become a dial target (S-29).
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use reqwest::header::ACCEPT;
use serde::Deserialize;
use url::Url;
use vpnte_base::{AppError, ErrorKind, Msg, http};

use crate::net::Host;

/// DoH JSON endpoints, tried in order. IP literals: the lookup needs no DNS of its own and sends
/// no SNI (the certificates of both services carry these addresses).
const DOH_ENDPOINTS: [&str; 2] = ["https://1.1.1.1/dns-query", "https://8.8.8.8/resolve"];
/// Per-request limits of the old curl DoH call (`--max-time 12 --connect-timeout 6`).
const DOH_TIMEOUT: Duration = Duration::from_secs(12);
const DOH_CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const DOH_BODY_CAP: usize = 64 * 1024;

/// How to resolve a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    /// The OS resolver (`getaddrinfo`); follows the system DNS, through the tunnel when it is up.
    System,
    /// DNS-over-HTTPS, direct: Cloudflare `1.1.1.1`, then Google `8.8.8.8`; A and AAAA.
    Doh,
}

/// Why a name gave no usable address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("not an IP literal or a valid host name")]
    InvalidName,
    #[error("the name has no addresses")]
    NotFound,
    #[error("every address was refused by the filter")]
    Filtered,
    #[error("the resolver failed")]
    Failed,
}

impl From<ResolveError> for AppError {
    fn from(err: ResolveError) -> Self {
        let (kind, key) = match err {
            ResolveError::InvalidName => (ErrorKind::Validation, "core.net.resolveInvalidName"),
            ResolveError::NotFound => (ErrorKind::Network, "core.net.resolveNotFound"),
            ResolveError::Filtered => (ErrorKind::Network, "core.net.resolveFiltered"),
            ResolveError::Failed => (ErrorKind::Network, "core.net.resolveFailed"),
        };
        AppError::msg(kind, Msg::new(key)).with_source(err)
    }
}

/// Resolves `name` to its addresses that pass `keep`: deduplicated, IPv4 (A) before IPv6
/// (AAAA). An IP literal is checked and returned without a lookup. `System` has no deadline of
/// its own (wrap the call in `tokio::time::timeout`); `Doh` allows 12 s per request. Dropping
/// the future cancels the lookup.
pub async fn resolve_host(
    name: &str,
    how: How,
    keep: impl Fn(IpAddr) -> bool,
) -> Result<Vec<IpAddr>, ResolveError> {
    let name = match Host::parse(name).map_err(|_| ResolveError::InvalidName)? {
        Host::Ip(ip) => return filtered(vec![ip], &keep),
        Host::Name(name) => name,
    };
    match how {
        How::System => filtered(system(&name).await?, &keep),
        How::Doh => doh(&DOH_ENDPOINTS, &name, &keep).await,
    }
}

async fn system(name: &str) -> Result<Vec<IpAddr>, ResolveError> {
    match tokio::net::lookup_host((name, 0)).await {
        Ok(addrs) => Ok(addrs.map(|addr| addr.ip()).collect()),
        Err(err) => {
            tracing::debug!(error = %err, "system DNS lookup failed");
            Err(lookup_error(&err))
        }
    }
}

/// WSAHOST_NOT_FOUND (11001) and WSANO_DATA (11004): the name does not exist or has no A/AAAA.
fn lookup_error(err: &io::Error) -> ResolveError {
    match err.raw_os_error() {
        Some(11001 | 11004) => ResolveError::NotFound,
        _ => ResolveError::Failed,
    }
}

/// Deduplicates, puts IPv4 first (stable within a family) and applies `keep`.
fn filtered(
    addrs: Vec<IpAddr>,
    keep: &impl Fn(IpAddr) -> bool,
) -> Result<Vec<IpAddr>, ResolveError> {
    if addrs.is_empty() {
        return Err(ResolveError::NotFound);
    }
    let mut unique: Vec<IpAddr> = Vec::with_capacity(addrs.len());
    for ip in addrs {
        if !unique.contains(&ip) {
            unique.push(ip);
        }
    }
    unique.sort_by_key(IpAddr::is_ipv6);
    unique.retain(|ip| keep(*ip));
    if unique.is_empty() {
        Err(ResolveError::Filtered)
    } else {
        Ok(unique)
    }
}

/// Asks each endpoint for A and AAAA (in parallel); the first endpoint with a usable address
/// wins. Final error: `Filtered` if some answer was refused by `keep`, else `NotFound` if some
/// endpoint answered without addresses, else `Failed`.
async fn doh(
    endpoints: &[&str],
    name: &str,
    keep: &impl Fn(IpAddr) -> bool,
) -> Result<Vec<IpAddr>, ResolveError> {
    let client = http::client_builder(DOH_TIMEOUT)
        .connect_timeout(DOH_CONNECT_TIMEOUT)
        .build()
        .map_err(|err| {
            tracing::warn!(error = %err, "DoH client could not be built");
            ResolveError::Failed
        })?;
    let mut outcome = ResolveError::Failed;
    for (index, endpoint) in endpoints.iter().enumerate() {
        let (a, aaaa) = tokio::join!(
            query(&client, endpoint, name, Record::A),
            query(&client, endpoint, name, Record::Aaaa)
        );
        let mut found = Vec::new();
        let mut answered = false;
        for result in [a, aaaa] {
            match result {
                Ok(addrs) => {
                    answered = true;
                    found.extend(addrs);
                }
                Err(ResolveError::NotFound) => answered = true,
                Err(_) => {}
            }
        }
        match filtered(found, keep) {
            Ok(addrs) => return Ok(addrs),
            Err(ResolveError::Filtered) => outcome = ResolveError::Filtered,
            Err(_) if answered && outcome == ResolveError::Failed => {
                outcome = ResolveError::NotFound
            }
            Err(_) => {}
        }
        tracing::debug!(
            endpoint = index,
            ?outcome,
            "DoH endpoint gave no usable address"
        );
    }
    Err(outcome)
}

#[derive(Debug, Clone, Copy)]
enum Record {
    A,
    Aaaa,
}

impl Record {
    fn name(self) -> &'static str {
        match self {
            Record::A => "A",
            Record::Aaaa => "AAAA",
        }
    }

    fn code(self) -> u16 {
        match self {
            Record::A => 1,
            Record::Aaaa => 28,
        }
    }

    /// Parses an answer's `data` as an address of this record's family.
    fn address(self, data: &str) -> Option<IpAddr> {
        let ip: IpAddr = data.trim().parse().ok()?;
        (ip.is_ipv4() == matches!(self, Record::A)).then_some(ip)
    }
}

/// JSON DoH reply (Cloudflare `application/dns-json` and Google `/resolve` share the shape).
#[derive(Deserialize)]
struct Reply {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer", default)]
    answer: Vec<Answer>,
}

#[derive(Deserialize)]
struct Answer {
    #[serde(rename = "type")]
    record: u16,
    data: String,
}

/// One DoH question. NXDOMAIN → `NotFound`; transport, HTTP, size or JSON problems → `Failed`;
/// NOERROR → the addresses of the asked type (CNAME steps and malformed data are skipped).
async fn query(
    client: &reqwest::Client,
    endpoint: &str,
    name: &str,
    record: Record,
) -> Result<Vec<IpAddr>, ResolveError> {
    let mut url = Url::parse(endpoint).map_err(|_| ResolveError::Failed)?;
    url.query_pairs_mut()
        .append_pair("name", name)
        .append_pair("type", record.name());
    let failed = |what: &str, err: Option<reqwest::Error>| {
        let err = err.map(|e| e.without_url().to_string()).unwrap_or_default();
        tracing::debug!(record = record.name(), error = %err, "DoH query failed: {what}");
        ResolveError::Failed
    };
    let response = client
        .get(url)
        .header(ACCEPT, "application/dns-json")
        .send()
        .await
        .map_err(|err| failed("request", Some(err)))?;
    if !response.status().is_success() {
        return Err(failed("HTTP status", None));
    }
    let body = read_capped(response, DOH_BODY_CAP)
        .await
        .ok_or_else(|| failed("body", None))?;
    let reply: Reply = serde_json::from_slice(&body).map_err(|_| failed("JSON", None))?;
    match reply.status {
        0 => Ok(reply
            .answer
            .iter()
            .filter(|answer| answer.record == record.code())
            .filter_map(|answer| record.address(&answer.data))
            .collect()),
        3 => Err(ResolveError::NotFound),
        _ => Err(failed("DNS status", None)),
    }
}

/// The body, or `None` when reading fails or it exceeds `cap` bytes.
async fn read_capped(mut response: reqwest::Response, cap: usize) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len() + chunk.len() > cap {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some(body)
}

#[cfg(test)]
mod tests;
