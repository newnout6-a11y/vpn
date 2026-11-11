//! Name resolution for app-side lookups: the OS resolver, or a direct chain of public resolvers
//! (DoH by IP literal, DoH by name, DNS over TCP) that survives the 2026 Russian DNS blocking
//! (ru-2026 Ф9), plus [`resolve_server`] for VPN server names with a last-known-address bridge.
//! Only the addresses the caller's filter accepts come back: a poisoned `127.0.0.1` answer must
//! never become a dial target (S-29).
use std::io;
use std::net::IpAddr;
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use vpnte_base::{AppError, ErrorKind, Msg};

use crate::net::Host;

mod chain;
mod server;
mod transport;
mod wire;

use chain::{Chain, STAGGER, UPSTREAM_LIMIT, UPSTREAMS};
use server::LastKnown;
pub use server::ServerAddrs;
use transport::Net;

/// Budget of the OS resolver inside [`resolve_server`] (the old endpoint-resolution limit).
const SYSTEM_LIMIT: Duration = Duration::from_millis(2_500);

/// How to resolve a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    /// The OS resolver (`getaddrinfo`); follows the system DNS, through the tunnel when it is up.
    System,
    /// The direct chain: DoH to 1.1.1.1, 9.9.9.9, 8.8.8.8, 94.140.14.140, then DoH by name
    /// (Yandex, Cloudflare), then DNS over TCP to 8.8.8.8, 1.1.1.1, 77.88.8.8; A and AAAA.
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
    /// Only forged answers came back (NXDOMAIN with AA, block-page addresses).
    #[error("the DNS answers were forged")]
    Poisoned,
    #[error("the resolver failed")]
    Failed,
}

impl From<ResolveError> for AppError {
    fn from(err: ResolveError) -> Self {
        let (kind, key) = match err {
            ResolveError::InvalidName => (ErrorKind::Validation, "core.net.resolveInvalidName"),
            ResolveError::NotFound => (ErrorKind::Network, "core.net.resolveNotFound"),
            ResolveError::Filtered => (ErrorKind::Network, "core.net.resolveFiltered"),
            ResolveError::Poisoned => (ErrorKind::Network, "core.net.resolvePoisoned"),
            ResolveError::Failed => (ErrorKind::Network, "core.net.resolveFailed"),
        };
        AppError::msg(kind, Msg::new(key)).with_source(err)
    }
}

/// Resolves `name` to its addresses that pass `keep`: deduplicated, IPv4 (A) before IPv6
/// (AAAA). An IP literal is checked and returned without a lookup. `System` has no deadline of
/// its own (wrap the call in `tokio::time::timeout`); `Doh` gives each upstream 3 s and starts
/// the next one after 0.7 s without an answer. Dropping the future cancels the lookup.
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
        How::Doh => chain().resolve(&name, &keep).await,
    }
}

/// Resolves a VPN server name before an engine dials it: the direct chain, then the OS
/// resolver (2.5 s), then the addresses this name resolved to last time in this process
/// (`last_known`, with a warning for the user) when DNS fails or is poisoned. Block-page
/// addresses are never returned. An IP literal comes back as is (filtered, not remembered).
pub async fn resolve_server(
    name: &str,
    keep: impl Fn(IpAddr) -> bool,
) -> Result<ServerAddrs, ResolveError> {
    let name = match Host::parse(name).map_err(|_| ResolveError::InvalidName)? {
        Host::Ip(ip) => {
            let addrs = filtered(vec![ip], &keep)?;
            return Ok(ServerAddrs {
                addrs,
                last_known: false,
            });
        }
        Host::Name(name) => name,
    };
    static LAST_KNOWN: LazyLock<LastKnown> = LazyLock::new(LastKnown::default);
    let os = || async {
        tokio::time::timeout(SYSTEM_LIMIT, system(&name))
            .await
            .unwrap_or(Err(ResolveError::Failed))
    };
    server::server(&name, &keep, chain(), &LAST_KNOWN, os).await
}

/// The process-wide chain: one connection pool and one remembered winner for every caller.
fn chain() -> &'static Chain<Net> {
    static CHAIN: OnceLock<Chain<Net>> = OnceLock::new();
    CHAIN.get_or_init(|| Chain::new(UPSTREAMS.to_vec(), Net::new(), STAGGER, UPSTREAM_LIMIT))
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

#[cfg(test)]
mod tests;
