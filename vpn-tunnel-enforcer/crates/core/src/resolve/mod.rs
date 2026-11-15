//! Name resolution for app-side lookups: the OS resolver, or a direct chain of public resolvers
//! (DoH by IP literal, DoH by name, DNS over TCP) that survives the 2026 Russian DNS blocking
//! (ru-2026 Ф9), plus [`resolve_server`] for VPN server names with a last-known-address bridge.
//! Only the addresses the caller's filter accepts come back: a poisoned `127.0.0.1` answer must
//! never become a dial target (S-29).
use std::io;
use std::net::IpAddr;
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use vpnte_base::types::Loopback;
use vpnte_base::{AppError, ErrorKind, Msg};

use crate::net::Host;

mod ahead;
mod chain;
mod memory;
mod server;
mod session;
mod transport;
mod wire;

use chain::{CLOUDFLARE_DOH, Chain, STAGGER, UPSTREAM_LIMIT, UPSTREAMS, YANDEX_DOH};
pub use memory::{MEMORY_TTL, ResolverMemoryDoc, persist, set_network};
use server::LastKnown;
pub use server::ServerAddrs;
pub use session::{
    RECENT_FOR, drop_names, end_session, forget, keep_for_session, keep_resolved, owned_by,
    remember, remembers,
};
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
    // The running session's server name: its kept answer, no lookup (lab F11); an ended
    // session's for 10 min more (S3-09 (a)).
    if let Some(addrs) = session::kept(&name).or_else(|| session::recent(&name)) {
        return filtered(addrs, &keep);
    }
    match how {
        How::System => filtered(system(&name).await?, &keep),
        How::Doh => chain().resolve(&name, &keep).await,
    }
}

/// One DoH-by-name resolver of the chain, asked on its own by the network-mode check: RU SNI
/// filtering cuts the foreign one while the Russian one stays reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DohByName {
    /// `cloudflare-dns.com`.
    Cloudflare,
    /// `common.dot.dns.yandex.net`.
    Yandex,
}

/// Asks exactly `resolver` for `name` (A and AAAA within 3 s), directly or through `via` (a
/// loopback SOCKS5 inbound). The process-wide chain and its remembered winner stay untouched.
pub async fn resolve_with(
    name: &str,
    resolver: DohByName,
    via: Option<&Loopback>,
    keep: impl Fn(IpAddr) -> bool,
) -> Result<Vec<IpAddr>, ResolveError> {
    let name = match Host::parse(name).map_err(|_| ResolveError::InvalidName)? {
        Host::Ip(ip) => return filtered(vec![ip], &keep),
        Host::Name(name) => name,
    };
    let upstream = match resolver {
        DohByName::Cloudflare => CLOUDFLARE_DOH,
        DohByName::Yandex => YANDEX_DOH,
    };
    let net = via.map_or_else(Net::new, Net::via);
    Chain::new(vec![upstream], net, STAGGER, UPSTREAM_LIMIT)
        .resolve(&name, &keep)
        .await
}

/// Resolves a VPN server name before an engine dials it: the running session's kept answer, an
/// ended session's recent one (S3-09 (a)), else the direct chain, then the OS resolver (2.5 s),
/// then the addresses this name resolved to last time in this process (`last_known`, with a
/// warning for the user) when DNS fails or is poisoned. Block-page addresses are never
/// returned. An IP literal comes back as is (filtered, not remembered).
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
    if let Some(addrs) = session::kept(&name).or_else(|| session::recent(&name)) {
        return Ok(ServerAddrs {
            addrs: filtered(addrs, &keep)?,
            last_known: false,
        });
    }
    // While a session runs the OS resolver is never asked: it would send the server's name in
    // clear text past the tunnel (lab F11).
    let running = session::running();
    let os = || async {
        if running {
            return Err(ResolveError::Failed);
        }
        tokio::time::timeout(SYSTEM_LIMIT, system(&name))
            .await
            .unwrap_or(Err(ResolveError::Failed))
    };
    server::server(&name, &keep, chain(), last_known(), os).await
}

/// speed3 S3-09 (b): a server name looked up before the click (the selected server, and since
/// lab L11-4 the user's likely picks) over the foreign IP-literal DoH resolvers only: no name to
/// resolve first, no SNI a filter could read, nothing to the ISP's or the OS's resolver, no
/// Russian resolver. An address to dial (no AAAA grace). The answer is remembered for this
/// Windows user for [`RECENT_FOR`] ([`remember`]); while it runs, a second asker of the name
/// joins it ([`recall`]). `Err`: the connect resolves as usual.
pub async fn resolve_ahead(name: &str) -> Result<Vec<IpAddr>, ResolveError> {
    let Host::Name(name) = Host::parse(name).map_err(|_| ResolveError::InvalidName)? else {
        // A literal needs no lookup.
        return Err(ResolveError::InvalidName);
    };
    let lookup = async {
        let found = foreign().resolve_dial(&name, &|_| true).await;
        // Remembered before the lookup leaves the flight: [`recall`] reads the flight first, so
        // no asker falls between the two.
        if let Ok(addrs) = &found {
            remember(&name, addrs.clone());
        }
        found
    };
    ahead::shared(session::owner(), &name, lookup).await
}

/// Lab L11-4: the answer for server name `name` this process holds without asking anyone: the
/// running session's kept one, a recent one of this Windows user (an ended session's, a lookup
/// ahead of the click), else what an ahead lookup of it in flight brings, joined (never asked
/// twice). Unfiltered: the caller filters it as a looked-up answer. `None`: ask as usual.
pub async fn recall(name: &str) -> Option<Vec<IpAddr>> {
    let Ok(Host::Name(name)) = Host::parse(name) else {
        return None;
    };
    let memory = || session::kept(&name).or_else(|| session::recent(&name));
    ahead::recall(session::owner().as_deref(), &name, memory).await
}

/// An address a server may have, as every lookup here judges it (block pages, loopback,
/// link-local and multicast never are): the filter of an address learned elsewhere (S3-09 hints).
pub fn may_be_server(ip: IpAddr) -> bool {
    !chain::block_page(ip)
}

/// The last good addresses of server names, shared with the persisted memory.
fn last_known() -> &'static LastKnown {
    static LAST_KNOWN: LazyLock<LastKnown> = LazyLock::new(LastKnown::default);
    &LAST_KNOWN
}

/// The foreign IP-literal DoH resolvers of [`resolve_ahead`]: one connection pool for every
/// lookup ahead (lab L12-5: a provider graph's names are looked up together, one TLS
/// connection instead of one per name).
fn foreign() -> &'static Chain<Net> {
    static FOREIGN: OnceLock<Chain<Net>> = OnceLock::new();
    FOREIGN.get_or_init(|| {
        let foreign = UPSTREAMS.into_iter().filter(chain::ip_literal_doh);
        Chain::new(foreign.collect(), Net::new(), STAGGER, UPSTREAM_LIMIT)
    })
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
