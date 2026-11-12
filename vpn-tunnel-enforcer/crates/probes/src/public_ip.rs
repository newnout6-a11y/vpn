//! Public-IP reads: one read ("wave") asks the providers of one address family one after
//! another through a chosen route and stops at the first valid answer.
//!
//! Sequential, not a race (RU discipline, Nov 2026): through a running tunnel every provider
//! connection is a new connection to the VPN server, a TLS handshake with its name that the
//! handshake budget never sees. Four parallel requests were four handshakes inside a few ms,
//! the burst that freezes a server for ~120 s. A wave now costs one connection while its first
//! provider answers; after a failure the next provider starts no sooner than
//! [`MIN_GAP`](crate::discipline::MIN_GAP) after the previous one. A provider that hangs (its
//! request timeout or the wave's budget) uses up the wave: into a frozen tunnel a second
//! connection only extends the freeze. It hands the first turn of the next wave to the provider
//! after it; otherwise the provider that answered last goes first.
//!
//! Field lessons kept from the old monitor: the IP-literal Cloudflare trace is the default first
//! provider (the only one that needs no DNS), requests never use the system proxy, never follow
//! redirects and never reuse a pooled socket across waves (a socket opened before a network
//! transition must not answer for the new route), and a provider that answers 429 is skipped
//! until its `Retry-After` passes. Answers outside the public range (a captive portal or a
//! transparent proxy saying `10.x`) are rejected, never sampled.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use parking_lot::Mutex;
use reqwest::header::{CACHE_CONTROL, CONNECTION, HeaderMap, RETRY_AFTER};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Loopback, ProxyKind, UnixMs, now_ms};
use vpnte_core::net::{self, HostPort, Route};

use crate::discipline::MIN_GAP;
pub use crate::ip_echo::parse_provider_body;

/// Hard ceiling of one wave; callers can only shorten it.
pub const WAVE_BUDGET: Duration = Duration::from_millis(2000);
/// Part of the budget left for the socket of an attempt cut at the deadline to close (old
/// `IP_SOCKET_DRAIN_MS`).
const DRAIN: Duration = Duration::from_millis(200);
/// Provider answers are a few dozen bytes; anything larger is not an IP service.
const MAX_BODY: usize = 4096;
/// Backoff after a 429 without a usable `Retry-After`.
const BACKOFF_DEFAULT: Duration = Duration::from_secs(60);
/// Longest backoff a provider can impose.
const BACKOFF_MAX: Duration = Duration::from_secs(300);

/// IP address family of a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// Family of `ip` (an IPv4-mapped IPv6 address counts as IPv4).
    pub fn of(ip: IpAddr) -> Family {
        match net::unmap(ip) {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

/// One public-IP service, addressed once per family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provider {
    /// IPv4-only endpoint.
    pub v4: &'static str,
    /// IPv6-only endpoint, when the service has one.
    pub v6: Option<&'static str>,
}

impl Provider {
    /// The endpoint for `family`.
    pub fn url(&self, family: Family) -> Option<&'static str> {
        match family {
            Family::V4 => Some(self.v4),
            Family::V6 => self.v6,
        }
    }
}

/// The providers in default order. Family-specific endpoints pin the family on every route, also
/// through a SOCKS proxy that resolves names itself (`socks5h`).
pub const PROVIDERS: [Provider; 4] = [
    // IP literals: no DNS needed; Cloudflare's certificate carries both IP SANs.
    Provider {
        v4: "https://1.1.1.1/cdn-cgi/trace",
        v6: Some("https://[2606:4700:4700::1111]/cdn-cgi/trace"),
    },
    Provider {
        v4: "https://api.ipify.org?format=json",
        v6: Some("https://api6.ipify.org?format=json"),
    },
    Provider {
        v4: "https://ipv4.icanhazip.com",
        v6: Some("https://ipv6.icanhazip.com"),
    },
    Provider {
        v4: "https://api.myip.com",
        v6: None,
    },
];

/// How the provider requests leave the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpRoute {
    /// Sockets bound to our TUN's own addresses. Under Windows' strong-host send model such a
    /// socket can only leave through the TUN, so a sample is provably "through the tunnel" and a
    /// TUN outage yields an error instead of the user's real IP.
    Tun { v4: Ipv4Addr, v6: Option<Ipv6Addr> },
    /// Through an app-owned loopback SOCKS5 listener (engine inbound or proxy slot).
    Loopback(Loopback),
    /// Plain OS routing (no tunnel).
    Direct,
}

impl IpRoute {
    /// True when a sample read over this route proves the tunnel carries traffic.
    pub fn is_tun(&self) -> bool {
        matches!(self, IpRoute::Tun { .. })
    }
}

/// One successful public-IP read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpSample {
    pub ip: IpAddr,
    /// Index into [`PROVIDERS`] of the provider that answered.
    pub provider: u8,
    pub at: UnixMs,
}

/// Why one provider gave no sample. Log vocabulary only: never shown, never carries the URL,
/// the answer or the OS error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// The route has no address of the family (or the client could not be built).
    NoPath,
    Timeout,
    Connect,
    Network,
    Status(u16),
    RateLimited(Duration),
    TooLarge,
    InvalidIp,
    FamilyMismatch,
    NotPublic,
}

impl Fault {
    fn code(self) -> &'static str {
        match self {
            Fault::NoPath => "NO_PATH",
            Fault::Timeout => "DEADLINE",
            Fault::Connect => "CONNECT",
            Fault::Network => "NETWORK",
            Fault::Status(_) => "HTTP_STATUS",
            Fault::RateLimited(_) => "RATE_LIMITED",
            Fault::TooLarge => "TOO_LARGE",
            Fault::InvalidIp => "INVALID_IP",
            Fault::FamilyMismatch => "IP_FAMILY_MISMATCH",
            Fault::NotPublic => "NOT_PUBLIC",
        }
    }
}

/// Acceptance rule for a parsed answer: the requested family and a public address (B-IP-5).
fn accept(ip: IpAddr, family: Family) -> Result<IpAddr, Fault> {
    let ip = net::unmap(ip);
    if Family::of(ip) != family {
        Err(Fault::FamilyMismatch)
    } else if !net::is_public_ip(ip) {
        Err(Fault::NotPublic)
    } else {
        Ok(ip)
    }
}

/// Backoff demanded by a 429: `Retry-After` as seconds or as an HTTP date (B-IP-6), capped at
/// 5 minutes; missing, unparsable or already elapsed means 60 s.
fn retry_after(value: Option<&str>, now: SystemTime) -> Duration {
    let wait = value.map(str::trim).and_then(|v| {
        if let Ok(secs) = v.parse::<f64>() {
            (secs.is_finite() && secs > 0.0).then(|| Duration::from_secs_f64(secs.min(1e6)))
        } else {
            let at = jiff::fmt::rfc2822::DateTimeParser::new()
                .parse_timestamp(v)
                .ok()?;
            SystemTime::from(at).duration_since(now).ok()
        }
    });
    match wait {
        Some(wait) if !wait.is_zero() => wait.min(BACKOFF_MAX),
        _ => BACKOFF_DEFAULT,
    }
}

fn classify(err: &reqwest::Error) -> Fault {
    if err.is_timeout() {
        Fault::Timeout
    } else if err.is_connect() {
        Fault::Connect
    } else {
        Fault::Network
    }
}

fn clamp_budget(budget: Duration) -> Duration {
    if budget.is_zero() {
        WAVE_BUDGET
    } else {
        budget.min(WAVE_BUDGET)
    }
}

/// Runs waves and keeps between them the per-provider 429 backoff and which provider goes first.
/// Share one per app (`Arc`).
#[derive(Debug, Default)]
pub struct IpReader {
    backoff: Mutex<HashMap<&'static str, Instant>>,
    /// Index into [`PROVIDERS`] of the provider that opens the next wave.
    first: AtomicUsize,
}

/// How a sequential wave ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    Answer(usize, IpAddr),
    /// Every provider asked failed (or none could be asked in time).
    Failed,
    /// The provider at this index was still being asked when the budget ran out.
    Hung(usize),
    Cancelled,
}

impl IpReader {
    /// A reader with no provider in backoff.
    pub fn new() -> Self {
        Self::default()
    }

    /// One wave: the providers of `family` not in backoff, one after another over `route`, each
    /// on its own connection; the first valid answer ends it (normally one connection per
    /// wave). `budget` is capped at [`WAVE_BUDGET`] (zero = the cap). `None` when nothing valid
    /// arrived in time, the route has no path for `family`, or `cancel` fired. Never returns a
    /// cached value.
    pub async fn wave(
        &self,
        route: &IpRoute,
        family: Family,
        budget: Duration,
        cancel: &CancellationToken,
    ) -> Option<IpSample> {
        if cancel.is_cancelled() {
            return None;
        }
        let budget = clamp_budget(budget);
        let per_request = budget.saturating_sub(DRAIN).max(Duration::from_millis(1));
        let client = match build_client(route, family, per_request) {
            Ok(client) => client,
            Err(fault) => {
                tracing::debug!(?family, code = fault.code(), "public ip wave skipped");
                return None;
            }
        };
        let providers = self.order(family);
        let ask = |index, url| self.fetch(index, &client, url, family);
        let ended = first_answer(providers, ask, budget, cancel).await;
        let (index, ip) = self.settle(ended)?;
        Some(IpSample {
            ip,
            provider: index as u8,
            at: now_ms(),
        })
    }

    /// Keeps the first turn with the provider that answered, or passes it on from one that hung.
    fn settle(&self, ended: Ended) -> Option<(usize, IpAddr)> {
        match ended {
            Ended::Answer(index, ip) => {
                self.first.store(index, Ordering::Relaxed);
                Some((index, ip))
            }
            Ended::Hung(index) => {
                tracing::debug!(
                    provider = index,
                    "public ip provider hung; next wave starts after it"
                );
                self.first
                    .store((index + 1) % PROVIDERS.len(), Ordering::Relaxed);
                None
            }
            Ended::Failed | Ended::Cancelled => None,
        }
    }

    /// The providers of `family` not in backoff, starting with the one that opens the wave.
    fn order(&self, family: Family) -> Vec<(usize, &'static str)> {
        let (first, now) = (self.first.load(Ordering::Relaxed), Instant::now());
        let backoff = self.backoff.lock();
        (0..PROVIDERS.len())
            .map(|k| (first + k) % PROVIDERS.len())
            .filter_map(|index| {
                let url = PROVIDERS[index].url(family)?;
                if backoff.get(url).is_some_and(|until| *until > now) {
                    tracing::debug!(provider = index, outcome = "backoff", "public ip provider");
                    return None;
                }
                Some((index, url))
            })
            .collect()
    }

    async fn fetch(
        &self,
        index: usize,
        client: &reqwest::Client,
        url: &'static str,
        family: Family,
    ) -> Result<IpAddr, Fault> {
        let started = Instant::now();
        let result = fetch_one(client, url, family).await;
        if let Err(Fault::RateLimited(wait)) = result {
            self.backoff.lock().insert(url, Instant::now() + wait);
        }
        let (outcome, code) = match result {
            Ok(_) => ("succeeded", "OK"),
            Err(Fault::Timeout) => ("timeout", Fault::Timeout.code()),
            Err(fault) => ("failed", fault.code()),
        };
        let status = match result {
            Err(Fault::Status(status)) => Some(status),
            _ => None,
        };
        tracing::debug!(
            provider = index,
            outcome,
            code,
            status,
            ms = started.elapsed().as_millis() as u64,
            "public ip provider"
        );
        result
    }
}

/// Asks `providers` in order until one gives a valid answer, within `budget` and unless `cancel`
/// fires; a provider is only asked once the one before it failed. Starts keep [`MIN_GAP`]
/// between them: through a tunnel each attempt is a handshake with the VPN server, and
/// handshakes closer than ~350 ms are the burst the freeze heuristic punishes. A provider that
/// runs into its own request timeout hung like one cut by the budget: the wave ends there.
async fn first_answer<F, Fut>(
    providers: Vec<(usize, &'static str)>,
    mut ask: F,
    budget: Duration,
    cancel: &CancellationToken,
) -> Ended
where
    F: FnMut(usize, &'static str) -> Fut,
    Fut: Future<Output = Result<IpAddr, Fault>>,
{
    let deadline = tokio::time::Instant::now() + budget;
    let mut start = tokio::time::Instant::now();
    for (index, url) in providers {
        if start >= deadline {
            break;
        }
        let attempt = async {
            tokio::time::sleep_until(start).await;
            let began = tokio::time::Instant::now();
            (began, ask(index, url).await)
        };
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ended::Cancelled,
            result = tokio::time::timeout_at(deadline, attempt) => result,
        };
        match result {
            Ok((_, Ok(ip))) => return Ended::Answer(index, ip),
            Ok((_, Err(Fault::Timeout))) | Err(_) => return Ended::Hung(index),
            Ok((began, Err(_))) => start = began + MIN_GAP,
        }
    }
    Ended::Failed
}

async fn fetch_one(client: &reqwest::Client, url: &str, family: Family) -> Result<IpAddr, Fault> {
    let mut response = client
        .get(url)
        .header(CONNECTION, "close")
        .header(CACHE_CONTROL, "no-cache")
        .send()
        .await
        .map_err(|err| classify(&err))?;
    let status = response.status();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let header = header_str(response.headers());
        return Err(Fault::RateLimited(retry_after(header, SystemTime::now())));
    }
    if !status.is_success() {
        return Err(Fault::Status(status.as_u16()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|err| classify(&err))? {
        if body.len() + chunk.len() > MAX_BODY {
            return Err(Fault::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let ip = parse_provider_body(&String::from_utf8_lossy(&body)).ok_or(Fault::InvalidIp)?;
    accept(ip, family)
}

fn header_str(headers: &HeaderMap) -> Option<&str> {
    headers.get(RETRY_AFTER).and_then(|v| v.to_str().ok())
}

/// A fresh client per wave: no pooled socket outlives the wave (keep-alive off, HTTP/1.1 with
/// `Connection: close`), no system proxy, no redirects. Names resolve to the wave's family
/// only: a socket of the other family would not be bound to the TUN address (the connector
/// binds per family) and could leave outside the tunnel.
fn build_client(
    route: &IpRoute,
    family: Family,
    timeout: Duration,
) -> Result<reqwest::Client, Fault> {
    let builder = match route {
        IpRoute::Tun { v4, v6 } => {
            let local = match family {
                Family::V4 => IpAddr::V4(*v4),
                Family::V6 => IpAddr::V6(v6.ok_or(Fault::NoPath)?),
            };
            net::builder_for(&Route::Direct, timeout)
                .map_err(|_| Fault::NoPath)?
                .local_address(local)
                .dns_resolver(FamilyResolver(family))
        }
        // `socks5h`: the proxy resolves names; the endpoint itself pins the family.
        IpRoute::Loopback(lo) => {
            let addr = HostPort::new("127.0.0.1", lo.port).map_err(|_| Fault::NoPath)?;
            let route = Route::proxy(ProxyKind::Socks5, &addr, lo.creds.as_ref());
            net::builder_for(&route, timeout).map_err(|_| Fault::NoPath)?
        }
        IpRoute::Direct => net::builder_for(&Route::Direct, timeout)
            .map_err(|_| Fault::NoPath)?
            .dns_resolver(FamilyResolver(family)),
    };
    builder
        .pool_max_idle_per_host(0)
        .http1_only()
        .build()
        .map_err(|_| Fault::NoPath)
}

/// The OS resolver, keeping only addresses of one family.
struct FamilyResolver(Family);

impl reqwest::dns::Resolve for FamilyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let family = self.0;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let found = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let kept: Vec<std::net::SocketAddr> =
                found.filter(|a| Family::of(a.ip()) == family).collect();
            if kept.is_empty() {
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
            }
            let addrs: reqwest::dns::Addrs = Box::new(kept.into_iter());
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests;
