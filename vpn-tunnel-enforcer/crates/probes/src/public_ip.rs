//! Public-IP provider race: one read ("wave") asks every provider of one address family in
//! parallel through a chosen route and takes the first valid answer.
//!
//! Field lessons kept from the old monitor: the IP-literal Cloudflare trace comes first (the
//! only provider that needs no DNS), requests never use the system proxy, never follow
//! redirects and never reuse a pooled socket across waves (a socket opened before a network
//! transition must not answer for the new route), and a provider that answers 429 is skipped
//! until its `Retry-After` passes. Answers outside the public range (a captive portal or a
//! transparent proxy saying `10.x`) are rejected, never sampled.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant, SystemTime};

use futures_util::stream::{FuturesUnordered, StreamExt};
use parking_lot::Mutex;
use reqwest::header::{CACHE_CONTROL, CONNECTION, HeaderMap, RETRY_AFTER};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Loopback, ProxyKind, UnixMs, now_ms};
use vpnte_core::net::{self, HostPort, Route};

/// Hard ceiling of one wave; callers can only shorten it.
pub const WAVE_BUDGET: Duration = Duration::from_millis(2000);
/// Part of the budget left for the dropped losers' sockets to close (old `IP_SOCKET_DRAIN_MS`).
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

/// The providers in race order. Family-specific endpoints pin the family on every route, also
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
    /// Index into [`PROVIDERS`] of the provider that answered first.
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

/// Extracts the address from a provider answer: a JSON object's `ip` (or `query`), a
/// Cloudflare trace `ip=` line, or a bare address. Range and family checks come after.
pub fn parse_provider_body(body: &str) -> Option<IpAddr> {
    let text = body.trim();
    let candidate = if text.starts_with('{') {
        let json: serde_json::Value = serde_json::from_str(text).ok()?;
        ["ip", "query"].iter().find_map(|key| {
            json.get(key)?
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .map(str::to_owned)
        })?
    } else if let Some(ip) = text.lines().find_map(|line| line.strip_prefix("ip=")) {
        ip.to_owned()
    } else {
        text.to_owned()
    };
    candidate.trim().parse().ok()
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

/// Runs waves and keeps the per-provider 429 backoff between them. Share one per app (`Arc`).
#[derive(Debug, Default)]
pub struct IpReader {
    backoff: Mutex<HashMap<&'static str, Instant>>,
}

impl IpReader {
    /// A reader with no provider in backoff.
    pub fn new() -> Self {
        Self::default()
    }

    /// One wave: every provider of `family` not in backoff, in parallel, over `route`; the first
    /// valid answer wins and the others are dropped (which closes their sockets). `budget` is
    /// capped at [`WAVE_BUDGET`] (zero = the cap). `None` when nothing valid arrived in time, the
    /// route has no path for `family`, or `cancel` fired. Never returns a cached value.
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
        let now = Instant::now();
        let fetches: FuturesUnordered<_> = PROVIDERS
            .iter()
            .enumerate()
            .filter_map(|(index, provider)| {
                let url = provider.url(family)?;
                if self
                    .backoff
                    .lock()
                    .get(url)
                    .is_some_and(|until| *until > now)
                {
                    tracing::debug!(provider = index, outcome = "backoff", "public ip provider");
                    return None;
                }
                Some(self.fetch(index, &client, url, family))
            })
            .collect();
        let (index, ip) = race(fetches, budget, cancel).await?;
        Some(IpSample {
            ip,
            provider: index as u8,
            at: now_ms(),
        })
    }

    async fn fetch(
        &self,
        index: usize,
        client: &reqwest::Client,
        url: &'static str,
        family: Family,
    ) -> (usize, Result<IpAddr, Fault>) {
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
        (index, result)
    }
}

/// First `Ok` of `fetches` within `budget`, unless `cancel` fires first. Returning drops the
/// remaining requests.
async fn race<F>(
    mut fetches: FuturesUnordered<F>,
    budget: Duration,
    cancel: &CancellationToken,
) -> Option<(usize, IpAddr)>
where
    F: Future<Output = (usize, Result<IpAddr, Fault>)>,
{
    let first = async {
        while let Some((index, result)) = fetches.next().await {
            if let Ok(ip) = result {
                return Some((index, ip));
            }
        }
        None
    };
    tokio::select! {
        biased;
        _ = cancel.cancelled() => None,
        found = tokio::time::timeout(budget, first) => found.ok().flatten(),
    }
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
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// AT-07-007: Cloudflare trace (IPv4 / IPv6), JSON string and object, plain text.
    #[test]
    fn provider_bodies_parse() {
        let trace = "fl=84f22\nh=cloudflare.com\nip=203.0.113.195\nts=1726246345.123\nvisit_scheme=https\nuag=Mozilla/5.0";
        assert_eq!(parse_provider_body(trace), Some(ip("203.0.113.195")));
        let trace6 = "fl=84f22\nh=cloudflare.com\nip=2001:db8::1\nts=1726246345.123";
        assert_eq!(parse_provider_body(trace6), Some(ip("2001:db8::1")));
        let json = r#"{"ip":"198.51.100.42","country":"Germany"}"#;
        assert_eq!(parse_provider_body(json), Some(ip("198.51.100.42")));
        assert_eq!(
            parse_provider_body(r#"{"query":"198.51.100.77"}"#),
            Some(ip("198.51.100.77"))
        );
        assert_eq!(
            parse_provider_body("203.0.113.88\n"),
            Some(ip("203.0.113.88"))
        );
        assert_eq!(
            parse_provider_body("ip=1.1.1.1\r\nts=1\r\n"),
            Some(ip("1.1.1.1"))
        );
    }

    /// AT-07-007: "response did not contain a valid IP".
    #[test]
    fn junk_bodies_are_rejected() {
        for body in [
            "<html>502 Bad Gateway</html>",
            "",
            "{}",
            r#"{"ip":""}"#,
            "999.1.1.1",
            "{",
        ] {
            assert_eq!(parse_provider_body(body), None, "{body}");
        }
    }

    /// B-IP-5 / B-IP-3: non-public answers and the wrong family are not samples.
    #[test]
    fn acceptance_needs_public_address_of_the_family() {
        assert_eq!(accept(ip("8.8.8.8"), Family::V4), Ok(ip("8.8.8.8")));
        assert_eq!(accept(ip("::ffff:8.8.8.8"), Family::V4), Ok(ip("8.8.8.8")));
        assert_eq!(
            accept(ip("2606:4700:4700::1111"), Family::V4),
            Err(Fault::FamilyMismatch)
        );
        assert_eq!(
            accept(ip("8.8.8.8"), Family::V6),
            Err(Fault::FamilyMismatch)
        );
        for private in [
            "10.1.2.3",
            "100.64.0.1",
            "192.168.1.1",
            "203.0.113.5",
            "127.0.0.1",
        ] {
            assert_eq!(
                accept(ip(private), Family::V4),
                Err(Fault::NotPublic),
                "{private}"
            );
        }
        assert_eq!(accept(ip("fd00::1"), Family::V6), Err(Fault::NotPublic));
        assert_eq!(
            accept(ip("2001:4860:4860::8888"), Family::V6),
            Ok(ip("2001:4860:4860::8888"))
        );
    }

    /// AT-07-007: 429 backoff, seconds or HTTP date (B-IP-6), 60 s default, 300 s cap.
    #[test]
    fn retry_after_values() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(retry_after(Some("60"), now), Duration::from_secs(60));
        assert_eq!(retry_after(Some(" 1.5 "), now), Duration::from_millis(1500));
        assert_eq!(retry_after(Some("100000"), now), BACKOFF_MAX);
        for fallback in [None, Some("0"), Some("-5"), Some("soon"), Some("NaN")] {
            assert_eq!(retry_after(fallback, now), BACKOFF_DEFAULT, "{fallback:?}");
        }
        // 1_700_000_000 = Tue, 14 Nov 2023 22:13:20 GMT
        let later = "Tue, 14 Nov 2023 22:15:20 GMT";
        assert_eq!(retry_after(Some(later), now), Duration::from_secs(120));
        let past = "Tue, 14 Nov 2023 22:00:00 GMT";
        assert_eq!(retry_after(Some(past), now), BACKOFF_DEFAULT);
        let far = "Wed, 15 Nov 2023 22:13:20 GMT";
        assert_eq!(retry_after(Some(far), now), BACKOFF_MAX);
    }

    #[test]
    fn budget_is_capped() {
        assert_eq!(clamp_budget(Duration::ZERO), WAVE_BUDGET);
        assert_eq!(clamp_budget(Duration::from_secs(9)), WAVE_BUDGET);
        assert_eq!(
            clamp_budget(Duration::from_millis(600)),
            Duration::from_millis(600)
        );
        assert_eq!(Family::of(ip("::ffff:1.2.3.4")), Family::V4);
        assert_eq!(
            PROVIDERS[0].url(Family::V6),
            Some("https://[2606:4700:4700::1111]/cdn-cgi/trace")
        );
        assert_eq!(PROVIDERS[3].url(Family::V6), None);
    }

    /// Drop guard that counts how many losing requests were aborted.
    struct Aborted(Arc<AtomicUsize>);
    impl Drop for Aborted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn fake(
        index: usize,
        delay_ms: u64,
        result: Result<IpAddr, Fault>,
        aborted: &Arc<AtomicUsize>,
    ) -> impl Future<Output = (usize, Result<IpAddr, Fault>)> {
        let guard = Aborted(aborted.clone());
        async move {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            std::mem::forget(guard);
            (index, result)
        }
    }

    /// AT-07-007 / AT-00-005: one provider rate-limited, another answers; the first valid answer
    /// aborts the other requests; all failing gives nothing.
    #[tokio::test]
    async fn race_takes_the_first_valid_answer_and_drops_the_rest() {
        let aborted = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let fetches: FuturesUnordered<_> = [
            fake(0, 10, Err(Fault::RateLimited(BACKOFF_DEFAULT)), &aborted),
            fake(1, 50, Ok(ip("198.51.100.1")), &aborted),
            fake(2, 900, Ok(ip("198.51.100.2")), &aborted),
            fake(3, 1500, Err(Fault::Timeout), &aborted),
        ]
        .into_iter()
        .collect();
        let won = race(fetches, WAVE_BUDGET, &cancel).await;
        assert_eq!(won, Some((1, ip("198.51.100.1"))));
        assert_eq!(
            aborted.load(Ordering::SeqCst),
            2,
            "the two slower requests were dropped"
        );

        let failing: FuturesUnordered<_> = (0..4)
            .map(|i| fake(i, 5, Err(Fault::Network), &aborted))
            .collect();
        assert_eq!(race(failing, WAVE_BUDGET, &cancel).await, None);
    }

    /// AT-07-007: a provider that ignores the deadline cannot stretch the wave.
    #[tokio::test]
    async fn race_respects_budget_and_cancel() {
        let aborted = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let slow: FuturesUnordered<_> = [fake(0, 5_000, Ok(ip("1.1.1.1")), &aborted)]
            .into_iter()
            .collect();
        let started = Instant::now();
        assert_eq!(race(slow, Duration::from_millis(300), &cancel).await, None);
        assert!(started.elapsed() < Duration::from_millis(1000));

        let child = cancel.child_token();
        let pending: FuturesUnordered<_> = [fake(0, 500, Ok(ip("1.1.1.1")), &aborted)]
            .into_iter()
            .collect();
        let cancel_later = child.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel_later.cancel();
        });
        assert_eq!(race(pending, WAVE_BUDGET, &child).await, None);
        assert_eq!(aborted.load(Ordering::SeqCst), 2);
    }

    /// A one-shot HTTP/1.1 server on loopback that answers every request with `response`.
    async fn serve(response: &'static str) -> (&'static str, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 2048];
                let _ = socket.read(&mut buf).await;
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        (
            Box::leak(format!("http://127.0.0.1:{port}/").into_boxed_str()),
            hits,
        )
    }

    fn direct_client() -> reqwest::Client {
        build_client(&IpRoute::Direct, Family::V4, Duration::from_secs(2)).unwrap()
    }

    /// AT-07-007: a 429 puts the provider into backoff for its `Retry-After`.
    #[tokio::test]
    async fn rate_limit_sets_backoff() {
        let (url, _) = serve("HTTP/1.1 429 Too Many Requests\r\nretry-after: 120\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
        let reader = IpReader::new();
        let (_, result) = reader.fetch(0, &direct_client(), url, Family::V4).await;
        assert_eq!(result, Err(Fault::RateLimited(Duration::from_secs(120))));
        let until = *reader.backoff.lock().get(url).unwrap();
        assert!(until > Instant::now() + Duration::from_secs(110));
    }

    /// Body parsing end to end; private answers and oversized bodies are refused.
    #[tokio::test]
    async fn fetch_parses_and_filters_answers() {
        let reader = IpReader::new();
        let client = direct_client();
        let (ok, _) = serve("HTTP/1.1 200 OK\r\ncontent-length: 22\r\nconnection: close\r\n\r\n{\"ip\":\"8.8.4.4\",\"x\":1}").await;
        assert_eq!(
            reader.fetch(1, &client, ok, Family::V4).await.1,
            Ok(ip("8.8.4.4"))
        );
        let (private, _) =
            serve("HTTP/1.1 200 OK\r\ncontent-length: 9\r\nconnection: close\r\n\r\n10.0.0.1\n")
                .await;
        assert_eq!(
            reader.fetch(1, &client, private, Family::V4).await.1,
            Err(Fault::NotPublic)
        );
        let big: &'static str = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: 5000\r\nconnection: close\r\n\r\n{}",
                "1".repeat(5000)
            )
            .into_boxed_str(),
        );
        let (large, _) = serve(big).await;
        assert_eq!(
            reader.fetch(1, &client, large, Family::V4).await.1,
            Err(Fault::TooLarge)
        );
        let (status, _) =
            serve("HTTP/1.1 503 Busy\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
        assert_eq!(
            reader.fetch(1, &client, status, Family::V4).await.1,
            Err(Fault::Status(503))
        );
    }

    /// A TUN route without an IPv6 address has no IPv6 path: no request, no sample.
    #[tokio::test]
    async fn tun_route_without_v6_has_no_v6_path() {
        let route = IpRoute::Tun {
            v4: Ipv4Addr::new(192, 168, 250, 253),
            v6: None,
        };
        assert!(route.is_tun());
        let cancel = CancellationToken::new();
        assert_eq!(
            IpReader::new()
                .wave(&route, Family::V6, WAVE_BUDGET, &cancel)
                .await,
            None
        );
        cancel.cancel();
        assert_eq!(
            IpReader::new()
                .wave(&IpRoute::Direct, Family::V4, WAVE_BUDGET, &cancel)
                .await,
            None
        );
    }

    /// Names resolve to the wave's family only; a loopback route needs a real port.
    #[tokio::test]
    async fn resolver_keeps_one_family() {
        use reqwest::dns::Resolve;
        let name: reqwest::dns::Name = "localhost".parse().unwrap();
        let addrs: Vec<_> = FamilyResolver(Family::V4)
            .resolve(name)
            .await
            .unwrap()
            .collect();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.is_ipv4()));
        let lo = IpRoute::Loopback(Loopback {
            port: 0,
            creds: None,
        });
        assert!(matches!(
            build_client(&lo, Family::V4, WAVE_BUDGET),
            Err(Fault::NoPath)
        ));
    }

    /// Live providers, once, over the plain route. Run by hand: `cargo test … -- --ignored`.
    #[tokio::test]
    #[ignore = "calls the public IP providers"]
    async fn live_wave_reads_a_public_ipv4() {
        let cancel = CancellationToken::new();
        let sample = IpReader::new()
            .wave(&IpRoute::Direct, Family::V4, WAVE_BUDGET, &cancel)
            .await
            .expect("a provider answered");
        assert!(sample.ip.is_ipv4() && net::is_public_ip(sample.ip));
        assert!(usize::from(sample.provider) < PROVIDERS.len());
    }
}
