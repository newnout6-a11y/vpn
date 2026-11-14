//! Country and ASN of an IP address (servers §2.7, §2.11, §3.9): three providers in parallel
//! under one 6 s deadline, majority vote with a fixed tie priority, per-provider 429 backoff,
//! a small cache, one shared read per IP for concurrent callers, and `disableGeoLookup` gating
//! every request. Addresses are never logged.
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::future::join_all;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;
use tokio::time::{Instant, interval, sleep_until, timeout};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::ProxyKind;
use vpnte_core::net::{HostPort, Route, is_public_ip};
use vpnte_core::resolve::{self, How};
use vpnte_core::settings::{BootstrapRouteMode, Settings};
use vpnte_profiles::countries::Iso2;

mod providers;
#[cfg(test)]
mod tests;

use providers::{Fault, HttpGet, JsonGet, Provider, VOTERS, backoff, vote};

/// Timing of lookups (tests shrink it).
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// One country read, all providers and routes included.
    deadline: Duration,
    /// How often waiting callers re-check that they still want the answer.
    poll: Duration,
    /// Cache life of a country / of a completed read without one.
    found_ttl: Duration,
    empty_ttl: Duration,
}

const TIMING: Timing = Timing {
    deadline: Duration::from_secs(6),
    poll: Duration::from_millis(25),
    found_ttl: Duration::from_secs(5 * 60),
    empty_ttl: Duration::from_secs(5),
};
/// Cache size (oldest entry evicted first).
const CACHE_MAX: usize = 256;
/// Entry-IP resolution before the lookup.
const RESOLVE_TIMEOUT: Duration = Duration::from_millis(2500);

/// Whoever asked for a lookup, answering "do you still want it?" (implemented by the app over
/// the server list and the tunnel runtime). For exit verification `is_current` must compare a
/// snapshot taken when the lookup started: the caller's generation, the selection generation,
/// the active profile id and the tunnel session.
pub trait LookupOwner: Send + Sync {
    /// The caller still owns the lookup; checked every 25 ms and after the answer.
    fn is_current(&self) -> bool;
    /// A server switch is running (exit verification refuses to start).
    fn switching(&self) -> bool {
        false
    }
    /// A profile is active, so an exit country has somewhere to go.
    fn has_active(&self) -> bool {
        true
    }
}

/// Owner of a one-off lookup: current until the token is cancelled.
struct TokenOwner(CancellationToken);

impl LookupOwner for TokenOwner {
    fn is_current(&self) -> bool {
        !self.0.is_cancelled()
    }
}

/// Why a country was not verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "kebab-case")]
pub enum VerifyReject {
    #[error("geo lookups are disabled")]
    GeoDisabled,
    /// Not a public address (geolocating it would only leak or mislead).
    #[error("not a public IP address")]
    InvalidIp,
    /// The caller, the selection or the tunnel session changed meanwhile.
    #[error("the lookup was superseded")]
    Superseded,
    #[error("a server switch is in progress")]
    SwitchInProgress,
    #[error("no active profile")]
    NoActiveProfile,
    #[error("the server name did not resolve")]
    ResolveFailed,
    #[error("no provider returned a country")]
    LookupFailed,
}

impl VerifyReject {
    /// User-facing text (`probes.geo.reject.*`).
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            VerifyReject::GeoDisabled => "probes.geo.reject.geoDisabled",
            VerifyReject::InvalidIp => "probes.geo.reject.invalidIp",
            VerifyReject::Superseded => "probes.geo.reject.superseded",
            VerifyReject::SwitchInProgress => "probes.geo.reject.switchInProgress",
            VerifyReject::NoActiveProfile => "probes.geo.reject.noActiveProfile",
            VerifyReject::ResolveFailed => "probes.geo.reject.resolveFailed",
            VerifyReject::LookupFailed => "probes.geo.reject.lookupFailed",
        })
    }
}

/// Network owner of an address (server details). Fields the providers left out are `None`;
/// the UI renders them as "unknown".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsnInfo {
    /// `AS13335` form.
    pub asn: Option<String>,
    pub org: Option<String>,
    pub network: Option<String>,
    /// Country name or code as the provider gave it.
    pub country: Option<String>,
}

/// Request routes of geo lookups (old `currentBootstrapRoutes`): with our TUN running and the
/// mode `auto`, direct only ("must not replay a failed geo request through stale local ports");
/// otherwise the bootstrap routes of the mode: direct, the configured proxy, then the well-known
/// local proxies 127.0.0.1:10808 (SOCKS5) and :10809 (HTTP), deduplicated.
pub fn geo_routes(settings: &Settings, tunnel_running: bool) -> Vec<Route> {
    let mode = match settings.bootstrap_route_mode {
        BootstrapRouteMode::Auto if tunnel_running => BootstrapRouteMode::Direct,
        mode => mode,
    };
    let mut routes = Vec::new();
    if matches!(mode, BootstrapRouteMode::Auto | BootstrapRouteMode::Direct) {
        routes.push(Route::Direct);
    }
    if matches!(
        mode,
        BootstrapRouteMode::Auto | BootstrapRouteMode::LocalProxy
    ) {
        let mut proxies: Vec<Route> = Vec::new();
        if let Some(own) = &settings.proxy_override {
            proxies.push(own.route(settings.proxy_type));
        }
        for (kind, port) in [(ProxyKind::Socks5, 10808), (ProxyKind::Http, 10809)] {
            if let Ok(addr) = HostPort::new("127.0.0.1", port) {
                proxies.push(Route::proxy(kind, &addr, None));
            }
        }
        for route in proxies {
            if !routes.iter().any(|r| r.label() == route.label()) {
                routes.push(route);
            }
        }
    }
    routes
}

/// One shared read of an IP's country.
struct Flight {
    id: u64,
    /// Callers still waiting; the read is abandoned when it drops to zero.
    consumers: AtomicUsize,
    /// Set once the read was abandoned: a new caller starts a fresh read instead of joining.
    abort: CancellationToken,
    /// `Some(answer)` once finished.
    done: watch::Sender<Option<Option<Iso2>>>,
}

/// Counts a waiting caller for as long as it waits (also when its future is dropped).
struct Waiting(Arc<Flight>);

impl Drop for Waiting {
    fn drop(&mut self) {
        self.0.consumers.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 429 state of one provider.
#[derive(Clone, Copy)]
struct Backoff {
    failures: u32,
    until: Instant,
}

/// How a read ended.
enum Wave {
    /// Every provider answered or failed in time; `answered` = at least one HTTP answer arrived.
    Done {
        country: Option<Iso2>,
        answered: bool,
    },
    /// Deadline or abandonment: nothing is cached.
    Abandoned,
}

/// Answers by IP with the time they were stored, plus insertion order for eviction.
#[derive(Default)]
struct Cache {
    map: HashMap<IpAddr, (Option<Iso2>, Instant)>,
    order: VecDeque<IpAddr>,
}

struct Inner {
    enabled: AtomicBool,
    get: Arc<dyn JsonGet>,
    timing: Timing,
    cache: Mutex<Cache>,
    flights: Mutex<HashMap<IpAddr, Arc<Flight>>>,
    backoff: Mutex<HashMap<Provider, Backoff>>,
    next_id: AtomicU64,
}

/// Geo lookups with their cache, shared reads and provider backoff. Cheap to clone; create one
/// for the app and keep `set_enabled` in step with `Settings::disable_geo_lookup`.
#[derive(Clone)]
pub struct Geo {
    inner: Arc<Inner>,
}

impl Geo {
    /// Lookups over HTTPS; `enabled = !settings.disable_geo_lookup`.
    pub fn new(enabled: bool) -> Self {
        Self::build(enabled, Arc::new(HttpGet::default()), TIMING)
    }

    fn build(enabled: bool, get: Arc<dyn JsonGet>, timing: Timing) -> Self {
        Self {
            inner: Arc::new(Inner {
                enabled: AtomicBool::new(enabled),
                get,
                timing,
                cache: Mutex::default(),
                flights: Mutex::default(),
                backoff: Mutex::default(),
                next_id: AtomicU64::new(1),
            }),
        }
    }

    /// Turns lookups on or off. Off: no request at all (cached answers included), and reads in
    /// flight are abandoned within one poll tick.
    pub fn set_enabled(&self, on: bool) {
        self.inner.enabled.store(on, Ordering::SeqCst);
    }

    pub fn enabled(&self) -> bool {
        self.inner.enabled.load(Ordering::SeqCst)
    }

    /// The country of `ip` by majority of geojs, ipinfo.io and ipwho.is (ties in that order),
    /// over `routes` (see [`geo_routes`]). `None` when lookups are off, `ip` is not public, no
    /// provider knew, the 6 s deadline passed, or `owner` stopped wanting the answer. Concurrent
    /// callers for one IP share one read; it is abandoned when none of them is current any more.
    pub async fn country(
        &self,
        ip: IpAddr,
        routes: Vec<Route>,
        owner: Arc<dyn LookupOwner>,
    ) -> Option<Iso2> {
        if !self.enabled() || !is_public_ip(ip) {
            return None;
        }
        if let Some(hit) = self.inner.cached(ip) {
            return hit;
        }
        let flight = self.inner.join(ip, routes);
        let _waiting = Waiting(flight.clone());
        let mut done = flight.done.subscribe();
        let mut tick = interval(self.inner.timing.poll);
        loop {
            tokio::select! {
                answer = done.wait_for(Option::is_some) => {
                    let answer = answer.ok().and_then(|a| *a).flatten();
                    return answer.filter(|_| owner.is_current() && self.enabled());
                }
                _ = tick.tick() => {
                    if !owner.is_current() || !self.enabled() {
                        return None;
                    }
                }
            }
        }
    }

    /// Exit-country verification of an observed exit IP (old `verifyActiveCountryForIp`, guard
    /// order kept). On `Ok` the caller records `{country, now, ip, source: exit-ip}` with the
    /// selection generation it snapshotted (`Servers::record_country`).
    pub async fn verify_exit(
        &self,
        ip: IpAddr,
        routes: Vec<Route>,
        owner: Arc<dyn LookupOwner>,
    ) -> Result<Iso2, VerifyReject> {
        if !self.enabled() {
            return Err(VerifyReject::GeoDisabled);
        }
        if !is_public_ip(ip) {
            return Err(VerifyReject::InvalidIp);
        }
        if !owner.is_current() {
            return Err(VerifyReject::Superseded);
        }
        if owner.switching() {
            return Err(VerifyReject::SwitchInProgress);
        }
        if !owner.has_active() {
            return Err(VerifyReject::NoActiveProfile);
        }
        let country = self.country(ip, routes, owner.clone()).await;
        if !self.enabled() {
            return Err(VerifyReject::GeoDisabled);
        }
        if !owner.is_current() {
            return Err(VerifyReject::Superseded);
        }
        country.ok_or(VerifyReject::LookupFailed)
    }

    /// Entry-IP country of a server name (manual button): first public A record, else AAAA.
    /// Wrong for bridged servers, so the caller stores it with source `entry-ip`, which never
    /// overrides fresher exit data.
    pub async fn verify_entry(
        &self,
        host: &str,
        routes: Vec<Route>,
        cancel: &CancellationToken,
    ) -> Result<(Iso2, IpAddr), VerifyReject> {
        if !self.enabled() {
            return Err(VerifyReject::GeoDisabled);
        }
        let lookup = resolve::resolve_host(host, How::System, is_public_ip);
        let ip = tokio::select! {
            () = cancel.cancelled() => return Err(VerifyReject::Superseded),
            answer = timeout(RESOLVE_TIMEOUT, lookup) => answer
                .ok()
                .and_then(Result::ok)
                .and_then(|ips| ips.first().copied())
                .ok_or(VerifyReject::ResolveFailed)?,
        };
        let owner = Arc::new(TokenOwner(cancel.clone()));
        match self.country(ip, routes, owner).await {
            Some(country) => Ok((country, ip)),
            None if cancel.is_cancelled() => Err(VerifyReject::Superseded),
            None if !self.enabled() => Err(VerifyReject::GeoDisabled),
            None => Err(VerifyReject::LookupFailed),
        }
    }

    /// ASN, organisation, network and country of `ip` (server details): ipapi.co, then
    /// ipwho.is, 6 s each. `None` when lookups are off, `ip` is not public or both failed.
    pub async fn asn(
        &self,
        ip: IpAddr,
        routes: &[Route],
        cancel: &CancellationToken,
    ) -> Option<AsnInfo> {
        if !self.enabled() || !is_public_ip(ip) {
            return None;
        }
        for provider in [Provider::IpApiCo, Provider::IpWhoIs] {
            let deadline = Instant::now() + provider.timeout();
            let body = tokio::select! {
                () = cancel.cancelled() => return None,
                body = self.inner.fetch(provider, ip, routes, deadline) => body,
            };
            if let Some(info) = body.as_ref().and_then(|b| asn_of(provider, b)) {
                return self.enabled().then_some(info);
            }
        }
        None
    }
}

/// Non-empty trimmed string field.
fn text(v: &Value, key: &str) -> Option<String> {
    let s = match v.get(key)? {
        Value::String(s) => s.trim().to_owned(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    (!s.is_empty()).then_some(s)
}

/// The ASN answer of a provider (`error` / `success: false` / nothing known = none).
fn asn_of(provider: Provider, body: &Value) -> Option<AsnInfo> {
    asn_fields(provider, body).filter(|info| *info != AsnInfo::default())
}

fn asn_fields(provider: Provider, body: &Value) -> Option<AsnInfo> {
    let as_prefixed = |asn: String| {
        if asn.to_ascii_uppercase().starts_with("AS") {
            asn
        } else {
            format!("AS{asn}")
        }
    };
    match provider {
        Provider::IpApiCo => {
            if body
                .get("error")
                .is_some_and(|e| e.as_bool() != Some(false))
            {
                return None;
            }
            Some(AsnInfo {
                asn: text(body, "asn").map(as_prefixed),
                org: text(body, "org"),
                network: text(body, "network"),
                country: text(body, "country_name").or_else(|| text(body, "country")),
            })
        }
        Provider::IpWhoIs => {
            if body.get("success").and_then(Value::as_bool) == Some(false) {
                return None;
            }
            let conn = body.get("connection").cloned().unwrap_or_default();
            Some(AsnInfo {
                asn: text(&conn, "asn").map(as_prefixed),
                org: text(&conn, "isp").or_else(|| text(&conn, "org")),
                network: None,
                country: text(body, "country"),
            })
        }
        _ => None,
    }
}

impl Inner {
    fn enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// `Some(answer)` while a cached answer is fresh (a country 5 min, "none" 5 s).
    fn cached(&self, ip: IpAddr) -> Option<Option<Iso2>> {
        let cache = self.cache.lock();
        let (country, at) = cache.map.get(&ip)?;
        let ttl = if country.is_some() {
            self.timing.found_ttl
        } else {
            self.timing.empty_ttl
        };
        (at.elapsed() < ttl).then_some(*country)
    }

    fn remember(&self, ip: IpAddr, country: Option<Iso2>) {
        let mut cache = self.cache.lock();
        let Cache { map, order } = &mut *cache;
        if map.insert(ip, (country, Instant::now())).is_none() {
            order.push_back(ip);
        }
        while order.len() > CACHE_MAX {
            if let Some(old) = order.pop_front() {
                map.remove(&old);
            }
        }
    }

    /// The live read of `ip` (counted as one more waiting caller), or a new one.
    fn join(self: &Arc<Self>, ip: IpAddr, routes: Vec<Route>) -> Arc<Flight> {
        let mut flights = self.flights.lock();
        if let Some(flight) = flights.get(&ip).filter(|f| !f.abort.is_cancelled()) {
            flight.consumers.fetch_add(1, Ordering::SeqCst);
            return flight.clone();
        }
        let flight = Arc::new(Flight {
            id: self.next_id.fetch_add(1, Ordering::SeqCst),
            consumers: AtomicUsize::new(1),
            abort: CancellationToken::new(),
            done: watch::Sender::new(None),
        });
        flights.insert(ip, flight.clone());
        tokio::spawn(self.clone().drive(ip, routes, flight.clone()));
        flight
    }

    /// Runs one read until it finishes, hits the deadline or nobody wants it any more.
    async fn drive(self: Arc<Self>, ip: IpAddr, routes: Vec<Route>, flight: Arc<Flight>) {
        let deadline = Instant::now() + self.timing.deadline;
        let wave = self.wave(ip, &routes, deadline);
        tokio::pin!(wave);
        let mut tick = interval(self.timing.poll);
        let outcome = loop {
            tokio::select! {
                outcome = &mut wave => break outcome,
                () = sleep_until(deadline) => break Wave::Abandoned,
                _ = tick.tick() => {
                    // Decided under the flights lock, so no caller joins an abandoned read.
                    let mut flights = self.flights.lock();
                    if flight.consumers.load(Ordering::SeqCst) == 0 || !self.enabled() {
                        flight.abort.cancel();
                        if flights.get(&ip).is_some_and(|f| f.id == flight.id) {
                            flights.remove(&ip);
                        }
                        break Wave::Abandoned;
                    }
                }
            }
        };
        let answer = match outcome {
            Wave::Done { country, answered } => {
                // Cached only for a caller still waiting; failures are never cached, a
                // completed read without a country only briefly.
                let wanted = flight.consumers.load(Ordering::SeqCst) > 0 && self.enabled();
                if wanted && (country.is_some() || answered) {
                    self.remember(ip, country);
                }
                country
            }
            Wave::Abandoned => None,
        };
        {
            let mut flights = self.flights.lock();
            if flights.get(&ip).is_some_and(|f| f.id == flight.id) {
                flights.remove(&ip);
            }
        }
        flight.done.send_replace(Some(answer));
    }

    /// The three voters in parallel (a slow one never delays the others), backoff respected.
    async fn wave(&self, ip: IpAddr, routes: &[Route], deadline: Instant) -> Wave {
        let asks = VOTERS.map(|provider| async move {
            let cap = (Instant::now() + provider.timeout()).min(deadline);
            let body = self.fetch(provider, ip, routes, cap).await;
            (provider, body)
        });
        let answers = join_all(asks).await;
        let answered = answers.iter().any(|(_, body)| body.is_some());
        let votes: Vec<(Provider, Option<Iso2>)> = answers
            .iter()
            .map(|(p, body)| (*p, body.as_ref().and_then(|b| p.country(ip, b))))
            .collect();
        if votes
            .iter()
            .filter_map(|(_, c)| *c)
            .collect::<std::collections::HashSet<_>>()
            .len()
            > 1
        {
            tracing::debug!("geo providers disagree");
        }
        Wave::Done {
            country: vote(&votes),
            answered,
        }
    }

    /// One provider request unless it is backing off; records 429s and successes.
    async fn fetch(
        &self,
        provider: Provider,
        ip: IpAddr,
        routes: &[Route],
        deadline: Instant,
    ) -> Option<Value> {
        if self
            .backoff
            .lock()
            .get(&provider)
            .is_some_and(|b| Instant::now() < b.until)
        {
            return None;
        }
        match self.get.get(provider.url(ip), routes, deadline).await {
            Ok(body) => {
                self.backoff.lock().remove(&provider);
                Some(body)
            }
            Err(Fault::RateLimited(retry_after)) => {
                let mut table = self.backoff.lock();
                let failures = table.get(&provider).map_or(0, |b| b.failures) + 1;
                let until = Instant::now() + backoff(failures, retry_after);
                table.insert(provider, Backoff { failures, until });
                tracing::warn!(provider = ?provider, failures, "geo provider rate-limited");
                None
            }
            Err(Fault::Failed) => None,
        }
    }
}
