//! The fetch plan of one URL (profiles §3.7, bounded as servers §6 / S-08 asks): route first; on a
//! route that answers, the User-Agent variants with the device headers, then without; a route that
//! fails at transport level is left at once; then a DoH-pinned direct retry; the strongest failure
//! wins. Mihomo providers of an answer are fetched the same way, the answering route first.
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use parking_lot::Mutex;
use reqwest::header::{ACCEPT, HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use tokio_util::sync::CancellationToken;
use url::Url;
use vpnte_base::types::ClientDevice;
use vpnte_base::{AppError, AppResult};
use vpnte_core::net::{Route, builder_for, is_public_ip};
use vpnte_core::resolve::{How, resolve_host};
use vpnte_profiles::clash::HttpProvider;
use vpnte_profiles::model::{ParseReport, SubscriptionMeta};
use vpnte_profiles::text::{self, ProviderKeys};
use vpnte_profiles::{clash, device};

use super::headers::header_map;
use super::http::{self, Abort, Answer, Hops};
use super::hwid;
use super::{DOH_MAX_IPS, FetchError, ProviderFailure, ProviderFetch, SubscriptionFetcher, policy};
use crate::common::http_url;
use crate::model::{BodyKind, FetchOutcome, NetFail, is_placeholder_profile, provider_words};
use crate::parse::{self, MAX_PROFILES};

/// One User-Agent, with or without the device headers.
pub(super) struct Variant {
    /// What the subscription's own origin gets.
    headers: HeaderMap,
    /// What another origin gets after a redirect: the same client without the HWID, no device
    /// headers, none of the user's headers (they may hold tokens; browsers, curl and reqwest drop
    /// credentials on a cross-origin redirect the same way).
    elsewhere: HeaderMap,
    /// The User-Agent family (`Happ`, `v2rayN`): logs and the group's remembered identity.
    family: String,
    /// Log label: the family and `+hwid` (never the HWID itself, S-27).
    label: String,
    with_ids: bool,
}

/// The User-Agents of `device` with the HWID headers, then the same without them (servers §2.5:
/// some panels answer an empty 200 without the HWID, others gate by client name). `hwid: None`
/// (the group does not send it) keeps only the variants without it. `prefer` (the family that
/// last brought servers, p-live-fix) goes first in each pass. The user's own headers go on last
/// and win; their `User-Agent` replaces the rotation.
pub(super) fn variants(
    device: ClientDevice,
    hwid: Option<&str>,
    custom: &[(String, String)],
    prefer: Option<&str>,
) -> Vec<Variant> {
    let custom = header_map(custom);
    let mut anonymous = device::user_agents(device, None);
    let mut agents = match custom.get(USER_AGENT) {
        Some(own) => vec![String::from_utf8_lossy(own.as_bytes()).into_owned()],
        None => device::user_agents(device, hwid),
    };
    if let Some(at) = prefer
        .and_then(|family| {
            agents
                .iter()
                .position(|a| device::agent_family(a) == family)
        })
        .filter(|_| custom.get(USER_AGENT).is_none())
    {
        agents[..=at].rotate_right(1);
        anonymous[..=at].rotate_right(1);
    }
    let ids = hwid.map(|h| device::device_headers(device, h));
    let passes: &[bool] = if ids.is_some() {
        &[true, false]
    } else {
        &[false]
    };
    let mut out = Vec::with_capacity(agents.len() * passes.len());
    for &with_ids in passes {
        for (at, agent) in agents.iter().enumerate() {
            let mut headers = basic_headers(agent);
            if let Some(ids) = ids.as_ref().filter(|_| with_ids) {
                for (name, value) in ids {
                    let name = HeaderName::from_bytes(name.as_bytes());
                    if let (Ok(name), Ok(value)) = (name, HeaderValue::from_str(value)) {
                        headers.insert(name, value);
                    }
                }
            }
            for (name, value) in &custom {
                headers.insert(name.clone(), value.clone());
            }
            // The rotation without the HWID has the same order; a user's own agent is replaced
            // by the first (Happ's).
            let plain = anonymous.get(at).or(anonymous.first());
            let family = device::agent_family(agent).to_owned();
            let label = format!("{family}{}", if with_ids { "+hwid" } else { "" });
            out.push(Variant {
                headers,
                elsewhere: basic_headers(plain.map_or("", String::as_str)),
                family,
                label,
                with_ids,
            });
        }
    }
    out
}

/// User-Agent, `Accept`, and a request for a fresh copy: panels behind CDNs answer stale lists
/// from cache otherwise (Remnawave guides).
fn basic_headers(agent: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(agent) {
        headers.insert(USER_AGENT, value);
    }
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers
}

/// What one URL brought back.
pub(super) struct Got {
    /// At least one profile, unless `providers` may still bring some.
    pub report: ParseReport,
    /// Controls and relocation hints (headers over body lines).
    pub keys: ProviderKeys,
    /// Where a leading run of 301 / 308 redirects pointed (the permanent new address).
    pub moved: Option<Url>,
    /// Mihomo `type: http` providers named by the body.
    pub providers: Vec<HttpProvider>,
    /// The plan route that answered (`None`: the DoH-pinned retry).
    pub route: Option<Route>,
    /// The User-Agent family that brought the servers.
    pub agent: String,
}

/// How one route ended.
enum Step {
    Done(Box<Got>),
    /// Go on with the next route.
    Next,
    /// The panel said enough (429, or 404 / 410 to every identified request): stop the plan.
    Stop,
}

/// The strongest failure seen so far, with the provider's words when it came as placeholders.
#[derive(Default)]
struct Failures {
    worst: Option<FetchOutcome>,
    said: Option<String>,
}

impl Failures {
    fn note(&mut self, outcome: FetchOutcome) {
        self.note_said(outcome, None);
    }

    /// `outcome` with the words of its placeholders: a stronger failure takes over (words and
    /// all), an equal one only adds words the first lacked.
    fn note_said(&mut self, outcome: FetchOutcome, said: Option<String>) {
        if self.worst.is_none_or(|seen| rank(outcome) < rank(seen)) {
            self.worst = Some(outcome);
            self.said = said;
        } else if self.worst == Some(outcome) && self.said.is_none() {
            self.said = said;
        }
    }

    fn into_error(self) -> FetchError {
        let outcome = self
            .worst
            .unwrap_or(FetchOutcome::Network(NetFail::Connect));
        match self.said {
            Some(said) => FetchError::Said(outcome, said),
            None => FetchError::Failed(outcome),
        }
    }

    fn seen(&self) -> bool {
        self.worst.is_some()
    }
}

/// Evidence order of servers §6: a received but unusable answer beats a later network failure;
/// a panel that named its reason for refusing the device beats everything; an answer only the
/// provider's own app can read, or its placeholders, say more than an empty list (p-live-fix).
pub(super) fn rank(outcome: FetchOutcome) -> u8 {
    match outcome {
        FetchOutcome::DeviceLimit => 0,
        FetchOutcome::HwidRequired => 1,
        FetchOutcome::Unparseable(BodyKind::Encrypted) => 2,
        FetchOutcome::Placeholder => 3,
        FetchOutcome::EmptyList => 4,
        FetchOutcome::Unparseable(_) => 5,
        FetchOutcome::Http(400..=499) => 6,
        FetchOutcome::Http(_) => 7,
        FetchOutcome::Network(_) => 8,
        FetchOutcome::Timeout => 9,
        FetchOutcome::Ok { .. } => 10,
    }
}

/// A body evaluated: the report with the header metadata merged in (headers win), the provider
/// keys, the Mihomo providers.
struct Evaluated {
    report: ParseReport,
    keys: ProviderKeys,
    providers: Vec<HttpProvider>,
}

/// Why a body gave no servers, with the provider's words when it gave placeholders only.
type NoServers = (FetchOutcome, Option<String>);

/// Up to 16 MiB of nested base64, YAML and thousands of keys is CPU work: it runs on the blocking
/// pool, not on a runtime worker.
async fn evaluate(headers: Vec<(String, String)>, body: Vec<u8>) -> Result<Evaluated, NoServers> {
    tokio::task::spawn_blocking(move || evaluate_now(&headers, &body))
        .await
        .unwrap_or_else(|err| {
            tracing::warn!("subscription: the body parser failed: {err}");
            Err((FetchOutcome::Unparseable(BodyKind::Other), None))
        })
}

/// Provider placeholders («Приложение не поддерживается» at `0.0.0.0:1`) are dropped from every
/// answer: an answer made of them only is the provider's refusal, never a list (p-live-fix).
fn evaluate_now(headers: &[(String, String)], body: &[u8]) -> Result<Evaluated, NoServers> {
    let parsed = parse::parse_body_full(body)
        .map_err(|_| (FetchOutcome::Unparseable(BodyKind::Other), None))?;
    let mut report = parsed.report;
    let (placeholders, servers): (Vec<_>, Vec<_>) = std::mem::take(&mut report.profiles)
        .into_iter()
        .partition(is_placeholder_profile);
    report.profiles = servers;
    let providers = clash::http_providers(&parsed.text);
    if report.profiles.is_empty() && providers.is_empty() {
        if !placeholders.is_empty() {
            let said = provider_words(placeholders.iter().map(|p| p.name.as_str()));
            return Err((FetchOutcome::Placeholder, said));
        }
        return Err((policy::classify_body(&parsed.text), None));
    }
    let pairs = || headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    let from_body = std::mem::take(&mut report.meta);
    report.meta = text::header_meta(pairs(), from_body);
    let keys = text::header_keys(pairs(), parsed.keys);
    Ok(Evaluated {
        report,
        keys,
        providers,
    })
}

impl SubscriptionFetcher {
    /// The client builder of `route` with the request timeout. Tests trust nothing but the
    /// certificate of their loopback HTTPS panels.
    fn builder(&self, route: &Route) -> AppResult<reqwest::ClientBuilder> {
        let builder = builder_for(route, self.request_timeout)?;
        #[cfg(test)]
        let builder = builder.tls_certs_only([super::tests::test_root()]);
        Ok(builder)
    }

    fn client(&self, route: &Route) -> AppResult<reqwest::Client> {
        self.builder(route)?
            .build()
            .map_err(|e| AppError::internal(e.without_url()))
    }
}

/// How the providers of an answer are fetched.
pub(super) struct ProviderRoutes {
    /// The route that answered first, then the rest of the plan: a blocked direct route costs one
    /// timeout, not one per provider.
    pub order: Vec<Route>,
    pub doh: bool,
    /// The answer came direct, so the system resolver may check provider names (behind a proxy
    /// that would leak them to the local resolver, which the plan avoids).
    pub local_dns: bool,
}

/// What every URL of one fetch shares: the fetcher (timeouts), the request variants, and which
/// URLs the panel told to stop.
pub(super) struct Ctx<'a> {
    fetcher: &'a SubscriptionFetcher,
    /// The subscription URL's and the fallback URL's requests: identity and the user's headers
    /// as the group says.
    pub own: Vec<Variant>,
    /// Requests to anyone else (a Mihomo provider on another host): no identity, no user headers.
    pub public: Vec<Variant>,
    /// URLs whose plan stopped on purpose (429, or 404 / 410 to every identified request).
    stopped: Mutex<Vec<Url>>,
    /// The subscription came from outside (a deep link, a QR code, a stored group added so):
    /// no request of this fetch — its URL, its fallback, its providers, every redirect — may
    /// reach the local network (see [`Ctx::linked_client`]).
    linked: bool,
}

impl<'a> Ctx<'a> {
    /// The requests of one fetch as `device`, with the HWID when `hwid` is set and `headers`;
    /// `prefer`: the User-Agent family to try first; `linked`: the subscription came from outside.
    pub(super) fn new(
        fetcher: &'a SubscriptionFetcher,
        device: ClientDevice,
        hwid: Option<&str>,
        headers: &[(String, String)],
        prefer: Option<&str>,
        linked: bool,
    ) -> Self {
        Self {
            fetcher,
            own: variants(device, hwid, headers, prefer),
            public: variants(device, None, &[], None),
            stopped: Mutex::new(Vec::new()),
            linked,
        }
    }

    /// The panel at `url` said enough (429, or gone for every identified request): asking it
    /// again from another address undoes that (S-08).
    pub(super) fn stopped(&self, url: &Url) -> bool {
        self.stopped.lock().contains(url)
    }

    /// `url` with `variants` over `routes` in order, then (when `doh`) one DoH-pinned direct
    /// retry for a domain host. A cancelled token stops at once.
    pub(super) async fn fetch_url(
        &self,
        url: &Url,
        variants: &[Variant],
        routes: &[Route],
        doh: bool,
        cancel: &CancellationToken,
    ) -> Result<Got, FetchError> {
        let host = url.host_str().unwrap_or_default().to_owned();
        let mut failures = Failures::default();
        let linked = self.linked;
        // The system resolver put a linked name into a non-public range: no direct request.
        // A fake-ip resolver (another client's TUN) answers so for every name, so the proxy
        // routes and the DoH retry still run; "local network" only when nothing else answered.
        let mut refused_direct = false;
        let pin_direct = |name: &str, to: &[SocketAddr]| self.pinned_client(name, to);
        let pin = linked.then_some(&pin_direct as http::Pin);
        // A link's local name or non-public IP literal needs no lookup: refused on every route.
        if linked
            && (policy::is_local_name(url)
                || policy::literal_ip(url).is_some_and(|ip| !is_public_ip(ip)))
        {
            tracing::info!(%host, "subscription: a link into the local network was refused");
            return Err(FetchError::LocalTarget);
        }
        for route in routes {
            let direct = *route == Route::Direct;
            let client = if linked && direct {
                match self.linked_client(url, cancel).await {
                    Err(FetchError::LocalTarget) => {
                        refused_direct = true;
                        None
                    }
                    other => other?,
                }
            } else {
                match self.fetcher.client(route) {
                    Ok(client) => Some(client),
                    Err(err) => {
                        tracing::warn!(route = %route.label(), "subscription: no HTTP client: {err}");
                        None
                    }
                }
            };
            let Some(client) = client else { continue };
            let hops = Hops {
                local_dns: direct,
                // A linked URL's direct client is pinned to addresses checked public.
                origin_public: (linked && direct).then_some(true),
            };
            let attempt = Attempt {
                client: &client,
                url,
                host: &host,
                label: route.label(),
                route: Some(route),
                hops,
                pin: pin.filter(|_| direct),
            };
            match attempt.run(variants, &mut failures, cancel).await? {
                Step::Done(got) => return Ok(*got),
                Step::Stop => return Err(self.stop(url, failures)),
                Step::Next => {}
            }
        }
        if doh
            && let Some(url::Host::Domain(name)) = url.host()
            && !policy::is_local_name(url)
        {
            let ips = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(FetchError::Cancelled),
                ips = resolve_host(name, How::Doh, is_public_ip) => ips,
            };
            match ips {
                Ok(ips) => {
                    let port = url.port_or_known_default().unwrap_or(443);
                    for ip in ips.into_iter().take(DOH_MAX_IPS) {
                        let pinned = self.fetcher.builder(&Route::Direct).and_then(|b| {
                            b.resolve_to_addrs(name, &[SocketAddr::new(ip, port)])
                                .build()
                                .map_err(|e| AppError::internal(e.without_url()))
                        });
                        let Ok(client) = pinned else { continue };
                        let attempt = Attempt {
                            client: &client,
                            url,
                            host: &host,
                            label: format!("doh-pinned {ip}"),
                            route: None,
                            hops: Hops {
                                local_dns: true,
                                origin_public: Some(true),
                            },
                            pin,
                        };
                        match attempt.run(variants, &mut failures, cancel).await? {
                            Step::Done(got) => return Ok(*got),
                            Step::Stop => return Err(self.stop(url, failures)),
                            Step::Next => {}
                        }
                    }
                }
                Err(err) => {
                    tracing::info!(%host, "subscription: DNS-over-HTTPS gave no address: {err}")
                }
            }
        }
        if refused_direct && !failures.seen() {
            return Err(FetchError::LocalTarget);
        }
        let err = failures.into_error();
        tracing::info!(%host, "subscription: every attempt failed: {err}");
        Err(err)
    }

    fn stop(&self, url: &Url, failures: Failures) -> FetchError {
        self.stopped.lock().push(url.clone());
        failures.into_error()
    }

    /// The direct client for a URL that came from outside (phones-a11): a name is resolved here
    /// and the request is pinned to those addresses, so no second lookup can answer otherwise
    /// (DNS rebinding). Any loopback, private, link-local or otherwise non-public address refuses
    /// the direct route before anything is sent (`LocalTarget`; literals and local names were
    /// refused by `fetch_url`). A name the system cannot resolve skips the direct route (`None`):
    /// an unchecked lookup is not left to the request.
    async fn linked_client(
        &self,
        url: &Url,
        cancel: &CancellationToken,
    ) -> Result<Option<reqwest::Client>, FetchError> {
        let host = url.host_str().unwrap_or_default();
        let addrs = match policy::literal_ip(url) {
            Some(ip) => vec![ip],
            None => tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(FetchError::Cancelled),
                addrs = http::lookup(url) => addrs,
            },
        };
        if addrs.iter().any(|ip| !is_public_ip(*ip)) {
            tracing::info!(%host, "subscription: a link's name resolves into a local range: no direct request");
            return Err(FetchError::LocalTarget);
        }
        if addrs.is_empty() {
            tracing::info!(%host, "subscription: a link's name did not resolve; no direct try");
            return Ok(None);
        }
        let port = url.port_or_known_default().unwrap_or(443);
        let pinned: Vec<SocketAddr> = addrs.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
        Ok(self.pinned_client(host, &pinned))
    }

    /// A direct client whose lookups of `name` answer `addrs` only (an IP literal's `name` is
    /// never looked up, so the pin is harmless there).
    fn pinned_client(&self, name: &str, addrs: &[SocketAddr]) -> Option<reqwest::Client> {
        let built = self.fetcher.builder(&Route::Direct).and_then(|b| {
            b.resolve_to_addrs(name, addrs)
                .build()
                .map_err(|e| AppError::internal(e.without_url()))
        });
        built
            .map_err(|err| tracing::warn!("subscription: no HTTP client: {err}"))
            .ok()
    }

    /// Fetches each Mihomo provider over `order` and merges new keys into `report`, at most
    /// [`MAX_PROFILES`] in all (a cut list is marked as such). A provider's own providers and
    /// relocation hints are ignored. The subscription's identity and the user's headers go only
    /// to a provider on the host of `own` (the subscription and fallback URLs): Mihomo itself
    /// never sends a subscription's headers to its providers. A provider that a redirect from
    /// `base` could not reach (`https` -> `http`, a public subscription into a private network)
    /// is refused, not fetched.
    pub(super) async fn providers(
        &self,
        refs: &[HttpProvider],
        base: &Url,
        own: &[&Url],
        routes: &ProviderRoutes,
        report: &mut ParseReport,
        cancel: &CancellationToken,
    ) -> Result<Vec<ProviderFetch>, FetchError> {
        // Speed audit ops7: fetched [`PROVIDER_WIDTH`] at a time and one per host (each panel
        // sees the load it saw before), then merged in the providers' order, so the cut at
        // MAX_PROFILES falls where it fell one after another.
        let width = tokio::sync::Semaphore::new(PROVIDER_WIDTH);
        let hosts: HashMap<String, tokio::sync::Mutex<()>> = (refs.iter())
            .filter_map(|p| Some(host_key(&http_url(&p.url)?)))
            .map(|host| (host, tokio::sync::Mutex::new(())))
            .collect();
        let fetches = refs.iter().map(|provider| async {
            let url = http_url(&provider.url)?;
            let allowed = tokio::select! {
                biased;
                () = cancel.cancelled() => return Some(Err(FetchError::Cancelled)),
                allowed = http::vet_relocation(base, &url, routes.local_dns) => allowed,
            };
            if !allowed {
                tracing::info!(provider = %provider.name, "subscription: provider URL refused");
                return Some(Err(FetchError::LocalTarget));
            }
            let _host = match hosts.get(&host_key(&url)) {
                Some(lock) => Some(lock.lock().await),
                None => None,
            };
            let Ok(_turn) = width.acquire().await else {
                return Some(Err(FetchError::Cancelled));
            };
            let ours = own.iter().any(|o| o.host() == url.host());
            let variants = if ours { &self.own } else { &self.public };
            Some(
                self.fetch_url(&url, variants, &routes.order, routes.doh, cancel)
                    .await,
            )
        });
        let fetched_all = futures_util::future::join_all(fetches).await;
        let mut seen: HashSet<[u8; 16]> = report.profiles.iter().map(|p| p.identity()).collect();
        let mut out = Vec::with_capacity(refs.len());
        for (provider, fetched) in refs.iter().zip(fetched_all) {
            let Some(fetched) = fetched else {
                continue;
            };
            let (servers, failed) = match fetched {
                Ok(got) => (merge(report, &mut seen, got.report), None),
                Err(FetchError::Failed(outcome) | FetchError::Said(outcome, _)) => {
                    (0, Some(ProviderFailure::Fetch(outcome)))
                }
                // A linked subscription's provider in the local network: that provider only.
                Err(FetchError::LocalTarget) => (0, Some(ProviderFailure::Refused)),
                Err(other) => return Err(other),
            };
            out.push(ProviderFetch {
                name: provider.name.clone(),
                servers,
                failed,
            });
        }
        Ok(out)
    }
}

/// The lower-case host of a provider URL (one fetch per host at a time).
fn host_key(url: &Url) -> String {
    url.host_str().unwrap_or_default().to_ascii_lowercase()
}

/// Adds the keys of `fetched` that `report` lacks, up to [`MAX_PROFILES`] in all; the first key
/// past the cap marks the list as cut, as the parser does. Returns how many were added.
fn merge(report: &mut ParseReport, seen: &mut HashSet<[u8; 16]>, fetched: ParseReport) -> usize {
    let before = report.profiles.len();
    for profile in fetched.profiles {
        if seen.contains(&profile.identity()) {
            continue;
        }
        if report.profiles.len() == MAX_PROFILES {
            report.skipped.push(parse::cut_marker(&profile));
            break;
        }
        seen.insert(profile.identity());
        report.profiles.push(profile);
    }
    report.skipped.extend(fetched.skipped);
    report.profiles.len() - before
}

/// Mihomo providers of one answer fetched at once (one per host).
const PROVIDER_WIDTH: usize = 3;

/// One route (or one pinned address) of the plan.
struct Attempt<'a> {
    client: &'a reqwest::Client,
    url: &'a Url,
    host: &'a str,
    /// Log label of the route (never credentials).
    label: String,
    route: Option<&'a Route>,
    hops: Hops,
    /// A linked direct fetch: every redirect hop is pinned ([`http::get`]).
    pin: Option<http::Pin<'a>>,
}

/// The answer carries the panel's own metadata (`subscription-userinfo`, `profile-title`, …):
/// the panel itself answered, not a block page or a portal in between.
fn panel_headers(headers: &[(String, String)]) -> bool {
    let pairs = headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    text::header_meta(pairs, SubscriptionMeta::default()) != SubscriptionMeta::default()
}

/// A parsed answer without servers that is the panel's own verdict on this device: its
/// notices, or an empty or encrypted list under its own headers.
fn panel_verdict(outcome: FetchOutcome, panel: bool) -> bool {
    match outcome {
        FetchOutcome::Placeholder => true,
        FetchOutcome::EmptyList | FetchOutcome::Unparseable(BodyKind::Encrypted) => panel,
        _ => false,
    }
}

impl Attempt<'_> {
    /// The variants in order on this route until one yields profiles (or providers).
    async fn run(
        &self,
        variants: &[Variant],
        failures: &mut Failures,
        cancel: &CancellationToken,
    ) -> Result<Step, FetchError> {
        let identified = variants.iter().filter(|v| v.with_ids).count();
        let mut gone = 0;
        let mut verdict = false;
        for variant in variants {
            let sends = http::Sends {
                own: &variant.headers,
                elsewhere: &variant.elsewhere,
            };
            // When the plan sends the HWID, its anonymous requests are only the fallback: the
            // panel's "send the HWID" to them is expected and says nothing new.
            let refusal = |code: u16, headers: &[(String, String)], body: &[u8]| {
                hwid::refusal(code, headers, body, variant.with_ids).filter(|r| {
                    variant.with_ids || identified == 0 || *r != FetchOutcome::HwidRequired
                })
            };
            let answer = http::get(self.client, self.url, sends, self.hops, self.pin, cancel).await;
            let mut said = None;
            let outcome = match answer {
                Err(Abort::Cancelled) => return Err(FetchError::Cancelled),
                Ok(Answer::Body {
                    headers,
                    body,
                    moved,
                }) => {
                    // A device-limited panel may send an empty list (or its placeholders) with
                    // the reason in headers.
                    let refused = refusal(200, &headers, b"");
                    let panel = panel_headers(&headers);
                    let parsed = tokio::select! {
                        biased;
                        () = cancel.cancelled() => return Err(FetchError::Cancelled),
                        parsed = evaluate(headers, body) => parsed,
                    };
                    match parsed {
                        Ok(found) => {
                            tracing::info!(host = %self.host, route = %self.label,
                                ua = %variant.label, profiles = found.report.profiles.len(),
                                providers = found.providers.len(), "subscription fetched");
                            return Ok(Step::Done(Box::new(Got {
                                report: found.report,
                                keys: found.keys,
                                moved,
                                providers: found.providers,
                                route: self.route.cloned(),
                                agent: variant.family.clone(),
                            })));
                        }
                        Err((outcome, words)) => {
                            if words.is_some() {
                                tracing::info!(host = %self.host, route = %self.label,
                                    ua = %variant.label, "subscription: placeholders instead of servers");
                            }
                            verdict |= panel_verdict(outcome, panel);
                            said = words;
                            refused.unwrap_or(outcome)
                        }
                    }
                }
                Ok(Answer::Status {
                    code,
                    headers,
                    body,
                }) => refusal(code, &headers, &body).unwrap_or(FetchOutcome::Http(code)),
                Ok(Answer::Unusable(reason)) => {
                    tracing::info!(host = %self.host, route = %self.label, ua = %variant.label,
                        "subscription: {reason}");
                    FetchOutcome::Unparseable(BodyKind::Other)
                }
                Err(Abort::Transport(outcome)) => {
                    tracing::info!(host = %self.host, route = %self.label, ua = %variant.label,
                        "subscription: route failed: {outcome:?}");
                    failures.note(outcome);
                    // A transport failure says nothing about User-Agents: next route (S-08).
                    return Ok(Step::Next);
                }
            };
            tracing::debug!(host = %self.host, route = %self.label, ua = %variant.label,
                "subscription attempt: {outcome:?}");
            failures.note_said(outcome, said);
            match outcome {
                // Rate limited: hammering other routes or agents would only make it worse.
                FetchOutcome::Http(429) => return Ok(Step::Stop),
                // The panel said why it refuses this device: other agents, routes or a spare
                // slot change nothing (only the HWID switch or the provider can).
                FetchOutcome::DeviceLimit => return Ok(Step::Stop),
                FetchOutcome::HwidRequired if !variant.with_ids => return Ok(Step::Stop),
                FetchOutcome::Http(404 | 410) | FetchOutcome::HwidRequired if variant.with_ids => {
                    gone += 1;
                    if gone == identified {
                        return Ok(Step::Stop);
                    }
                }
                _ => {}
            }
        }
        if verdict {
            // Speed audit ops1: the panel judged this device on every agent; another route, a
            // DoH-pinned address or a spare slot only asks it again (20-40 requests).
            tracing::info!(host = %self.host, route = %self.label,
                "subscription: the panel's own answer; no other route");
            return Ok(Step::Stop);
        }
        Ok(Step::Next)
    }
}
