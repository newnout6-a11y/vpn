//! The fetch plan of one URL (profiles §3.7, bounded as servers §6 / S-08 asks): route first; on a
//! route that answers, the User-Agent variants with the device headers, then without; a route that
//! fails at transport level is left at once; then a DoH-pinned direct retry; the strongest failure
//! wins. Mihomo providers of an answer are fetched the same way, the answering route first.
use std::collections::HashSet;
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
use vpnte_profiles::model::ParseReport;
use vpnte_profiles::text::{self, ProviderKeys};
use vpnte_profiles::{clash, device};

use super::headers::header_map;
use super::http::{self, Abort, Answer, Hops};
use super::hwid;
use super::{DOH_MAX_IPS, FetchError, ProviderFailure, ProviderFetch, SubscriptionFetcher, policy};
use crate::common::http_url;
use crate::model::{BodyKind, FetchOutcome, NetFail};
use crate::parse::{self, MAX_PROFILES};

/// One User-Agent, with or without the device headers.
pub(super) struct Variant {
    /// What the subscription's own origin gets.
    headers: HeaderMap,
    /// What another origin gets after a redirect: the same client without the HWID, no device
    /// headers, none of the user's headers (they may hold tokens; browsers, curl and reqwest drop
    /// credentials on a cross-origin redirect the same way).
    elsewhere: HeaderMap,
    /// Log label: the User-Agent family and `+hwid` (never the HWID itself, S-27).
    label: String,
    with_ids: bool,
}

/// The User-Agents of `device` with the HWID headers, then the same without them (servers §2.5:
/// some panels answer an empty 200 without the HWID, others gate by client name). `hwid: None`
/// (the group does not send it) keeps only the variants without it. The user's own headers go on
/// last and win; their `User-Agent` replaces the rotation.
pub(super) fn variants(
    device: ClientDevice,
    hwid: Option<&str>,
    custom: &[(String, String)],
) -> Vec<Variant> {
    let custom = header_map(custom);
    let anonymous = device::user_agents(device, None);
    let agents = match custom.get(USER_AGENT) {
        Some(own) => vec![String::from_utf8_lossy(own.as_bytes()).into_owned()],
        None => device::user_agents(device, hwid),
    };
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
            let family = agent.split('/').next().unwrap_or_default();
            let label = format!("{family}{}", if with_ids { "+hwid" } else { "" });
            out.push(Variant {
                headers,
                elsewhere: basic_headers(plain.map_or("", String::as_str)),
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
}

/// How one route ended.
enum Step {
    Done(Box<Got>),
    /// Go on with the next route.
    Next,
    /// The panel said enough (429, or 404 / 410 to every identified request): stop the plan.
    Stop,
}

/// The strongest failure seen so far.
#[derive(Default)]
struct Failures(Option<FetchOutcome>);

impl Failures {
    fn note(&mut self, outcome: FetchOutcome) {
        if self.0.is_none_or(|seen| rank(outcome) < rank(seen)) {
            self.0 = Some(outcome);
        }
    }

    fn into_error(self) -> FetchError {
        FetchError::Failed(self.0.unwrap_or(FetchOutcome::Network(NetFail::Connect)))
    }
}

/// Evidence order of servers §6: a received but unusable answer beats a later network failure;
/// a panel that named its reason for refusing the device beats everything.
pub(super) fn rank(outcome: FetchOutcome) -> u8 {
    match outcome {
        FetchOutcome::DeviceLimit => 0,
        FetchOutcome::HwidRequired => 1,
        FetchOutcome::EmptyList => 2,
        FetchOutcome::Unparseable(_) => 3,
        FetchOutcome::Http(400..=499) => 4,
        FetchOutcome::Http(_) => 5,
        FetchOutcome::Network(_) => 6,
        FetchOutcome::Timeout => 7,
        FetchOutcome::Ok { .. } => 8,
    }
}

/// A body evaluated: the report with the header metadata merged in (headers win), the provider
/// keys, the Mihomo providers.
struct Evaluated {
    report: ParseReport,
    keys: ProviderKeys,
    providers: Vec<HttpProvider>,
}

/// Up to 16 MiB of nested base64, YAML and thousands of keys is CPU work: it runs on the blocking
/// pool, not on a runtime worker.
async fn evaluate(
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<Evaluated, FetchOutcome> {
    tokio::task::spawn_blocking(move || evaluate_now(&headers, &body))
        .await
        .unwrap_or_else(|err| {
            tracing::warn!("subscription: the body parser failed: {err}");
            Err(FetchOutcome::Unparseable(BodyKind::Other))
        })
}

fn evaluate_now(headers: &[(String, String)], body: &[u8]) -> Result<Evaluated, FetchOutcome> {
    let parsed =
        parse::parse_body_full(body).map_err(|_| FetchOutcome::Unparseable(BodyKind::Other))?;
    let mut report = parsed.report;
    let providers = clash::http_providers(&parsed.text);
    if report.profiles.is_empty() && providers.is_empty() {
        return Err(policy::classify_body(&parsed.text));
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
    /// `linked`: the subscription came from outside.
    pub(super) fn new(
        fetcher: &'a SubscriptionFetcher,
        device: ClientDevice,
        hwid: Option<&str>,
        headers: &[(String, String)],
        linked: bool,
    ) -> Self {
        Self {
            fetcher,
            own: variants(device, hwid, headers),
            public: variants(device, None, &[]),
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
        if refused_direct && failures.0.is_none() {
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
        let mut seen: HashSet<[u8; 16]> = report.profiles.iter().map(|p| p.identity()).collect();
        let mut out = Vec::with_capacity(refs.len());
        for provider in refs {
            let Some(url) = http_url(&provider.url) else {
                continue;
            };
            let allowed = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(FetchError::Cancelled),
                allowed = http::vet_relocation(base, &url, routes.local_dns) => allowed,
            };
            if !allowed {
                tracing::info!(provider = %provider.name, "subscription: provider URL refused");
                out.push(ProviderFetch {
                    name: provider.name.clone(),
                    servers: 0,
                    failed: Some(ProviderFailure::Refused),
                });
                continue;
            }
            let ours = own.iter().any(|o| o.host() == url.host());
            let variants = if ours { &self.own } else { &self.public };
            let fetched = self
                .fetch_url(&url, variants, &routes.order, routes.doh, cancel)
                .await;
            let (servers, failed) = match fetched {
                Ok(got) => (merge(report, &mut seen, got.report), None),
                Err(FetchError::Failed(outcome)) => (0, Some(ProviderFailure::Fetch(outcome))),
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
            let outcome = match answer {
                Err(Abort::Cancelled) => return Err(FetchError::Cancelled),
                Ok(Answer::Body {
                    headers,
                    body,
                    moved,
                }) => {
                    // A device-limited panel may send an empty list with the reason in headers.
                    let refused = refusal(200, &headers, b"");
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
                            })));
                        }
                        Err(outcome) => refused.unwrap_or(outcome),
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
            failures.note(outcome);
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
        Ok(Step::Next)
    }
}
