//! The fetch plan (profiles §3.7, bounded as servers §6 / S-08 asks): route first; on a route that
//! answers, the User-Agent variants with the device headers, then without; a route that fails at
//! transport level is left at once; then a DoH-pinned direct retry; the strongest failure wins.
use std::net::SocketAddr;

use reqwest::header::{ACCEPT, HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use tokio_util::sync::CancellationToken;
use url::Url;
use vpnte_base::types::ClientDevice;
use vpnte_core::net::{Route, builder_for, client_for, is_public_ip};
use vpnte_core::resolve::{How, resolve_host};
use vpnte_profiles::model::ParseReport;
use vpnte_profiles::{device, text};

use super::http::{self, Abort, Answer, Hops};
use super::{DOH_MAX_IPS, FetchError, SubscriptionFetcher, policy};
use crate::common::http_url;
use crate::model::{BodyKind, FetchOutcome, NetFail};
use crate::parse;

/// One User-Agent, with or without the device headers.
struct Variant {
    headers: HeaderMap,
    /// Log label: the User-Agent family and `+hwid` (never the HWID itself, S-27).
    label: String,
    with_ids: bool,
}

/// The User-Agents of `device` with the HWID headers, then the same without them (servers §2.5:
/// some panels answer an empty 200 without the HWID, others gate by client name).
fn variants(device: ClientDevice, hwid: &str) -> Vec<Variant> {
    let agents = device::user_agents(device, hwid);
    let ids = device::device_headers(device, hwid);
    let mut out = Vec::with_capacity(agents.len() * 2);
    for with_ids in [true, false] {
        for agent in &agents {
            let mut headers = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(agent) {
                headers.insert(USER_AGENT, value);
            }
            headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
            if with_ids {
                for (name, value) in &ids {
                    let name = HeaderName::from_bytes(name.as_bytes());
                    if let (Ok(name), Ok(value)) = (name, HeaderValue::from_str(value)) {
                        headers.insert(name, value);
                    }
                }
            }
            let family = agent.split('/').next().unwrap_or_default();
            let label = format!("{family}{}", if with_ids { "+hwid" } else { "" });
            out.push(Variant {
                headers,
                label,
                with_ids,
            });
        }
    }
    out
}

/// How one route ended.
enum Step {
    Done(Box<ParseReport>),
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

/// Evidence order of servers §6: a received but unusable answer beats a later network failure.
fn rank(outcome: FetchOutcome) -> u8 {
    match outcome {
        FetchOutcome::EmptyList => 0,
        FetchOutcome::Unparseable(_) => 1,
        FetchOutcome::Http(400..=499) => 2,
        FetchOutcome::Http(_) => 3,
        FetchOutcome::Network(_) => 4,
        FetchOutcome::Timeout => 5,
        FetchOutcome::Ok { .. } => 6,
    }
}

/// A body -> profiles with the header metadata merged in (headers win), or why it is unusable.
fn evaluate(headers: &[(String, String)], body: &[u8]) -> Result<ParseReport, FetchOutcome> {
    let mut report =
        parse::parse_body(body).map_err(|_| FetchOutcome::Unparseable(BodyKind::Other))?;
    if report.profiles.is_empty() {
        let decoded = text::decode_body(body, text::MAX_BODY_BYTES).unwrap_or_default();
        return Err(policy::classify_body(&decoded));
    }
    let from_body = std::mem::take(&mut report.meta);
    let pairs = headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    report.meta = text::header_meta(pairs, from_body);
    Ok(report)
}

impl SubscriptionFetcher {
    /// Downloads and parses the subscription at `url` as `device` would. `Ok` holds at least one
    /// profile; its `meta` merges the userinfo headers over the body's `#key:` lines. A cancelled
    /// token stops at once, and a token cancelled beforehand sends no request.
    pub async fn fetch(
        &self,
        url: &Url,
        device: ClientDevice,
        cancel: &CancellationToken,
    ) -> Result<ParseReport, FetchError> {
        let url = http_url(url.as_str()).ok_or(FetchError::InvalidUrl)?;
        if cancel.is_cancelled() {
            return Err(FetchError::Cancelled);
        }
        let host = url.host_str().unwrap_or_default().to_owned();
        let plan = self.plan();
        let variants = variants(device, self.hwids.get(device));
        let mut failures = Failures::default();
        for route in &plan.routes {
            let client = match client_for(route, self.request_timeout) {
                Ok(client) => client,
                Err(err) => {
                    tracing::warn!(route = %route.label(), "subscription: no HTTP client: {err}");
                    continue;
                }
            };
            let hops = Hops {
                local_dns: *route == Route::Direct,
                origin_public: None,
            };
            let ctx = Attempt {
                client: &client,
                url: &url,
                host: &host,
                route: route.label(),
                hops,
            };
            match ctx.run(&variants, &mut failures, cancel).await? {
                Step::Done(report) => return Ok(*report),
                Step::Stop => return Err(failures.into_error()),
                Step::Next => {}
            }
        }
        if plan.doh
            && let Some(url::Host::Domain(name)) = url.host()
            && !policy::is_local_name(&url)
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
                        let pinned =
                            builder_for(&Route::Direct, self.request_timeout).and_then(|b| {
                                b.resolve_to_addrs(name, &[SocketAddr::new(ip, port)])
                                    .build()
                                    .map_err(|e| vpnte_base::AppError::internal(e.without_url()))
                            });
                        let Ok(client) = pinned else { continue };
                        let hops = Hops {
                            local_dns: true,
                            origin_public: Some(true),
                        };
                        let route = format!("doh-pinned {ip}");
                        let ctx = Attempt {
                            client: &client,
                            url: &url,
                            host: &host,
                            route,
                            hops,
                        };
                        match ctx.run(&variants, &mut failures, cancel).await? {
                            Step::Done(report) => return Ok(*report),
                            Step::Stop => return Err(failures.into_error()),
                            Step::Next => {}
                        }
                    }
                }
                Err(err) => {
                    tracing::info!(%host, "subscription: DNS-over-HTTPS gave no address: {err}")
                }
            }
        }
        let err = failures.into_error();
        tracing::info!(%host, "subscription: every attempt failed: {err}");
        Err(err)
    }
}

/// One route (or one pinned address) of the plan.
struct Attempt<'a> {
    client: &'a reqwest::Client,
    url: &'a Url,
    host: &'a str,
    route: String,
    hops: Hops,
}

impl Attempt<'_> {
    /// The variants in order on this route until one yields profiles.
    async fn run(
        &self,
        variants: &[Variant],
        failures: &mut Failures,
        cancel: &CancellationToken,
    ) -> Result<Step, FetchError> {
        let identified = variants.iter().filter(|v| v.with_ids).count();
        let mut gone = 0;
        for variant in variants {
            let answer =
                http::get(self.client, self.url, &variant.headers, self.hops, cancel).await;
            let outcome = match answer {
                Err(Abort::Cancelled) => return Err(FetchError::Cancelled),
                Ok(Answer::Body { headers, body }) => match evaluate(&headers, &body) {
                    Ok(report) => {
                        tracing::info!(host = %self.host, route = %self.route, ua = %variant.label,
                            profiles = report.profiles.len(), "subscription fetched");
                        return Ok(Step::Done(Box::new(report)));
                    }
                    Err(outcome) => outcome,
                },
                Ok(Answer::Status(code)) => FetchOutcome::Http(code),
                Ok(Answer::Unusable(reason)) => {
                    tracing::info!(host = %self.host, route = %self.route, ua = %variant.label,
                        "subscription: {reason}");
                    FetchOutcome::Unparseable(BodyKind::Other)
                }
                Err(Abort::Transport(outcome)) => {
                    tracing::info!(host = %self.host, route = %self.route, ua = %variant.label,
                        "subscription: route failed: {outcome:?}");
                    failures.note(outcome);
                    // A transport failure says nothing about User-Agents: next route (S-08).
                    return Ok(Step::Next);
                }
            };
            tracing::debug!(host = %self.host, route = %self.route, ua = %variant.label,
                "subscription attempt: {outcome:?}");
            failures.note(outcome);
            match outcome {
                // Rate limited: hammering other routes or agents would only make it worse.
                FetchOutcome::Http(429) => return Ok(Step::Stop),
                FetchOutcome::Http(404 | 410) if variant.with_ids => {
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
