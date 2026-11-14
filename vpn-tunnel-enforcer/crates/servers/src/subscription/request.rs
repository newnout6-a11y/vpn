//! One subscription fetch end to end (ru-2026 items 1 and 3): the URL over the route plan with
//! Happ's fallback rule, one more try through a borrowed slot when everything failed, the Mihomo
//! providers, and the provider's relocation hints, vetted like redirects.
use std::fmt;

use tokio_util::sync::CancellationToken;
use url::Url;
use vpnte_base::types::ClientDevice;
use vpnte_core::net::Route;
use vpnte_profiles::model::ParseReport;
use vpnte_profiles::text::{Controls, Relocation};

use super::fallback::{Source, with_fallback};
use super::fetch::{Ctx, Got, ProviderRoutes};
use super::relay::Spare;
use super::{FALLBACK_AFTER, FetchError, RoutePlan, SubscriptionFetcher, http, is_complete};
use crate::common::{canonical_source, http_url};
use crate::model::{BodyKind, FetchOutcome, NetFail};

/// What a fetch needs besides the URL. `Debug` shows the host only (the URL is a token).
#[derive(Clone)]
pub struct FetchRequest {
    pub url: Url,
    pub device: ClientDevice,
    /// Send the device HWID headers and the HWID in the Happ User-Agent.
    pub send_hwid: bool,
    /// The subscription's own HWID (the user reset it); `None` sends this PC's.
    pub hwid: Option<String>,
    /// The user's extra headers (checked by [`super::parse_headers`]), applied last.
    pub headers: Vec<(String, String)>,
    /// The provider's fallback URL from an earlier answer.
    pub fallback: Option<Url>,
    /// The URL came from outside (a deep link, a QR code): it must not lead into the local
    /// network, also through a public name (phones-a11). A URL the user typed may.
    pub from_link: bool,
    /// The User-Agent family that last brought this subscription's servers: tried first
    /// (p-live-fix).
    pub prefer_agent: Option<String>,
    /// The plan route (its label) that last brought them: tried first (speed audit ops2).
    pub prefer_route: Option<String>,
}

impl FetchRequest {
    /// `url` as `device` and nothing else: no HWID (a new group's default), no extra headers, no
    /// fallback, typed by the user.
    pub fn new(url: Url, device: ClientDevice) -> Self {
        Self {
            url,
            device,
            send_hwid: false,
            hwid: None,
            headers: Vec::new(),
            fallback: None,
            from_link: false,
            prefer_agent: None,
            prefer_route: None,
        }
    }
}

impl fmt::Debug for FetchRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchRequest")
            .field("host", &self.url.host_str())
            .field("device", &self.device)
            .field("send_hwid", &self.send_hwid)
            .field("own_hwid", &self.hwid.is_some())
            .field("headers", &self.headers.len())
            .field("fallback", &self.fallback.is_some())
            .field("from_link", &self.from_link)
            .field("prefer_agent", &self.prefer_agent)
            .field("prefer_route", &self.prefer_route)
            .finish()
    }
}

/// One Mihomo provider of the answer, for the import report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFetch {
    pub name: String,
    /// New keys it added.
    pub servers: usize,
    /// Why it gave nothing (its keys then count as missing evidence, not as removed).
    pub failed: Option<ProviderFailure>,
}

/// Why a Mihomo provider gave nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFailure {
    /// It was asked and failed so.
    Fetch(FetchOutcome),
    /// It was not asked: its URL is `http` under an `https` subscription, or points a public
    /// subscription into a private network (the redirect rules).
    Refused,
}

/// A successful fetch. `Debug` hides the URLs.
pub struct Fetched {
    /// At least one profile; metadata = headers over body lines.
    pub report: ParseReport,
    /// The provider's controls of this answer.
    pub controls: Controls,
    /// The subscription's vetted permanent new address (`new-url`, `moved-permanently-to`,
    /// `new-domain` or a followed 301 / 308 of the URL itself), only from an answer of the URL
    /// that may re-point it (see [`may_relocate`]).
    pub moved_to: Option<Url>,
    /// A vetted fallback URL named by an answer that may re-point the subscription.
    pub fallback: Option<Url>,
    /// The answer came from the fallback URL.
    pub via_fallback: bool,
    /// Mihomo providers fetched and merged.
    pub providers: Vec<ProviderFetch>,
    /// The User-Agent family that brought the servers (remembered per group, p-live-fix).
    pub agent: String,
    /// The plan route that brought them (its label; `None`: the DoH-pinned retry or a spare).
    pub route: Option<String>,
}

impl Fetched {
    /// Only duplicates were skipped and every provider answered: absence is evidence.
    pub fn complete(&self) -> bool {
        is_complete(&self.report) && self.providers.iter().all(|p| p.failed.is_none())
    }
}

impl fmt::Debug for Fetched {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fetched")
            .field("profiles", &self.report.profiles.len())
            .field("controls", &self.controls)
            .field("moved", &self.moved_to.is_some())
            .field("fallback", &self.fallback.is_some())
            .field("via_fallback", &self.via_fallback)
            .field("providers", &self.providers)
            .field("agent", &self.agent)
            .field("route", &self.route)
            .finish()
    }
}

impl SubscriptionFetcher {
    /// Downloads and parses the subscription at `url` as `device` would, as a new group does (no
    /// HWID, no extra headers). `Ok` holds at least one profile.
    pub async fn fetch(
        &self,
        url: &Url,
        device: ClientDevice,
        cancel: &CancellationToken,
    ) -> Result<ParseReport, FetchError> {
        let req = FetchRequest::new(url.clone(), device);
        self.fetch_request(&req, cancel).await.map(|f| f.report)
    }

    /// The whole fetch of `req`: the URL over the plan (the session's route right after direct),
    /// the fallback URL when the URL fails or is silent for 9 s, one more try of both through a
    /// borrowed slot when everything failed, then the Mihomo providers and the relocation hints.
    /// A cancelled token stops at once; one cancelled beforehand sends no request.
    pub async fn fetch_request(
        &self,
        req: &FetchRequest,
        cancel: &CancellationToken,
    ) -> Result<Fetched, FetchError> {
        let url = http_url(req.url.as_str()).ok_or(FetchError::InvalidUrl)?;
        if cancel.is_cancelled() {
            return Err(FetchError::Cancelled);
        }
        let fallback = req
            .fallback
            .as_ref()
            .and_then(|f| http_url(f.as_str()))
            .filter(|f| *f != url);
        let plan = self.plan().preferring(req.prefer_route.as_deref());
        let hwid = req
            .send_hwid
            .then(|| req.hwid.as_deref().unwrap_or(self.hwids.get(req.device)));
        let ctx = Ctx::new(
            self,
            req.device,
            hwid,
            &req.headers,
            req.prefer_agent.as_deref(),
            req.from_link,
        );
        let tried = with_fallback(
            ctx.fetch_url(&url, &ctx.own, &plan.routes, plan.doh, cancel),
            fallback.as_ref().map(|f| {
                let (ctx, plan) = (&ctx, &plan);
                // A linked subscription's fallback in the local network fails as that URL only:
                // the subscription's own URL may still answer.
                async move {
                    ctx.fetch_url(f, &ctx.own, &plan.routes, plan.doh, cancel)
                        .await
                        .map_err(|e| match e {
                            FetchError::LocalTarget => {
                                FetchError::Failed(FetchOutcome::Network(NetFail::Connect))
                            }
                            other => other,
                        })
                }
            }),
            FALLBACK_AFTER,
        )
        .await;
        // Held until the providers are fetched: they go the way the answer came.
        let mut spare: Option<Spare> = None;
        let (got, source) = match tried {
            Ok(found) => found,
            Err(failed) if failed.outcome().is_some() => {
                match self
                    .through_spare(&ctx, &plan, &url, fallback.as_ref(), cancel)
                    .await?
                {
                    Some((found, borrowed)) => {
                        spare = Some(borrowed);
                        found
                    }
                    None => return Err(failed),
                }
            }
            Err(other) => return Err(other),
        };
        let answer = Answered {
            url: &url,
            fallback: fallback.as_ref(),
            source,
            via_spare: spare.is_some(),
        };
        let fetched = self.finish(&ctx, &plan, &answer, got, cancel).await;
        drop(spare);
        fetched
    }

    /// One more try of the URL, then the fallback, through a slot on a healthy server of the
    /// list (when the plan allows it and the app lends one). A URL whose panel said enough (429,
    /// gone for every identified request) is not asked again from another address (S-08); when
    /// that leaves nothing to try, no slot is started.
    async fn through_spare(
        &self,
        ctx: &Ctx<'_>,
        plan: &RoutePlan,
        url: &Url,
        fallback: Option<&Url>,
        cancel: &CancellationToken,
    ) -> Result<Option<((Got, Source), Spare)>, FetchError> {
        let Some(relays) = self.relays.get().filter(|_| plan.relay) else {
            return Ok(None);
        };
        let targets: Vec<(&Url, Source)> =
            [(Some(url), Source::Main), (fallback, Source::Fallback)]
                .into_iter()
                .filter_map(|(target, source)| Some((target?, source)))
                .filter(|(target, _)| !ctx.stopped(target))
                .collect();
        let host = url.host_str().unwrap_or_default();
        if targets.is_empty() {
            tracing::info!(%host, "subscription: the panel said stop; no spare slot");
            return Ok(None);
        }
        let borrowed = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(FetchError::Cancelled),
            spare = relays.spare_route(cancel.clone()) => spare,
        };
        let Some(spare) = borrowed else {
            tracing::info!(%host, "subscription: no spare slot to try through");
            return Ok(None);
        };
        tracing::info!(%host, route = %spare.route().label(), "subscription: trying a spare slot");
        let routes = [spare.route().clone()];
        for (target, source) in targets {
            match ctx
                .fetch_url(target, &ctx.own, &routes, false, cancel)
                .await
            {
                Ok(got) => return Ok(Some(((got, source), spare))),
                Err(err) if err.outcome().is_some() => {}
                Err(other) => return Err(other),
            }
        }
        Ok(None)
    }

    /// The providers merged in, the relocation hints vetted.
    async fn finish(
        &self,
        ctx: &Ctx<'_>,
        plan: &RoutePlan,
        answer: &Answered<'_>,
        got: Got,
        cancel: &CancellationToken,
    ) -> Result<Fetched, FetchError> {
        let Got {
            mut report,
            keys,
            moved,
            providers: refs,
            route,
            agent,
        } = got;
        let remembered = route
            .as_ref()
            .filter(|_| !answer.via_spare)
            .map(Route::label);
        // Names are checked by the system resolver only when the answer came direct.
        let local_dns = route == Some(Route::Direct);
        let providers = if refs.is_empty() {
            Vec::new()
        } else {
            let mut order: Vec<Route> = route.iter().cloned().collect();
            order.extend(
                plan.routes
                    .iter()
                    .filter(|r| Some(*r) != route.as_ref())
                    .cloned(),
            );
            let routes = ProviderRoutes {
                order,
                doh: plan.doh,
                local_dns,
            };
            let own: Vec<&Url> = [Some(answer.url), answer.fallback]
                .into_iter()
                .flatten()
                .collect();
            ctx.providers(&refs, answer.url, &own, &routes, &mut report, cancel)
                .await?
        };
        if report.profiles.is_empty() {
            // Only providers were named and none of them gave a key.
            let failed = providers.iter().filter_map(|p| match p.failed {
                Some(ProviderFailure::Fetch(outcome)) => Some(outcome),
                _ => None,
            });
            let outcome = failed.min_by_key(|o| super::fetch::rank(*o));
            return Err(FetchError::Failed(
                outcome.unwrap_or(FetchOutcome::Unparseable(BodyKind::Other)),
            ));
        }
        // A 301 / 308 or a hint of the fallback URL says nothing about the URL itself.
        let candidate = match answer.source {
            Source::Main => relocation(answer.url, &keys.relocation, moved),
            Source::Fallback => None,
        };
        let named = keys.relocation.fallback_url.as_deref().and_then(http_url);
        let trusted = may_relocate(answer.answering(), answer.via_spare);
        if !trusted && (candidate.is_some() || named.is_some()) {
            tracing::info!(host = ?answer.url.host_str(), via_spare = answer.via_spare,
                "subscription: relocation hints ignored: not over HTTPS on the user's routes");
        }
        let (candidate, named) = if trusted {
            (candidate, named)
        } else {
            (None, None)
        };
        let moved_to = vetted(answer.url, candidate, local_dns, cancel).await?;
        let fallback = vetted(answer.url, named, local_dns, cancel).await?;
        Ok(Fetched {
            report,
            controls: keys.controls,
            moved_to,
            fallback,
            via_fallback: answer.source == Source::Fallback,
            providers,
            agent,
            route: remembered,
        })
    }
}

/// Which URL answered, and how.
struct Answered<'u> {
    /// The subscription URL.
    url: &'u Url,
    fallback: Option<&'u Url>,
    source: Source,
    /// Through a borrowed slot on a server of the list.
    via_spare: bool,
}

impl Answered<'_> {
    /// The URL that gave the answer.
    fn answering(&self) -> &Url {
        match (self.source, self.fallback) {
            (Source::Fallback, Some(fallback)) => fallback,
            _ => self.url,
        }
    }
}

/// Whether an answer of `answering` may re-point the stored subscription (a move, a new fallback
/// URL): only over HTTPS, and not through a borrowed slot. Happ trusts these keys only from a
/// registered provider; what this app can check is that nobody on the path wrote them: a plain
/// `http` answer can be rewritten by any hop, and a borrowed slot's server is a third party.
/// Anything else is ignored (logged), never applied.
pub(super) fn may_relocate(answering: &Url, via_spare: bool) -> bool {
    answering.scheme() == "https" && !via_spare
}

/// The new address the answer names: `new-url` / `moved-permanently-to`, else `new-domain` on the
/// URL (same path), else the URL's permanent redirect target.
pub(super) fn relocation(url: &Url, hints: &Relocation, redirect: Option<Url>) -> Option<Url> {
    if let Some(next) = hints.new_url.as_deref().and_then(http_url) {
        return Some(next);
    }
    if let Some(domain) = &hints.new_domain {
        let target = Url::parse(&format!("http://{domain}/")).ok()?;
        let mut next = url.clone();
        next.set_host(target.host_str()).ok()?;
        next.set_port(target.port()).ok()?;
        return Some(next);
    }
    redirect
}

/// `target` in canonical form when it differs from `url` and passes the redirect rules.
async fn vetted(
    url: &Url,
    target: Option<Url>,
    local_dns: bool,
    cancel: &CancellationToken,
) -> Result<Option<Url>, FetchError> {
    let Some(target) = target.and_then(|t| canonical_source(t.as_str())) else {
        return Ok(None);
    };
    if target == *url {
        return Ok(None);
    }
    let allowed = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(FetchError::Cancelled),
        allowed = http::vet_relocation(url, &target, local_dns) => allowed,
    };
    if !allowed {
        tracing::info!(host = ?url.host_str(), "subscription: a relocation hint was refused");
    }
    Ok(allowed.then_some(target))
}
