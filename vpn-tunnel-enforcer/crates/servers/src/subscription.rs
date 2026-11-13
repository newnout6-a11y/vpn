//! Subscription fetching (servers §2.5, profiles §3.7): bootstrap routes, device identity (User-Agent
//! rotation + HWID headers), manual redirects with the downgrade / private-network rules, a 16 MiB
//! body cap, a DoH-pinned direct retry, then `crate::parse::parse_body` and the userinfo headers.
//!
//! Logs carry the host, the route label and the User-Agent family only: never the URL path or
//! query (the access token), the HWID or the headers (S-27).
use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use vpnte_base::types::{ClientDevice, ProxyKind};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::net::{HostPort, Route};
use vpnte_core::settings::{BootstrapRouteMode, Settings};
use vpnte_profiles::deeplink::DeepLinkError;
use vpnte_profiles::device::{self, MachineIdentity};
use vpnte_profiles::model::{ParseReport, SkipReason};

use crate::model::{BodyKind, FetchOutcome, NetFail};

mod fallback;
mod fetch;
mod headers;
mod http;
mod hwid;
mod policy;
#[cfg(test)]
mod refusal_tests;
mod relay;
mod request;
#[cfg(test)]
mod request_tests;
#[cfg(test)]
pub(crate) mod tests;

pub use crate::common::canonical_source;
pub use headers::{MAX_HEADERS, header_names, parse_headers, stored_headers};
pub use policy::{classify_body, normalize_redirect};
pub use relay::{Relays, Spare, SpareFuture};
pub use request::{FetchRequest, Fetched, ProviderFailure, ProviderFetch};

/// Whole-request limit of one HTTP request (old curl `--max-time 25`).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(25);
/// Requests per attempt: the first one plus at most five redirects.
pub const MAX_REQUESTS: usize = 6;
/// Pinned addresses taken from DNS-over-HTTPS.
pub const DOH_MAX_IPS: usize = 3;
/// Happ's rule: the fallback URL is tried when the URL has not answered after 9 s.
pub const FALLBACK_AFTER: Duration = Duration::from_secs(9);
/// Happ's local proxies, tried after the user's own proxy (old `bootstrapRoute.ts`).
const HAPP_SOCKS: &str = "127.0.0.1:10808";
const HAPP_HTTP: &str = "127.0.0.1:10809";

/// The HWID announced per device, computed once. One value feeds both the Happ User-Agent and the
/// `x-hwid` header (S-44: the old app sent two different ids when the override was set).
#[derive(Clone, PartialEq, Eq)]
pub struct Hwids([String; 4]);

impl Hwids {
    /// This machine: `VPNTE_SUBSCRIPTION_HWID` when set, else the Electron app's hash, so
    /// HWID-limited panels do not count the new client as another device.
    pub fn current() -> Self {
        Self::of(&MachineIdentity::current(), device::hwid_override())
    }

    /// The HWIDs of `id`; `fixed` (the environment override) replaces all four.
    pub fn of(id: &MachineIdentity, fixed: Option<String>) -> Self {
        Self(DEVICES.map(|d| fixed.clone().unwrap_or_else(|| device::legacy_hwid(d, id))))
    }

    /// The HWID of `device`.
    pub fn get(&self, device: ClientDevice) -> &str {
        &self.0[device_index(device)]
    }
}

impl fmt::Debug for Hwids {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hwids(..)")
    }
}

const DEVICES: [ClientDevice; 4] = [
    ClientDevice::Pc,
    ClientDevice::Android,
    ClientDevice::Ios,
    ClientDevice::Mac,
];

fn device_index(device: ClientDevice) -> usize {
    match device {
        ClientDevice::Pc => 0,
        ClientDevice::Android => 1,
        ClientDevice::Ios => 2,
        ClientDevice::Mac => 3,
    }
}

/// Where subscription requests may go, in order, and what may follow when they all fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    pub routes: Vec<Route>,
    /// True unless the user chose "local proxy only" (the retry goes out directly).
    pub doh: bool,
    /// Only in "auto": the running session's route joins the plan, and a short-lived slot on a
    /// healthy server of the list may be borrowed when every route failed. "Direct only" and
    /// "local proxy only" mean what they say: the session's engine and a borrowed slot dial out
    /// on their own (Smart RU sends Russian hosts direct, a slot connects to a VPN server).
    pub relay: bool,
}

impl RoutePlan {
    /// The plan with the session's own route right after direct (first without direct); a route
    /// already in the plan is not repeated. Nothing changes when `relay` is off.
    pub fn with_session(mut self, session: Option<Route>) -> Self {
        let Some(route) = session.filter(|_| self.relay) else {
            return self;
        };
        if self.routes.iter().any(|r| r.label() == route.label()) {
            return self;
        }
        let at = usize::from(self.routes.first() == Some(&Route::Direct));
        self.routes.insert(at, route);
        self
    }
}

/// The bootstrap routes of `settings` (old `bootstrapRoute.ts`): `auto` = direct, the user's proxy,
/// Happ's SOCKS `127.0.0.1:10808`, Happ's HTTP `127.0.0.1:10809` (plus the session's route and a
/// spare slot, see [`RoutePlan::relay`]); `direct` = direct only; `localProxy` = the proxies only.
/// Duplicates (same scheme and address) are dropped.
pub fn route_plan(settings: &Settings) -> RoutePlan {
    let mode = settings.bootstrap_route_mode;
    let mut routes = Vec::new();
    if mode != BootstrapRouteMode::LocalProxy {
        routes.push(Route::Direct);
    }
    if mode != BootstrapRouteMode::Direct {
        let user = settings
            .proxy_override
            .as_ref()
            .map(|p| p.route(settings.proxy_type));
        let happ = [
            (ProxyKind::Socks5, HAPP_SOCKS),
            (ProxyKind::Http, HAPP_HTTP),
        ]
        .into_iter()
        .filter_map(|(kind, addr)| Some(Route::proxy(kind, &HostPort::parse(addr).ok()?, None)));
        for route in user.into_iter().chain(happ) {
            if !routes.iter().any(|r: &Route| r.label() == route.label()) {
                routes.push(route);
            }
        }
    }
    RoutePlan {
        routes,
        doh: mode != BootstrapRouteMode::LocalProxy,
        relay: mode == BootstrapRouteMode::Auto,
    }
}

/// Why a fetch produced no profiles.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// Every attempt failed; the strongest evidence wins (servers §6: empty list > unparseable
    /// body > HTTP 4xx > HTTP 5xx > network > timeout).
    #[error("subscription fetch failed: {0:?}")]
    Failed(FetchOutcome),
    /// As `Failed`, and the strongest answer came as provider placeholders instead of servers:
    /// their words («Приложение не поддерживается»), one line (p-live-fix).
    #[error("subscription fetch failed: {0:?} (the provider answered with placeholders)")]
    Said(FetchOutcome, String),
    /// Not a single-line `http(s)://host` URL.
    #[error("not a subscription URL")]
    InvalidUrl,
    /// A subscription that came from outside (a deep link, a QR code) resolves into the local
    /// network: nothing was sent (phones-a11).
    #[error("subscription link into a local network")]
    LocalTarget,
    /// The caller cancelled; nothing is recorded.
    #[error("subscription fetch cancelled")]
    Cancelled,
}

impl From<FetchError> for AppError {
    fn from(err: FetchError) -> Self {
        match &err {
            FetchError::Failed(outcome) | FetchError::Said(outcome, _) => {
                let kind = match outcome {
                    FetchOutcome::EmptyList
                    | FetchOutcome::HwidRequired
                    | FetchOutcome::DeviceLimit
                    | FetchOutcome::Placeholder
                    | FetchOutcome::Unparseable(_) => ErrorKind::Validation,
                    FetchOutcome::Timeout => ErrorKind::Timeout,
                    _ => ErrorKind::Network,
                };
                // A refusal the panel typed (HWID, device limit) keeps its own sentence: the
                // add dialog offers the HWID switch by it; the group keeps the words.
                let msg = match (&err, outcome) {
                    (FetchError::Said(_, said), FetchOutcome::Placeholder) => {
                        Msg::new("servers.fetch.said").arg("said", said)
                    }
                    _ => outcome_msg(*outcome),
                };
                AppError::msg(kind, msg).with_source(err)
            }
            FetchError::InvalidUrl => {
                AppError::validation(Msg::new("servers.fetch.invalidUrl")).with_source(err)
            }
            FetchError::LocalTarget => {
                AppError::validation(DeepLinkError::LocalTarget.msg()).with_source(err)
            }
            FetchError::Cancelled => AppError::cancelled(),
        }
    }
}

impl FetchError {
    /// The typed outcome of a failed fetch (`None`: not a failure of the panel or the network).
    pub fn outcome(&self) -> Option<FetchOutcome> {
        match self {
            FetchError::Failed(outcome) | FetchError::Said(outcome, _) => Some(*outcome),
            _ => None,
        }
    }

    /// The provider's own words, when its answer was placeholders.
    pub fn said(&self) -> Option<&str> {
        match self {
            FetchError::Said(_, said) => Some(said),
            _ => None,
        }
    }

    /// The error of a group's fetch: an empty list fetched without the HWID suggests sending it
    /// (HWID-bound panels answer an unknown device with an empty list).
    pub fn for_group(self, send_hwid: bool) -> AppError {
        match self {
            FetchError::Failed(FetchOutcome::EmptyList) if !send_hwid => {
                AppError::validation(Msg::new("servers.fetch.emptyListNoHwid")).with_source(self)
            }
            other => other.into(),
        }
    }
}

/// The sentence for a fetch outcome (the group's last result, or a failed import).
pub fn outcome_msg(outcome: FetchOutcome) -> Msg {
    match outcome {
        FetchOutcome::Ok { partial: false } => Msg::new("servers.fetch.ok"),
        FetchOutcome::Ok { partial: true } => Msg::new("servers.fetch.partial"),
        FetchOutcome::EmptyList => Msg::new("servers.fetch.emptyList"),
        FetchOutcome::HwidRequired => Msg::new("servers.fetch.hwidRequired"),
        FetchOutcome::DeviceLimit => Msg::new("servers.fetch.deviceLimit"),
        FetchOutcome::Placeholder => Msg::new("servers.fetch.placeholder"),
        FetchOutcome::Unparseable(kind) => Msg::new(match kind {
            BodyKind::Html => "servers.fetch.body.html",
            BodyKind::Json => "servers.fetch.body.json",
            BodyKind::Base64 => "servers.fetch.body.base64",
            BodyKind::Uris => "servers.fetch.body.uris",
            BodyKind::Encrypted => "servers.fetch.body.encrypted",
            BodyKind::Other => "servers.fetch.body.other",
        }),
        FetchOutcome::Http(code) => Msg::new("servers.fetch.http").arg("code", code),
        FetchOutcome::Network(fail) => Msg::new(match fail {
            NetFail::Dns => "servers.fetch.net.dns",
            NetFail::Connect => "servers.fetch.net.connect",
            NetFail::Tls => "servers.fetch.net.tls",
            NetFail::Proxy => "servers.fetch.net.proxy",
            NetFail::Reset => "servers.fetch.net.reset",
        }),
        FetchOutcome::Timeout => Msg::new("servers.fetch.timeout"),
    }
}

/// True when the parser skipped nothing but duplicates: only then may a refresh treat a missing key
/// as removed by the provider (servers §3.3 `ParseReport.complete`).
pub fn is_complete(report: &ParseReport) -> bool {
    report
        .skipped
        .iter()
        .all(|s| s.reason == SkipReason::Duplicate)
}

/// Where a fetcher takes its routes from.
enum Plans {
    /// Read at every fetch, so a changed proxy setting applies to the next refresh.
    Settings(Arc<vpnte_core::store::Store<Settings>>),
    Fixed(RoutePlan),
}

/// Downloads subscriptions the way Happ-compatible panels expect. Share it in an `Arc`.
pub struct SubscriptionFetcher {
    hwids: Hwids,
    plans: Plans,
    request_timeout: Duration,
    /// Set once by the app when the tunnel and the proxy slots exist.
    relays: OnceLock<Arc<dyn Relays>>,
}

impl SubscriptionFetcher {
    /// A fetcher that follows the proxy and bootstrap settings of `settings`.
    pub fn new(hwids: Hwids, settings: Arc<vpnte_core::store::Store<Settings>>) -> Self {
        Self {
            hwids,
            plans: Plans::Settings(settings),
            request_timeout: REQUEST_TIMEOUT,
            relays: OnceLock::new(),
        }
    }

    /// A fetcher with fixed routes (probes, tests).
    pub fn with_plan(hwids: Hwids, plan: RoutePlan) -> Self {
        Self {
            hwids,
            plans: Plans::Fixed(plan),
            request_timeout: REQUEST_TIMEOUT,
            relays: OnceLock::new(),
        }
    }

    /// Lends the fetcher the session route and the spare slots; the first call wins.
    pub fn set_relays(&self, relays: Arc<dyn Relays>) {
        if self.relays.set(relays).is_err() {
            tracing::warn!("subscription: relays were set already");
        }
    }

    /// The routes the next fetch will use (the session's route included while one runs).
    pub fn plan(&self) -> RoutePlan {
        let plan = match &self.plans {
            Plans::Settings(store) => store.read(route_plan),
            Plans::Fixed(plan) => plan.clone(),
        };
        plan.with_session(self.relays.get().and_then(|r| r.session_route()))
    }

    /// This PC's HWIDs: what a subscription without its own ID sends.
    pub fn hwids(&self) -> &Hwids {
        &self.hwids
    }

    #[cfg(test)]
    pub(crate) fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
}

impl fmt::Debug for SubscriptionFetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionFetcher")
            .field("plan", &self.plan())
            .finish_non_exhaustive()
    }
}
