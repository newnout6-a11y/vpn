//! View-model of the Availability page: what one URL check and one routing self-test showed.
//! Display data only; every sentence the backend composes arrives as a [`Msg`].
use std::net::IpAddr;

use vpnte_base::Msg;
use vpnte_base::types::UnixMs;

/// Pushed page state (one snapshot; the page mirrors it into a signal).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AvailabilityState {
    /// The tunnel is up, so a check measures both paths and the routing test can run.
    pub tunnel_running: bool,
    /// Saved URL checks, newest first (the backend keeps at most 50; the page shows 20).
    pub history: Vec<UrlCheck>,
    /// The saved history could not be read: shown instead of "no history yet" (U-06).
    pub history_error: Option<Msg>,
}

/// The result of one URL check.
#[derive(Debug, Clone, PartialEq)]
pub struct UrlCheck {
    pub id: String,
    /// The normalised address that was probed (`scheme://host[:port]/path`, no query).
    pub url: String,
    pub tested_at: UnixMs,
    /// Whether the tunnel was up when the check ran.
    pub tunnel_active: bool,
    /// Through the tunnel under the current rules; `None` when the tunnel was off.
    pub protected: Option<PathReport>,
    /// Without the VPN (the engine's direct exit while the tunnel is up, else the plain network).
    pub direct: Option<PathReport>,
    pub verdict: UrlVerdict,
    /// What to do about it, composed by the backend.
    pub recommendation: Msg,
}

/// The answer to "do I need the VPN for this site?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UrlVerdict {
    WorksBoth,
    WorksOnlyWithVpn,
    WorksOnlyWithoutVpn,
    BlockedEverywhere,
    /// The site answers 401/403: reachable, but availability is not confirmed (owner §10.5).
    AuthRequired,
    Unknown,
}

impl UrlVerdict {
    /// Every verdict (locale key checks iterate it).
    pub const ALL: [UrlVerdict; 6] = [
        UrlVerdict::WorksBoth,
        UrlVerdict::WorksOnlyWithVpn,
        UrlVerdict::WorksOnlyWithoutVpn,
        UrlVerdict::BlockedEverywhere,
        UrlVerdict::AuthRequired,
        UrlVerdict::Unknown,
    ];
}

/// How a path was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PathSource {
    /// Stage by stage from the app: DNS, TCP, TLS, HTTP.
    #[default]
    Native,
    /// One HTTP request through the engine's direct inbound: no DNS / TCP / TLS detail.
    DirectInbound,
}

/// One measured path. A stage that did not run is `None` and its row is not shown.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PathReport {
    pub source: PathSource,
    /// `false`: the path could not be measured at all (never read as "blocked").
    pub measured: bool,
    pub available: bool,
    /// The site itself refuses this region (451, block page), although the network passes.
    pub geo_blocked: bool,
    pub total_ms: Option<u32>,
    /// Why the path failed, or what is odd about it.
    pub message: Option<Msg>,
    pub dns: Option<DnsStage>,
    pub tcp: Option<TcpStage>,
    pub tls: Option<TlsStage>,
    pub http: Option<HttpStage>,
    pub geo: Option<GeoInfo>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DnsStage {
    pub resolved: bool,
    pub ips: Vec<String>,
    /// A stub or non-public answer for a public name: suspected DNS tampering.
    pub poisoned: bool,
    pub ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TcpStage {
    pub connected: bool,
    pub ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TlsStage {
    pub ok: bool,
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct HttpStage {
    /// `None`: no HTTP answer at all.
    pub status: Option<u16>,
    /// The `Server` header.
    pub server: Option<String>,
    pub ms: Option<u32>,
}

/// Where the first resolved address lives.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GeoInfo {
    pub country: String,
    pub org: String,
}

/// The routing self-test: the egress seen through the VPN versus the real one.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingReport {
    pub ran_at: UnixMs,
    pub verdict: RoutingVerdict,
    /// The explanation, composed by the backend.
    pub message: Msg,
    pub vpn_ip: Option<IpAddr>,
    pub direct_ip: Option<IpAddr>,
    /// Smart RU was on, so a Russian echo page was asked as well.
    pub smart_ru: bool,
    /// What the Russian echo page saw (`None`: not asked or no answer).
    pub ru_ip: Option<IpAddr>,
}

/// Outcome of the routing self-test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoutingVerdict {
    Ok,
    Partial,
    Leak,
    TunnelOff,
    Inconclusive,
}

impl RoutingVerdict {
    /// Every verdict (locale key checks iterate it).
    pub const ALL: [RoutingVerdict; 5] = [
        RoutingVerdict::Ok,
        RoutingVerdict::Partial,
        RoutingVerdict::Leak,
        RoutingVerdict::TunnelOff,
        RoutingVerdict::Inconclusive,
    ];
}
