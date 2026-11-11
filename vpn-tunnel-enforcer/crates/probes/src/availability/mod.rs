//! URL availability: "does this link work with and without the VPN?" (monitoring §3.9, §4.7).
//!
//! With the tunnel up both paths run in parallel: "с защитой" = the app's own DNS / TCP / TLS /
//! HTTP stages with sockets bound to the TUN address (what the user's apps experience under the
//! current rules), and "без VPN" = the same HTTP probe through the engine's direct inbound. With
//! the tunnel down only the native probe runs (it IS the direct path). A page fetch on each side
//! feeds the geo-block scoring; then the verdict, and the result goes to a history of 50.
mod geo_block;
mod history;
mod probe;
mod report;
mod target;
mod verdict;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Loopback, ProxyKind, UnixMs, now_ms};
use vpnte_base::{AppError, AppResult};
use vpnte_core::net::{HostPort, Route, is_public_ip};
use vpnte_core::ops::{FeatureKind, OperationRegistry, RunOpts};
use vpnte_core::store::Store;

pub use geo_block::{
    GeoReason, GeoVerdict, INTERSTITIAL_TEXT_MAX, PageSignal, compare_renders, html_to_signal,
    score_single_page,
};
pub use history::{MAX_HISTORY, UrlChecks};
pub use report::{
    DnsStage, ErrorCode, GeoInfo, HttpClass, HttpStage, PathReport, PathSource, Stage, TcpStage,
    TlsStage,
};
pub use target::ProbeTarget;
pub use verdict::{AvailabilityVerdict, Recommendation, derive_verdict};

use probe::{Bind, Clients};

/// Upper bound of one whole check (B-UA-8): both paths run in parallel inside it.
pub const CHECK_BUDGET: Duration = Duration::from_secs(30);
/// Budget of one path's DNS → HTTP stages; the page fetch may use the rest of the check budget.
pub const PATH_BUDGET: Duration = Duration::from_secs(15);
/// The geo lookup runs beside the TCP / TLS stages and never longer than this.
const GEO_LIMIT: Duration = Duration::from_secs(5);
/// Time to see the engine's direct inbound answer a SOCKS greeting.
const INBOUND_LIMIT: Duration = Duration::from_millis(1500);

/// How the paths leave the machine during a check (facts from the tunnel runtime).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Paths {
    /// No tunnel: one native measurement through the OS routes and resolver.
    Direct,
    /// Tunnel up. The protected side binds to the TUN addresses when known (unbound it still
    /// rides the TUN routes); the direct side needs the engine's direct inbound, without it the
    /// side is reported as not measured.
    Tunnel {
        tun_v4: Option<Ipv4Addr>,
        tun_v6: Option<Ipv6Addr>,
        direct_inbound: Option<Loopback>,
    },
}

/// Country / network lookup of an address (the app wires `probes::geo`; it owns the limiter,
/// cache and 429 backoff). Not called at all when the user disabled geo lookups.
pub trait GeoLookup: Send + Sync {
    /// Geo facts of a public address; `None` when unknown.
    fn lookup(&self, ip: IpAddr) -> BoxFuture<'_, Option<GeoInfo>>;
}

/// Everything a check needs besides the URL.
#[derive(Clone)]
pub struct CheckEnv {
    pub paths: Paths,
    /// `None` when geo lookups are disabled.
    pub geo: Option<Arc<dyn GeoLookup>>,
}

/// One finished check, as shown and stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailabilityResult {
    pub id: String,
    /// `scheme://host[:port]/path`: no userinfo, query or fragment (B-UA-5).
    pub url: String,
    pub tested_at: UnixMs,
    pub tunnel_active: bool,
    /// "С защитой": through the TUN under the current rules; `None` with the tunnel off.
    #[serde(default)]
    pub protected: Option<PathReport>,
    /// "Без VPN".
    #[serde(default)]
    pub direct: Option<PathReport>,
    pub verdict: AvailabilityVerdict,
    pub recommendation: Recommendation,
}

/// Checks one target. Cancellation is prompt (every socket is dropped with the future);
/// nothing is persisted here. Errors: `Cancelled`, `Timeout` (past [`CHECK_BUDGET`]).
pub async fn check_url(
    env: &CheckEnv,
    target: &ProbeTarget,
    cancel: &CancellationToken,
) -> AppResult<AvailabilityResult> {
    let tunnel_active = matches!(env.paths, Paths::Tunnel { .. });
    tracing::info!(host = %target.log_host(), port = target.port(), tunnel_active, "availability check started");
    let deadline = Instant::now() + CHECK_BUDGET;
    let work = measure(env, target, deadline);
    let (protected, direct) = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(AppError::cancelled()),
        sides = tokio::time::timeout(CHECK_BUDGET, work) => sides.map_err(|_| AppError::timeout())?,
    };
    let (verdict, recommendation) = derive_verdict(protected.as_ref(), direct.as_ref());
    tracing::info!(
        host = %target.log_host(),
        ?verdict,
        protected_ok = protected.as_ref().map(|p| p.available),
        direct_ok = direct.as_ref().map(|d| d.available),
        "availability check finished"
    );
    Ok(AvailabilityResult {
        id: uuid::Uuid::new_v4().to_string(),
        url: target.history_url(),
        tested_at: now_ms(),
        tunnel_active,
        protected,
        direct,
        verdict,
        recommendation,
    })
}

/// Parses `input`, runs the check as a feature operation (one per call, so two checks may run
/// at once) and records it at the front of the history. A bad URL is refused before admission.
pub async fn run_check(
    ops: &OperationRegistry,
    history: Arc<Store<UrlChecks>>,
    env: CheckEnv,
    input: &str,
    opts: RunOpts,
) -> AppResult<AvailabilityResult> {
    let target = ProbeTarget::parse(input)?;
    let resource = format!(
        "{}:{}",
        FeatureKind::AvailabilityCheck.as_str(),
        uuid::Uuid::new_v4()
    );
    let opts = RunOpts {
        resource: Some(resource.into()),
        ..opts
    };
    ops.run(
        FeatureKind::AvailabilityCheck,
        opts,
        move |lease| async move {
            let token = lease.token().clone();
            let result = lease
                .wait(async move { check_url(&env, &target, &token).await })
                .await??;
            lease.commit(|| {
                history.update(|doc| doc.push(result.clone()))?;
                Ok(result)
            })
        },
    )
    .await
}

/// Measures the sides `env.paths` has and applies the geo-block scoring to the pages.
async fn measure(
    env: &CheckEnv,
    target: &ProbeTarget,
    deadline: Instant,
) -> (Option<PathReport>, Option<PathReport>) {
    let geo = env.geo.as_deref();
    match &env.paths {
        Paths::Direct => {
            let (mut direct, signal) = native(target, Bind::default(), geo, deadline).await;
            if let Some(signal) = &signal {
                mark_geo_blocked(&mut direct, score_single_page(signal));
            }
            (None, Some(direct))
        }
        Paths::Tunnel {
            tun_v4,
            tun_v6,
            direct_inbound,
        } => {
            let bind = Bind {
                v4: *tun_v4,
                v6: *tun_v6,
            };
            let ((mut protected, p_signal), (mut direct, d_signal)) = tokio::join!(
                native(target, bind, geo, deadline),
                inbound(target, direct_inbound.as_ref(), deadline),
            );
            if let (Some(p), Some(d)) = (&p_signal, &d_signal) {
                mark_geo_blocked(&mut direct, compare_renders(p, d));
            } else if let Some(d) = &d_signal {
                mark_geo_blocked(&mut direct, score_single_page(d));
            }
            if let Some(p) = &p_signal {
                mark_geo_blocked(&mut protected, score_single_page(p));
            }
            (Some(protected), Some(direct))
        }
    }
}

fn mark_geo_blocked(report: &mut PathReport, verdict: GeoVerdict) {
    if !verdict.blocked {
        return;
    }
    report.available = false;
    report.geo_blocked = true;
    report.error_stage = Some(Stage::Http);
    for reason in verdict.reasons {
        if !report.geo_reasons.contains(&reason) {
            report.geo_reasons.push(reason);
        }
    }
}

fn failed(
    mut report: PathReport,
    stage: Stage,
    code: Option<ErrorCode>,
    start: Instant,
) -> PathReport {
    report.error_stage = Some(stage);
    report.error = Some(code.unwrap_or(ErrorCode::Unknown));
    report.total_ms = Some(probe::ms(start));
    report
}

/// The native path: DNS, then TCP / TLS / HTTP with the geo lookup beside them.
async fn native(
    target: &ProbeTarget,
    bind: Bind,
    geo: Option<&dyn GeoLookup>,
    deadline: Instant,
) -> (PathReport, Option<PageSignal>) {
    let start = Instant::now();
    let path_deadline = (start + PATH_BUDGET).min(deadline);
    let mut report = PathReport::new(PathSource::Native);
    let (dns, stop) = probe::dns_stage(target.host(), path_deadline).await;
    let addrs: Vec<SocketAddr> = dns
        .ips
        .iter()
        .map(|ip| SocketAddr::new(*ip, target.port()))
        .collect();
    let first_public = dns.ips.first().copied().filter(|ip| is_public_ip(*ip));
    let resolved = dns.resolved;
    report.dns = Some(dns);
    if stop.is_some() || !resolved {
        return (failed(report, Stage::Dns, stop, start), None);
    }
    let lookup = async move {
        let (geo, ip) = (geo?, first_public?);
        probe::limited(path_deadline, GEO_LIMIT, geo.lookup(ip))
            .await
            .ok()
            .flatten()
    };
    let stages = async move {
        let (tcp, err) = probe::tcp_stage(&addrs, bind, path_deadline).await;
        let connected = tcp.connected;
        report.tcp = Some(tcp);
        if !connected {
            return (failed(report, Stage::Tcp, err, start), None);
        }
        if target.https() {
            let (tls, err) = probe::tls_stage(target, &addrs, bind, path_deadline).await;
            let ok = tls.handshake_ok;
            report.tls = Some(tls);
            if !ok {
                return (failed(report, Stage::Tls, err, start), None);
            }
        }
        match Clients::new(&Route::Direct, bind) {
            Some(clients) => {
                http_and_page(report, &clients, target, path_deadline, deadline, start).await
            }
            None => (failed(report, Stage::Http, None, start), None),
        }
    };
    let ((mut report, signal), geo) = tokio::join!(stages, lookup);
    report.geo = geo;
    (report, signal)
}

/// The direct side through the engine's direct inbound: HTTP stage and page only.
async fn inbound(
    target: &ProbeTarget,
    inbound: Option<&Loopback>,
    deadline: Instant,
) -> (PathReport, Option<PageSignal>) {
    let start = Instant::now();
    let unmeasured = || {
        (
            PathReport::unmeasured(PathSource::DirectInbound, ErrorCode::ProxyFailed),
            None,
        )
    };
    let Some(inbound) = inbound else {
        return unmeasured();
    };
    let Ok(addr) = HostPort::new("127.0.0.1", inbound.port) else {
        return unmeasured();
    };
    // A dead inbound must read as "not measured", not as the provider blocking the site.
    if !inbound_alive(inbound).await {
        tracing::warn!("direct inbound did not answer; the direct path is not measured");
        return unmeasured();
    }
    let route = Route::proxy(ProxyKind::Socks5, &addr, inbound.creds.as_ref());
    let Some(clients) = Clients::new(&route, Bind::default()) else {
        return unmeasured();
    };
    let report = PathReport::new(PathSource::DirectInbound);
    let path_deadline = (start + PATH_BUDGET).min(deadline);
    http_and_page(report, &clients, target, path_deadline, deadline, start).await
}

async fn inbound_alive(inbound: &Loopback) -> bool {
    let greet = async {
        let mut stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, inbound.port))
            .await
            .ok()?;
        vpnte_core::socks5::negotiate(&mut stream, inbound.creds.as_ref())
            .await
            .ok()
    };
    matches!(
        tokio::time::timeout(INBOUND_LIMIT, greet).await,
        Ok(Some(()))
    )
}

/// HTTP stage, availability from its status, then the page fetch when the origin answered.
async fn http_and_page(
    mut report: PathReport,
    clients: &Clients,
    target: &ProbeTarget,
    path_deadline: Instant,
    deadline: Instant,
    start: Instant,
) -> (PathReport, Option<PageSignal>) {
    let (http, err) = probe::http_stage(clients, target.url(), path_deadline).await;
    let status = http.status;
    report.http = Some(http);
    report.total_ms = Some(probe::ms(start));
    match status.map(HttpClass::of) {
        None => return (failed(report, Stage::Http, err, start), None),
        Some(HttpClass::Legal) => {
            report.geo_blocked = true;
            report.geo_reasons.push(GeoReason::Http451);
            report.error_stage = Some(Stage::Http);
        }
        Some(HttpClass::ServerError) => report.error_stage = Some(Stage::Http),
        Some(_) => report.available = true,
    }
    let signal = probe::page_signal(clients, target.url(), deadline).await;
    (report, signal)
}

#[cfg(test)]
pub(crate) mod tests;
