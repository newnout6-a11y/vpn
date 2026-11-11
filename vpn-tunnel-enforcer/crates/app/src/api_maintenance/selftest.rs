//! «Проверить защиту»: the leak self-test (curl bound to every physical address, IP services
//! cross-checked) and the routing self-test (VPN exit vs direct exit, Smart RU). Both only with
//! a session; no elevation needed. Soft sessions block nothing outside the system proxy
//! (NOADMIN §2): reach from a physical address is judged as with the kill switch off, and the
//! routing test, which measures the OS route, says it does not apply.
use std::net::IpAddr;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, KillSwitchLevel};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_probes::diagnostics::{self, RoutingInputs, RoutingVerdict};
use vpnte_probes::leak::{
    AddrProbe, Reach, SelfTestResult, SelfTestVerdict, SystemEnv, report, run_self_test,
};
use vpnte_tunnel::api::{CaptureKind, TunStatus};
use vpnte_ui::maintenance::{
    AdapterProbe, LeakTestView, LeakVerdict, ProbeReach, RouteTestView, RouteVerdict, TunnelPhase,
};

use super::{Shared, project, refused};

/// The leak self-test of the running session.
pub(crate) async fn leak(shared: &Shared, cancel: CancellationToken) -> AppResult<LeakTestView> {
    let tunnel = session_tunnel(shared)?;
    let status = tunnel.runtime_status().borrow().clone();
    let level = if is_tun(&status) {
        tunnel.kill_switch().await.settings.level
    } else {
        KillSwitchLevel::Off
    };
    let result = run_self_test(&SystemEnv, level, &cancel).await;
    if result.cancelled && cancel.is_cancelled() {
        return Err(AppError::cancelled());
    }
    tracing::info!(verdict = ?report(&result).verdict, probes = result.probes.len(),
        "maintenance: leak self-test finished");
    Ok(leak_view(&result))
}

/// The routing self-test of the running session.
pub(crate) async fn route(shared: &Shared, cancel: CancellationToken) -> AppResult<RouteTestView> {
    let tunnel = session_tunnel(shared)?;
    let status = tunnel.runtime_status().borrow().clone();
    if !is_tun(&status) {
        return Ok(RouteTestView {
            verdict: RouteVerdict::Inconclusive,
            message: Msg::new("app.maintenance.route.softMode"),
        });
    }
    let settings = shared.backend.settings.snapshot();
    let inputs = RoutingInputs {
        tunnel_active: true,
        direct: tunnel.probe_ctx(ClientDevice::default()).net.tun_direct,
        tun_source: Some(IpAddr::V4(vpnte_winnet::adapters::TUN_V4.addr())),
        smart_ru: settings.smart_ru_split,
        disable_geo_lookup: settings.disable_geo_lookup,
    };
    let result = diagnostics::routing_test(inputs, cancel).await?;
    Ok(RouteTestView {
        verdict: route_verdict(result.verdict),
        message: result.message,
    })
}

/// The tunnel, when a session is up (the page asks only then; a session may end meanwhile).
fn session_tunnel(shared: &Shared) -> AppResult<std::sync::Arc<dyn crate::services::TunnelOps>> {
    if project::live_phase(shared) != TunnelPhase::On {
        return Err(refused("app.maintenance.selfTest.needsSession"));
    }
    Ok(shared.backend.tunnel()?.clone())
}

fn is_tun(status: &TunStatus) -> bool {
    status.running && status.capture == Some(CaptureKind::Tun)
}

/// The panel's view of a run; every sentence comes from the evidence (probes' `report`).
pub(crate) fn leak_view(r: &SelfTestResult) -> LeakTestView {
    let summary = report(r);
    LeakTestView {
        at: r.at,
        verdict: match summary.verdict {
            SelfTestVerdict::Leak => LeakVerdict::Leak,
            SelfTestVerdict::PossibleLeak => LeakVerdict::PossibleLeak,
            SelfTestVerdict::Ok => LeakVerdict::Ok,
            SelfTestVerdict::Inconclusive => LeakVerdict::Inconclusive,
        },
        cancelled: r.cancelled,
        headline: summary.headline,
        tun_ip: r.default_v4.map(|ip| ip.to_string()),
        adapters: r.probes.iter().map(probe_view).collect(),
        disagreement: r.services_disagree.map(|d| {
            Msg::new("probes.leak.selfTest.disagreement")
                .arg("other", d.other_service_ip)
                .arg("default", d.default_ip)
        }),
    }
}

fn probe_view(p: &AddrProbe) -> AdapterProbe {
    AdapterProbe {
        alias: p.alias.clone(),
        local: Some(p.local.to_string()),
        reach: match p.reach {
            Reach::Reached { ip } => ProbeReach::Reached {
                public_ip: ip.to_string(),
            },
            Reach::NotReached { curl_exit } => ProbeReach::NotReached { curl_exit },
            Reach::Inconclusive { curl_exit, why } => ProbeReach::Unknown {
                curl_exit,
                why: why.label(),
            },
        },
        stderr_tail: p.stderr_tail.clone(),
    }
}

fn route_verdict(v: RoutingVerdict) -> RouteVerdict {
    match v {
        RoutingVerdict::Ok => RouteVerdict::Ok,
        RoutingVerdict::Partial => RouteVerdict::Partial,
        RoutingVerdict::Leak => RouteVerdict::Leak,
        RoutingVerdict::TunnelOff => RouteVerdict::TunnelOff,
        RoutingVerdict::Inconclusive => RouteVerdict::Inconclusive,
    }
}
