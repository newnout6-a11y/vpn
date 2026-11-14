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
use crate::svc_tunnel::scope::{self, RunScope};

/// The leak self-test of the running session.
pub(crate) async fn leak(shared: &Shared, cancel: CancellationToken) -> AppResult<LeakTestView> {
    let tunnel = session_tunnel(shared)?;
    let status = tunnel.runtime_status().borrow().clone();
    let level = if is_tun(&status) {
        tunnel.kill_switch().await.settings.level
    } else {
        KillSwitchLevel::Off
    };
    let listed_only = listed_run(&shared.run_scope, &status, || {
        scope::saved_listed(&shared.backend.settings)
    });
    let result = run_self_test(&SystemEnv, level, &cancel)
        .await
        .with_scope(listed_only);
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

/// Only the listed apps use the running Tunnel session's VPN, so curl's default-route read goes
/// around it (p-app-split). The run's own scope labels and judges it, never the saved one: a
/// flipped switch applies from the next connection (appsplit-b4, p-follow3). `saved` is read
/// only for a run nobody has seen yet.
fn listed_run(run: &RunScope, status: &TunStatus, saved: impl FnOnce() -> bool) -> bool {
    run.observe(scope::run_start(status), saved);
    is_tun(status) && run.listed()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// appsplit-b4 (p-follow3): the self-test of a Tunnel run that started with only the listed
    /// apps keeps that scope after the switch flipped; Proxy mode has no app scope; the next
    /// run reads the saved one.
    #[test]
    fn the_self_test_reads_the_running_scope() {
        let run = RunScope::default();
        let status = TunStatus {
            running: true,
            started_at: Some(1_000),
            capture: Some(CaptureKind::Tun),
            ..TunStatus::default()
        };
        // the tunnel's copy saw the run start with «Только выбранные приложения»
        run.observe(Some(1_000), || true);
        assert!(
            listed_run(&run, &status, || false),
            "the switch flipped mid-run"
        );
        let proxy = TunStatus {
            capture: Some(CaptureKind::Proxy),
            ..status.clone()
        };
        assert!(!listed_run(&run, &proxy, || true));
        let next = TunStatus {
            started_at: Some(2_000),
            ..status
        };
        assert!(!listed_run(&run, &next, || false), "the next run, all apps");
        assert!(
            !listed_run(&run, &TunStatus::default(), || true),
            "nothing runs"
        );
    }
}
