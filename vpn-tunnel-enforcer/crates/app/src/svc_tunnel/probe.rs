//! Measurements over the running session (pings, the server-probe context, the leak check) and
//! the Smart RU rule-set auto refresh.
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, Creds, EnginePref, Loopback, ProxyKind};
use vpnte_base::{AppError, AppResult};
use vpnte_core::net::{HostPort, Route};
use vpnte_core::settings::{ConnectionMode, Settings};
use vpnte_core::store::Store;
use vpnte_engine::routing::rulesets::{RefreshOutcome, RefreshSettings, RuleSetService};
use vpnte_probes::ip_monitor::IpEvidence;
use vpnte_probes::key_health::ProbeCtx;
use vpnte_probes::leak::{CheckInput, CheckReport, Mode, SelfTestResult};
use vpnte_probes::ping::{NetPath, PingSample, PingTarget, ping_all};
use vpnte_probes::public_ip::IpReader;
use vpnte_servers::model::ProfileId;
use vpnte_servers::store::Servers;
use vpnte_tunnel::api::{CaptureKind, ModeKind, TunStatus};

use crate::services::Engines;
use crate::svc_core::notify::Notifier;

/// How much of each engine log the leak check reads (its error summary needs recent lines only).
const LOG_TAIL_BYTES: u64 = 64 * 1024;
/// Rule-set auto refresh period (the service itself decides whether a download is due).
const RULE_SET_CHECK: Duration = Duration::from_secs(3600);

/// The path probes take while our TUN runs: its authenticated direct-out, so probe traffic
/// bypasses the tunnel. A Soft session needs none: the app's own sockets never use the system
/// proxy.
pub(super) fn net_path(status: &TunStatus) -> NetPath {
    let tun_direct = match (status.capture, status.session.as_ref()) {
        (Some(CaptureKind::Tun), Some(s)) => Some(Loopback {
            port: s.direct.port,
            creds: Some(Creds {
                user: s.direct.user.clone(),
                pass: s.direct.pass.clone(),
            }),
        }),
        _ => None,
    };
    NetPath { tun_direct }
}

/// What a server probe needs now. The runtime publishes no DNS bootstrap listener, so probes
/// resolve on their own (`dns_bootstrap_in: None`).
pub(super) fn probe_ctx(
    engines: &Engines,
    engine_pref: EnginePref,
    device: ClientDevice,
    status: &TunStatus,
) -> ProbeCtx {
    ProbeCtx {
        singbox_exe: engines.singbox.clone(),
        xray_exe: engines.xray.clone(),
        engine_pref,
        device,
        net: net_path(status),
        dns_bootstrap_in: None,
    }
}

/// Pings `ids` (a window of six at a time) and records each answer in the server list as it
/// lands. A missing or unreadable server gets no answer and no record.
pub(super) async fn ping(
    servers: &Servers,
    ids: Vec<ProfileId>,
    net: NetPath,
    cancel: CancellationToken,
) -> AppResult<Vec<(ProfileId, Option<PingSample>)>> {
    let mut results = Vec::with_capacity(ids.len());
    let mut targets = Vec::with_capacity(ids.len());
    for id in ids {
        match servers.get(&id).map(|row| row.profile()) {
            Some(Ok(profile)) => targets.push((id, PingTarget::of(&profile))),
            _ => results.push((id, None)),
        }
    }
    let mut answers = std::pin::pin!(ping_all(targets, net, cancel.clone()));
    while let Some((id, sample)) = answers.next().await {
        servers.record_ping(&id, sample.as_ref().map(|s| s.ms));
        results.push((id, sample));
    }
    if cancel.is_cancelled() {
        return Err(AppError::cancelled());
    }
    Ok(results)
}

/// The leak check for the current state (at most 15 s). The upstream is the running session's,
/// else the configured one; `self_test` is this session's latest background self-test (TUN
/// sessions, run where their filters live: this elevated process or the helper service). The
/// direct-out audit is not wired (`direct: None`: "not checked").
pub(super) async fn leak_check(
    reader: &IpReader,
    settings: &Settings,
    status: &TunStatus,
    evidence: IpEvidence,
    self_test: Option<SelfTestResult>,
    cancel: &CancellationToken,
) -> AppResult<CheckReport> {
    let configured = || settings.proxy_override.as_ref().map(|o| o.addr.clone());
    let mode = match (status.mode, settings.connection_mode) {
        (Some(ModeKind::DirectVpn), _) | (None, ConnectionMode::DirectVpn) => Mode::DirectVpn,
        (Some(ModeKind::LocalProxy), _) => Mode::LocalProxy {
            upstream: status
                .proxy_addr
                .as_deref()
                .and_then(|a| HostPort::parse(a).ok())
                .or_else(configured),
        },
        (None, ConnectionMode::LocalProxy) => Mode::LocalProxy {
            upstream: configured(),
        },
    };
    let engine_log = match &status.session {
        Some(s) if status.running => engine_log(s.logs.clone()).await,
        _ => None,
    };
    let input = CheckInput {
        mode,
        tunnel_up: status.running,
        evidence,
        self_test,
        engine_log,
        direct: None,
    };
    tokio::select! {
        report = vpnte_probes::leak::leak_check(reader, input, cancel) => Ok(report),
        () = cancel.cancelled() => Err(AppError::cancelled()),
    }
}

/// The recent lines of the session's engine logs; `None` when none could be read.
async fn engine_log(paths: Vec<PathBuf>) -> Option<Vec<String>> {
    tokio::task::spawn_blocking(move || {
        let mut lines = Vec::new();
        let mut read_any = false;
        for path in &paths {
            match tail_lines(path) {
                Ok(tail) => {
                    read_any = true;
                    lines.extend(tail);
                }
                Err(e) => tracing::debug!(error = %e, "engine log not readable"),
            }
        }
        read_any.then_some(lines)
    })
    .await
    .ok()
    .flatten()
}

fn tail_lines(path: &Path) -> std::io::Result<Vec<String>> {
    let mut file = std::fs::File::open(path)?;
    let start = file.metadata()?.len().saturating_sub(LOG_TAIL_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut lines: Vec<String> = String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::to_owned)
        .collect();
    if start > 0 && !lines.is_empty() {
        // The read began inside a line.
        lines.remove(0);
    }
    Ok(lines)
}

/// The running session's route for the app's own downloads (re-check item 12c): the proxy
/// capture's loopback mixed inbound (it takes no credentials: loopback only, NOADMIN §2). Under
/// the TUN capture a direct request already rides the tunnel; idle, there is none.
pub(crate) fn session_route(status: &TunStatus) -> Option<Route> {
    match (status.capture, status.session.as_ref()) {
        (Some(CaptureKind::Proxy), Some(session)) => {
            let addr = HostPort::new("127.0.0.1", session.proxy_port?).ok()?;
            Some(Route::proxy(ProxyKind::Socks5, &addr, None))
        }
        _ => None,
    }
}

/// Smart RU rule-set auto refresh (engine API): at start, hourly, when a rule-set setting
/// changed and when a session starts (its route may reach the lists when direct did not), only
/// while the settings allow it, through the running session first. A failure is one toast per
/// streak: updates are on by default, and a network that cannot reach the lists would otherwise
/// show the same toast every hour.
pub(super) async fn refresh_rule_sets(
    service: Arc<RuleSetService>,
    settings: Arc<Store<Settings>>,
    mut status: watch::Receiver<TunStatus>,
    notifier: Arc<Notifier>,
    wake: Arc<Notify>,
    cancel: CancellationToken,
) {
    let mut failing = false;
    loop {
        let s = settings.snapshot();
        let mut cfg = RefreshSettings::from_settings(&s);
        cfg.session = session_route(&status.borrow());
        if cfg.auto_refresh(s.smart_ru_split) {
            // `RuleSetService::refresh` is not `Send` (an `AsyncFn` closure inside), so it cannot
            // be spawned: a blocking thread drives it with the runtime's handle.
            let handle = tokio::runtime::Handle::current();
            let (service, token) = (service.clone(), cancel.clone());
            let outcome = tokio::task::spawn_blocking(move || {
                handle.block_on(service.refresh(&cfg, false, &token))
            })
            .await;
            match outcome {
                Ok(RefreshOutcome::Cancelled) => {}
                Ok(outcome) => {
                    if let Some(notice) = outcome.notice().filter(|_| !failing) {
                        notifier.notify(notice, None);
                    }
                    failing = matches!(outcome, RefreshOutcome::Failed(_));
                }
                Err(e) => tracing::warn!(error = %e, "rule-set refresh task failed"),
            }
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = wake.notified() => {}
            () = tokio::time::sleep(RULE_SET_CHECK) => {}
            () = session_started(&mut status) => {}
        }
    }
}

/// Resolves when a session starts running; never when the status sender is gone.
async fn session_started(status: &mut watch::Receiver<TunStatus>) {
    let mut running = status.borrow_and_update().running;
    while status.changed().await.is_ok() {
        let now = status.borrow_and_update().running;
        if now && !running {
            return;
        }
        running = now;
    }
    std::future::pending().await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use vpnte_tunnel::api::{ProxyEndpoint, SessionEndpoints};

    use super::*;

    fn status(capture: Option<CaptureKind>, proxy_port: Option<u16>) -> TunStatus {
        TunStatus {
            running: capture.is_some(),
            capture,
            session: capture.map(|_| SessionEndpoints {
                clash_port: 9090,
                clash_secret: "0".repeat(32),
                direct: ProxyEndpoint {
                    port: 9091,
                    user: "u".into(),
                    pass: "p".into(),
                },
                probe: None,
                tun_luid: None,
                tun_alias: None,
                proxy_port,
                logs: Vec::new(),
            }),
            ..TunStatus::default()
        }
    }

    /// Re-check item 12c: the proxy capture's own inbound is the session route; under the TUN
    /// a direct request already rides the tunnel, and idle there is none.
    #[test]
    fn the_session_route_is_the_proxy_capture_inbound() {
        let route = session_route(&status(Some(CaptureKind::Proxy), Some(20808)));
        assert_eq!(
            route.map(|r| r.label()).as_deref(),
            Some("socks5h://127.0.0.1:20808")
        );
        assert_eq!(session_route(&status(Some(CaptureKind::Tun), None)), None);
        assert_eq!(session_route(&status(None, None)), None);
    }

    /// A session start wakes the refresh (its route may reach the lists); other changes do not.
    #[tokio::test]
    async fn a_session_start_wakes_the_refresh() {
        let (tx, mut rx) = watch::channel(status(None, None));
        let waiting = tokio::spawn(async move { session_started(&mut rx).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send_replace(status(None, None));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished(), "not running yet");
        tx.send_replace(status(Some(CaptureKind::Proxy), Some(20808)));
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("woken")
            .expect("task");
    }
}
