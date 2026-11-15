//! Measurements over the running session (pings, the server-probe context, the leak check) and
//! the Smart RU rule-set auto refresh.
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, Creds, EnginePref, KillSwitchLevel, Loopback, ProxyKind};
use vpnte_base::{AppError, AppResult};
use vpnte_core::net::{HostPort, Route};
use vpnte_core::settings::{ConnectionMode, Settings};
use vpnte_core::store::Store;
use vpnte_engine::clash_api::{ClashApi, ClashEndpoint, Connection};
use vpnte_engine::routing::process::THIRD_PARTY_CORES;
use vpnte_engine::routing::rulesets::{RefreshOutcome, RefreshSettings, RouteKind, RuleSetService};
use vpnte_probes::ip_monitor::IpEvidence;
use vpnte_probes::key_health::ProbeCtx;
use vpnte_probes::leak::{
    CheckInput, CheckReport, ConnRecord, DirectAudit, Mode, SelfTestResult, audit_direct,
};
use vpnte_probes::ping::{NetPath, PingSample, PingTarget, ping_all};
use vpnte_probes::public_ip::IpReader;
use vpnte_servers::model::ProfileId;
use vpnte_servers::store::Servers;
use vpnte_service::proto::{EngineLog, Request};
use vpnte_tunnel::api::{CaptureKind, ModeKind, TunStatus};

use crate::api_logs::ServiceAnswer;
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
/// sessions, run where their filters live: this elevated process or the helper service); the
/// direct-out audit reads the session's open engine connections.
pub(super) async fn leak_check(
    reader: &IpReader,
    settings: &Settings,
    status: &TunStatus,
    evidence: IpEvidence,
    self_test: Option<SelfTestResult>,
    logs: EngineLogs,
    cancel: &CancellationToken,
) -> AppResult<CheckReport> {
    let run = async {
        let input = check_input(settings, status, evidence, self_test, logs).await;
        vpnte_probes::leak::leak_check(reader, input, cancel).await
    };
    tokio::select! {
        report = run => Ok(report),
        () = cancel.cancelled() => Err(AppError::cancelled()),
    }
}

/// What the card cannot measure itself, for `status`'s session.
async fn check_input(
    settings: &Settings,
    status: &TunStatus,
    evidence: IpEvidence,
    self_test: Option<SelfTestResult>,
    logs: EngineLogs,
) -> CheckInput {
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
    let smart_ru = settings.smart_ru_split;
    let (engine_log, direct) = tokio::join!(logs.read(), direct_audit(status, smart_ru));
    CheckInput {
        mode,
        tunnel_up: status.running,
        evidence,
        self_test,
        self_test_applies: self_test_applies(status, settings),
        engine_log,
        direct,
    }
}

/// The session runs the background self-test: a TUN session with the kill switch on (the gate
/// of this process's runs and of the helper service's alike).
fn self_test_applies(status: &TunStatus, settings: &Settings) -> bool {
    status.capture == Some(CaptureKind::Tun) && settings.kill_switch != KillSwitchLevel::Off
}

/// The direct-out audit over the running session's open engine connections (`None`: no session
/// or no answer, "not checked"). The endpoint comes with the status, from the helper service
/// through its pipe: the loopback API the traffic counters read too (lab live-13 L13-1).
async fn direct_audit(status: &TunStatus, smart_ru: bool) -> Option<DirectAudit> {
    let s = status.session.as_ref().filter(|_| status.running)?;
    let ep = ClashEndpoint {
        port: s.clash_port,
        secret: s.clash_secret.clone(),
    };
    let read = match ClashApi::new(&ep) {
        Ok(api) => api.connections().await,
        Err(e) => Err(e),
    };
    let conns = read
        .inspect_err(|e| tracing::info!(error = %e, "direct-out audit: no connections read"))
        .ok()?;
    let records: Vec<ConnRecord> = conns.connections.iter().map(conn_record).collect();
    Some(audit_direct(&records, smart_ru, &is_core_process))
}

/// One engine connection as the audit reads it (an empty field is unknown).
fn conn_record(c: &Connection) -> ConnRecord {
    let known = |s: &str| Some(s.to_owned()).filter(|s| !s.is_empty());
    ConnRecord {
        chains: c.chains.clone(),
        rule: c.rule.clone(),
        host: known(&c.metadata.host),
        destination_ip: c.metadata.destination_ip.parse().ok(),
        process_path: known(&c.metadata.process_path),
    }
}

/// Our engines and the VPN cores routing sends direct: one list for the config and the check.
fn is_core_process(path: &str) -> bool {
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    THIRD_PARTY_CORES
        .iter()
        .any(|core| core.eq_ignore_ascii_case(name))
}

/// Where the leak check reads the running session's engine lines.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum EngineLogs {
    /// No session runs.
    None,
    /// This process's engines: their files.
    Files(Vec<PathBuf>),
    /// The helper service's: through its pipe (owner logs O-4: their folder is SYSTEM and
    /// Administrators only, and this user may read his own session's lines only).
    Service(Vec<EngineLog>),
}

impl EngineLogs {
    /// The logs of `status`'s running session; `in_service`: the helper service hosts it.
    pub(super) fn of(status: &TunStatus, in_service: bool) -> Self {
        match &status.session {
            Some(s) if status.running && in_service => {
                Self::Service(s.logs.iter().filter_map(|p| engine_log_of(p)).collect())
            }
            Some(s) if status.running => Self::Files(s.logs.clone()),
            _ => Self::None,
        }
    }

    /// The recent lines; `None` when none could be read.
    async fn read(self) -> Option<Vec<String>> {
        match self {
            Self::None => None,
            Self::Files(paths) => engine_log(paths).await,
            Self::Service(logs) => service_engine_log(logs).await,
        }
    }
}

/// The service's name of an engine log file (`sing-box.log` -> `SingBox`).
fn engine_log_of(path: &Path) -> Option<EngineLog> {
    match path.file_stem()?.to_str()? {
        "sing-box" => Some(EngineLog::SingBox),
        "xray-a" => Some(EngineLog::XrayA),
        "xray-b" => Some(EngineLog::XrayB),
        _ => None,
    }
}

/// The service's answers for `logs`, each cut to the bytes a file read takes.
async fn service_engine_log(logs: Vec<EngineLog>) -> Option<Vec<String>> {
    let mut lines = Vec::new();
    let mut read_any = false;
    for log in logs {
        match crate::api_logs::ask_for(Request::EngineLog(log)).await {
            Ok(ServiceAnswer::Lines(wire)) => {
                read_any = true;
                lines.extend(recent(wire.lines.into_iter().map(|l| l.text).collect()));
            }
            Ok(_) => tracing::debug!(?log, "the service gave no engine log"),
            Err(e) => tracing::debug!(error = %e, ?log, "engine log not read from the service"),
        }
    }
    read_any.then_some(lines)
}

/// The last lines of `lines` within [`LOG_TAIL_BYTES`], as a file read would give them.
fn recent(mut lines: Vec<String>) -> Vec<String> {
    let mut bytes = 0u64;
    let keep = lines
        .iter()
        .rev()
        .take_while(|l| {
            bytes += l.len() as u64 + 1;
            bytes <= LOG_TAIL_BYTES
        })
        .count();
    lines.split_off(lines.len() - keep)
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
/// while the settings allow it, through the running session first. A refresh that failed while a
/// session came up is tried again through it at once, before any toast (psmart-a1/b6). A failure
/// is one toast per streak: updates are on by default, and a network that cannot reach the
/// lists would otherwise show the same toast every hour. New lists are a journal event of the
/// data folder `root`.
pub(super) async fn refresh_rule_sets(
    service: Arc<RuleSetService>,
    settings: Arc<Store<Settings>>,
    mut status: watch::Receiver<TunStatus>,
    notifier: Arc<Notifier>,
    wake: Arc<Notify>,
    cancel: CancellationToken,
    root: PathBuf,
) {
    let mut failing = false;
    loop {
        let s = settings.snapshot();
        let mut cfg = RefreshSettings::from_settings(&s);
        // Marked seen: a session that starts during the refresh is a change after this read.
        let before = status.borrow_and_update().clone();
        cfg.session = session_route(&before);
        if cfg.auto_refresh(s.smart_ru_split) {
            let tried = cfg.clone();
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
                Ok(outcome)
                    if retry_through_session(&tried, &outcome, &before, &status.borrow()) =>
                {
                    tracing::info!("rule-set refresh failed; trying again through the new session");
                    continue;
                }
                Ok(outcome) => {
                    crate::svc_journal::smart_ru_refreshed(&root, &outcome);
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

/// A failed refresh is tried again at once when a session came up meanwhile (`before` -> `now`)
/// whose route the download routes would take (the mode and the user's choices decide, as in
/// `routes`), or a Tunnel session: the app's own downloads ride its TUN (fixlists-a4).
fn retry_through_session(
    tried: &RefreshSettings,
    outcome: &RefreshOutcome,
    before: &TunStatus,
    now: &TunStatus,
) -> bool {
    if !matches!(outcome, RefreshOutcome::Failed(_)) {
        return false;
    }
    let new_run = now.running && (!before.running || now.started_at != before.started_at);
    if new_run && now.capture == Some(CaptureKind::Tun) {
        return true;
    }
    let route = session_route(now);
    if route.is_none() || route == tried.session {
        return false;
    }
    let again = RefreshSettings {
        session: route,
        ..tried.clone()
    };
    again
        .routes()
        .iter()
        .any(|(kind, _)| *kind == RouteKind::Session)
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

    use vpnte_probes::leak::{CheckStatus, check, summarize};
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

    /// Owner logs O-4: a session in the helper service has its engine lines read through the
    /// pipe (its folder is SYSTEM and Administrators only), one of this process from its files,
    /// none while idle; the pipe's lines are cut to what a file read takes.
    #[test]
    fn the_engine_lines_come_from_where_the_engines_run() {
        let mut tun = status(Some(CaptureKind::Tun), None);
        if let Some(s) = tun.session.as_mut() {
            s.logs = ["sing-box.log", "xray-a.log", "other.log"]
                .map(|f| PathBuf::from(r"C:\data\logs").join(f))
                .to_vec();
        }
        assert_eq!(
            EngineLogs::of(&tun, true),
            EngineLogs::Service(vec![EngineLog::SingBox, EngineLog::XrayA])
        );
        let files = tun
            .session
            .as_ref()
            .map(|s| s.logs.clone())
            .unwrap_or_default();
        assert_eq!(EngineLogs::of(&tun, false), EngineLogs::Files(files));
        assert_eq!(EngineLogs::of(&status(None, None), true), EngineLogs::None);
        let long = vec!["x".repeat(40 * 1024), "y".repeat(30 * 1024), "z".into()];
        assert_eq!(recent(long), vec!["y".repeat(30 * 1024), "z".to_owned()]);
    }

    /// psmart-a1/b6: a refresh that failed while a session came up is tried again through it at
    /// once (no toast first); not when the session's route was the one that failed, when the
    /// user's route choice excludes it, or when the refresh did not fail.
    #[test]
    fn a_session_that_came_up_during_a_failed_refresh_gets_a_retry() {
        use vpnte_core::settings::BootstrapRouteMode;
        use vpnte_engine::routing::rulesets::RefreshFault;
        let idle = RefreshSettings::from_settings(&Settings::default());
        let failed = RefreshOutcome::Failed(RefreshFault::Download {
            file: "geoip-ru.srs".into(),
        });
        let up = status(Some(CaptureKind::Proxy), Some(20808));
        let none = status(None, None);
        assert!(retry_through_session(&idle, &failed, &none, &up));
        assert!(!retry_through_session(&idle, &failed, &none, &none));
        assert!(!retry_through_session(
            &idle,
            &RefreshOutcome::Fresh,
            &none,
            &up
        ));
        let through = RefreshSettings {
            session: session_route(&up),
            ..idle.clone()
        };
        assert!(
            !retry_through_session(&through, &failed, &up, &up),
            "it was tried"
        );
        let direct_only = RefreshSettings {
            bootstrap: BootstrapRouteMode::Direct,
            ..idle
        };
        assert!(!retry_through_session(&direct_only, &failed, &none, &up));
    }

    /// fixlists-a4: a Tunnel session that came up while a refresh failed is tried at once (the
    /// app's own downloads ride its TUN), whatever the route choice; one that ran already is not.
    #[test]
    fn a_tunnel_session_that_came_up_during_a_failed_refresh_gets_a_retry() {
        use vpnte_core::settings::BootstrapRouteMode;
        use vpnte_engine::routing::rulesets::RefreshFault;
        let direct_only = RefreshSettings {
            bootstrap: BootstrapRouteMode::Direct,
            ..RefreshSettings::from_settings(&Settings::default())
        };
        let failed = RefreshOutcome::Failed(RefreshFault::Download {
            file: "geoip-ru.srs".into(),
        });
        let (none, tun) = (status(None, None), status(Some(CaptureKind::Tun), None));
        assert!(retry_through_session(&direct_only, &failed, &none, &tun));
        assert!(
            !retry_through_session(&direct_only, &failed, &tun, &tun),
            "it ran already"
        );
        let restarted = TunStatus {
            started_at: Some(2_000),
            ..tun.clone()
        };
        assert!(retry_through_session(
            &direct_only,
            &failed,
            &tun,
            &restarted
        ));
        let updated = RefreshOutcome::Updated {
            generation: "gen-1".into(),
        };
        assert!(!retry_through_session(&direct_only, &updated, &none, &tun));
    }

    /// p-tails-a: new Smart RU lists are a journal event; a refresh that changed nothing is not
    /// (a failed one reaches the journal through its toast).
    #[test]
    fn new_lists_are_a_journal_event() {
        use vpnte_engine::routing::rulesets::RefreshFault;
        let dir = crate::api_settings::test_support::TempDir::new("probe-journal");
        let fault = RefreshFault::Download {
            file: "geoip-ru.srs".into(),
        };
        for outcome in [RefreshOutcome::Fresh, RefreshOutcome::Failed(fault)] {
            crate::svc_journal::smart_ru_refreshed(&dir.0, &outcome);
        }
        let journal = crate::svc_journal::Journal::open(&dir.0);
        assert!(journal.records().is_empty());
        let updated = RefreshOutcome::Updated {
            generation: "gen-1".into(),
        };
        crate::svc_journal::smart_ru_refreshed(&dir.0, &updated);
        let keys: Vec<String> = (journal.records().iter())
            .map(|r| r.title.key.to_string())
            .collect();
        assert_eq!(keys, ["app.journal.smartRu.updated"]);
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

    /// A loopback stand-in for the session's Clash API: answers every request with `body`.
    async fn clash_answering(body: String) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let (mut buf, mut head) = (vec![0u8; 4096], Vec::new());
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(reply.as_bytes()).await;
                });
            }
        });
        port
    }

    fn conn(host: &str, dst: &str, process: &str, chain: &str, rule: &str) -> serde_json::Value {
        serde_json::json!({
            "id": "1", "upload": 0, "download": 0, "start": "", "chains": [chain], "rule": rule,
            "metadata": {
                "network": "tcp", "type": "tun/tun-in", "sourceIP": "172.19.0.1",
                "sourcePort": "50000", "destinationIP": dst, "destinationPort": "443",
                "host": host, "processPath": process,
            },
        })
    }

    /// Lab live-13 L13-1: a Tunnel check read «—» because the direct-out audit was never wired
    /// and the self-test, which runs only with the kill switch on, counted as missing. The
    /// session's open connections are audited now (a rule's direct route and our own cores are
    /// expected) and the self-test out of its mode is informational: a clean session reads «Нет».
    #[tokio::test]
    async fn a_clean_tunnel_session_reads_no_leaks() {
        let browser = r"C:\Apps\browser.exe";
        let xray = r"C:\Program Files\VPN Tunnel Enforcer Service\resources\xray.exe";
        // Public destinations: the audit leaves private and documentation ranges out.
        let body = serde_json::json!({
            "downloadTotal": 0, "uploadTotal": 0,
            "connections": [
                conn("ya.ru", "77.88.55.242", browser, "direct-out", "rule_set=geoip-ru => route(direct-out)"),
                conn("", "185.12.13.14", xray, "direct-out", "process_path_regex => route(direct-out)"),
                conn("example.com", "93.184.215.14", browser, "proxy-out", "final"),
            ],
        });
        let mut tun = status(Some(CaptureKind::Tun), None);
        let port = clash_answering(body.to_string()).await;
        if let Some(s) = tun.session.as_mut() {
            s.clash_port = port;
        }
        let settings = Settings {
            kill_switch: KillSwitchLevel::Off,
            smart_ru_split: true,
            ..Settings::default()
        };
        let input = check_input(
            &settings,
            &tun,
            IpEvidence::default(),
            None,
            EngineLogs::None,
        )
        .await;
        let audit = input
            .direct
            .clone()
            .expect("the session's connections were read");
        assert_eq!(
            (
                audit.by_rule,
                audit.smart_ru,
                audit.core,
                audit.leaked_count
            ),
            (1, 1, 1, 0)
        );
        assert!(!input.self_test_applies);
        let items = [
            check::ipv6_item(None, Some(&[]), true),
            check::self_test_item(input.self_test.as_ref(), input.self_test_applies),
            check::direct_out_item(input.direct.as_ref(), true),
        ];
        assert_eq!(summarize(&items), CheckStatus::Ok);
        // With the kill switch on the self-test belongs to the session (until its first run the
        // card stays «not checked»); Proxy mode has nothing to self-test.
        let on = Settings {
            kill_switch: KillSwitchLevel::Standard,
            ..settings
        };
        assert!(self_test_applies(&tun, &on));
        assert!(!self_test_applies(
            &status(Some(CaptureKind::Proxy), Some(20808)),
            &on
        ));
    }

    /// An engine that does not answer leaves the audit unknown, never a pass.
    #[tokio::test]
    async fn an_unanswered_audit_is_not_a_pass() {
        let dead = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = dead.local_addr().expect("addr").port();
        drop(dead);
        let mut tun = status(Some(CaptureKind::Tun), None);
        if let Some(s) = tun.session.as_mut() {
            s.clash_port = port;
        }
        assert_eq!(direct_audit(&tun, false).await, None);
        assert_eq!(direct_audit(&status(None, None), false).await, None);
    }
}
