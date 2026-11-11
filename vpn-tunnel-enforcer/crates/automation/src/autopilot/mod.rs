//! AutoPilot: the launch-time planner of local-proxy Hard mode.
//!
//! It decides whether to start anything and, if so, asks the [`Coordinator`] like any other owner
//! (`Owner::Autopilot`, the second-lowest priority). It never stops a session and never writes the
//! user's settings (fixes P1, P2, P4): an existing session or a running operation means "nothing to
//! do"; a foreign VPN tunnel means "observe only" (never two TUNs); an unreadable adapter list means
//! "do not start" (P6); a TUN is started only through a proxy endpoint that answered a handshake,
//! passed in the connect request instead of being pinned into `proxyOverride`.
mod probe;
#[cfg(test)]
mod tests;

use std::future::Future;
use std::sync::Arc;
use std::sync::LazyLock;

use regex::Regex;
use tokio::sync::watch;
use vpnte_base::types::{ProxyKind, UnixMs};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::net::HostPort;
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;

use crate::coordinator::{Coordinator, ProxyEndpoint};
use crate::scheduler::SchedulerStatus;

pub use probe::Timing;

/// Who asked for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoPilotTrigger {
    /// Once at app start (after startup recovery and the scheduler's first pass).
    AppLaunch,
    /// An explicit user action (extension point; also ignores the `autopilot` switch).
    UserRequest,
}

/// The routing mode the run left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AutoPilotMode {
    Off,
    /// A foreign VPN carries the traffic; this app only observes.
    External,
    Hard,
    Soft,
}

/// Outcome of a run or of one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StepStatus {
    Ok,
    Warn,
    Fail,
    Info,
}

/// One explained decision, shown as a log line `AutoPilot: <label> → <after>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoPilotStep {
    pub label: Msg,
    pub before: Msg,
    pub after: Msg,
    pub status: StepStatus,
}

/// What a run did, for the mode badge, the log and one toast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoPilotResult {
    pub ran_at: UnixMs,
    pub summary: StepStatus,
    pub mode: AutoPilotMode,
    pub title: Msg,
    pub message: Msg,
    /// A tunnel was started.
    pub changed: bool,
    pub steps: Vec<AutoPilotStep>,
}

/// A TCP listener that may be a local proxy core (from the monitoring listener table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    /// Listening address as the table reports it (`0.0.0.0`, `::`, `127.0.0.1`, …).
    pub host: String,
    pub port: u16,
    /// Process image name (`xray.exe`, `Happ`, …), empty when unknown.
    pub process: String,
}

/// What AutoPilot needs from the rest of the app; implemented by the app.
pub trait AutoPilotEnv: Send + Sync + 'static {
    /// Listeners on loopback / wildcard addresses whose process or port looks like a proxy core.
    fn listeners(&self) -> Vec<Listener>;

    /// A local proxy found by VPN-client detection (`vpnte_probes::local_proxy`), if any.
    fn detect(&self) -> impl Future<Output = Option<ProxyEndpoint>> + Send;

    /// Names of Up tunnel adapters that are not ours; `Err` when the adapters could not be read.
    /// The default asks winnet (our leftover TUN aliases are not foreign).
    fn foreign_tunnels(&self) -> impl Future<Output = AppResult<Vec<String>>> + Send {
        async {
            let read = tokio::task::spawn_blocking(|| {
                let own = vpnte_winnet::adapters::alias::all_aliases();
                let own: Vec<&str> = own.iter().map(String::as_str).collect();
                vpnte_winnet::adapters::foreign_tun::detect(None, &own)
            });
            match read.await {
                Ok(Ok(found)) => Ok(found.into_iter().map(|f| f.name).collect()),
                Ok(Err(err)) => Err(AppError::internal(err)),
                Err(err) => Err(AppError::internal(err)),
            }
        }
    }
}

/// Wildcard and IPv6-loopback listener addresses are reached through `127.0.0.1` (AP:18-21).
pub fn normalize_host(host: &str) -> &str {
    match host {
        "::" | "::1" | "0.0.0.0" | "" => "127.0.0.1",
        other => other,
    }
}

/// Listener rank: well-known proxy ports +10, proxy-core process names +5 (AP:90-98).
pub fn score(port: u16, process: &str) -> i32 {
    static CORE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)xray|v2ray|sing|happ|hiddify|mihomo|clash").expect("valid regex")
    });
    let mut score = 0;
    if [10808, 2080, 7890, 1080, 10809, 7891].contains(&port) {
        score += 10;
    }
    if CORE.is_match(process) {
        score += 5;
    }
    score
}

/// Listeners best-first (stable: ties keep table order), one per normalised `host:port`.
pub fn rank_listeners(listeners: &[Listener]) -> Vec<(HostPort, &Listener)> {
    let mut ranked: Vec<&Listener> = listeners.iter().collect();
    ranked.sort_by_key(|l| std::cmp::Reverse(score(l.port, &l.process)));
    let mut out: Vec<(HostPort, &Listener)> = Vec::new();
    for listener in ranked {
        let Ok(addr) = HostPort::new(normalize_host(&listener.host), listener.port) else {
            continue;
        };
        if !out.iter().any(|(seen, _)| *seen == addr) {
            out.push((addr, listener));
        }
    }
    out
}

/// The planner. One run at a time; [`AutoPilot::run`] is called by the app.
pub struct AutoPilot<C: Coordinator, E: AutoPilotEnv> {
    coord: Arc<C>,
    env: Arc<E>,
    settings: Arc<Store<Settings>>,
    schedule: Option<watch::Receiver<SchedulerStatus>>,
    running: tokio::sync::Mutex<()>,
    timing: Timing,
}

fn step(name: &str, status: StepStatus) -> AutoPilotStep {
    let key = |part: &str| Msg::new(format!("automation.autopilot.step.{name}.{part}"));
    AutoPilotStep {
        label: key("label"),
        before: key("before"),
        after: key("after"),
        status,
    }
}

fn result(
    summary: StepStatus,
    mode: AutoPilotMode,
    name: &str,
    steps: Vec<AutoPilotStep>,
) -> AutoPilotResult {
    AutoPilotResult {
        ran_at: vpnte_base::types::now_ms(),
        summary,
        mode,
        title: Msg::new(format!("automation.autopilot.{name}Title")),
        message: Msg::new(format!("automation.autopilot.{name}")),
        changed: false,
        steps,
    }
}

impl<C: Coordinator, E: AutoPilotEnv> AutoPilot<C, E> {
    /// `schedule`: the scheduler's status; an app-launch run waits for its first pass and stays
    /// out of an active schedule run.
    pub fn new(
        coord: Arc<C>,
        env: Arc<E>,
        settings: Arc<Store<Settings>>,
        schedule: Option<watch::Receiver<SchedulerStatus>>,
    ) -> Self {
        Self::with_timing(coord, env, settings, schedule, Timing::default())
    }

    /// Same with other probe deadlines.
    pub fn with_timing(
        coord: Arc<C>,
        env: Arc<E>,
        settings: Arc<Store<Settings>>,
        schedule: Option<watch::Receiver<SchedulerStatus>>,
        timing: Timing,
    ) -> Self {
        Self {
            coord,
            env,
            settings,
            schedule,
            running: tokio::sync::Mutex::new(()),
            timing,
        }
    }

    /// Runs the planner. `None`: skipped silently (local-proxy Hard mode not selected, the
    /// `autopilot` switch off for an app-launch run, or a schedule run active / connecting).
    pub async fn run(&self, trigger: AutoPilotTrigger) -> Option<AutoPilotResult> {
        let Ok(_single) = self.running.try_lock() else {
            let steps = vec![step("busy", StepStatus::Warn)];
            return Some(result(StepStatus::Warn, self.session_mode(), "busy", steps));
        };
        let settings = self.settings.snapshot();
        let local_hard = settings.routing_mode == vpnte_core::settings::RoutingMode::Hard
            && settings.connection_mode == vpnte_core::settings::ConnectionMode::LocalProxy;
        if !local_hard || (trigger == AutoPilotTrigger::AppLaunch && !settings.autopilot) {
            return None;
        }
        if trigger == AutoPilotTrigger::AppLaunch && self.schedule_owns_launch().await {
            tracing::info!("autopilot: skipped, a schedule run owns the connection");
            return None;
        }
        Some(self.plan(&settings).await)
    }

    async fn plan(&self, settings: &Settings) -> AutoPilotResult {
        // Fix P1/P2: a running session or operation belongs to someone else; never touch it.
        if self.coord.session().is_some() || self.coord.busy() {
            let steps = vec![step("active", StepStatus::Info)];
            return result(StepStatus::Ok, self.session_mode(), "active", steps);
        }
        match self.env.foreign_tunnels().await {
            // Fix P6: an unknown adapter list is not "no foreign tunnel".
            Err(err) => {
                tracing::warn!("autopilot: adapter enumeration failed: {err}");
                let steps = vec![step("tunnelsUnknown", StepStatus::Warn)];
                return result(
                    StepStatus::Warn,
                    AutoPilotMode::Off,
                    "tunnelsUnknown",
                    steps,
                );
            }
            Ok(found) if !found.is_empty() => {
                tracing::info!(
                    count = found.len(),
                    "autopilot: foreign tunnel present, observing"
                );
                let steps = vec![step("external", StepStatus::Info)];
                return result(StepStatus::Ok, AutoPilotMode::External, "external", steps);
            }
            Ok(_) => {}
        }
        let Some(endpoint) = self.find_endpoint(settings).await else {
            let none = AutoPilotStep {
                before: Msg::new("automation.autopilot.step.proxy.noneBefore"),
                after: Msg::new("automation.autopilot.step.proxy.noneAfter"),
                ..step("proxy", StepStatus::Fail)
            };
            return result(StepStatus::Fail, AutoPilotMode::Off, "noProxy", vec![none]);
        };
        let kind = match endpoint.kind {
            ProxyKind::Socks5 => "socks5",
            ProxyKind::Http => "http",
        };
        let mut found = step("proxy", StepStatus::Ok);
        found.after = found
            .after
            .arg("endpoint", &endpoint.addr)
            .arg("kind", kind);
        let request = crate::coordinator::ConnectRequest::LocalProxyHard {
            endpoint: Some(endpoint),
        };
        match self
            .coord
            .connect(vpnte_base::types::Owner::Autopilot, request)
            .await
        {
            Ok(outcome) => {
                let steps = vec![found, step("start", StepStatus::Ok)];
                let mut done = result(StepStatus::Ok, AutoPilotMode::Hard, "success", steps);
                done.changed = outcome == crate::coordinator::ConnectOutcome::Connected;
                done
            }
            Err(err) => {
                tracing::warn!("autopilot: connect failed: {err}");
                let failed = AutoPilotStep {
                    after: Msg::new("automation.autopilot.step.start.failed"),
                    ..step("start", StepStatus::Fail)
                };
                let mut done = result(
                    StepStatus::Fail,
                    AutoPilotMode::Off,
                    "failed",
                    vec![found, failed],
                );
                done.message = err.reason();
                done
            }
        }
    }
}

impl<C: Coordinator, E: AutoPilotEnv> AutoPilot<C, E> {
    fn session_mode(&self) -> AutoPilotMode {
        match self.coord.session().map(|s| s.kind) {
            None => AutoPilotMode::Off,
            Some(crate::coordinator::SessionKind::Soft) => AutoPilotMode::Soft,
            Some(_) => AutoPilotMode::Hard,
        }
    }

    /// Waits for the scheduler's first pass; `true` while a schedule run is active or connecting
    /// (the schedule decides the connection then, the old renderer timer raced it).
    async fn schedule_owns_launch(&self) -> bool {
        let Some(mut status) = self.schedule.clone() else {
            return false;
        };
        match status.wait_for(|s| s.ready).await {
            Ok(s) => s.run.is_some() || s.connecting,
            Err(_) => false,
        }
    }

    /// The first endpoint that answers: the user's proxy override (its own protocol), then the
    /// VPN client detection, then listeners by rank.
    async fn find_endpoint(&self, settings: &Settings) -> Option<ProxyEndpoint> {
        if let Some(over) = &settings.proxy_override {
            let ep = ProxyEndpoint {
                addr: over.addr.clone(),
                kind: settings.proxy_type,
                creds: over.creds(),
            };
            if probe::verify_endpoint(&ep, self.timing).await {
                return Some(ep);
            }
        }
        if let Some(ep) = self.env.detect().await
            && probe::verify_endpoint(&ep, self.timing).await
        {
            return Some(ep);
        }
        let listeners = self.env.listeners();
        for (addr, listener) in rank_listeners(&listeners) {
            if let Some(ep) = probe::verify_listener(&addr, &listener.process, self.timing).await {
                return Some(ep);
            }
        }
        None
    }
}
