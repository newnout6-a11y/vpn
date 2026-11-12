//! The lifecycle actor: the only place that decides WHO may change the tunnel.
//!
//! One task owns the connection lane (connect / disconnect / switch / restart / maintenance),
//! the state machine ([`Fsm`]) and the live session. Commands arrive with an [`Owner`]; a
//! strictly higher owner pre-empts a running start, a stop pre-empts everything except a
//! higher-priority start. Effects run as child tasks with their own cancellation token and a
//! deadline and report back to the actor; the engines are driven only through
//! [`crate::api::Runtime`]. Every path that brings a tunnel up ends in one `on_connected` hook and
//! every path that ends a session writes exactly one history row (lifecycle-app §6.3, §6.4).
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, Owner, ProxyKind, UnixMs};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::ops::{CorrelationId, Source};

use crate::api::{EngineRun, TunError};
use crate::fsm::{FaultState, TunnelSnapshot};
use crate::history::SessionMode;
use crate::outcome::{NetworkTransition, OutcomeKind};

mod actor;
mod deps;
mod effects;
mod session;
#[cfg(test)]
mod tests;

pub use crate::api::TUN_SETUP_KEY_PREFIX;
pub use deps::{
    ExternalProxies, Forensics, LifecycleDeps, Monitor, NoticeKind, Notifier, ProfileSource,
    ServerChoice, SoftProxy,
};

/// Message keys of this package (fragment `locales/tunnel-lifecycle.{ru,en}.json`).
mod key {
    pub const STOP_IN_PROGRESS: &str = "tunnel.lifecycle.lane.stopInProgress";
    pub const CANCELLED_DRAINING: &str = "tunnel.lifecycle.lane.cancelledDraining";
    pub const PREEMPT_FAILED: &str = "tunnel.lifecycle.lane.preemptFailed";
    pub const START_IN_PROGRESS: &str = "tunnel.lifecycle.lane.startInProgress";
    pub const STATE_REFUSES_START: &str = "tunnel.lifecycle.lane.stateRefusesStart";
    pub const HIGHER_PRIORITY: &str = "tunnel.lifecycle.lane.higherPriority";
    pub const START_CANCELLED: &str = "tunnel.lifecycle.lane.startCancelled";
    pub const START_TIMEOUT: &str = "tunnel.lifecycle.lane.startTimeout";
    pub const STOP_TIMEOUT: &str = "tunnel.lifecycle.lane.stopTimeout";
    pub const CONFIRMATION_MISSING: &str = "tunnel.lifecycle.lane.confirmationMissing";
    pub const CLEANUP_UNCONFIRMED: &str = "tunnel.lifecycle.lane.cleanupUnconfirmed";
    pub const SWITCH_FAILED: &str = "tunnel.lifecycle.lane.switchFailed";
    pub const NOT_RUNNING: &str = "tunnel.lifecycle.lane.notRunning";
    pub const MAINTENANCE_REFUSED: &str = "tunnel.lifecycle.lane.maintenanceRefused";
    pub const MAINTENANCE_BUSY: &str = "tunnel.lifecycle.lane.maintenanceBusy";
    pub const MAINTENANCE_TIMEOUT: &str = "tunnel.lifecycle.lane.maintenanceTimeout";
    pub const NO_SERVER: &str = "tunnel.lifecycle.server.none";
    pub const SERVER_UNAVAILABLE: &str = "tunnel.lifecycle.server.unavailable";
    pub const SOFT_ROLLBACK_BEFORE_START: &str = "tunnel.lifecycle.soft.rollbackBeforeStart";
    pub const SOFT_APPLY_FAILED: &str = "tunnel.lifecycle.soft.applyFailed";
    pub const SOFT_ENV_ROLLBACK_FAILED: &str = "tunnel.lifecycle.soft.envRollbackFailed";
    pub const SOFT_STRICT: &str = "tunnel.lifecycle.soft.strictUnavailable";
    pub const OUTCOME_SOFT_MODE_SWITCH: &str = "tunnel.lifecycle.outcome.softModeSwitch";
    pub const OUTCOME_CANCELLED: &str = "tunnel.lifecycle.outcome.cancelled";
    pub const OUTCOME_TIMEOUT: &str = "tunnel.lifecycle.outcome.timeout";
    pub const OUTCOME_PREEMPTED: &str = "tunnel.lifecycle.outcome.preempted";
    pub const OUTCOME_FAILED: &str = "tunnel.lifecycle.outcome.failed";
    pub const OUTCOME_FAILOVER: &str = "tunnel.lifecycle.outcome.failover";
    pub const OUTCOME_FAILOVER_RESTARTS: &str = "tunnel.lifecycle.outcome.failoverRestarts";
    pub const NOTICE: &str = "tunnel.lifecycle.notice";
}

/// Work budget of every lane operation (old `timeoutMs` default).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Budget of a maintenance action (short in tests, which cannot wait two minutes).
#[cfg(not(test))]
const MAINTENANCE_BUDGET: Duration = DEFAULT_TIMEOUT;
#[cfg(test)]
const MAINTENANCE_BUDGET: Duration = Duration::from_secs(1);

/// What to connect. Hard targets capture through the TUN (elevated process only: otherwise the
/// start answers `Permission`); Soft targets run the same engine behind a loopback mixed inbound
/// and point the user-level tweaks ([`SoftProxy`]) at it (NOADMIN.md §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectTarget {
    /// Hard: sing-box TUN through a local upstream proxy (`host:port`).
    LocalProxy { addr: String, kind: ProxyKind },
    /// Hard: a server of the server list; `None` = the active selection.
    DirectVpn { profile_id: Option<String> },
    /// Soft through a local upstream proxy (`host:port`, e.g. Happ's).
    Soft { addr: String, kind: ProxyKind },
    /// Soft through a server of the server list; `None` = the active selection.
    SoftVpn { profile_id: Option<String> },
}

impl ConnectTarget {
    /// Soft mode (proxy capture plus the user-level tweaks).
    pub fn is_soft(&self) -> bool {
        matches!(
            self,
            ConnectTarget::Soft { .. } | ConnectTarget::SoftVpn { .. }
        )
    }
}

/// A connect request.
#[derive(Debug, Clone)]
pub struct ConnectReq {
    pub target: ConnectTarget,
    pub owner: Owner,
    pub source: Source,
    /// The user action this belongs to (a fresh id when `None`); history rows keep it.
    pub correlation: Option<CorrelationId>,
    /// Compatibility mode the adaptive bypass chose for this network and server.
    pub adaptive: AdaptiveMode,
    pub timeout: Duration,
    /// Cancels the connect (a registry lease, the UI). Dropping the `connect` future does too.
    pub cancel: Option<CancellationToken>,
}

impl ConnectReq {
    /// A request with the defaults: new correlation, baseline mode, 120 s, no external token.
    pub fn new(target: ConnectTarget, owner: Owner, source: Source) -> Self {
        Self {
            target,
            owner,
            source,
            correlation: None,
            adaptive: AdaptiveMode::Baseline,
            timeout: DEFAULT_TIMEOUT,
            cancel: None,
        }
    }
}

/// Why a stop was asked for; decides the history outcome of the session it ends (L-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StopCause {
    User,
    AppQuit,
    Schedule,
    /// Compensation of a start that ran out of time.
    Timeout,
    /// Compensation of a cancelled start ("Cancel" button, caller gone).
    Cancelled,
    /// A higher-priority operation took the lane.
    Preempted,
    /// Compensation of an operation that failed or could not be confirmed.
    Failed,
}

/// A disconnect request.
#[derive(Debug, Clone)]
pub struct DisconnectReq {
    pub cause: StopCause,
    pub owner: Owner,
    pub source: Source,
    pub correlation: Option<CorrelationId>,
    /// After this the caller gets `Timeout`; the rollback itself keeps running.
    pub timeout: Duration,
    /// Ends the session but leaves the kill switch blocking when it is on (adaptive bypass gave
    /// up on an unproven server): TUN keeps its firewall block, Soft its tweaks on the dead port;
    /// the state reads `blocked` until a connect or a full disconnect. Kill switch `off`: a plain
    /// full stop. A full stop asked meanwhile runs right after it.
    pub keep_protection: bool,
}

impl DisconnectReq {
    /// A full stop with a fresh correlation and the 120 s budget.
    pub fn new(cause: StopCause, owner: Owner, source: Source) -> Self {
        Self {
            cause,
            owner,
            source,
            correlation: None,
            timeout: DEFAULT_TIMEOUT,
            keep_protection: false,
        }
    }
}

/// Moves a running tunnel to another server (rotation, server switch).
#[derive(Debug, Clone)]
pub struct SwitchReq {
    pub profile_id: String,
    pub owner: Owner,
    pub source: Source,
    pub correlation: Option<CorrelationId>,
    pub timeout: Duration,
    pub cancel: Option<CancellationToken>,
}

impl SwitchReq {
    /// A request with the defaults (fresh correlation, 120 s, no external token).
    pub fn new(profile_id: impl Into<String>, owner: Owner, source: Source) -> Self {
        Self {
            profile_id: profile_id.into(),
            owner,
            source,
            correlation: None,
            timeout: DEFAULT_TIMEOUT,
            cancel: None,
        }
    }
}

/// A successful lane operation and what the user should know about it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Done {
    pub warnings: Vec<Msg>,
}

/// Why a lane operation did not succeed.
#[derive(Debug, thiserror::Error)]
pub enum ConnError {
    /// Not admitted (busy, state, priority, closing); nothing was touched.
    #[error("refused: {}", .0.key)]
    Refused(Msg),
    /// No server is selected, or the requested one is not in the server list.
    #[error("no server: {}", .0.key)]
    NoServer(Msg),
    /// Cancelled by the caller, a stop or a higher-priority operation; compensation runs on.
    #[error("cancelled")]
    Cancelled(Msg),
    /// The deadline passed; the lane keeps compensating (or rolling back) in the background.
    #[error("timed out")]
    Timeout(Msg),
    /// The operation ran and failed.
    #[error(transparent)]
    Failed(TunError),
}

impl ConnError {
    /// Error category (UI branching, quiet cancellation).
    pub fn kind(&self) -> ErrorKind {
        match self {
            ConnError::Refused(_) | ConnError::NoServer(_) => ErrorKind::Conflict,
            ConnError::Cancelled(_) => ErrorKind::Cancelled,
            ConnError::Timeout(_) => ErrorKind::Timeout,
            ConnError::Failed(e) => e.kind(),
        }
    }

    /// The message to show.
    pub fn user_msg(&self) -> Msg {
        match self {
            ConnError::Refused(m)
            | ConnError::NoServer(m)
            | ConnError::Cancelled(m)
            | ConnError::Timeout(m) => m.clone(),
            ConnError::Failed(e) => e.user_msg(),
        }
    }

    /// Warnings collected before the failure.
    pub fn warnings(&self) -> &[Msg] {
        match self {
            ConnError::Failed(e) => &e.warnings,
            _ => &[],
        }
    }
}

impl From<ConnError> for AppError {
    fn from(err: ConnError) -> Self {
        match err {
            ConnError::Failed(e) => e.into(),
            other => AppError::msg(other.kind(), other.user_msg()),
        }
    }
}

/// The live session as other services see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    /// Who holds the session: the owner that opened it. Restarts and switches keep it.
    pub owner: Owner,
    /// Server-list id, or the synthetic `local-proxy` / `local-proxy-soft-<type>` / `direct-vpn`.
    pub profile_id: String,
    pub profile_name: String,
    pub mode: SessionMode,
    /// Engine run of the session (Hard or Soft).
    pub generation: Option<u64>,
    /// Adaptive compatibility mode the engine was started with.
    pub adaptive: AdaptiveMode,
    pub started_at: UnixMs,
    /// The engine that carries the upstream and why (`None` until a run reported it).
    pub engine: Option<EngineRun>,
}

impl SessionView {
    /// The server-list id when the session runs over a server of the list (Hard or Soft);
    /// `None` for a local proxy.
    pub fn server_id(&self) -> Option<&str> {
        session::server_id(self.mode, &self.profile_id)
    }
}

/// Session changes, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// A session came up, or continues on a new engine run (switch, restart, auto-restart).
    Up(SessionView),
    /// The session ended and its history row was written.
    Ended {
        session: SessionView,
        outcome: OutcomeKind,
        /// The next event is the `Up` of the run that replaces it (a switch that took, a runtime
        /// failover, a protected restart). `false`: nothing runs after it, whatever the outcome
        /// kind says (a switch that lost the tunnel ends the session as that switch).
        continues: bool,
    },
}

/// What the shutdown cleanup achieved (the app decides whether to exit or ask).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShutdownReport {
    /// The runtime confirmed our engine processes gone.
    pub engines_stopped: bool,
    /// The Soft proxy settings were restored (or never applied).
    pub soft_restored: bool,
    /// The forensics session (and its capture) is confirmed stopped.
    pub capture_stopped: bool,
    /// The budget ran out first; the cleanup goes on in the background.
    pub timed_out: bool,
}

/// Handle of the lifecycle actor; clones share it.
#[derive(Clone)]
pub struct Lifecycle {
    tx: mpsc::UnboundedSender<actor::Cmd>,
    snapshot: watch::Receiver<TunnelSnapshot>,
    session: watch::Receiver<Option<SessionView>>,
    events: broadcast::Sender<SessionEvent>,
    busy: watch::Receiver<bool>,
    kept_by: watch::Receiver<Option<Owner>>,
}

impl Lifecycle {
    /// Starts the actor on the current tokio runtime.
    pub fn spawn(deps: LifecycleDeps) -> Self {
        actor::spawn(deps)
    }

    fn send(&self, cmd: actor::Cmd) {
        // The actor only ends with the runtime; a send then has nobody to act on it anyway.
        let _ = self.tx.send(cmd);
    }

    /// Connects. Refused while another operation runs (a strictly higher owner pre-empts a
    /// running start), while the state does not allow a start (connected: in either mode), and
    /// while closing. Soft with the kill switch `strict` fails before anything is touched.
    pub async fn connect(&self, req: ConnectReq) -> Result<Done, ConnError> {
        let job = actor::Job::Connect {
            target: req.target,
            adaptive: req.adaptive,
        };
        let head = actor::Head::new(req.owner, req.source, req.correlation, req.timeout);
        self.start(job, head, req.cancel).await
    }

    /// Rolls back the Soft tweaks, then stops the engines. Joins a stop already in flight;
    /// refused only while a start of a higher owner runs. Dropping the future stops waiting, not
    /// the rollback.
    pub async fn disconnect(&self, req: DisconnectReq) -> Result<Done, ConnError> {
        let (reply, rx) = oneshot::channel();
        self.send(actor::Cmd::Disconnect { req, reply });
        rx.await.unwrap_or_else(|_| Err(gone()))
    }

    /// Moves the running tunnel to `req.profile_id` as a rotation (history: `rotation`).
    pub async fn rotate(&self, req: SwitchReq) -> Result<Done, ConnError> {
        self.switch(req, OutcomeKind::Rotation).await
    }

    /// Moves the running tunnel to `req.profile_id` as a server switch, in place when the
    /// runtime can (history: `server-switch`).
    pub async fn switch_upstream(&self, req: SwitchReq) -> Result<Done, ConnError> {
        self.switch(req, OutcomeKind::ServerSwitch).await
    }

    async fn switch(&self, req: SwitchReq, kind: OutcomeKind) -> Result<Done, ConnError> {
        let job = actor::Job::Switch {
            profile_id: req.profile_id,
            kind,
        };
        let head = actor::Head::new(req.owner, req.source, req.correlation, req.timeout);
        self.start(job, head, req.cancel).await
    }

    /// Re-applies the last start with the current settings (settings changed); a no-op success
    /// when nothing runs.
    pub async fn restart_with_last(
        &self,
        reason: impl Into<String>,
        owner: Owner,
        source: Source,
    ) -> Result<Done, ConnError> {
        let job = actor::Job::RestartLast {
            reason: reason.into(),
        };
        let head = actor::Head::new(owner, source, None, DEFAULT_TIMEOUT);
        self.start(job, head, None).await
    }

    /// Protected restart in another adaptive mode, optionally on a sibling server.
    pub async fn restart_adaptive(
        &self,
        mode: AdaptiveMode,
        sibling: Option<String>,
        owner: Owner,
    ) -> Result<Done, ConnError> {
        let job = actor::Job::RestartAdaptive { mode, sibling };
        let head = actor::Head::new(owner, Source::Lifecycle, None, DEFAULT_TIMEOUT);
        self.start(job, head, None).await
    }

    async fn start(
        &self,
        job: actor::Job,
        head: actor::Head,
        cancel: Option<CancellationToken>,
    ) -> Result<Done, ConnError> {
        let token = cancel.map_or_else(CancellationToken::new, |t| t.child_token());
        // Dropping this future (caller gone) cancels the operation; the lane compensates.
        let guard = token.clone().drop_guard();
        let (reply, rx) = oneshot::channel();
        self.send(actor::Cmd::Start(actor::StartCmd {
            job,
            head,
            token,
            reply,
        }));
        let out = rx.await.unwrap_or_else(|_| Err(gone()));
        guard.disarm();
        out
    }
}

impl Lifecycle {
    /// The "Cancel" button: stops a start, switch or native reconnect in flight. A no-op when
    /// nothing is in flight (never poisons a running tunnel, H-04).
    pub fn cancel_pending(&self) {
        self.send(actor::Cmd::CancelPending);
    }

    /// Runs a network maintenance action (kill-switch repair, baseline rollback, …) with the lane
    /// held, only while no operation runs and the state is not `connected` (A-05). The escape
    /// hatches stay allowed in `error` / `blocked` / `unknown`. Past the lane budget the action is
    /// dropped, the caller gets `Timeout` and the state reads unknown (its changes are unproven).
    pub async fn maintenance<T, F, Fut>(&self, f: F) -> Result<T, ConnError>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
    {
        let (value_tx, value_rx) = oneshot::channel();
        let tx = self.tx.clone();
        let job: actor::MaintenanceJob = Box::new(move || {
            Box::pin(async move {
                let value = tokio::time::timeout(MAINTENANCE_BUDGET, f()).await;
                if value.is_err() {
                    let _ = tx.send(actor::Cmd::Fault(FaultState::Unknown));
                }
                let _ = value_tx.send(value);
            })
        });
        let (admit, admitted) = oneshot::channel();
        self.send(actor::Cmd::Maintenance { job, admit });
        admitted.await.unwrap_or_else(|_| Err(gone()))?;
        match value_rx.await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(ConnError::Timeout(Msg::new(key::MAINTENANCE_TIMEOUT))),
            Err(_) => Err(gone()),
        }
    }

    /// Closes the lane for good (until [`Lifecycle::reopen`]), cancels a start in flight, waits
    /// for it, then stops the tunnel as `app-quit` and rolls Soft mode back. Bounded by `budget`.
    pub async fn shutdown(&self, budget: Duration) -> ShutdownReport {
        let (reply, rx) = oneshot::channel();
        self.send(actor::Cmd::Shutdown { reply });
        match tokio::time::timeout(budget, rx).await {
            Ok(Ok(report)) => report,
            _ => ShutdownReport {
                timed_out: true,
                ..ShutdownReport::default()
            },
        }
    }

    /// Re-admits operations after a refused quit; only when nothing is in flight and nothing of
    /// ours is left running or applied (A-06).
    pub async fn reopen(&self) -> bool {
        let (reply, rx) = oneshot::channel();
        self.send(actor::Cmd::Reopen { reply });
        rx.await.unwrap_or(false)
    }

    /// The published tunnel state.
    pub fn snapshot(&self) -> watch::Receiver<TunnelSnapshot> {
        self.snapshot.clone()
    }

    /// The live session, if any.
    pub fn session(&self) -> watch::Receiver<Option<SessionView>> {
        self.session.clone()
    }

    /// Session changes from now on.
    pub fn events(&self) -> broadcast::Receiver<SessionEvent> {
        self.events.subscribe()
    }

    /// A lane operation (start, switch, restart, stop, maintenance) is in flight.
    pub fn busy(&self) -> bool {
        *self.busy.borrow()
    }

    /// The holder of the session a `keep_protection` stop ended, while the kill switch's block
    /// it kept lasts (anything that leaves `blocked` clears it: a start that runs, a full stop).
    /// Whoever ends that holder's run releases the block with a full stop.
    pub fn kept_by(&self) -> Option<Owner> {
        *self.kept_by.borrow()
    }

    /// Resolves once no lane operation is in flight, e.g. after a failed switch, whose recovery
    /// stop still holds the lane when the switch's caller gets its answer. Callers bound it.
    pub async fn idle(&self) {
        let mut busy = self.busy.clone();
        // The sender lives in the actor; gone = nothing can hold the lane any more.
        let _ = busy.wait_for(|busy| !*busy).await;
    }

    /// Forces a fault state (start-up recovery could not confirm the network, a supervised task
    /// panicked). Never touches the network.
    pub fn fault(&self, state: FaultState) {
        self.send(actor::Cmd::Fault(state));
    }

    /// A higher owner takes the running session over (it asked for the very session that runs);
    /// a lower or equal one changes nothing.
    pub fn adopt(&self, owner: Owner) {
        self.send(actor::Cmd::Adopt(owner));
    }

    /// The system resumed from sleep or the screen was unlocked.
    pub fn resumed(&self) {
        self.send(actor::Cmd::Resumed);
    }

    /// The physical network changed.
    pub fn network_changed(&self, transition: NetworkTransition) {
        self.send(actor::Cmd::NetworkChanged(transition));
    }

    /// Monitoring saw a leak during the session (kept as session evidence).
    pub fn leak_detected(&self) {
        self.send(actor::Cmd::LeakDetected);
    }
}

#[cfg(test)]
impl Lifecycle {
    /// Waits until the actor handled everything sent before.
    pub(crate) async fn barrier(&self) {
        let (done, rx) = oneshot::channel();
        self.send(actor::Cmd::Barrier(done));
        let _ = rx.await;
    }
}

/// The actor is gone (only after a panic in it): nothing can be admitted.
fn gone() -> ConnError {
    ConnError::Failed(AppError::new(ErrorKind::Internal).into())
}
