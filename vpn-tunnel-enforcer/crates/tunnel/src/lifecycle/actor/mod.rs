//! The actor task: owns the lane, the state machine and the live session. Handlers never await
//! long work; effects run as child tasks and report back through the same inbox.
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, Level, Notice, Owner, UnixMs, now_ms};
use vpnte_base::{ErrorKind, Msg};
use vpnte_core::ops::{CorrelationId, OpId, OpKind, OpMeta, OpStatus, Source};

use super::effects::{self, Captured, Ctx, Keep, StartReport, StopReport, Target, Up, Want};
use super::pause::{KillSwitchView, Pause, SessionGuard};
use super::session::{self, LiveSession, Provenance, SessionProfile, start_failure_row};
use super::{
    ConnError, ConnectTarget, DEFAULT_TIMEOUT, DisconnectReq, Done, Lifecycle, LifecycleDeps,
    NoticeKind, SessionEvent, SessionView, ShutdownReport, StopCause, key,
};
use crate::api::{CaptureKind, ModeKind, TunError, TunStatus, TunStatusKind, TunnelEvent};
use crate::fsm::{Evidence, FaultState, Fsm, Transition, TunnelSnapshot, TunnelState};
use crate::outcome::{
    self, EndSignals, EngineExit, NetworkTransition, OutcomeKind, SessionOutcome,
};

mod connected;
mod events;
mod guard;
mod paused;
mod start;
mod stop;

use connected::notice_key;
use start::{abort_error, reply};

/// A maintenance action, called once the lane admitted it.
pub(super) type MaintenanceJob = Box<dyn FnOnce() -> BoxFuture<'static, ()> + Send>;

type Reply = oneshot::Sender<Result<Done, ConnError>>;

/// What a start-type operation does.
#[derive(Debug, Clone)]
pub(super) enum Job {
    Connect {
        target: ConnectTarget,
        adaptive: AdaptiveMode,
    },
    /// `kind`: `Rotation` or `ServerSwitch` (history of the session it ends).
    Switch {
        profile_id: String,
        kind: OutcomeKind,
    },
    RestartLast {
        reason: String,
    },
    RestartAdaptive {
        mode: AdaptiveMode,
        sibling: Option<String>,
    },
}

impl Job {
    fn op_kind(&self) -> OpKind {
        match self {
            Job::Connect { .. } => OpKind::Connect,
            _ => OpKind::Rotation,
        }
    }
}

/// Who asks, and the budget.
#[derive(Debug, Clone)]
pub(super) struct Head {
    pub owner: Owner,
    pub source: Source,
    pub correlation: CorrelationId,
    pub timeout: Duration,
}

impl Head {
    pub fn new(
        owner: Owner,
        source: Source,
        correlation: Option<CorrelationId>,
        timeout: Duration,
    ) -> Self {
        Self {
            owner,
            source,
            correlation: correlation.unwrap_or_default(),
            timeout,
        }
    }
}

pub(super) struct StartCmd {
    pub job: Job,
    pub head: Head,
    /// The caller's token (cancelled when the caller goes away).
    pub token: CancellationToken,
    pub reply: Reply,
}

/// The actor's inbox: commands from the handle, effect reports, runtime events.
pub(super) enum Cmd {
    Start(StartCmd),
    Disconnect {
        req: DisconnectReq,
        reply: Reply,
    },
    CancelPending,
    Maintenance {
        job: MaintenanceJob,
        admit: oneshot::Sender<Result<(), ConnError>>,
    },
    Shutdown {
        reply: oneshot::Sender<ShutdownReport>,
    },
    Reopen {
        reply: oneshot::Sender<bool>,
    },
    Fault(FaultState),
    Adopt(Owner),
    Resumed,
    NetworkChanged(NetworkTransition),
    LeakDetected,
    Confirm {
        op: OpId,
        want: Want,
        reply: oneshot::Sender<bool>,
    },
    StartDone {
        op: OpId,
        report: Box<StartReport>,
    },
    /// The caller's token fired (`Cancelled`) or the deadline passed (`Timeout`).
    StartAbort {
        op: OpId,
        kind: ErrorKind,
    },
    StopDone {
        op: OpId,
        report: Box<StopReport>,
    },
    StopTimeout {
        op: OpId,
    },
    MaintenanceDone,
    /// A supervised effect panicked: nothing about the tunnel is proven any more (A-01).
    EffectPanicked,
    /// «Подключить» in the paused state.
    RetryNow {
        reply: oneshot::Sender<bool>,
    },
    /// The pause that began at `since` lasted long enough to be worth one notice.
    PauseNotice {
        since: UnixMs,
    },
    /// The user changed the kill-switch level (it is stored already).
    KillSwitchChanged,
    /// Time to look again whether another VPN still keeps the session from pausing.
    GuardCheck,
    /// Answers once everything queued before it was handled.
    #[cfg(test)]
    Barrier(oneshot::Sender<()>),
}

/// The start-type operation in flight.
struct Start {
    op: OpMeta,
    job: Job,
    /// The effect's token: cancelled on abort, and once the effect drained.
    token: CancellationToken,
    reply: Option<Reply>,
    /// Set once cancelled / timed out: the caller has its answer, the effect still drains.
    aborted: Option<ErrorKind>,
    terminal_published: bool,
}

/// The stop in flight. Every disconnect arriving meanwhile joins it.
struct Stop {
    op: OpMeta,
    cause: StopCause,
    waiters: Vec<Reply>,
    /// Effect spawned (otherwise it waits for the start to drain first).
    running: bool,
    terminal_published: bool,
    /// Session facts captured right before the runtime stop.
    captured: Captured,
    /// Cancelled when the stop ends (ends its deadline timer).
    timer: CancellationToken,
    shutdown: Option<oneshot::Sender<ShutdownReport>>,
    /// Starts that pre-empted a lower one: re-admitted once this stop succeeded.
    then: Vec<StartCmd>,
    /// The kill switch keeps blocking after it (`DisconnectReq::keep_protection`).
    keep: bool,
    /// Full stops asked while this one keeps protection: they run once it ended.
    release: Vec<(DisconnectReq, Reply)>,
}

struct Actor {
    deps: Arc<LifecycleDeps>,
    tx: mpsc::UnboundedSender<Cmd>,
    status: watch::Receiver<TunStatus>,
    fsm: Fsm,
    snap_tx: watch::Sender<TunnelSnapshot>,
    session_tx: watch::Sender<Option<SessionView>>,
    events: broadcast::Sender<SessionEvent>,
    /// A lane operation is in flight (published after every handled command).
    busy: watch::Sender<bool>,
    /// The holder of the session a kept stop ended, while its block lasts.
    kept_by: watch::Sender<Option<Owner>>,
    start: Option<Start>,
    stop: Option<Stop>,
    maintenance: bool,
    closed: bool,
    /// A shutdown waits for the operation in flight before its own stop.
    shutdown: Option<oneshot::Sender<ShutdownReport>>,
    session: Option<LiveSession>,
    /// What a drop does to the live session (decided at its connect, kept current: `guard`).
    guard: SessionGuard,
    /// A [`Cmd::GuardCheck`] is on its way.
    foreign_watch: bool,
    /// The internet is paused (the session's kill switch holds a drop).
    paused: Option<paused::Paused>,
    kill_switch: watch::Sender<KillSwitchView>,
    /// The runtime's last status kind, also while an operation owned the lane (a failed planned
    /// reconnect hands the session to the runtime's recovery).
    last_kind: Option<TunStatusKind>,
    /// The runtime's failover run, from its `FailedOver` until the session follows it.
    failover: Option<events::Failover>,
    last_resume: Option<Instant>,
    last_network_change: Option<Instant>,
}

pub(super) fn spawn(deps: LifecycleDeps) -> Lifecycle {
    let (tx, rx) = mpsc::unbounded_channel();
    let fsm = Fsm::new();
    let (snap_tx, snapshot) = watch::channel(fsm.snapshot().clone());
    let (session_tx, session) = watch::channel(None);
    let (events, _) = broadcast::channel(64);
    let (busy, idle) = watch::channel(false);
    let (kept_by, kept) = watch::channel(None);
    let (kill_switch, kill_switch_rx) = watch::channel(KillSwitchView::default());
    // Subscribe before the first command so no runtime event is missed.
    let runtime_events = deps.runtime.subscribe();
    let actor = Actor {
        status: deps.runtime.status(),
        deps: Arc::new(deps),
        tx: tx.clone(),
        fsm,
        snap_tx,
        session_tx,
        events: events.clone(),
        busy,
        kept_by,
        start: None,
        stop: None,
        maintenance: false,
        closed: false,
        shutdown: None,
        session: None,
        guard: SessionGuard::default(),
        foreign_watch: false,
        paused: None,
        kill_switch,
        last_kind: None,
        failover: None,
        last_resume: None,
        last_network_change: None,
    };
    tokio::spawn(actor.run(rx, runtime_events));
    Lifecycle {
        tx,
        snapshot,
        session,
        events,
        busy: idle,
        kept_by: kept,
        kill_switch: kill_switch_rx,
    }
}

/// Operation record of a lane operation.
fn op_meta(kind: OpKind, head: &Head) -> OpMeta {
    let now = now_ms();
    let budget = UnixMs::try_from(head.timeout.as_millis()).unwrap_or(UnixMs::MAX);
    OpMeta {
        id: OpId::next(),
        correlation: head.correlation.clone(),
        owner: head.owner,
        source: head.source,
        kind,
        started_at: now,
        deadline: Some(now.saturating_add(budget)),
        status: OpStatus::Running,
        category: None,
    }
}

/// The record of `op` ended with `kind` (`None` = success).
fn terminal(op: &OpMeta, kind: Option<ErrorKind>) -> OpMeta {
    OpMeta {
        status: match kind {
            None => OpStatus::Success,
            Some(ErrorKind::Cancelled) => OpStatus::Cancelled,
            Some(_) => OpStatus::Error,
        },
        category: kind,
        ..op.clone()
    }
}

impl Actor {
    /// Runtime events are read here, not by a forwarding task: everything the runtime emitted
    /// before an effect reported back is applied before that report (a late `Stopped` after a
    /// confirmed stop would otherwise read as "unknown").
    async fn run(
        mut self,
        mut rx: mpsc::UnboundedReceiver<Cmd>,
        mut events: broadcast::Receiver<TunnelEvent>,
    ) {
        let mut events_open = true;
        loop {
            tokio::select! {
                biased;
                event = events.recv(), if events_open => match event {
                    Ok(event) => self.on_runtime(event).await,
                    Err(RecvError::Lagged(lost)) => self.lagged(lost).await,
                    Err(RecvError::Closed) => events_open = false,
                },
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    if events_open {
                        events_open = self.drain_events(&mut events).await;
                    }
                    self.handle(cmd).await;
                }
            }
            self.push_snapshot();
            let busy = self.start.is_some() || self.stop.is_some() || self.maintenance;
            self.busy
                .send_if_modified(|was| std::mem::replace(was, busy) != busy);
            if self.fsm.snapshot().state != TunnelState::Blocked {
                // The kept block is gone (a start ran, a full stop released it).
                self.kept_by.send_if_modified(|kept| kept.take().is_some());
            }
        }
    }

    /// Applies every runtime event already queued; `false` once the runtime is gone.
    async fn drain_events(&mut self, events: &mut broadcast::Receiver<TunnelEvent>) -> bool {
        loop {
            match events.try_recv() {
                Ok(event) => self.on_runtime(event).await,
                Err(TryRecvError::Lagged(lost)) => self.lagged(lost).await,
                Err(TryRecvError::Empty) => return true,
                Err(TryRecvError::Closed) => return false,
            }
        }
    }

    async fn lagged(&mut self, lost: u64) {
        tracing::warn!(lost, "lifecycle lagged behind runtime events; resyncing");
        self.resync().await;
    }

    async fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Start(cmd) => self.admit_start(cmd),
            Cmd::Disconnect { req, reply } => self.admit_stop(req, reply),
            Cmd::CancelPending => self.cancel_pending(),
            Cmd::Maintenance { job, admit } => self.admit_maintenance(job, admit),
            Cmd::Shutdown { reply } => self.begin_shutdown(reply),
            Cmd::Reopen { reply } => {
                let _ = reply.send(self.reopen());
            }
            Cmd::Fault(state) => {
                let e = self.evidence();
                self.fsm.fault(state, e);
            }
            Cmd::Adopt(owner) => {
                if let Some(live) = self.session.as_mut().filter(|s| owner > s.holder) {
                    live.holder = owner;
                }
                self.push_session();
            }
            Cmd::Resumed => self.last_resume = Some(Instant::now()),
            Cmd::NetworkChanged(transition) => {
                self.last_network_change = Some(Instant::now());
                if let Some(s) = self.session.as_mut() {
                    s.transition = Some(transition);
                }
            }
            Cmd::LeakDetected => {
                if let Some(s) = self.session.as_mut() {
                    s.leak_detected = true;
                }
            }
            Cmd::Confirm { op, want, reply } => {
                let _ = reply.send(self.confirmable(op, want));
            }
            Cmd::StartDone { op, report } => self.start_done(op, *report).await,
            Cmd::StartAbort { op, kind } => self.abort_start(op, kind),
            Cmd::StopDone { op, report } => self.stop_done(op, *report).await,
            Cmd::StopTimeout { op } => self.stop_timeout(op),
            Cmd::MaintenanceDone => {
                self.maintenance = false;
                self.after_drain();
            }
            Cmd::EffectPanicked => {
                let e = self.evidence();
                self.fsm.fault(FaultState::Unknown, e);
                let kind = NoticeKind::ConnectionError;
                self.notify(Level::Error, "internalError", kind, None);
            }
            Cmd::RetryNow { reply } => {
                if self.paused.is_none() || !self.lane_idle() {
                    let _ = reply.send(false);
                    return;
                }
                // The runtime answers once its command is taken; a run of its own in flight
                // must not hold this actor (events keep flowing meanwhile).
                let runtime = self.deps.runtime.clone();
                tokio::spawn(async move {
                    let _ = reply.send(runtime.retry_now().await);
                });
            }
            Cmd::PauseNotice { since } => self.pause_notice(since),
            Cmd::KillSwitchChanged => self.refresh_guard().await,
            Cmd::GuardCheck => self.guard_check().await,
            #[cfg(test)]
            Cmd::Barrier(done) => {
                let _ = done.send(());
            }
        }
    }

    /// What the OS shows right now; `None` when the Soft state cannot be read (fail closed).
    fn evidence(&self) -> Option<Evidence> {
        let soft = self.deps.soft.applied()?;
        Some(Evidence::from_status(&self.status.borrow(), soft))
    }

    fn runtime_running(&self) -> bool {
        self.status.borrow().running
    }

    /// Feeds an operation record to the state machine (a stale record is rejected there).
    fn publish(&mut self, op: &OpMeta) {
        let e = self.evidence();
        if self.fsm.op_changed(op, e).is_err() {
            tracing::debug!(op = %op.id, status = ?op.status, "operation record not applied");
        }
        tracing::info!(
            op = %op.id,
            correlation = %op.correlation,
            kind = ?op.kind,
            owner = ?op.owner,
            status = ?op.status,
            "connection operation"
        );
    }

    fn push_snapshot(&self) {
        let snap = self.fsm.snapshot();
        self.snap_tx.send_if_modified(|current| {
            let changed = current != snap;
            if changed {
                *current = snap.clone();
            }
            changed
        });
    }

    fn push_session(&self) {
        let view = self.session.as_ref().map(LiveSession::view);
        self.session_tx.send_if_modified(|current| {
            let changed = *current != view;
            if changed {
                *current = view;
            }
            changed
        });
    }

    /// Does the state machine accept the start of `op` with the protection `want`?
    fn confirmable(&self, op: OpId, want: Want) -> bool {
        let current = self
            .start
            .as_ref()
            .is_some_and(|s| s.op.id == op && s.aborted.is_none());
        let e = self.evidence();
        current
            && self.fsm.can_confirm_start(e)
            && e.is_some_and(|e| {
                let run = e.running && e.pid.is_some_and(|pid| pid > 0);
                match want {
                    Want::Tun => run && !e.proxy_capture,
                    Want::Soft => run && e.proxy_capture && e.soft_applied,
                }
            })
    }
}

fn refuse(reply: Reply, msg: &'static str) {
    let _ = reply.send(Err(ConnError::Refused(Msg::new(msg))));
}

/// Runs `fut` as a child task; a panic becomes `on_panic()` so the lane is never stranded, after
/// the actor was told the state is no longer proven.
fn supervise<T: Send + 'static>(
    tx: &mpsc::UnboundedSender<Cmd>,
    fut: impl Future<Output = T> + Send + 'static,
    on_panic: impl FnOnce() -> T + Send + 'static,
    done: impl FnOnce(T) + Send + 'static,
) {
    let handle = tokio::spawn(fut);
    let tx = tx.clone();
    tokio::spawn(async move {
        let out = match handle.await {
            Ok(out) => out,
            Err(e) => {
                tracing::error!(error = %e, "lifecycle effect panicked");
                let _ = tx.send(Cmd::EffectPanicked);
                on_panic()
            }
        };
        done(out);
    });
}
