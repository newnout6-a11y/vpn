//! The owner task: state, the main loop and the dispatch of commands. Operations run inline
//! (strictly one at a time); the handle pre-empts a start / switch / restart in flight by
//! cancelling its token, so a stop never waits behind a long start.

use std::future::pending;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::UnixMs;
use vpnte_engine::clash_api::ClashEndpoint;
use vpnte_engine::singbox_config::Listeners;
use vpnte_engine::singbox_process::ExitInfo as EngineExit;
use vpnte_engine::slot::{Slot, SlotEndpoint};
use vpnte_engine::xray_process::XrayEvent;

use super::RuntimeDeps;
use super::capture::{Capture, CaptureCheck, CapturePlan, CaptureProof};
use super::engines::{CoreProc, Slots};
use super::handle::{Cmd, Shared};
use crate::api::{
    CaptureKind, EngineRun, FailoverCause, SessionEndpoints, StartRequest, StopOptions,
    StopReceipt, TunStatus, TunStatusKind, TunWarning, TunnelEvent,
};

/// The Xray side of a slot-mode session.
pub(super) struct SlotSession {
    pub slots: Box<dyn Slots>,
    /// Port and credentials of each slot as the sing-box config names them.
    pub endpoints: [SlotEndpoint; 2],
    pub active: Slot,
    /// Public IP each slot reached when it was probed.
    pub egress: [Option<IpAddr>; 2],
    /// `dns-bootstrap-in`: candidate server names resolve through it while the TUN is up.
    pub dns_bootstrap: u16,
    /// A stage failed although the previous upstream survived: the standby port may belong to
    /// someone else now, so the next switch goes through a protected restart.
    pub suspect: bool,
    /// Restarts of the active slot in the current window.
    pub restarts: Vec<Instant>,
}

/// A running session.
pub(super) struct Session {
    pub generation: u64,
    pub req: StartRequest,
    pub plan: CapturePlan,
    pub proof: CaptureProof,
    pub core: Arc<dyn CoreProc>,
    pub slots: Option<SlotSession>,
    pub clash: ClashEndpoint,
    pub listeners: Listeners,
    pub compat: [u8; 32],
    /// The upstream's engine and why (an in-place switch updates it).
    pub engine: EngineRun,
    pub started_at: UnixMs,
    pub endpoints: SessionEndpoints,
    /// Cancels this session's watchdog tasks.
    pub watch: CancellationToken,
    /// The competing tunnel currently reported (display label).
    pub competing: Option<String>,
}

/// The core ended unexpectedly: its protection keeps blocking (`Capture::lost`), so the next
/// start continues it; the crash policy decides what follows.
pub(super) struct Crashed {
    pub plan: CapturePlan,
    pub slots: Option<SlotSession>,
}

/// An exit that could not be proven: everything is retained, the protection keeps blocking
/// (engines exist only after `Capture::begin`), nothing is released.
pub(super) struct Retained {
    pub core: Option<Arc<dyn CoreProc>>,
    pub slots: Option<SlotSession>,
    pub plan: Option<CapturePlan>,
}

pub(super) enum Phase {
    Idle,
    /// Preserved stop: protection kept, no engines (only a start or a full stop leaves it).
    Adapting(CapturePlan),
    Running(Box<Session>),
    Crashed(Box<Crashed>),
    Faulted(Box<Retained>),
}

/// Reports of this session's watchdog tasks (stale generations are ignored).
#[derive(Debug)]
pub(super) enum Internal {
    ProxyDown {
        generation: u64,
    },
    ProxyUp {
        generation: u64,
    },
    Capture {
        generation: u64,
        check: CaptureCheck,
    },
}

pub(super) struct Actor {
    pub deps: RuntimeDeps,
    /// Strategy of the current (or last) session; every capture call goes here. Replaced only
    /// by a start with the other strategy, after the old one released what it held.
    pub capture: Arc<dyn Capture>,
    pub strategy: CaptureKind,
    inbox: mpsc::Receiver<Cmd>,
    /// The last stop: calls issued before it finished share its receipt.
    pub last_stop: Option<DoneStop>,
    /// A release failed: the next stop retries it even with nothing running.
    pub protection_dirty: bool,
    status: watch::Sender<TunStatus>,
    events: broadcast::Sender<TunnelEvent>,
    pub shared: Arc<Shared>,
    pub phase: Phase,
    /// Native generation: one per start (lane or crash restart).
    pub generation: u64,
    /// Upstream switch generation.
    pub switches: u64,
    /// The last start request (restarts, crash recovery); cleared by a full stop.
    pub last: Option<StartRequest>,
    /// Crash restarts made in the current window and whether the failover was tried.
    pub attempt: u8,
    pub failover_tried: bool,
    /// Slow retries made in the current pause (the kill switch holds, the budget is spent).
    pub slow: u8,
    /// The failover candidate (profile id) the start in flight dials and why the runtime
    /// failed over: its success is announced as [`TunnelEvent::FailedOver`] before its
    /// `StartFinished`.
    pub failing_over: Option<(String, FailoverCause)>,
    pub restart_due: Option<Instant>,
    /// The server (profile id) whose crash showed an outbound fault, and until when crash
    /// restarts keep away from it (freeze window, `crash` module).
    pub quiet: Option<(String, Instant)>,
    pub stable_at: Option<Instant>,
    pub slot_due: Option<Instant>,
    pub exit: Option<watch::Receiver<Option<EngineExit>>>,
    pub xray_rx: Option<mpsc::Receiver<XrayEvent>>,
    pub internal_tx: mpsc::Sender<Internal>,
    internal_rx: mpsc::Receiver<Internal>,
}

async fn wait_exit(exit: &mut Option<watch::Receiver<Option<EngineExit>>>) -> EngineExit {
    if let Some(rx) = exit
        && let Ok(seen) = rx.wait_for(Option::is_some).await
        && let Some(info) = seen.clone()
    {
        return info;
    }
    pending().await
}

async fn recv_opt<T>(rx: &mut Option<mpsc::Receiver<T>>) -> Option<T> {
    match rx {
        Some(rx) => rx.recv().await,
        None => pending().await,
    }
}

async fn sleep_opt(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => pending().await,
    }
}

impl Actor {
    pub(super) fn new(
        deps: RuntimeDeps,
        inbox: mpsc::Receiver<Cmd>,
        status: watch::Sender<TunStatus>,
        events: broadcast::Sender<TunnelEvent>,
        shared: Arc<Shared>,
    ) -> Self {
        let (internal_tx, internal_rx) = mpsc::channel(16);
        Self {
            capture: deps.proxy.clone(),
            strategy: CaptureKind::Proxy,
            deps,
            inbox,
            last_stop: None,
            protection_dirty: false,
            status,
            events,
            shared,
            phase: Phase::Idle,
            generation: 0,
            switches: 0,
            last: None,
            attempt: 0,
            failover_tried: false,
            slow: 0,
            failing_over: None,
            restart_due: None,
            quiet: None,
            stable_at: None,
            slot_due: None,
            exit: None,
            xray_rx: None,
            internal_tx,
            internal_rx,
        }
    }

    /// The loop: commands, engine exits, watchdog reports and timers, one at a time.
    pub(super) async fn run(mut self) {
        loop {
            tokio::select! {
                cmd = self.inbox.recv() => match cmd {
                    Some(cmd) => self.dispatch(cmd).await,
                    None => break,
                },
                Some(report) = self.internal_rx.recv() => self.on_internal(report).await,
                info = wait_exit(&mut self.exit) => self.on_core_exit(info).await,
                Some(event) = recv_opt(&mut self.xray_rx) => self.on_xray(event).await,
                () = sleep_opt(self.restart_due) => self.recover().await,
                () = sleep_opt(self.slot_due) => self.restart_slot().await,
                () = sleep_opt(self.stable_at) => self.stable(),
            }
        }
        // The last handle is gone: leave nothing running and nothing blocking.
        let receipt = self.stop(StopOptions::default()).await;
        tracing::info!(ok = receipt.ok, "tunnel runtime closed");
    }

    async fn dispatch(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Start {
                req,
                cancel,
                stops,
                reply,
            } => {
                let result = self.cmd_start(req, cancel, stops).await;
                let _ = reply.send(result);
            }
            Cmd::Stop { opts, seq, reply } => {
                let receipt = self.cmd_stop(opts, seq).await;
                let _ = reply.send(receipt);
            }
            Cmd::Restart {
                reason,
                next,
                opts,
                reply,
            } => {
                let result = self.cmd_restart(reason, next, opts).await;
                let _ = reply.send(result);
            }
            Cmd::Switch {
                next,
                cancel,
                is_owner,
                stops,
                reply,
            } => {
                let receipt = self.cmd_switch(next, cancel, is_owner, stops).await;
                let _ = reply.send(receipt);
            }
            Cmd::RetryNow { reply } => {
                let due = self.retry_due_now();
                let _ = reply.send(due);
                if due {
                    self.retry(true).await;
                }
            }
        }
    }

    /// A stop call issued while an earlier stop ran shares that stop's receipt; a full stop
    /// after a preserved one runs (escalation); a preserved stop after a full one is refused
    /// (protection cannot be considered preserved any more).
    async fn cmd_stop(&mut self, opts: StopOptions, seq: u64) -> StopReceipt {
        if let Some(done) = &self.last_stop
            && seq <= done.upto
        {
            match (done.preserved, opts.preserve_protection) {
                (a, b) if a == b => return done.receipt.clone(),
                (false, true) => {
                    let mut refused = done.receipt.clone();
                    refused.ok = false;
                    refused
                        .warnings
                        .push(vpnte_base::Msg::new("tunnel.runtime.fullStopRan"));
                    return refused;
                }
                _ => {}
            }
        }
        self.stop(opts).await
    }

    /// The run lasted long enough: the crash-restart budget starts over.
    fn stable(&mut self) {
        self.stable_at = None;
        if self.attempt > 0 {
            tracing::info!("tunnel stable: crash-restart budget reset");
        }
        self.attempt = 0;
        self.failover_tried = false;
        self.slow = 0;
        self.publish(|s| s.restart_attempt = 0);
    }

    /// A paused session (crashed, or held by its kill switch after a failed start) with a last
    /// start to retry: the user's «Подключить» runs that retry now.
    fn retry_due_now(&self) -> bool {
        let paused = matches!(self.phase, Phase::Crashed(_) | Phase::Adapting(_));
        paused && self.last.is_some() && self.shared.op.lock().is_none()
    }

    pub(super) fn publish(&self, f: impl FnOnce(&mut TunStatus)) {
        self.status.send_modify(f);
    }

    /// The status as last published.
    pub(super) fn status_now(&self) -> watch::Ref<'_, TunStatus> {
        self.status.borrow()
    }

    pub(super) fn emit(&self, event: TunnelEvent) {
        // No subscriber is fine: the status watch carries the state.
        let _ = self.events.send(event);
    }

    /// Status change: the watch is updated by the caller first, then the event goes out.
    pub(super) fn announce(&self, kind: TunStatusKind) {
        tracing::info!(status = %kind, "tunnel status");
        self.emit(TunnelEvent::Status(kind));
    }

    pub(super) fn warn(&self, warning: TunWarning) {
        self.emit(TunnelEvent::Warning(warning));
    }

    /// Registers the token of the operation a stop must pre-empt.
    pub(super) fn guard_op(&self, token: &CancellationToken) {
        *self.shared.op.lock() = Some(token.clone());
    }

    /// A stop was requested that has not run yet. Checked by automatic work after `guard_op`:
    /// a stop requested earlier is seen here, a later one cancels the registered token.
    pub(super) fn stop_pending(&self) -> bool {
        let done = self.last_stop.as_ref().map_or(0, |d| d.upto);
        self.shared.stops.load(Ordering::SeqCst) > done
    }

    pub(super) fn clear_op(&self) {
        self.shared.op.lock().take();
    }
}

/// A finished stop as later stop calls see it.
pub(super) struct DoneStop {
    /// Stop calls numbered up to this one were issued before the stop finished.
    pub upto: u64,
    pub preserved: bool,
    pub receipt: StopReceipt,
}
