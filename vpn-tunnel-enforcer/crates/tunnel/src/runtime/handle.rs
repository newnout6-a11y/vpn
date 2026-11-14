//! [`TunnelHandle`]: the cloneable front of the actor; implements [`Runtime`].
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, KillSwitchLevel, OutboundFault};
use vpnte_base::{AppError, ErrorKind, Msg};

use super::RuntimeDeps;
use super::actor::Actor;
use super::engines::CoreProc;
use crate::api::{
    ExitInfo, OwnerCheck, RestartOptions, Runtime, StartReceipt, StartRequest, StopOptions,
    StopReceipt, SwitchReceipt, TunError, TunStatus, TunnelEvent, VpnProfile,
};

/// What a protected restart starts.
pub(super) enum Next {
    Given(StartRequest),
    /// The last start with the current settings (`restart_with_last`).
    WithLast,
    /// The last start in another adaptive mode, optionally with another profile.
    Adaptive {
        mode: AdaptiveMode,
        profile: Option<VpnProfile>,
    },
}

type Reply<T> = oneshot::Sender<T>;

/// Commands, processed strictly in order by the actor.
pub(super) enum Cmd {
    Start {
        req: StartRequest,
        cancel: CancellationToken,
        /// Stop counter when the start was requested: a stop issued later cancels it.
        stops: u64,
        reply: Reply<Result<StartReceipt, TunError>>,
    },
    Stop {
        opts: StopOptions,
        /// Order of this stop call: calls issued before a stop finished share its receipt.
        seq: u64,
        reply: Reply<StopReceipt>,
    },
    Restart {
        reason: String,
        next: Next,
        opts: RestartOptions,
        reply: Reply<Result<Option<StartReceipt>, TunError>>,
    },
    Switch {
        next: StartRequest,
        cancel: CancellationToken,
        is_owner: OwnerCheck,
        /// Stop counter when the switch was requested: a later stop ends its ownership.
        stops: u64,
        reply: Reply<Option<SwitchReceipt>>,
    },
    /// The paused session's recovery start, now instead of after its wait.
    RetryNow { reply: Reply<bool> },
    /// The running session's kill switch changed.
    KillSwitch { level: KillSwitchLevel },
}

/// State shared between the handle and the actor (short locks, never across `.await`).
#[derive(Default)]
pub(super) struct Shared {
    /// Token of the start / switch / restart in flight: a stop cancels it at once.
    pub op: Mutex<Option<CancellationToken>>,
    /// Bumped by every stop before it is queued.
    pub stops: AtomicU64,
    pub last_exit: Mutex<Option<ExitInfo>>,
    /// The core of the current (or last) run, for the fault classifier.
    pub core: Mutex<Option<Arc<dyn CoreProc>>>,
}

/// Front of the runtime actor. Cheap to clone; the actor ends when the last handle is dropped
/// (after a full stop).
#[derive(Clone)]
pub struct TunnelHandle {
    tx: mpsc::Sender<Cmd>,
    status: watch::Receiver<TunStatus>,
    events: broadcast::Sender<TunnelEvent>,
    shared: Arc<Shared>,
}

impl TunnelHandle {
    /// Spawns the actor (needs a tokio runtime).
    pub fn spawn(deps: RuntimeDeps) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let (status_tx, status) = watch::channel(TunStatus::default());
        let (events, _) = broadcast::channel(256);
        let shared = Arc::new(Shared::default());
        let actor = Actor::new(deps, rx, status_tx, events.clone(), shared.clone());
        tokio::spawn(actor.run());
        Self {
            tx,
            status,
            events,
            shared,
        }
    }

    async fn ask<T>(&self, cmd: impl FnOnce(Reply<T>) -> Cmd) -> Option<T> {
        let (reply, answer) = oneshot::channel();
        self.tx.send(cmd(reply)).await.ok()?;
        answer.await.ok()
    }
}

fn gone() -> TunError {
    TunError::new(ErrorKind::Internal, Msg::new("tunnel.runtime.actorGone"))
}

/// A stop that could not reach the actor proves nothing.
fn unanswered_stop() -> StopReceipt {
    StopReceipt {
        operation_id: format!("stop_{}", uuid::Uuid::new_v4().simple()),
        ok: false,
        runtime_stopped: false,
        forced: false,
        protection_released: None,
        baseline_restored: None,
        adapter_gone: false,
        warnings: vec![Msg::new("tunnel.runtime.actorGone")],
    }
}

#[async_trait]
impl Runtime for TunnelHandle {
    async fn start(
        &self,
        req: StartRequest,
        cancel: CancellationToken,
    ) -> Result<StartReceipt, TunError> {
        let stops = self.shared.stops.load(Ordering::SeqCst);
        self.ask(|reply| Cmd::Start {
            req,
            cancel,
            stops,
            reply,
        })
        .await
        .unwrap_or_else(|| Err(gone()))
    }

    async fn stop(&self, opts: StopOptions) -> StopReceipt {
        let seq = self.shared.stops.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(op) = self.shared.op.lock().as_ref() {
            op.cancel();
        }
        self.ask(|reply| Cmd::Stop { opts, seq, reply })
            .await
            .unwrap_or_else(unanswered_stop)
    }

    async fn restart_protected(
        &self,
        reason: String,
        next: StartRequest,
        opts: RestartOptions,
    ) -> Result<StartReceipt, TunError> {
        let next = Next::Given(next);
        let answer = self
            .ask(|reply| Cmd::Restart {
                reason,
                next,
                opts,
                reply,
            })
            .await
            .unwrap_or_else(|| Err(gone()))?;
        answer.ok_or_else(|| AppError::conflict(Msg::new("tunnel.runtime.notRunning")).into())
    }

    async fn restart_with_last(&self, reason: String) -> Result<Option<StartReceipt>, TunError> {
        self.ask(|reply| Cmd::Restart {
            reason,
            next: Next::WithLast,
            opts: RestartOptions::default(),
            reply,
        })
        .await
        .unwrap_or_else(|| Err(gone()))
    }

    async fn restart_adaptive(
        &self,
        mode: AdaptiveMode,
        reason: String,
        profile: Option<VpnProfile>,
    ) -> Result<StartReceipt, TunError> {
        let next = Next::Adaptive { mode, profile };
        let answer = self
            .ask(|reply| Cmd::Restart {
                reason,
                next,
                opts: RestartOptions::default(),
                reply,
            })
            .await
            .unwrap_or_else(|| Err(gone()))?;
        answer.ok_or_else(|| AppError::conflict(Msg::new("tunnel.runtime.notRunning")).into())
    }

    async fn switch_upstream(
        &self,
        next: StartRequest,
        cancel: CancellationToken,
        is_owner: OwnerCheck,
    ) -> Option<SwitchReceipt> {
        let stops = self.shared.stops.load(Ordering::SeqCst);
        self.ask(|reply| Cmd::Switch {
            next,
            cancel,
            is_owner,
            stops,
            reply,
        })
        .await
        .flatten()
    }

    async fn retry_now(&self) -> bool {
        self.ask(|reply| Cmd::RetryNow { reply })
            .await
            .unwrap_or(false)
    }

    async fn set_kill_switch(&self, level: KillSwitchLevel) {
        // Ordered after everything queued before; a gone actor has no session to follow it.
        let _ = self.tx.send(Cmd::KillSwitch { level }).await;
    }

    fn status(&self) -> watch::Receiver<TunStatus> {
        self.status.clone()
    }

    fn subscribe(&self) -> broadcast::Receiver<TunnelEvent> {
        self.events.subscribe()
    }

    fn last_exit(&self) -> Option<ExitInfo> {
        self.shared.last_exit.lock().clone()
    }

    fn recent_fault(&self) -> Option<OutboundFault> {
        self.shared.core.lock().as_ref()?.recent_fault()
    }
}
