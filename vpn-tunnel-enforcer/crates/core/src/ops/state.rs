//! Shared state of the registry: live operations, the bounded history, and the transitions
//! (publish, abort, settle, user-wait pause, commit fence, outcome) that keep them consistent.
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{broadcast, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::{CorrelationId, OpId, OpMeta, OpStatus};

/// Records kept for the UI; live records are never evicted.
pub(super) const HISTORY_CAP: usize = 1000;

pub(super) struct Inner {
    pub(super) state: Mutex<State>,
    pub(super) events: broadcast::Sender<OpMeta>,
}

#[derive(Default)]
pub(super) struct State {
    pub(super) closed: bool,
    /// Bumped by `close()`: a replacement queued before it is never admitted afterwards.
    pub(super) generation: u64,
    /// Cancelled by `close()`; wakes replacements waiting for a predecessor's drain.
    pub(super) closing: CancellationToken,
    pub(super) active: HashMap<Cow<'static, str>, Live>,
    pub(super) history: History,
}

/// Control data of an admitted operation; stays in `State::active` until every effect settled.
pub(super) struct Live {
    pub(super) op: Arc<Op>,
    /// Authoritative metadata (mirrored into the history on every publish).
    pub(super) meta: OpMeta,
    pub(super) committing: bool,
    pub(super) committed: bool,
    /// First abort refused during a commit: another thread may land one there (the old
    /// single-threaded registry could not); it applies if the commit fails.
    pub(super) deferred: Option<ErrorKind>,
    pub(super) user_waits: u32,
    /// Work budget left at `clock` (frozen while the user decides).
    pub(super) remaining: Duration,
    pub(super) clock: Instant,
}

/// Handles of an admitted operation shared by the registry, its supervisor and its leases.
pub(super) struct Op {
    pub(super) id: OpId,
    pub(super) correlation: CorrelationId,
    pub(super) resource: Cow<'static, str>,
    /// Lease signal: cancelled on abort, on the effect's own failure (siblings stop) and once drained.
    pub(super) token: CancellationToken,
    /// Set only by an abort (cancel / timeout / pre-emption / close); the caller races it.
    pub(super) aborted: CancellationToken,
    pub(super) fault: OnceLock<ErrorKind>,
    /// Set once every effect settled and the resource is free again.
    pub(super) drained: CancellationToken,
    pub(super) tracker: TaskTracker,
    /// Monotonic end of the work budget; `None` while paused, committing or finished.
    pub(super) deadline: watch::Sender<Option<Instant>>,
    pub(super) span: tracing::Span,
}

impl Op {
    /// The error an aborted operation reports (cancelled when it ended for another reason).
    pub(super) fn abort_error(&self) -> AppError {
        AppError::new(self.fault.get().copied().unwrap_or(ErrorKind::Cancelled))
    }
}

pub(super) fn busy() -> AppError {
    AppError::conflict(Msg::new("core.ops.busy"))
}

pub(super) fn closing() -> AppError {
    AppError::conflict(Msg::new("core.ops.closing"))
}

/// Milliseconds rounded up, so a full budget publishes `deadline - started_at == timeout`.
pub(super) fn ceil_ms(d: Duration) -> UnixMs {
    UnixMs::try_from(d.as_nanos().div_ceil(1_000_000)).unwrap_or(UnixMs::MAX)
}

fn outcome(failure: Option<ErrorKind>) -> (OpStatus, Option<ErrorKind>) {
    match failure {
        None => (OpStatus::Success, None),
        Some(ErrorKind::Cancelled) => (OpStatus::Cancelled, Some(ErrorKind::Cancelled)),
        Some(kind) => (OpStatus::Error, Some(kind)),
    }
}

fn find_live<'a>(
    active: &'a mut HashMap<Cow<'static, str>, Live>,
    op: &Op,
) -> Option<&'a mut Live> {
    active
        .get_mut(op.resource.as_ref())
        .filter(|live| std::ptr::eq(Arc::as_ptr(&live.op), op))
}

pub(super) type History = BTreeMap<OpId, OpMeta>;

impl State {
    /// The live record of `op` (until it drained) and the history, borrowed side by side.
    fn live(&mut self, op: &Op) -> Option<(&mut Live, &mut History)> {
        Some((find_live(&mut self.active, op)?, &mut self.history))
    }
}

fn running(live: &Live) -> bool {
    live.meta.status == OpStatus::Running && !live.op.token.is_cancelled()
}

pub(super) fn evict(history: &mut History, active: &HashMap<Cow<'static, str>, Live>) {
    while history.len() > HISTORY_CAP {
        let is_live = |id: &OpId| active.values().any(|live| live.op.id == *id);
        let Some(oldest) = history.keys().copied().find(|id| !is_live(id)) else {
            break;
        };
        history.remove(&oldest);
    }
}

impl Inner {
    /// Mirrors the live record into the history and tells subscribers. Called with the state
    /// locked, so events arrive in transition order.
    pub(super) fn publish(&self, history: &mut History, live: &Live) {
        let meta = &live.meta;
        history.insert(meta.id, meta.clone());
        // No subscriber is not an error: the history still has the record.
        let _ = self.events.send(meta.clone());
        // The op span carries `op`, `kind`, `owner`, `source` and `corr` (the log's correlation
        // slot), also when the transition comes from outside the operation (cancel, close).
        let _span = live.op.span.enter();
        match meta.status {
            OpStatus::Running => tracing::debug!(deadline = ?meta.deadline, "feature operation"),
            _ => {
                tracing::info!(status = ?meta.status, category = ?meta.category, "feature operation")
            }
        }
    }

    fn finish(&self, live: &mut Live, history: &mut History, failure: Option<ErrorKind>) {
        if live.meta.status != OpStatus::Running {
            return;
        }
        (live.meta.status, live.meta.category) = outcome(failure);
        live.op.deadline.send_replace(None);
        self.publish(history, live);
    }

    /// Ends a running operation with `kind` (cancelled or timeout). Refused once its outcome is
    /// known, and while it commits (then remembered for a failed commit). The caller learns at
    /// once; effects keep the resource until they settle.
    pub(super) fn abort(&self, op: &Op, kind: ErrorKind) -> bool {
        let aborted = self.abort_locked(&mut self.state.lock(), op, kind);
        if aborted {
            op.token.cancel();
            op.aborted.cancel();
        }
        aborted
    }

    /// State part of [`Inner::abort`]; the caller signals the tokens after unlocking.
    pub(super) fn abort_locked(&self, state: &mut State, op: &Op, kind: ErrorKind) -> bool {
        let Some((live, history)) = state.live(op) else {
            return false;
        };
        if live.meta.status != OpStatus::Running {
            return false;
        }
        if live.committing {
            live.deferred.get_or_insert(kind);
            return false;
        }
        let _ = op.fault.set(kind);
        self.finish(live, history, Some(kind));
        true
    }

    /// Frees the resource once every effect settled (also on panic or runtime shutdown).
    pub(super) fn settle(&self, op: &Op) {
        let mut guard = self.state.lock();
        if let Some((live, history)) = guard.live(op) {
            // A supervisor that vanished must not leave a ghost "running" record behind.
            self.finish(live, history, Some(ErrorKind::Internal));
            guard.active.remove(op.resource.as_ref());
        }
        drop(guard);
        op.token.cancel();
        op.drained.cancel();
    }

    /// The lease may still act: admitted, running and not aborted.
    pub(super) fn is_active(&self, op: &Op) -> bool {
        let mut guard = self.state.lock();
        find_live(&mut guard.active, op).is_some_and(|live| running(live))
    }

    /// Current metadata of `op` (live record, else history).
    pub(super) fn meta(&self, op: &Op) -> Option<OpMeta> {
        let mut guard = self.state.lock();
        match guard.live(op) {
            Some((live, _)) => Some(live.meta.clone()),
            None => guard.history.get(&op.id).cloned(),
        }
    }

    /// First concurrent user wait stops the work clock; an exhausted budget times out instead.
    pub(super) fn pause_budget(&self, op: &Op) -> AppResult<()> {
        let mut guard = self.state.lock();
        let (live, history) = guard
            .live(op)
            .filter(|(live, _)| running(live))
            .ok_or_else(|| op.abort_error())?;
        if live.user_waits == 0 {
            live.remaining = live.remaining.saturating_sub(live.clock.elapsed());
            if live.remaining.is_zero() {
                drop(guard);
                self.abort(op, ErrorKind::Timeout);
                return Err(op.abort_error());
            }
            op.deadline.send_replace(None);
            live.meta.deadline = None;
            self.publish(history, live);
        }
        live.user_waits += 1;
        Ok(())
    }

    /// The last user wait ended: the remaining budget runs again from now.
    pub(super) fn resume_budget(&self, op: &Op) {
        let mut guard = self.state.lock();
        let Some((live, history)) = guard.live(op) else {
            return;
        };
        live.user_waits = live.user_waits.saturating_sub(1);
        if live.user_waits == 0 && live.meta.status == OpStatus::Running && !live.committing {
            live.clock = Instant::now();
            op.deadline.send_replace(Some(live.clock + live.remaining));
            live.meta.deadline = Some(now_ms() + ceil_ms(live.remaining));
            self.publish(history, live);
        }
    }

    /// Fences a final commit: active, no tracked effect pending; cancellation and the deadline
    /// are suspended until [`Inner::end_commit`].
    pub(super) fn begin_commit(&self, op: &Op) -> AppResult<()> {
        let mut guard = self.state.lock();
        let live = find_live(&mut guard.active, op)
            .filter(|live| running(live))
            .ok_or_else(|| op.abort_error())?;
        if !op.tracker.is_empty() {
            return Err(
                AppError::new(ErrorKind::Conflict).with_source(anyhow::anyhow!(
                    "commit refused: tracked effects still pending"
                )),
            );
        }
        live.committing = true;
        op.deadline.send_replace(None);
        Ok(())
    }

    /// A successful commit makes success terminal at once; a failed one leaves the outcome to
    /// the effect's error (which normally propagates it), unless an abort landed meanwhile.
    pub(super) fn end_commit(&self, op: &Op, ok: bool) {
        let mut guard = self.state.lock();
        let Some((live, history)) = guard.live(op) else {
            return;
        };
        live.committing = false;
        let deferred = live.deferred.take();
        if ok {
            live.committed = true;
            self.finish(live, history, None);
        } else if live.meta.status == OpStatus::Running && live.user_waits == 0 {
            // Restore the budget's original end; the commit attempt does not extend it.
            op.deadline.send_replace(Some(live.clock + live.remaining));
        }
        drop(guard);
        // As if the abort had come right after the failed commit.
        if let (false, Some(kind)) = (ok, deferred) {
            self.abort(op, kind);
        }
    }

    /// The effect itself failed: terminal at once (unless a commit already decided the outcome).
    /// Returns `true` when the failure came after a commit.
    pub(super) fn effect_failed(&self, op: &Op, kind: ErrorKind) -> bool {
        let mut guard = self.state.lock();
        let Some((live, history)) = guard.live(op) else {
            return false;
        };
        if live.committed {
            // The text stays out of the log: only the category, like every operation record. The
            // supervisor calls this inside the op span, which identifies the operation.
            tracing::error!(category = ?kind, "feature post-commit failure");
            return true;
        }
        self.finish(live, history, Some(kind));
        false
    }

    /// The effect succeeded and every effect settled: success, unless aborted meanwhile.
    pub(super) fn succeed(&self, op: &Op) -> AppResult<()> {
        let mut guard = self.state.lock();
        match guard.live(op) {
            Some((live, _)) if live.committed => Ok(()),
            Some((live, history)) if live.meta.status == OpStatus::Running => {
                self.finish(live, history, None);
                Ok(())
            }
            _ => Err(op.abort_error()),
        }
    }
}
