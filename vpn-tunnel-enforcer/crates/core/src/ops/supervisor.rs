//! The task that drives one admitted operation, and the drop guards that keep its resource and
//! its caller consistent whatever happens (panic, dropped future, runtime shutdown).
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::pin;
use std::sync::Arc;

use futures_util::FutureExt as _;
use tokio::sync::{oneshot, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, ErrorKind};

use super::state::{Inner, Op};

/// Drives one operation on its own task: runs the effect while enforcing the deadline and the
/// caller's token, records the outcome, waits for every tracked effect, frees the resource.
pub(super) struct Supervisor {
    pub(super) settle: SettleOnDrop,
    pub(super) deadline: watch::Receiver<Option<Instant>>,
    pub(super) external: CancellationToken,
    pub(super) external_fired: bool,
}

impl Supervisor {
    pub(super) async fn run<T>(
        mut self,
        effect: impl Future<Output = AppResult<T>>,
        tx: oneshot::Sender<AppResult<T>>,
    ) {
        let (inner, op) = (self.settle.inner.clone(), self.settle.op.clone());
        // An operation aborted before its first poll (close or cancel racing the admission)
        // never enters its effect.
        let result = if !inner.is_active(&op) {
            Err(op.abort_error())
        } else {
            match self.guarded(AssertUnwindSafe(effect).catch_unwind()).await {
                Ok(result) => result,
                Err(_) => Err(AppError::internal(anyhow::anyhow!(
                    "feature operation panicked"
                ))),
            }
        };
        if let Err(e) = &result
            && !inner.effect_failed(&op, e.kind)
        {
            // A terminal failure stops sibling effects too; the drain below waits for them.
            op.token.cancel();
        }
        op.tracker.close();
        self.guarded(op.tracker.wait()).await;
        let result = result.and_then(|value| inner.succeed(&op).map(|()| value));
        // Free the resource before answering: an awaited `run` leaves its resource idle.
        drop(self);
        let _ = tx.send(result);
    }

    /// Polls `fut` while servicing the work deadline and the caller's cancellation token.
    async fn guarded<F: Future>(&mut self, fut: F) -> F::Output {
        let mut fut = pin!(fut);
        loop {
            let deadline = *self.deadline.borrow_and_update();
            tokio::select! {
                biased;
                out = &mut fut => return out,
                () = self.external.cancelled(), if !self.external_fired => {
                    self.external_fired = true;
                    self.settle.inner.abort(&self.settle.op, ErrorKind::Cancelled);
                }
                () = budget_end(deadline) => {
                    self.settle.inner.abort(&self.settle.op, ErrorKind::Timeout);
                }
                _ = self.deadline.changed() => {}
            }
        }
    }
}

/// Completes at the end of the work budget; never while it is paused or finished.
async fn budget_end(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Frees the resource when the supervisor ends, however it ends (panic, runtime shutdown).
pub(super) struct SettleOnDrop {
    pub(super) inner: Arc<Inner>,
    pub(super) op: Arc<Op>,
}

impl Drop for SettleOnDrop {
    fn drop(&mut self) {
        self.inner.settle(&self.op);
    }
}

/// Cancels the operation when the caller drops its `run` future before the outcome.
pub(super) struct CancelOnDrop<'a> {
    pub(super) inner: &'a Inner,
    pub(super) op: &'a Op,
    pub(super) armed: bool,
}

impl Drop for CancelOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.inner.abort(self.op, ErrorKind::Cancelled);
        }
    }
}
