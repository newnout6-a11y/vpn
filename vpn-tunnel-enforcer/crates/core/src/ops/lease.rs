//! What an admitted effect holds: its cancellation signal, tracked waits, the user-wait budget
//! pause and the final commit.
use std::future::Future;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;
use vpnte_base::{AppError, AppResult, ErrorKind};

use super::state::{Inner, Op};
use super::{CorrelationId, OpId, OpMeta};

/// The admitted operation as its effect sees it. Clones share the same operation.
#[derive(Clone)]
pub struct Lease {
    inner: Arc<Inner>,
    op: Arc<Op>,
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Lease").field(&self.op.id).finish()
    }
}

impl Lease {
    pub(super) fn new(inner: Arc<Inner>, op: Arc<Op>) -> Self {
        Self { inner, op }
    }

    /// Id of the operation.
    pub fn id(&self) -> OpId {
        self.op.id
    }

    /// Correlation id of the user action the operation belongs to.
    pub fn correlation(&self) -> &CorrelationId {
        &self.op.correlation
    }

    /// Current metadata (a copy); `None` once the record left the bounded history.
    pub fn meta(&self) -> Option<OpMeta> {
        self.inner.meta(&self.op)
    }

    /// Cancelled when the operation is aborted or fails, and once it is over. Hand it (or a
    /// child token) to I/O the effect starts outside [`Lease::wait`].
    pub fn token(&self) -> &CancellationToken {
        &self.op.token
    }

    /// `Ok` while the operation may still act and publish; otherwise its abort error. Call it
    /// before publishing any result.
    pub fn assert_active(&self) -> AppResult<()> {
        if self.inner.is_active(&self.op) {
            Ok(())
        } else {
            Err(self.op.abort_error())
        }
    }

    /// Spawns `fut` at once on the operation's tracker (the resource stays busy until it settles,
    /// even if the returned future is dropped) and waits for it unless the operation ends first.
    /// Nothing is spawned when the operation is no longer active.
    pub fn wait<T: Send + 'static>(
        &self,
        fut: impl Future<Output = T> + Send + 'static,
    ) -> impl Future<Output = AppResult<T>> + Send + 'static {
        let spawned = self
            .assert_active()
            .map(|()| self.op.tracker.spawn(fut.instrument(self.op.span.clone())));
        let lease = self.clone();
        async move {
            let handle = spawned?;
            tokio::select! {
                biased;
                () = lease.op.token.cancelled() => Err(lease.op.abort_error()),
                joined = handle => {
                    let value = joined.map_err(AppError::internal)?;
                    lease.assert_active()?;
                    Ok(value)
                }
            }
        }
    }

    /// Like [`Lease::wait`] for a native dialog or picker: the work budget is paused while any
    /// user wait is open and resumes with what was left. Cancellation still ends it at once.
    pub fn wait_for_user<T: Send + 'static>(
        &self,
        fut: impl Future<Output = T> + Send + 'static,
    ) -> impl Future<Output = AppResult<T>> + Send + 'static {
        let waiting = self.inner.pause_budget(&self.op).map(|()| {
            let resume = ResumeOnDrop(self.clone());
            self.wait(async move {
                let _resume = resume;
                fut.await
            })
        });
        async move { waiting?.await }
    }

    /// Final synchronous persistence: runs `f` with cancellation and the deadline suspended and,
    /// when it succeeds, records success at once, so no late abort can relabel persisted work.
    /// `Conflict` while a tracked effect is pending. A failed `f` records nothing: its error is
    /// the effect's to return (an abort that landed during `f` applies then). A panic in `f`
    /// lowers the fence like a failure. Nothing may follow a successful commit.
    pub fn commit<T>(&self, f: impl FnOnce() -> AppResult<T>) -> AppResult<T> {
        self.inner.begin_commit(&self.op)?;
        let mut fence = CommitFence {
            lease: self,
            ok: false,
        };
        let result = f();
        fence.ok = result.is_ok();
        drop(fence);
        result
    }

    /// Cancels the operation (a coordinator ending its own lease early).
    pub fn cancel(&self) -> bool {
        self.inner.abort(&self.op, ErrorKind::Cancelled)
    }

    /// Ends the operation with a timeout (a coordinator whose shorter budget ran out).
    pub fn expire(&self) -> bool {
        self.inner.abort(&self.op, ErrorKind::Timeout)
    }
}

/// Ends one user wait when the waited future settles or is dropped.
struct ResumeOnDrop(Lease);

impl Drop for ResumeOnDrop {
    fn drop(&mut self) {
        self.0.inner.resume_budget(&self.0.op);
    }
}

/// Lowers the commit fence on every exit of [`Lease::commit`]. Without it a panic in the
/// closure, caught by an untracked caller, left the operation uncancellable.
struct CommitFence<'a> {
    lease: &'a Lease,
    ok: bool,
}

impl Drop for CommitFence<'_> {
    fn drop(&mut self) {
        self.lease.inner.end_commit(&self.lease.op, self.ok);
    }
}
