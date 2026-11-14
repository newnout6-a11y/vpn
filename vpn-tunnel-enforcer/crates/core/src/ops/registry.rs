//! The public registry: admission (single flight, pre-emption, deadlines), queries, shutdown.
use std::borrow::Cow;
use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{broadcast, oneshot, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument as _;
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::state::{Inner, Live, Op, State, busy, ceil_ms, closing, evict};
use super::supervisor::{CancelOnDrop, SettleOnDrop, Supervisor};
use super::{CorrelationId, FeatureKind, Lease, OpId, OpMeta, OpStatus, Owner, Source};

/// Longest accepted work budget: the old timer limit, 2^31 - 1 ms.
const MAX_TIMEOUT: Duration = Duration::from_millis(i32::MAX as u64);
/// Metadata events buffered per subscriber; a lagging subscriber resyncs with `list()`.
const EVENTS_CAP: usize = 256;

/// Options of [`OperationRegistry::run`].
#[derive(Debug, Clone)]
pub struct RunOpts {
    /// Who asks; a higher owner pre-empts a running lower one on the same resource.
    pub owner: Owner,
    /// Where the request came from (provenance only).
    pub source: Source,
    /// Single-flight key, default = the kind's wire name. Dynamic (`refresh:<groupId>`) or unique
    /// per call when same-kind operations may run side by side (`server-probe:<id>`).
    pub resource: Option<Cow<'static, str>>,
    /// Work budget, default = [`FeatureKind::deadline`]; must be 1 ms ..= 2^31 - 1 ms.
    pub timeout: Option<Duration>,
    /// Cancels the operation (Cancel button, unmounted component).
    pub cancel: Option<CancellationToken>,
    /// The user action this operation belongs to; default = a fresh id.
    pub correlation: Option<CorrelationId>,
}

impl Default for RunOpts {
    fn default() -> Self {
        Self {
            owner: Owner::Manual,
            source: Source::default(),
            resource: None,
            timeout: None,
            cancel: None,
            correlation: None,
        }
    }
}

/// Registry of long feature operations. Cheap to clone; all clones share one registry.
#[derive(Clone)]
pub struct OperationRegistry {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for OperationRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.inner.state.lock();
        f.debug_struct("OperationRegistry")
            .field("closed", &state.closed)
            .field("active", &state.active.len())
            .field("history", &state.history.len())
            .finish()
    }
}

/// Inputs of one admission attempt.
struct Request {
    kind: FeatureKind,
    owner: Owner,
    source: Source,
    resource: Cow<'static, str>,
    correlation: CorrelationId,
    expires: Instant,
    generation: u64,
}

enum Admission {
    Admitted(Arc<Op>),
    /// A lower-priority predecessor was cancelled: wait for its drain, then try again.
    Wait {
        drained: CancellationToken,
        closing: CancellationToken,
    },
}

impl Default for OperationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationRegistry {
    /// An empty registry that admits work.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::default(),
                events: broadcast::channel(EVENTS_CAP).0,
            }),
        }
    }

    /// Runs `f` as an operation of `kind` on its resource.
    ///
    /// Single flight per resource: a running operation of a lower owner is cancelled and the
    /// newcomer is admitted once it has drained, all within the newcomer's own deadline; an equal
    /// or higher owner, or a predecessor already ending, gives `Conflict`. The effect runs on its
    /// own task. The caller gets the abort error (cancel, timeout, pre-emption, close) at once,
    /// while the resource stays busy until every effect settled. Dropping the returned future
    /// cancels the operation.
    pub async fn run<T, F, Fut>(&self, kind: FeatureKind, opts: RunOpts, f: F) -> AppResult<T>
    where
        T: Send + 'static,
        F: FnOnce(Lease) -> Fut,
        Fut: Future<Output = AppResult<T>> + Send + 'static,
    {
        let timeout = opts.timeout.unwrap_or(kind.deadline());
        if timeout < Duration::from_millis(1) || timeout > MAX_TIMEOUT {
            return Err(AppError::validation(Msg::new("core.ops.invalidTimeout")));
        }
        let cancel = opts.cancel.unwrap_or_default();
        let req = Request {
            kind,
            owner: opts.owner,
            source: opts.source,
            resource: opts.resource.unwrap_or(Cow::Borrowed(kind.as_str())),
            correlation: opts.correlation.unwrap_or_default(),
            expires: Instant::now() + timeout,
            generation: self.inner.state.lock().generation,
        };
        let op = loop {
            let (drained, shutdown) = match self.try_admit(&req, &cancel)? {
                Admission::Admitted(op) => break op,
                Admission::Wait { drained, closing } => (drained, closing),
            };
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(AppError::cancelled()),
                () = shutdown.cancelled() => return Err(closing()),
                () = drained.cancelled() => {}
                () = tokio::time::sleep_until(req.expires) => return Err(AppError::timeout()),
            }
        };
        // Created before `f` runs: a panicking `f` must not strand the resource either.
        let settle = SettleOnDrop {
            inner: self.inner.clone(),
            op: op.clone(),
        };
        let effect = f(Lease::new(self.inner.clone(), op.clone()));
        let (tx, rx) = oneshot::channel();
        let supervisor = Supervisor {
            deadline: op.deadline.subscribe(),
            settle,
            external: cancel,
            external_fired: false,
        };
        tokio::spawn(supervisor.run(effect, tx).instrument(op.span.clone()));
        let mut guard = CancelOnDrop {
            inner: &self.inner,
            op: &op,
            armed: true,
        };
        // An abort wins: it is only possible while the outcome was still open, and the history
        // already records it.
        let result = tokio::select! {
            biased;
            () = op.aborted.cancelled() => Err(op.abort_error()),
            done = rx => done.unwrap_or_else(|_| {
                Err(AppError::internal(anyhow::anyhow!("operation supervisor ended without a result")))
            }),
        };
        guard.armed = false;
        result
    }

    fn try_admit(&self, req: &Request, cancel: &CancellationToken) -> AppResult<Admission> {
        let mut guard = self.inner.state.lock();
        let state = &mut *guard;
        if cancel.is_cancelled() {
            return Err(AppError::cancelled());
        }
        if state.closed || state.generation != req.generation {
            return Err(closing());
        }
        if let Some(prev) = state.active.get(req.resource.as_ref()) {
            if prev.meta.status != OpStatus::Running || req.owner <= prev.meta.owner {
                return Err(busy());
            }
            let prev = prev.op.clone();
            let wait = Admission::Wait {
                drained: prev.drained.clone(),
                closing: state.closing.clone(),
            };
            let aborted = self.inner.abort_locked(state, &prev, ErrorKind::Cancelled);
            drop(guard);
            if aborted {
                prev.token.cancel();
                prev.aborted.cancel();
            }
            return Ok(wait);
        }
        let now = Instant::now();
        let remaining = req.expires.saturating_duration_since(now);
        if remaining.is_zero() {
            return Err(AppError::timeout());
        }
        let id = OpId::next();
        let started_at = now_ms();
        let meta = OpMeta {
            id,
            correlation: req.correlation.clone(),
            owner: req.owner,
            source: req.source,
            kind: req.kind.into(),
            started_at,
            deadline: Some(started_at + ceil_ms(remaining)),
            status: OpStatus::Running,
            category: None,
        };
        // `corr` is the correlation slot of every log line (core-log, storage spec §6.5).
        let span = tracing::info_span!(
            "op", op = %id, kind = %req.kind, owner = ?req.owner, source = ?req.source,
            corr = %req.correlation
        );
        let op = Arc::new(Op {
            id,
            correlation: req.correlation.clone(),
            resource: req.resource.clone(),
            token: CancellationToken::new(),
            aborted: CancellationToken::new(),
            fault: OnceLock::new(),
            drained: CancellationToken::new(),
            tracker: TaskTracker::new(),
            deadline: watch::Sender::new(Some(req.expires)),
            span,
        });
        let State {
            active, history, ..
        } = state;
        let live = Live {
            op: op.clone(),
            meta,
            committing: false,
            committed: false,
            deferred: None,
            user_waits: 0,
            remaining,
            clock: now,
        };
        self.inner.publish(history, &live);
        active.insert(req.resource.clone(), live);
        evict(history, active);
        Ok(Admission::Admitted(op))
    }

    /// Cancels the live operation `id`; `false` when it is unknown, finished or committing (a
    /// cancel during a commit still applies if the commit fails).
    pub fn cancel(&self, id: OpId) -> bool {
        let op = self
            .inner
            .state
            .lock()
            .active
            .values()
            .find(|live| live.op.id == id)
            .map(|live| live.op.clone());
        op.is_some_and(|op| self.inner.abort(&op, ErrorKind::Cancelled))
    }

    /// Whether an operation (running, or ended but still draining its effects) holds `resource`.
    pub fn is_busy(&self, resource: &str) -> bool {
        self.inner.state.lock().active.contains_key(resource)
    }

    /// Recorded operations, oldest first: at most 1000, live ones are never evicted.
    pub fn list(&self) -> Vec<OpMeta> {
        self.inner.state.lock().history.values().cloned().collect()
    }

    /// Every metadata change (admission, deadline pause / resume, outcome) in order. A lagging
    /// receiver gets `Lagged` and should resync with [`OperationRegistry::list`].
    pub fn subscribe(&self) -> broadcast::Receiver<OpMeta> {
        self.inner.events.subscribe()
    }

    /// Refuses new work (including replacements already queued), cancels every operation and
    /// waits until all their effects settled. The refusal and the cancellation happen before the
    /// first await, so the wait may be bounded with `tokio::time::timeout`.
    pub async fn close(&self) {
        let (ops, closing) = {
            let mut state = self.inner.state.lock();
            state.closed = true;
            state.generation += 1;
            let ops: Vec<Arc<Op>> = state.active.values().map(|live| live.op.clone()).collect();
            (ops, state.closing.clone())
        };
        closing.cancel();
        for op in &ops {
            self.inner.abort(op, ErrorKind::Cancelled);
        }
        for op in ops {
            op.drained.cancelled().await;
        }
    }

    /// After a refused quit: admits work again once every old effect drained. `true` when the
    /// registry is open (it was never closed, or it reopened now).
    pub fn resume_admission(&self) -> bool {
        let mut state = self.inner.state.lock();
        if !state.closed {
            return true;
        }
        if !state.active.is_empty() {
            return false;
        }
        state.closing = CancellationToken::new();
        state.closed = false;
        true
    }
}
