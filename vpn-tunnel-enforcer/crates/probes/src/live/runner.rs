//! The job runner (B-23): one FIFO queue of check jobs — a single check or a batch of ≤ 12
//! profiles — executed one at a time by one task. A job has a cancel token, a `watch` of its
//! whole progress (per-stage state, so two transitions between UI polls cannot lose one) and a
//! one-shot outcome. Shutdown cancels everything and waits until the running job has wound
//! down (probe engine reaped).
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::check::{Budget, Reporter, Stages, run_check};
use super::env::LiveEnv;
use super::history::HistoryStore;
use super::model::LiveCheck;
use super::wire::Wire;
use super::{CheckMode, CheckRequest, CheckTarget, JobRequest, MAX_BATCH, ms};
use crate::live_stages::SystemDns;
use crate::live_stages::dns::DnsBackend;
use crate::live_stages::geo::GeoCache;

/// Job number, unique per service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct JobId(pub u64);

/// The 13 progress stages of a check (old vocabulary; the split-tunnel snapshot is not one).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StageId {
    Dns,
    Reachability,
    Tls,
    Http,
    Ports,
    Route,
    Infrastructure,
    Handshake,
    Egress,
    MediaStream,
    Throughput,
    Path,
    Pmtu,
}

impl StageId {
    /// All stages in display order.
    pub const ALL: [StageId; 13] = [
        StageId::Dns,
        StageId::Reachability,
        StageId::Tls,
        StageId::Http,
        StageId::Ports,
        StageId::Route,
        StageId::Infrastructure,
        StageId::Handshake,
        StageId::Egress,
        StageId::MediaStream,
        StageId::Throughput,
        StageId::Path,
        StageId::Pmtu,
    ];
}

/// State of one stage in the progress view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProgressStatus {
    Running,
    Completed,
    Failed,
    Skipped,
}

/// Where a job is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    #[default]
    Queued,
    Running,
    Done,
}

/// Where one check of a job is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemState {
    #[default]
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Progress of one check of a job (a batch has one per eligible profile).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemProgress {
    pub profile_id: Option<String>,
    pub state: ItemState,
    /// Per stage, indexed like [`StageId::ALL`]; `None` = not started.
    pub stages: [Option<ProgressStatus>; 13],
    /// Stages that ended (completed, failed or skipped).
    pub completed: u8,
    pub elapsed_ms: u64,
    /// Median throughput of the finished check (batch ranking).
    pub median_mbps: Option<f64>,
    pub error: Option<Msg>,
}

/// The whole job's progress (the `watch` value).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressSnapshot {
    pub state: JobState,
    pub items: Vec<ItemProgress>,
    /// Index of the running item.
    pub current: Option<usize>,
}

/// A batch profile that produced no check.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchError {
    pub profile_id: String,
    pub error: Msg,
}

/// Outcome of a batch (§3.21).
#[derive(Debug, Clone, PartialEq)]
pub struct BatchResult {
    pub mode: CheckMode,
    pub started_at: UnixMs,
    pub finished_at: UnixMs,
    pub cancelled: bool,
    pub results: Vec<LiveCheck>,
    pub errors: Vec<BatchError>,
}

/// What a job produced.
#[derive(Debug)]
pub enum JobOutcome {
    Single(AppResult<Box<LiveCheck>>),
    Batch(BatchResult),
}

/// The caller's side of a queued job. Dropping it does not cancel the job; cancel the token.
pub struct JobHandle {
    pub id: JobId,
    pub cancel: CancellationToken,
    pub progress: watch::Receiver<ProgressSnapshot>,
    pub done: oneshot::Receiver<JobOutcome>,
}

struct Job {
    request: JobRequest,
    cancel: CancellationToken,
    progress: watch::Sender<ProgressSnapshot>,
    done: oneshot::Sender<JobOutcome>,
}

struct Inner<B> {
    stages: Stages<B>,
    env: Arc<dyn LiveEnv>,
    history: Arc<HistoryStore>,
}

/// The live-check service: one per app.
pub struct LiveCheckService<B: DnsBackend + Send + 'static = SystemDns> {
    inner: Arc<Inner<B>>,
    queue: Mutex<Option<mpsc::UnboundedSender<Job>>>,
    runner: Mutex<Option<JoinHandle<()>>>,
    shutdown: CancellationToken,
    next: AtomicU64,
}

impl LiveCheckService<SystemDns> {
    /// The production service: Windows DNS client, geo cache, TLS against the Windows trust
    /// store. Needs a tokio runtime (spawns the runner task).
    pub fn new(env: Arc<dyn LiveEnv>, history: Arc<HistoryStore>) -> AppResult<Self> {
        let stages = Stages {
            dns: SystemDns::new()?,
            geo: GeoCache::new()?,
            wire: Wire::verified().map_err(AppError::internal)?,
            budget: Budget::default(),
        };
        Ok(Self::with_stages(stages, env, history))
    }
}

impl<B: DnsBackend + Send + 'static> LiveCheckService<B> {
    pub(crate) fn with_stages(
        stages: Stages<B>,
        env: Arc<dyn LiveEnv>,
        history: Arc<HistoryStore>,
    ) -> Self {
        let inner = Arc::new(Inner {
            stages,
            env,
            history,
        });
        let (tx, rx) = mpsc::unbounded_channel();
        let runner = tokio::spawn(run_jobs(inner.clone(), rx));
        LiveCheckService {
            inner,
            queue: Mutex::new(Some(tx)),
            runner: Mutex::new(Some(runner)),
            shutdown: CancellationToken::new(),
            next: AtomicU64::new(1),
        }
    }

    /// The history this service writes to.
    pub fn history(&self) -> &Arc<HistoryStore> {
        &self.inner.history
    }

    /// Queues a job behind the running one (FIFO). A batch must name 1..=12 profiles.
    pub fn submit(&self, request: JobRequest) -> AppResult<JobHandle> {
        if let JobRequest::Batch { profiles, .. } = &request
            && (profiles.is_empty() || profiles.len() > MAX_BATCH)
        {
            return Err(AppError::validation(
                Msg::new("probes.live.batch.size").arg("max", MAX_BATCH),
            ));
        }
        let queue = self.queue.lock();
        let Some(tx) = queue.as_ref() else {
            return Err(AppError::conflict(Msg::new("probes.live.shuttingDown")));
        };
        let id = JobId(self.next.fetch_add(1, Ordering::Relaxed));
        let cancel = self.shutdown.child_token();
        let (progress, rx) = watch::channel(ProgressSnapshot::default());
        let (done_tx, done) = oneshot::channel();
        let job = Job {
            request,
            cancel: cancel.clone(),
            progress,
            done: done_tx,
        };
        tx.send(job)
            .map_err(|_| AppError::conflict(Msg::new("probes.live.shuttingDown")))?;
        Ok(JobHandle {
            id,
            cancel,
            progress: rx,
            done,
        })
    }

    /// Cancels every job (queued ones end at once as cancelled) and waits for the runner, so no
    /// probe engine or socket outlives the service.
    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        self.queue.lock().take();
        let runner = self.runner.lock().take();
        if let Some(runner) = runner
            && let Err(err) = runner.await
        {
            tracing::warn!(error = %err, "live check runner ended abnormally");
        }
    }
}

async fn run_jobs<B: DnsBackend + Send + 'static>(
    inner: Arc<Inner<B>>,
    mut rx: mpsc::UnboundedReceiver<Job>,
) {
    while let Some(job) = rx.recv().await {
        job.progress.send_modify(|p| p.state = JobState::Running);
        let outcome = match &job.request {
            JobRequest::Single(req) => {
                JobOutcome::Single(run_single(&inner, req, &job).await.map(Box::new))
            }
            JobRequest::Batch {
                profiles,
                mode,
                throughput,
            } => JobOutcome::Batch(run_batch(&inner, profiles, *mode, *throughput, &job).await),
        };
        let cancelled = job.cancel.is_cancelled();
        job.progress.send_modify(|p| {
            p.state = JobState::Done;
            p.current = None;
            if cancelled {
                // Stage events stop at the cancel; the items it cut short end as cancelled.
                for item in &mut p.items {
                    if matches!(item.state, ItemState::Pending | ItemState::Running) {
                        item.state = ItemState::Cancelled;
                    }
                }
            }
        });
        // The caller may have stopped waiting: nothing to do then.
        let _ = job.done.send(outcome);
    }
}

/// Records the stage events of item `index` (the check's `Reporter` stops after a cancel).
fn item_sink(
    progress: &watch::Sender<ProgressSnapshot>,
    index: usize,
    start: Instant,
) -> impl Fn(StageId, ProgressStatus) + Send + Sync + '_ {
    move |stage, status| {
        progress.send_modify(|p| {
            let Some(item) = p.items.get_mut(index) else {
                return;
            };
            item.stages[stage as usize] = Some(status);
            item.completed = item
                .stages
                .iter()
                .filter(|s| s.is_some_and(|s| s != ProgressStatus::Running))
                .count() as u8;
            item.elapsed_ms = ms(start.elapsed());
        });
    }
}

/// Runs the check of item `index` with its progress wired up.
async fn check_item<B: DnsBackend + Send + 'static>(
    inner: &Inner<B>,
    req: &CheckRequest,
    job: &Job,
    index: usize,
) -> AppResult<LiveCheck> {
    let start = Instant::now();
    job.progress.send_modify(|p| {
        p.current = Some(index);
        if let Some(item) = p.items.get_mut(index) {
            item.state = ItemState::Running;
        }
    });
    let sink = item_sink(&job.progress, index, start);
    let report = Reporter {
        cancel: &job.cancel,
        sink: &sink,
    };
    let result = run_check(
        &inner.stages,
        inner.env.as_ref(),
        &inner.history,
        req,
        &job.cancel,
        &report,
    )
    .await;
    if !job.cancel.is_cancelled() || result.is_ok() {
        job.progress.send_modify(|p| {
            if let Some(item) = p.items.get_mut(index) {
                match &result {
                    Ok(check) => {
                        item.state = ItemState::Completed;
                        item.median_mbps = check.throughput.as_ref().and_then(|t| t.median_mbps);
                    }
                    Err(err) => {
                        item.state = ItemState::Failed;
                        item.error = Some(err.user_msg());
                    }
                }
            }
        });
    }
    result
}

async fn run_single<B: DnsBackend + Send + 'static>(
    inner: &Inner<B>,
    req: &CheckRequest,
    job: &Job,
) -> AppResult<LiveCheck> {
    let profile_id = match &req.target {
        CheckTarget::Profile(id) => Some(id.clone()),
        CheckTarget::Endpoint { .. } => None,
    };
    job.progress.send_modify(|p| {
        p.items = vec![ItemProgress {
            profile_id,
            ..ItemProgress::default()
        }]
    });
    let result = check_item(inner, req, job, 0).await;
    if let Err(err) = &result {
        match err.kind {
            ErrorKind::Cancelled | ErrorKind::Timeout => {
                tracing::info!(kind = ?err.kind, "live check ended early");
            }
            _ => tracing::warn!(error = %err, "live check failed"),
        }
    }
    result
}

/// Sequential checks of the eligible profiles (§3.21): checks through engines share the
/// uplink, so running them together would make the ranking noisy.
async fn run_batch<B: DnsBackend + Send + 'static>(
    inner: &Inner<B>,
    profiles: &[String],
    mode: CheckMode,
    throughput: bool,
    job: &Job,
) -> BatchResult {
    let started_at = now_ms();
    let mut ids: Vec<&String> = Vec::new();
    for id in profiles {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    let (eligible, refused): (Vec<&String>, Vec<&String>) = ids
        .into_iter()
        .partition(|id| inner.env.profile(id).is_some_and(|p| p.eligible));
    job.progress.send_modify(|p| {
        p.items = eligible
            .iter()
            .map(|id| ItemProgress {
                profile_id: Some((*id).clone()),
                ..ItemProgress::default()
            })
            .collect();
    });
    let (mut results, mut errors) = (Vec::new(), Vec::new());
    for (index, id) in eligible.iter().enumerate() {
        if job.cancel.is_cancelled() {
            break;
        }
        let req = CheckRequest {
            target: CheckTarget::Profile((*id).clone()),
            mode,
            throughput,
        };
        match check_item(inner, &req, job, index).await {
            // A check that reached the history is kept even when a cancel raced its write.
            Ok(check) => results.push(check),
            Err(_) if job.cancel.is_cancelled() => break,
            Err(err) => errors.push(BatchError {
                profile_id: (*id).clone(),
                error: err.user_msg(),
            }),
        }
    }
    errors.extend(refused.into_iter().map(|id| BatchError {
        profile_id: id.clone(),
        error: Msg::new("probes.live.batch.notEligible"),
    }));
    BatchResult {
        mode,
        started_at,
        finished_at: now_ms(),
        cancelled: job.cancel.is_cancelled(),
        results,
        errors,
    }
}
