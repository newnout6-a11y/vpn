//! The live server check of the Servers page over the runner the tunnel hosts
//! (`TunnelOps::live_checks`): one check with its stage progress, the history, and the batch
//! comparison with its soft stop (the server being checked finishes, then the run ends: B-2). A
//! check whose call is dropped is cancelled, and the probes never store a cancelled check.
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use vpnte_base::i18n::Lang;
use vpnte_base::{AppError, AppResult};
use vpnte_probes::live::{
    CheckMode, CheckRequest, CheckTarget, HISTORY_PER_TARGET, ItemProgress, ItemState, JobOutcome,
    JobRequest, LiveCheckService, ProgressSnapshot, ProgressStatus, StageId,
};
use vpnte_ui::servers as ui;

use super::live_view::{self, ms};

#[cfg(test)]
mod tests;

/// Progress denominator: every stage reports a final status, skipped ones included.
const STAGES: u8 = StageId::ALL.len() as u8;

/// One check of server `id`; stage events go to `tx` as they land. `cancel` (the page dropped
/// the call) cancels the job.
pub(super) async fn single(
    service: Arc<LiveCheckService>,
    id: String,
    mode: ui::LiveMode,
    lang: Lang,
    tx: mpsc::UnboundedSender<ui::LiveProgress>,
    cancel: CancellationToken,
) -> AppResult<ui::LiveCheck> {
    let mode = match mode {
        ui::LiveMode::Basic => CheckMode::Basic,
        // The page's extended check includes the short throughput test.
        ui::LiveMode::Extended => CheckMode::Extended,
    };
    let handle = service.submit(JobRequest::Single(CheckRequest {
        target: CheckTarget::Profile(id),
        mode,
        throughput: mode.extended(),
    }))?;
    let (job, mut progress, mut done) = (handle.cancel, handle.progress, handle.done);
    let mut seen = [None; StageId::ALL.len()];
    loop {
        tokio::select! {
            outcome = &mut done => return single_outcome(outcome, lang),
            () = cancel.cancelled() => {
                job.cancel();
                return Err(AppError::cancelled());
            }
            changed = progress.changed() => {
                // The runner let go of the job: only its outcome is left.
                if changed.is_err() {
                    break;
                }
                if let Some(item) = progress.borrow_and_update().items.first() {
                    send_stages(item, &mut seen, &tx);
                }
            }
        }
    }
    tokio::select! {
        outcome = done => single_outcome(outcome, lang),
        () = cancel.cancelled() => {
            job.cancel();
            Err(AppError::cancelled())
        }
    }
}

/// Stored receipts of server `id`, newest first.
pub(super) fn history(service: &LiveCheckService, id: &str, lang: Lang) -> Vec<ui::LiveCheck> {
    service
        .history()
        .list(Some(id), None)
        .iter()
        .take(HISTORY_PER_TARGET)
        .map(|c| live_view::check(c, lang))
        .collect()
}

/// The batch comparison of `ids` (basic checks with throughput, the main ranking signal: B-27).
/// `stop` lets the server being checked finish, then ends the run with the receipts so far;
/// `cancel` (the page dropped the call) ends it at once.
pub(super) async fn batch(
    service: Arc<LiveCheckService>,
    ids: Vec<String>,
    stop: CancellationToken,
    lang: Lang,
    tx: mpsc::UnboundedSender<ui::BatchProgress>,
    cancel: CancellationToken,
) -> AppResult<ui::BatchResult> {
    let handle = service.submit(JobRequest::Batch {
        profiles: ids,
        mode: CheckMode::Basic,
        throughput: true,
    })?;
    let (job, mut progress, mut done) = (handle.cancel, handle.progress, handle.done);
    let mut sent: Vec<Option<Sent>> = Vec::new();
    // Soft stop: the item that was running when the stop came (`None`: nothing was running).
    let mut stopping: Option<Option<usize>> = None;
    loop {
        tokio::select! {
            outcome = &mut done => return batch_outcome(outcome, lang),
            () = cancel.cancelled() => {
                job.cancel();
                return Err(AppError::cancelled());
            }
            () = stop.cancelled(), if stopping.is_none() => {
                stopping = Some(progress.borrow().current);
            }
            changed = progress.changed() => {
                if changed.is_err() {
                    break;
                }
                send_items(&progress.borrow_and_update(), &mut sent, &tx);
            }
        }
        if let Some(at) = stopping
            && finished(&progress.borrow(), at)
        {
            job.cancel();
        }
    }
    tokio::select! {
        outcome = done => batch_outcome(outcome, lang),
        () = cancel.cancelled() => {
            job.cancel();
            Err(AppError::cancelled())
        }
    }
}

/// What was last sent for one batch item: status, running stage, median throughput.
type Sent = (ui::ProgressStatus, Option<ui::Stage>, Option<f64>);

/// The soft stop is due: the item running at the stop ended, or nothing was running.
fn finished(snap: &ProgressSnapshot, at: Option<usize>) -> bool {
    let Some(i) = at else {
        return true;
    };
    snap.current != Some(i)
        || snap
            .items
            .get(i)
            .is_none_or(|item| !matches!(item.state, ItemState::Pending | ItemState::Running))
}

/// One event per stage whose status changed since the last snapshot.
fn send_stages(
    item: &ItemProgress,
    seen: &mut [Option<ProgressStatus>; StageId::ALL.len()],
    tx: &mpsc::UnboundedSender<ui::LiveProgress>,
) {
    for id in StageId::ALL {
        let i = id as usize;
        let (Some(now), true) = (item.stages[i], item.stages[i] != seen[i]) else {
            continue;
        };
        seen[i] = Some(now);
        let _ = tx.send(ui::LiveProgress {
            stage: stage(id),
            status: status(now),
            completed: item.completed,
            total: STAGES,
            elapsed_ms: ms(item.elapsed_ms),
        });
    }
}

/// One event per batch item whose status, running stage or throughput changed.
fn send_items(
    snap: &ProgressSnapshot,
    sent: &mut Vec<Option<Sent>>,
    tx: &mpsc::UnboundedSender<ui::BatchProgress>,
) {
    sent.resize(snap.items.len(), None);
    let total = u16::try_from(snap.items.len()).unwrap_or(u16::MAX);
    for (index, item) in snap.items.iter().enumerate() {
        let status = match item.state {
            ItemState::Pending => continue,
            ItemState::Running => ui::ProgressStatus::Running,
            ItemState::Completed => ui::ProgressStatus::Completed,
            ItemState::Failed => ui::ProgressStatus::Failed,
            ItemState::Cancelled => ui::ProgressStatus::Skipped,
        };
        // A cut-short item may keep a stage marked running: only a running item has one.
        let running = StageId::ALL
            .into_iter()
            .filter(|_| status == ui::ProgressStatus::Running)
            .find(|&id| item.stages[id as usize] == Some(ProgressStatus::Running))
            .map(stage);
        let now = (status, running, item.median_mbps);
        if sent[index] == Some(now) {
            continue;
        }
        sent[index] = Some(now);
        let _ = tx.send(ui::BatchProgress {
            profile_id: item.profile_id.clone().unwrap_or_default(),
            index: u16::try_from(index).unwrap_or(u16::MAX),
            total,
            status,
            stage: running,
            median_mbps: item.median_mbps,
        });
    }
}

fn single_outcome(
    outcome: Result<JobOutcome, oneshot::error::RecvError>,
    lang: Lang,
) -> AppResult<ui::LiveCheck> {
    match outcome {
        Ok(JobOutcome::Single(result)) => result.map(|c| live_view::check(&c, lang)),
        Ok(JobOutcome::Batch(_)) => Err(AppError::internal(anyhow::anyhow!(
            "a single live check answered with a batch"
        ))),
        // The runner shut down before the job ran.
        Err(_) => Err(AppError::cancelled()),
    }
}

fn batch_outcome(
    outcome: Result<JobOutcome, oneshot::error::RecvError>,
    lang: Lang,
) -> AppResult<ui::BatchResult> {
    match outcome {
        Ok(JobOutcome::Batch(r)) => Ok(ui::BatchResult {
            cancelled: r.cancelled,
            results: r
                .results
                .iter()
                .map(|c| live_view::check(c, lang))
                .collect(),
            errors: r
                .errors
                .into_iter()
                .map(|e| (e.profile_id, e.error))
                .collect(),
        }),
        Ok(JobOutcome::Single(_)) => Err(AppError::internal(anyhow::anyhow!(
            "a live batch answered with a single check"
        ))),
        Err(_) => Err(AppError::cancelled()),
    }
}

fn status(s: ProgressStatus) -> ui::ProgressStatus {
    match s {
        ProgressStatus::Running => ui::ProgressStatus::Running,
        ProgressStatus::Completed => ui::ProgressStatus::Completed,
        ProgressStatus::Failed => ui::ProgressStatus::Failed,
        ProgressStatus::Skipped => ui::ProgressStatus::Skipped,
    }
}

fn stage(id: StageId) -> ui::Stage {
    match id {
        StageId::Dns => ui::Stage::Dns,
        StageId::Reachability => ui::Stage::Reachability,
        StageId::Tls => ui::Stage::Tls,
        StageId::Http => ui::Stage::Http,
        StageId::Ports => ui::Stage::Ports,
        StageId::Route => ui::Stage::Route,
        StageId::Infrastructure => ui::Stage::Infrastructure,
        StageId::Handshake => ui::Stage::Handshake,
        StageId::Egress => ui::Stage::Egress,
        StageId::MediaStream => ui::Stage::MediaStream,
        StageId::Throughput => ui::Stage::Throughput,
        StageId::Path => ui::Stage::Path,
        StageId::Pmtu => ui::Stage::Pmtu,
    }
}
