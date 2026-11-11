//! Stage results mapped onto the per-stage progress statuses the UI shows.

use super::Reporter;
use crate::live::engine_probe::EngineStage;
use crate::live::model::{EgressStatus, HandshakeStatus, MediaStatus, ThroughputStatus};
use crate::live::runner::{ProgressStatus, StageId};
use crate::live_stages::TimedStatus;
use crate::live_stages::icmp::PmtuStatus;
use crate::live_stages::path::PathStatus;

pub(super) fn timed_progress(status: TimedStatus) -> ProgressStatus {
    match status {
        TimedStatus::Ok => ProgressStatus::Completed,
        TimedStatus::Skipped | TimedStatus::NotChecked => ProgressStatus::Skipped,
        TimedStatus::Error => ProgressStatus::Failed,
    }
}

pub(super) fn path_progress(status: PathStatus) -> ProgressStatus {
    match status {
        PathStatus::Ok => ProgressStatus::Completed,
        PathStatus::Skipped | PathStatus::NotChecked => ProgressStatus::Skipped,
        PathStatus::Error => ProgressStatus::Failed,
    }
}

pub(super) fn pmtu_progress(status: PmtuStatus) -> ProgressStatus {
    match status {
        PmtuStatus::Ok | PmtuStatus::LowerBound => ProgressStatus::Completed,
        PmtuStatus::Skipped | PmtuStatus::NotChecked => ProgressStatus::Skipped,
        PmtuStatus::BlackholeSuspected | PmtuStatus::IcmpBlocked => ProgressStatus::Failed,
    }
}

pub(super) fn engine_progress(stage: &EngineStage, report: &Reporter<'_>) {
    use StageId as S;
    let p = |ok: bool, skipped: bool| match (ok, skipped) {
        (true, _) => ProgressStatus::Completed,
        (_, true) => ProgressStatus::Skipped,
        _ => ProgressStatus::Failed,
    };
    let h = stage.handshake.status;
    report.set(
        S::Handshake,
        p(
            h == HandshakeStatus::Ok,
            matches!(h, HandshakeStatus::Skipped | HandshakeStatus::NotChecked),
        ),
    );
    let e = stage.egress.status;
    report.set(
        S::Egress,
        p(
            e == EgressStatus::Ok,
            matches!(e, EgressStatus::Skipped | EgressStatus::NotChecked),
        ),
    );
    let m = stage.media.status;
    report.set(
        S::MediaStream,
        p(
            m == MediaStatus::Ok,
            matches!(m, MediaStatus::Skipped | MediaStatus::NotChecked),
        ),
    );
    // An endpoint-only check has no throughput: skipped, not failed (B-36).
    let t = stage
        .throughput
        .as_ref()
        .map_or(ThroughputStatus::Skipped, |t| t.status);
    report.set(
        S::Throughput,
        p(
            t == ThroughputStatus::Ok,
            matches!(t, ThroughputStatus::Skipped | ThroughputStatus::NotChecked),
        ),
    );
}
