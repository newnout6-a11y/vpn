//! «Починить»: the auto-repair as one backend task (leaving the page never stops it between two
//! steps). Steps run in order, each independent of the others' outcome:
//! 1. our WFP filters removed outside a session (elevated only; strict filters are kept),
//! 2. the old version's network cleanup run again (elevated only),
//! 3. engines of ours that no session owns stopped (own processes: no elevation needed).
//!
//! A step this process may not run is `blocked` with the reason, never reported as done.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_cleanup::legacy::{self, CleanupMarker, CleanupReport, Context, Mode, Run};
use vpnte_core::ops::{OpKind, OpStatus};
use vpnte_core::store::Store;
use vpnte_ui::maintenance::{RepairStep, RepairView, StepOutcome, StepState, TunnelPhase};
use vpnte_winnet::process::SweepReport;
use vpnte_winnet::wfp::{KillSwitchState as WfpState, RemoveReport};

use super::{Shared, project, refused};
use crate::services::{Engines, KillSwitchStatus, TunnelOps};
use crate::support::{blocking, detached};

/// Engines the sweep stops, in stop order (the TUN consumer first, then its upstreams).
pub(crate) const ENGINE_NAMES: [&str; 2] = ["sing-box.exe", "xray.exe"];

/// What the repair does to the machine. The app uses [`WindowsHost`]; tests use fakes, so no
/// test ever scans or stops a real process.
pub(crate) trait RepairHost: Send + Sync + 'static {
    /// `vpnte_cleanup::legacy::run` in "run again" mode (blocking).
    fn legacy(&self, marker: &Store<CleanupMarker>, ctx: &Context) -> AppResult<Run>;
    /// `vpnte_winnet::process::sweep_orphans` over `prefixes` (blocking, ≤ 3 s per name).
    fn sweep(&self, prefixes: &[PathBuf], names: &[&str]) -> AppResult<SweepReport>;
}

/// The real machine.
pub(crate) struct WindowsHost;

impl RepairHost for WindowsHost {
    /// Refused while the old per-machine version is still installed: its boot-recovery task and
    /// firewall rules are its working parts then, not leftovers.
    fn legacy(&self, marker: &Store<CleanupMarker>, ctx: &Context) -> AppResult<Run> {
        if crate::setup::system::machine_wide_installed() {
            return Err(refused("app.maintenance.repair.legacyInstalled"));
        }
        legacy::run(marker, ctx, Mode::Again)
    }

    fn sweep(&self, prefixes: &[PathBuf], names: &[&str]) -> AppResult<SweepReport> {
        Ok(vpnte_winnet::process::sweep_orphans(prefixes, names)?)
    }
}

/// Runs the repair in its own task and returns the view published last. Refused unless the
/// tunnel is idle, and while another repair runs.
pub(crate) async fn run(shared: Arc<Shared>) -> AppResult<RepairView> {
    detached(async move {
        idle(&shared)?;
        let started = shared.state.send_if_modified(|s| {
            if s.repair.running {
                return false;
            }
            s.repair = RepairView {
                running: true,
                steps: RepairStep::ALL
                    .iter()
                    .map(|step| (*step, StepState::Pending))
                    .collect(),
            };
            true
        });
        if !started {
            return Err(refused("app.maintenance.repair.running"));
        }
        tracing::warn!("maintenance: auto-repair started");
        for step in RepairStep::ALL {
            set_step(&shared, step, StepState::Running);
            let outcome = match idle(&shared) {
                // A session started meanwhile: the remaining steps are refused, not failed.
                Err(err) => StepOutcome::blocked(err.user_msg()),
                Ok(()) => run_step(&shared, step).await,
            };
            tracing::info!(
                step = step.id(),
                success = outcome.success,
                blocked = outcome.blocked,
                "maintenance: repair step finished"
            );
            set_step(&shared, step, StepState::Done(outcome));
        }
        shared.state.send_modify(|s| s.repair.running = false);
        shared.touch();
        Ok(shared.state.borrow().repair.clone())
    })
    .await
}

/// The repair needs a tunnel without a session and without a transition.
fn idle(shared: &Shared) -> AppResult<()> {
    match project::live_phase(shared) {
        TunnelPhase::Off => Ok(()),
        TunnelPhase::Busy => Err(refused("app.maintenance.tunnelBusy")),
        TunnelPhase::On => Err(refused("app.maintenance.repair.disconnectFirst")),
    }
}

fn set_step(shared: &Shared, step: RepairStep, state: StepState) {
    shared.state.send_modify(|s| {
        if let Some((_, slot)) = s.repair.steps.iter_mut().find(|(id, _)| *id == step) {
            *slot = state;
        }
    });
}

async fn run_step(shared: &Arc<Shared>, step: RepairStep) -> StepOutcome {
    match step {
        RepairStep::Filters => filters(shared).await,
        RepairStep::Legacy => legacy_again(shared).await,
        RepairStep::Engines => engines(shared).await,
    }
}

/// Step 1: our filters. Strict keeps its persistent filters (the reset would also switch the
/// level to off: a downgrade nobody asked for); the release itself holds the tunnel's lane.
async fn filters(shared: &Arc<Shared>) -> StepOutcome {
    match shared.backend.tunnel() {
        Ok(tunnel) => filters_step(shared.backend.elevated, tunnel.as_ref()).await,
        Err(err) => StepOutcome::failed(err.user_msg()),
    }
}

pub(crate) async fn filters_step(elevated: bool, tunnel: &dyn TunnelOps) -> StepOutcome {
    if !elevated {
        return StepOutcome::blocked(project::needs_admin_msg());
    }
    let level = tunnel.kill_switch().await.settings.level;
    if level.effective(tunnel.always_available()) == KillSwitchLevel::Strict {
        return StepOutcome::blocked(Msg::new("app.maintenance.repair.strictKept"));
    }
    filters_outcome(tunnel.release_kill_switch().await)
}

/// A refusal (no WFP here, a session meanwhile) is `blocked`; any other error `failed`.
pub(crate) fn filters_outcome(result: AppResult<RemoveReport>) -> StepOutcome {
    match result {
        Ok(r) if r.filters == 0 && !r.sublayer && !r.provider => StepOutcome::done(Vec::new()),
        Ok(r) => StepOutcome {
            message: Some(
                Msg::new("app.maintenance.repair.filtersRemoved").arg("count", r.filters),
            ),
            ..StepOutcome::done(Vec::new())
        },
        Err(err) => refusal_or_failure(&err),
    }
}

fn refusal_or_failure(err: &AppError) -> StepOutcome {
    match err.kind {
        ErrorKind::Permission | ErrorKind::Conflict => StepOutcome::blocked(err.user_msg()),
        _ => StepOutcome::failed(err.user_msg()),
    }
}

/// Step 2: the old version's leftovers, removed again ("run again" ignores the marker).
async fn legacy_again(shared: &Arc<Shared>) -> StepOutcome {
    if !shared.backend.elevated {
        return StepOutcome::blocked(project::needs_admin_msg());
    }
    let ctx = match shared.backend.tunnel() {
        Ok(tunnel) => {
            let always = tunnel.always_available();
            cleanup_context(shared, &tunnel.kill_switch().await, always)
        }
        Err(err) => return StepOutcome::failed(err.user_msg()),
    };
    let (host, marker) = (shared.host.clone(), shared.backend.cleanup.clone());
    legacy_outcome(blocking(move || host.legacy(&marker, &ctx)).await)
}

/// `strict_ready`: the persistent strict set is in place, so the old blocks may go (spec
/// firewall-recovery §6.6 step 0); for the other levels it does not matter.
/// `always`: "Always" is in force here; otherwise a stored `strict` counts as `standard`.
fn cleanup_context(shared: &Shared, status: &KillSwitchStatus, always: bool) -> Context {
    let level = status.settings.level.effective(always);
    let strict_ready = status.wfp.as_ref().is_some_and(|w| {
        w.kill_switch != WfpState::Failed && w.persistent_filters.unwrap_or(0) > 0
    });
    Context {
        resources: shared.backend.dirs.resources.clone(),
        level,
        strict_ready: level != KillSwitchLevel::Strict || strict_ready,
    }
}

pub(crate) fn legacy_outcome(result: AppResult<Run>) -> StepOutcome {
    match result {
        Ok(Run::Finished(report)) => cleanup_outcome(&report),
        Ok(Run::NotDue) => StepOutcome::done(Vec::new()),
        Ok(Run::Deferred) => {
            StepOutcome::blocked(Msg::new("app.maintenance.repair.legacyDeferred"))
        }
        Err(err) => refusal_or_failure(&err),
    }
}

fn cleanup_outcome(report: &CleanupReport) -> StepOutcome {
    let changed = report.steps.iter().filter(|r| r.changed).count();
    let failed = report
        .steps
        .iter()
        .filter(|r| r.outcome == legacy::Outcome::Failed)
        .count();
    let summary = Msg::new("cleanup.legacy.notice.summary")
        .arg("changed", changed)
        .arg("failed", failed);
    if report.failed() {
        StepOutcome::failed(summary)
    } else if changed == 0 {
        StepOutcome::done(Vec::new())
    } else {
        StepOutcome {
            message: Some(summary),
            // The old firewall was reset: worth a look even though nothing failed.
            warning: report.firewall_reset || report.firewall_allow_all,
            ..StepOutcome::done(Vec::new())
        }
    }
}

/// Step 3: engines under the folders our engines run from that no session owns. Refused while
/// a server check runs its own probe engines (they live there too); the repair already
/// requires a tunnel without a session, so no session engine is running.
async fn engines(shared: &Arc<Shared>) -> StepOutcome {
    if probes_running(shared) {
        return StepOutcome::blocked(Msg::new("app.maintenance.repair.checkRunning"));
    }
    // The app start's folders and the live ones: after an engine update either may hold one.
    let mut dirs = engine_dirs(&shared.backend.engines);
    dirs.extend(engine_dirs(&shared.backend.live_engines()));
    dirs.sort();
    dirs.dedup();
    let host = shared.host.clone();
    engines_outcome(blocking(move || host.sweep(&dirs, &ENGINE_NAMES)).await)
}

/// The folders of the bundled engines, spelled as they are launched (canonical when present):
/// the sweep matches image paths, and another spelling of the same folder would match nothing.
pub(crate) fn engine_dirs(engines: &Engines) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = [&engines.singbox, &engines.xray]
        .into_iter()
        .filter_map(|exe| exe.parent().map(Path::to_path_buf))
        .collect();
    dirs.dedup();
    dirs
}

/// A key health check of the servers page runs temporary probe engines.
fn probes_running(shared: &Shared) -> bool {
    shared
        .backend
        .ops
        .list()
        .iter()
        .any(|op| op.status == OpStatus::Running && op.kind == OpKind::HealthCheck)
}

/// Survivors fail the step; candidates of unknown ownership are a warning (never "clean").
pub(crate) fn engines_outcome(result: AppResult<SweepReport>) -> StepOutcome {
    let report = match result {
        Ok(report) => report,
        Err(err) => return StepOutcome::failed(err.user_msg()),
    };
    let Some(summary) = report.summary() else {
        return StepOutcome::done(Vec::new());
    };
    if !report.survived.is_empty() {
        return StepOutcome::failed(summary);
    }
    StepOutcome {
        message: Some(summary),
        warning: !report.unknown.is_empty(),
        ..StepOutcome::done(Vec::new())
    }
}
