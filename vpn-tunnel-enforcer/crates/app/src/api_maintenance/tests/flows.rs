//! The actions over a throw-away backend and a fake tunnel: guards, refusals and the repair.
//! The repair runs over a fake host: no test scans or stops a real process.
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppResult, ErrorKind, Msg};
use vpnte_cleanup::legacy::{CleanupMarker, Context, Run};
use vpnte_core::store::Store;
use vpnte_tunnel::fsm::{Transition, TunnelSnapshot, TunnelState};
use vpnte_ui::maintenance::{
    KillSwitchState, MaintenanceApi, MaintenanceState, RepairStep, StepOutcome, StepState,
    TunnelPhase,
};
use vpnte_winnet::process::{OwnedProc, SweepReport};

use crate::api_maintenance::repair::{ENGINE_NAMES, filters_step};
use crate::api_maintenance::{MaintenanceService, RepairHost, Shared};
use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};

/// Records what the repair asked of the machine.
#[derive(Default)]
struct FakeHost {
    legacy_runs: AtomicUsize,
    sweeps: Mutex<Vec<(Vec<PathBuf>, Vec<String>)>>,
}

impl RepairHost for FakeHost {
    fn legacy(&self, _marker: &Store<CleanupMarker>, _ctx: &Context) -> AppResult<Run> {
        self.legacy_runs.fetch_add(1, Ordering::SeqCst);
        Ok(Run::NotDue)
    }

    fn sweep(&self, prefixes: &[PathBuf], names: &[&str]) -> AppResult<SweepReport> {
        let names = names.iter().map(|n| (*n).to_owned()).collect();
        self.sweeps.lock().push((prefixes.to_vec(), names));
        Ok(SweepReport {
            stopped: vec![OwnedProc {
                pid: 4242,
                path: prefixes[0].join("sing-box.exe"),
            }],
            ..SweepReport::default()
        })
    }
}

struct Rig {
    _dir: TempDir,
    tunnel: Arc<FakeTunnel>,
    host: Arc<FakeHost>,
    shared: Arc<Shared>,
    api: MaintenanceService,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.shared.backend.shutdown.cancel();
    }
}

fn rig(name: &str) -> Rig {
    let dir = TempDir::new(&format!("maint-{name}"));
    let tunnel = FakeTunnel::new(false);
    let host = Arc::new(FakeHost::default());
    let shared = Shared::start(
        backend(&dir, tunnel.clone()),
        host.clone(),
        None,
        None,
        crate::svc_tunnel::scope::RunScope::default(),
    );
    Rig {
        _dir: dir,
        tunnel,
        host,
        api: MaintenanceService(shared.clone()),
        shared,
    }
}

fn set_tunnel(tunnel: &FakeTunnel, state: TunnelState, transition: Option<Transition>) {
    tunnel.snapshot.send_replace(TunnelSnapshot {
        state,
        transition,
        ..TunnelSnapshot::default()
    });
}

fn refusal_key(result: AppResult<impl std::fmt::Debug>) -> (ErrorKind, String) {
    let err = result.expect_err("refused");
    (err.kind, err.user_msg().key.into_owned())
}

/// AT-00-007: every mutation is refused while the tunnel connects (nothing is changed).
#[tokio::test]
async fn mutations_wait_for_a_settled_tunnel() {
    let r = rig("busy");
    set_tunnel(
        &r.tunnel,
        TunnelState::Disconnected,
        Some(Transition::Connecting),
    );
    let busy = (ErrorKind::Conflict, "app.maintenance.tunnelBusy".to_owned());
    assert_eq!(refusal_key(r.api.repair().await), busy);
    assert_eq!(refusal_key(r.api.delete_legacy_data().await), busy);
    assert_eq!(
        refusal_key(r.api.set_aside_corrupt("profiles".into()).await),
        busy
    );
    assert_eq!(refusal_key(r.api.restart_capture().await), busy);
    assert_eq!(refusal_key(r.api.retry_secrets_import().await), busy);
    assert!(!r.shared.state.borrow().repair.running);
    assert!(r.host.sweeps.lock().is_empty());
}

/// The repair needs a tunnel without a session.
#[tokio::test]
async fn repair_is_refused_during_a_session() {
    let r = rig("session");
    set_tunnel(&r.tunnel, TunnelState::Connected, None);
    r.tunnel.open_session(1);
    assert_eq!(
        refusal_key(r.api.repair().await),
        (
            ErrorKind::Conflict,
            "app.maintenance.repair.disconnectFirst".to_owned()
        )
    );
    assert_eq!(r.host.legacy_runs.load(Ordering::SeqCst), 0);
}

/// NOADMIN §0 / AT-03-007: unelevated without the service, the two privileged steps are refused
/// with their calm reason (never "done"; the filters are the service's, the old version's
/// leftovers are not in this version) while our own stale engines are still swept, under the
/// resources dir only, sing-box first. The final view is the one published last.
#[tokio::test]
async fn unelevated_repair_refuses_privileged_steps_and_sweeps_engines() {
    let r = rig("repair");
    let view = r.api.repair().await.expect("repair ran");
    assert!(!view.running);
    let via_service = StepOutcome::blocked(Msg::new("app.maintenance.repair.viaService"));
    assert_eq!(
        view.steps[0],
        (RepairStep::Filters, StepState::Done(via_service))
    );
    let not_here = StepOutcome::blocked(Msg::new("app.maintenance.repair.notInVersion"));
    assert_eq!(
        view.steps[1],
        (RepairStep::Legacy, StepState::Done(not_here))
    );
    let StepState::Done(engines) = &view.steps[2].1 else {
        panic!("engines step not finished: {:?}", view.steps[2]);
    };
    assert!(engines.success);
    assert_eq!(
        engines.message,
        Some(Msg::new("winnet.process.sweep.stopped").arg("count", 1))
    );
    assert_eq!(
        r.host.legacy_runs.load(Ordering::SeqCst),
        0,
        "cleanup needs elevation"
    );
    let sweeps = r.host.sweeps.lock().clone();
    assert_eq!(sweeps.len(), 1);
    assert_eq!(sweeps[0].0, vec![r.shared.backend.dirs.resources.clone()]);
    assert_eq!(sweeps[0].1, ENGINE_NAMES.map(str::to_owned).to_vec());
    assert_eq!(r.shared.state.borrow().repair, view);
}

/// A key health check runs probe engines from the same folder: the sweep waits for it.
#[tokio::test]
async fn engine_sweep_waits_for_a_server_check() {
    use vpnte_core::ops::{FeatureKind, RunOpts};
    let r = rig("probes");
    let ops = r.shared.backend.ops.clone();
    let release = CancellationToken::new();
    let hold = release.clone();
    let check = tokio::spawn(async move {
        ops.run(
            FeatureKind::HealthCheck,
            RunOpts::default(),
            move |_lease| async move {
                hold.cancelled().await;
                Ok(())
            },
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !r
            .shared
            .backend
            .ops
            .is_busy(FeatureKind::HealthCheck.as_str())
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("health check registered");
    let view = r.api.repair().await.expect("repair ran");
    assert_eq!(
        view.steps[2].1,
        StepState::Done(StepOutcome::blocked(Msg::new(
            "app.maintenance.repair.checkRunning"
        )))
    );
    assert!(r.host.sweeps.lock().is_empty());
    release.cancel();
    let _ = check.await;
}

/// With our filters reachable, the strict level keeps its persistent filters; other levels release them
/// through the tunnel (whose refusal is reported as a refusal). ks-a: only an "Always" in force
/// (the helper service) is kept; a stored strict without it is released like the others.
#[tokio::test]
async fn strict_filters_are_kept_by_the_repair() {
    let tunnel = FakeTunnel::new(false);
    *tunnel.level.lock() = KillSwitchLevel::Strict;
    tunnel.always.store(true, Ordering::Relaxed);
    assert_eq!(
        filters_step(true, tunnel.as_ref()).await,
        StepOutcome::blocked(Msg::new("app.maintenance.repair.strictKept"))
    );
    tunnel.always.store(false, Ordering::Relaxed);
    assert_eq!(
        filters_step(true, tunnel.as_ref()).await,
        StepOutcome::blocked(Msg::new("app.base.needsAdmin")),
        "released through the tunnel (the fake has no WFP)"
    );
    *tunnel.level.lock() = KillSwitchLevel::Standard;
    assert!(
        filters_step(true, tunnel.as_ref()).await.blocked,
        "fake has no WFP"
    );
    // No filters reachable here (no service, unelevated): said as the service's, calmly.
    assert_eq!(
        filters_step(false, tunnel.as_ref()).await,
        StepOutcome::blocked(Msg::new("app.maintenance.repair.viaService"))
    );
}

/// Unelevated without the service, the read-back says the protection acts through the system
/// proxy (calm, not a failure) and is published.
#[tokio::test]
async fn unelevated_protection_read_back_is_published() {
    let r = rig("protection");
    let view = r.api.verify_protection().await.expect("read back");
    assert_eq!(view.kill_switch, KillSwitchState::ProxyOnly);
    assert_eq!(view.last_verified, None);
    assert_eq!(r.shared.state.borrow().protection.as_ref(), Some(&view));
}

/// Unavailable features answer honestly: capture is not in this version, the key re-import does
/// not exist, unknown documents are refused.
#[tokio::test]
async fn unavailable_actions_say_so() {
    let r = rig("unavailable");
    assert_eq!(
        refusal_key(r.api.restart_capture().await),
        (
            ErrorKind::Conflict,
            "app.maintenance.capture.unavailable".to_owned()
        )
    );
    assert_eq!(
        refusal_key(r.api.retry_secrets_import().await),
        (
            ErrorKind::Conflict,
            "app.maintenance.legacy.retryUnavailable".to_owned()
        )
    );
    assert_eq!(
        refusal_key(r.api.set_aside_corrupt("rules".into()).await),
        (
            ErrorKind::Validation,
            "app.maintenance.legacy.unknownStore".to_owned()
        )
    );
    // Packet capture is not in this version, elevated or not: said as such, never as «install
    // the service» or «run as administrator» (p-noadmin-ui).
    let state = r.shared.state.borrow().clone();
    assert_eq!(
        state.capture.warnings,
        vec![Msg::new("app.maintenance.capture.unavailable")]
    );
}

/// The projection follows the tunnel: a transition is published as busy, then off again.
#[tokio::test]
async fn tunnel_phase_is_projected() {
    let r = rig("phase");
    let mut rx = r.api.state();
    set_tunnel(
        &r.tunnel,
        TunnelState::Disconnected,
        Some(Transition::Connecting),
    );
    wait_phase(&mut rx, TunnelPhase::Busy).await;
    set_tunnel(&r.tunnel, TunnelState::Disconnected, None);
    wait_phase(&mut rx, TunnelPhase::Off).await;
}

async fn wait_phase(rx: &mut watch::Receiver<MaintenanceState>, want: TunnelPhase) {
    let reached = tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|s| s.tunnel == want))
        .await
        .expect("projected in time")
        .is_ok();
    assert!(reached, "state channel open");
}

/// Throw-away data and old-data folders under %TEMP%.
fn dirs(name: &str) -> (TempDir, vpnte_core::paths::DataDirs) {
    let dir = TempDir::new(&format!("maint-legacy-{name}"));
    let dirs =
        vpnte_core::paths::DataDirs::new(dir.0.join("data"), dir.0.join("old"), dir.0.join("res"));
    std::fs::create_dir_all(&dirs.root).expect("data dir");
    std::fs::create_dir_all(&dirs.legacy_electron).expect("old dir");
    (dir, dirs)
}

/// The old data directory goes only after the import finished, only when it is recognisably
/// the old app's folder, never when it overlaps the new data dir; a missing one is done.
#[test]
fn old_data_directory_is_removed_only_when_safe() {
    use crate::api_maintenance::legacy::remove_old_dir;
    let (_tmp, dirs) = dirs("guards");
    std::fs::write(dirs.legacy_electron.join("notes.txt"), "user file").expect("file");
    let pending = remove_old_dir(&dirs).expect_err("import not finished");
    assert_eq!(
        pending.user_msg().key,
        "app.maintenance.legacy.importPending"
    );
    std::fs::write(dirs.root.join("migration.json"), r#"{"locked":2}"#).expect("marker");
    let keys = remove_old_dir(&dirs).expect_err("keys still in the old files");
    assert_eq!(keys.user_msg().key, "app.maintenance.legacy.keysPending");
    std::fs::write(dirs.root.join("migration.json"), r#"{"locked":0}"#).expect("marker");
    let foreign = remove_old_dir(&dirs).expect_err("not the old app's folder");
    assert_eq!(foreign.kind, ErrorKind::Validation);
    assert!(
        dirs.legacy_electron.join("notes.txt").exists(),
        "nothing deleted"
    );

    std::fs::write(dirs.legacy_electron.join("Local State"), "{}").expect("key file");
    remove_old_dir(&dirs).expect("removed");
    assert!(!dirs.legacy_electron.exists());
    remove_old_dir(&dirs).expect("already gone is fine");

    let mut nested = dirs.clone();
    nested.legacy_electron = dirs.root.join("old");
    std::fs::create_dir_all(&nested.legacy_electron).expect("nested");
    std::fs::write(nested.legacy_electron.join("Local State"), "{}").expect("key file");
    let overlap = remove_old_dir(&nested).expect_err("inside the data dir");
    assert_eq!(overlap.kind, ErrorKind::Validation);
    let mut parent = dirs.clone();
    parent.legacy_electron = dirs.root.parent().expect("parent").to_path_buf();
    assert_eq!(
        remove_old_dir(&parent).expect_err("parent of data").kind,
        ErrorKind::Validation
    );
    // The new data folder in another spelling: never old data, even with a `settings.json`.
    std::fs::write(dirs.root.join("settings.json"), "{}").expect("new settings");
    let mut same = dirs.clone();
    same.legacy_electron = PathBuf::from(dirs.root.to_string_lossy().to_uppercase());
    assert_eq!(
        remove_old_dir(&same).expect_err("the new data dir").kind,
        ErrorKind::Validation
    );
    assert!(dirs.root.join("migration.json").exists());
    assert!(dirs.root.join("settings.json").exists());
}

/// A second export while the first one's Save dialog is still open is refused before a second
/// dialog opens (the busy check used to see only a running pack); the claim is released again.
#[tokio::test]
async fn a_second_export_is_refused_while_the_first_asks_where_to_save() {
    use crate::api_maintenance::export::ExportClaim;

    let r = rig("export-twice");
    let first = ExportClaim::take(r.shared.clone()).expect("the first export claims it");
    assert_eq!(
        refusal_key(r.api.export_diagnostics(CancellationToken::new()).await),
        (ErrorKind::Conflict, "core.ops.busy".to_owned())
    );
    drop(first);
    assert!(
        ExportClaim::take(r.shared.clone()).is_some(),
        "the claim is released with its holder"
    );
}

/// The claim goes with the detached pack: a page that goes away mid-export (its future dropped)
/// does not free it, since nothing else marks the export busy before the pack registers.
#[tokio::test]
async fn the_export_claim_lives_as_long_as_the_detached_pack() {
    use crate::api_maintenance::export::{ExportClaim, in_background};

    let r = rig("export-detached");
    let claim = ExportClaim::take(r.shared.clone()).expect("the export claims it");
    let (finish, finished) = tokio::sync::oneshot::channel::<()>();
    let mut page = Box::pin(in_background(claim, async move {
        let _ = finished.await;
        Ok(())
    }));
    // The page polls once (the pack task starts), then goes away.
    let _ = tokio::time::timeout(Duration::ZERO, &mut page).await;
    drop(page);
    assert!(
        ExportClaim::take(r.shared.clone()).is_none(),
        "the running pack still holds the claim"
    );
    let _ = finish.send(());
    for _ in 0..200 {
        if ExportClaim::take(r.shared.clone()).is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the claim outlived the pack");
}

/// Cancel works from the first moment of the pack, while the engines' `version` runs are still
/// gathered: the export ends Cancelled, writes nothing, and the page shows it idle again.
#[tokio::test]
async fn an_export_cancelled_while_gathering_writes_nothing() {
    let r = rig("export-cancel-early");
    let cancel = CancellationToken::new();
    cancel.cancel();
    let dest = r._dir.0.join("diag.zip");
    let err = crate::api_maintenance::export::pack(r.shared.clone(), dest.clone(), cancel)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
    assert!(!dest.exists(), "nothing written");
    assert!(!r.shared.state.borrow().export.running, "idle again");
}
