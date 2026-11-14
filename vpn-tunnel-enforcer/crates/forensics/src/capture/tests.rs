//! Lifecycle vectors of §7.5 (trafficForensics.test.ts, trafficForensicsStopNative.test.ts,
//! diagnosticsPreflight.test.ts) against a fake pktmon / ETW.
use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use futures_util::future::{BoxFuture, ready};
use parking_lot::Mutex;
use tokio::sync::{Semaphore, watch};

use super::*;
use crate::etw::{DigestSnapshot, EtwStopStats, LossStats};
use crate::test_support::TempDir;

#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<String>>,
    /// Exit codes of successive `pktmon stop` runs (0 when empty).
    stop_codes: Mutex<VecDeque<i32>>,
    start_code: AtomicU32,
    etl_released: AtomicBool,
    etw_fails: AtomicBool,
    etw_alive: Arc<AtomicBool>,
    reclaim: AtomicBool,
    /// When set, `pktmon stop` waits for a permit.
    gate: Mutex<Option<Arc<Semaphore>>>,
    /// When set, the start snapshot turns the manifest path into a directory: later writes fail.
    break_manifest: AtomicBool,
}

impl Fake {
    fn calls(&self, verb: &str) -> usize {
        self.calls.lock().iter().filter(|c| *c == verb).count()
    }
}

struct FakeEtw {
    alive: Arc<AtomicBool>,
}

impl Etw for FakeEtw {
    fn digest(&self) -> DigestSnapshot {
        DigestSnapshot {
            events: 2,
            data_events: 1,
            engine: Some(crate::etw::ENGINE.into()),
            ..Default::default()
        }
    }
    fn is_running(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
    fn loss(&self) -> Option<LossStats> {
        None
    }
    fn stop(self: Box<Self>, _reason: &str) -> EtwStopStats {
        EtwStopStats {
            writer: Default::default(),
            digest: self.digest(),
            loss: None,
            clean: true,
        }
    }
}

impl System for Fake {
    fn pktmon(
        &self,
        args: Vec<OsString>,
        _timeout: Duration,
    ) -> BoxFuture<'static, io::Result<Outcome>> {
        let first = args[0].to_string_lossy().into_owned();
        let verb = match first.as_str() {
            "counters" if args.len() == 3 => "counters-drop".to_string(),
            _ => first,
        };
        self.calls.lock().push(verb.clone());
        let code = match verb.as_str() {
            "start" => {
                let at = args.iter().position(|a| a == "--file-name").unwrap();
                std::fs::write(&args[at + 1], b"etl bytes").unwrap();
                self.start_code.load(Ordering::SeqCst) as i32
            }
            "stop" => self.stop_codes.lock().pop_front().unwrap_or(0),
            _ => 0,
        };
        let gate = (verb == "stop").then(|| self.gate.lock().clone()).flatten();
        Box::pin(async move {
            if let Some(gate) = gate {
                let _permit = gate.acquire().await;
            }
            Ok(Outcome {
                code: Some(code),
                stdout: b"{}".to_vec(),
                stderr: Vec::new(),
            })
        })
    }

    fn etl_released(&self, _etl: &Path) -> bool {
        self.etl_released.load(Ordering::SeqCst)
    }

    fn start_etw(
        &self,
        _dir: PathBuf,
        _session: String,
    ) -> BoxFuture<'static, Result<Box<dyn Etw>, String>> {
        self.calls.lock().push("etw-start".into());
        let result: Result<Box<dyn Etw>, String> = if self.etw_fails.load(Ordering::SeqCst) {
            Err("no etw".into())
        } else {
            self.etw_alive.store(true, Ordering::SeqCst);
            Ok(Box::new(FakeEtw {
                alive: self.etw_alive.clone(),
            }))
        };
        Box::pin(ready(result))
    }

    fn reclaim_etw(&self) -> bool {
        self.reclaim.swap(false, Ordering::SeqCst)
    }

    fn snapshot(&self, dir: PathBuf, phase: &'static str) -> BoxFuture<'static, ()> {
        self.calls.lock().push(format!("snapshot-{phase}"));
        if phase == "start" && self.break_manifest.load(Ordering::SeqCst) {
            let path = dir.join(manifest::MANIFEST_FILE);
            std::fs::remove_file(&path).unwrap();
            std::fs::create_dir(&path).unwrap();
        }
        Box::pin(ready(()))
    }
}

fn config() -> CaptureConfig {
    CaptureConfig {
        enabled: true,
        consent_at: Some(1),
        max_size_mb: 128,
        quota_mb: 65_536,
    }
}

struct Rig {
    root: TempDir,
    fake: Arc<Fake>,
    cfg: watch::Sender<CaptureConfig>,
    capture: Capture,
}

fn rig(cfg: CaptureConfig) -> Rig {
    let root = TempDir::new("capture");
    let fake = Arc::new(Fake::default());
    let (tx, rx) = watch::channel(cfg);
    let capture = Capture::new(root.path().to_path_buf(), rx, fake.clone());
    Rig {
        root,
        fake,
        cfg: tx,
        capture,
    }
}

fn ctx(target: &str) -> SessionCtx {
    SessionCtx {
        mode: ConnectionMode::LocalProxy,
        target: target.into(),
    }
}

fn marker_exists(r: &Rig) -> bool {
    r.root.path().join(manifest::MARKER_FILE).exists()
}

/// AT-08-005 / preflight '3. pktmon start script': the field-proven argv, without the old
/// `filter remove` / `reset` (B-27).
#[test]
fn start_argv_matches_the_field_proven_command() {
    let args = pktmon::start_args(Path::new(r"C:\x\pktmon.etl"), 512);
    let line = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    for part in [
        "start --capture --trace --comp nics --pkt-size 0 --flags 0x01A",
        "--provider Microsoft-Windows-TCPIP --keywords 0x7FFFFFFFFFFFFFFF --level 17",
        "--provider Microsoft-Windows-WFP --keywords 0x7FFFFFFFFFFFFFFF --level 255",
        "--provider Microsoft-Windows-Winsock-AFD --keywords 0x3FFFFFFFFFFF --level 255",
        "--provider Microsoft-Windows-WebIO --keywords 0xFFFFFFFFFFFFFFFF --level 255",
        r"--file-name C:\x\pktmon.etl --file-size 512 --log-mode circular",
    ] {
        assert!(line.contains(part), "{part}\n{line}");
    }
    assert!(!line.contains("filter") && !line.contains("reset"));
    let exe = pktmon::exe().to_string_lossy().to_lowercase();
    assert!(exe.ends_with(r"\system32\pktmon.exe"), "{exe}");
}

/// AT-08-009: capture on without a recorded consent refuses to start; off is a quiet no-op.
#[tokio::test]
async fn consent_is_required_and_disabled_is_a_no_op() {
    let r = rig(CaptureConfig {
        consent_at: None,
        ..config()
    });
    let err = r.capture.start(ctx("127.0.0.1:1080")).await.unwrap_err();
    assert!(matches!(err, CaptureError::ConsentRequired));
    let app = AppError::from(err);
    assert_eq!(app.kind, ErrorKind::Conflict);
    assert_eq!(
        app.user_msg().key,
        "forensics.capture.error.consentRequired"
    );
    r.cfg.send_modify(|c| c.enabled = false);
    let status = r.capture.start(ctx("127.0.0.1:1080")).await.unwrap();
    assert!(!status.enabled && !status.running);
    assert!(r.fake.calls.lock().is_empty());
}

/// AT-08-005 'preserves cleanup ownership and retries after stop failure': the stop itself
/// fails, the session stays running / pending with the marker; the second stop confirms.
#[tokio::test]
async fn unconfirmed_stop_keeps_ownership_and_retries() {
    let r = rig(config());
    r.fake.stop_codes.lock().extend([5, 0]);
    let started = r.capture.start(ctx("127.0.0.1:1080")).await.unwrap();
    assert!(started.running && started.pktmon == PktmonState::Running);
    assert!(marker_exists(&r));
    let err = r.capture.stop(StopReason::VpnStop).await.unwrap_err();
    assert!(matches!(
        err,
        CaptureError::StopUnconfirmed { code: Some(5), .. }
    ));
    let st = r.capture.status().borrow().clone();
    assert!(st.running && st.cleanup_pending && st.stopped_at.is_none());
    assert_eq!(
        st.last_error.unwrap().key,
        "forensics.capture.error.stopUnconfirmed"
    );
    let dir = st.session_dir.unwrap();
    assert!(manifest::read_manifest(&dir).unwrap().running);
    assert!(marker_exists(&r));

    let st = r.capture.stop(StopReason::VpnStop).await.unwrap();
    assert!(!st.running && !st.cleanup_pending && st.stopped_at.is_some());
    assert_eq!(r.fake.calls("stop"), 2);
    assert!(!marker_exists(&r));
    let m = manifest::read_manifest(&dir).unwrap();
    assert!(!m.running && m.last_error.is_none());
    assert_eq!(m.stop_reason.as_deref(), Some("vpn-stop"));
}

/// Review regression: a manifest write that fails after pktmon and ETW started must not drop
/// the session (it returned `Err` and left both running with nothing that would stop them).
#[tokio::test]
async fn failed_manifest_write_keeps_the_running_session() {
    let r = rig(config());
    r.fake.break_manifest.store(true, Ordering::SeqCst);
    let st = r.capture.start(ctx("a")).await.unwrap();
    assert!(st.running && st.pktmon == PktmonState::Running);
    // The manifest write really failed: its path is still the directory the fake put there.
    let dir = st.session_dir.unwrap();
    assert!(dir.join(manifest::MANIFEST_FILE).is_dir());
    assert!(r.fake.etw_alive.load(Ordering::SeqCst));
    let st = r.capture.stop(StopReason::VpnStop).await.unwrap();
    assert!(!st.running && st.pktmon == PktmonState::Stopped);
    assert_eq!(r.fake.calls("stop"), 1);
    assert!(!marker_exists(&r));
}

/// trafficForensicsStopNative (AT-01-009/AT-08-005): the mandatory provider stop precedes the
/// best-effort collection; exit 5 counts as stopped only when the ETL is observed released.
#[tokio::test]
async fn provider_stop_precedes_collection() {
    let r = rig(config());
    r.capture.start(ctx("a")).await.unwrap();
    r.fake.stop_codes.lock().push_back(5);
    r.fake.etl_released.store(true, Ordering::SeqCst);
    let st = r.capture.stop(StopReason::VpnStop).await.unwrap();
    assert!(!st.running && st.pktmon == PktmonState::Stopped);
    let calls = r.fake.calls.lock().clone();
    let at = calls.iter().position(|c| c == "stop").unwrap();
    assert_eq!(
        calls[at - 1..],
        [
            "snapshot-stop",
            "stop",
            "counters",
            "counters-drop",
            "etl2pcap"
        ]
    );
    let dir = st.session_dir.unwrap();
    assert!(dir.join(pktmon::COUNTERS_FILE).exists());
    assert!(!dir.join(STOP_ERRORS_FILE).exists());
}

/// 'serializes concurrent provider stops…': two parallel stops run `pktmon stop` once.
#[tokio::test]
async fn concurrent_stops_run_one_provider_stop() {
    let r = rig(config());
    r.capture.start(ctx("a")).await.unwrap();
    let (a, b) = tokio::join!(
        r.capture.stop(StopReason::VpnStop),
        r.capture.stop(StopReason::VpnStop)
    );
    assert!(!a.unwrap().running && !b.unwrap().running);
    assert_eq!(r.fake.calls("stop"), 1);
}

/// F-198 'orders stop/start and a subsequent stop across finalization': a start queued behind a
/// slow stop gets a fresh running session for the new target; a later stop ends it.
#[tokio::test]
async fn transitions_queue_behind_a_slow_stop() {
    for stop_again in [false, true] {
        let r = rig(config());
        r.capture.start(ctx("old")).await.unwrap();
        let gate = Arc::new(Semaphore::new(0));
        *r.fake.gate.lock() = Some(gate.clone());
        let c1 = r.capture.clone();
        let first = tokio::spawn(async move { c1.stop(StopReason::VpnStop).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let c2 = r.capture.clone();
        let start = tokio::spawn(async move { c2.start(ctx("new")).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let last = stop_again.then(|| {
            let c3 = r.capture.clone();
            tokio::spawn(async move { c3.stop(StopReason::VpnStop).await })
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        gate.add_permits(10);
        assert!(!first.await.unwrap().unwrap().running);
        let started = start.await.unwrap().unwrap();
        assert!(started.running && !started.cleanup_pending);
        assert_eq!(started.target.as_deref(), Some("new"));
        if let Some(last) = last {
            assert!(!last.await.unwrap().unwrap().running);
        }
        let fin = r.capture.status().borrow().clone();
        assert_eq!(fin.running, !stop_again);
        assert_eq!(r.fake.calls("stop"), 1 + usize::from(stop_again));
        assert_eq!(r.fake.calls("start"), 2);
    }
}

/// 'orders restart before a subsequent stop…'.
#[tokio::test]
async fn restart_then_stop() {
    let r = rig(config());
    r.capture.start(ctx("a")).await.unwrap();
    let (restarted, stopped) =
        tokio::join!(r.capture.restart(), r.capture.stop(StopReason::VpnStop));
    assert!(restarted.unwrap().running);
    assert!(!stopped.unwrap().running);
    assert!(!r.capture.status().borrow().running);
    assert_eq!(r.fake.calls("stop"), 2);
    assert_eq!(r.fake.calls("start"), 2);
    // The protection ended: a restart now has no context and starts nothing.
    assert!(!r.capture.restart().await.unwrap().running);
    assert_eq!(r.fake.calls("start"), 2);
}

/// 'does not mistake … sidecar exit for provider termination': the ETW consumer dying leaves the
/// capture running and reports ETW failed.
#[tokio::test]
async fn etw_death_is_not_a_capture_stop() {
    let r = rig(config());
    r.capture.start(ctx("a")).await.unwrap();
    r.fake.etw_alive.store(false, Ordering::SeqCst);
    r.capture.refresh().await;
    let st = r.capture.status().borrow().clone();
    assert!(st.running && st.stopped_at.is_none());
    assert!(matches!(st.etw, EtwState::Failed(_)));
    assert!(
        st.warnings
            .iter()
            .any(|w| w.key == "forensics.capture.warn.etwFailed")
    );
    // The stop records the consumer as failed, not as stopped like a healthy one.
    r.capture.stop(StopReason::VpnStop).await.unwrap();
    let m = manifest::read_manifest(&st.session_dir.unwrap()).unwrap();
    assert_eq!(m.etw, EtwState::Failed(service::ETW_ENDED.into()));
}

/// §3.4: every stop of a running session takes the stop snapshot, whether ETW runs or not.
#[tokio::test]
async fn stop_snapshot_does_not_depend_on_etw() {
    let r = rig(config());
    r.fake.etw_fails.store(true, Ordering::SeqCst);
    let st = r.capture.start(ctx("a")).await.unwrap();
    assert!(st.running && matches!(st.etw, EtwState::Failed(_)));
    r.capture.stop(StopReason::VpnStop).await.unwrap();
    assert_eq!(r.fake.calls("snapshot-stop"), 1);
}

/// A caller that gives up (the app's shutdown timeout) does not cancel the stop halfway: it ends
/// on its own task, removes the marker and records the session stopped.
#[tokio::test]
async fn an_abandoned_stop_still_completes() {
    let r = rig(config());
    let st = r.capture.start(ctx("a")).await.unwrap();
    let gate = Arc::new(Semaphore::new(0));
    *r.fake.gate.lock() = Some(gate.clone());
    let stop = r.capture.stop(StopReason::Shutdown);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), stop)
            .await
            .is_err()
    );
    assert!(r.capture.status().borrow().running);
    gate.add_permits(1);
    // Queues behind the abandoned stop and finds the session stopped.
    let fin = r.capture.stop(StopReason::Shutdown).await.unwrap();
    assert!(!fin.running && fin.session_id == st.session_id);
    assert!(!marker_exists(&r));
    assert!(
        !manifest::read_manifest(&st.session_dir.unwrap())
            .unwrap()
            .running
    );
    assert_eq!(r.fake.calls("stop"), 1);
}

fn orphan_session(r: &Rig, id: &str) -> PathBuf {
    let dir = manifest::session_dir(r.root.path(), id);
    std::fs::create_dir_all(&dir).unwrap();
    let m = SessionManifest {
        schema_version: manifest::SCHEMA_VERSION,
        app_version: "2.0.0".into(),
        session_id: id.into(),
        running: true,
        engine: Some("pktmon".into()),
        mode: Some(ConnectionMode::DirectVpn),
        target: Some("p".into()),
        started_at: 1,
        stopped_at: None,
        max_size_mb: 128,
        stop_reason: None,
        last_error: None,
        pktmon: PktmonState::Running,
        etw: EtwState::Running,
        etw_stats: None,
        warnings: vec![],
        app_events_dropped: 0,
    };
    manifest::write_manifest(&dir, &m).unwrap();
    manifest::write_marker(r.root.path(), id).unwrap();
    dir
}

/// AT-08-004: a marker at boot means a capture we started may still run: one `pktmon stop`, the
/// session is closed as recovered, an orphaned ETW session is reclaimed (both logged).
#[tokio::test]
async fn boot_recovery_stops_our_orphan() {
    let r = rig(config());
    let dir = orphan_session(&r, "2026-01-01T00-00-00-000Z");
    r.fake.reclaim.store(true, Ordering::SeqCst);
    let report = r.capture.recover_on_boot(None).await;
    assert!(report.orphan_suspected && report.pktmon_stopped && report.etw_reclaimed);
    assert_eq!(report.sessions_closed, 1);
    assert_eq!(r.fake.calls("stop"), 1);
    assert!(!marker_exists(&r));
    let m = manifest::read_manifest(&dir).unwrap();
    assert!(!m.running);
    assert_eq!(m.stop_reason.as_deref(), Some(RECOVERED_AT_STARTUP));
    assert_eq!(m.pktmon, PktmonState::Stopped);
}

/// An unconfirmed recovery stop becomes the pending session; the next start retries it first.
#[tokio::test]
async fn unconfirmed_boot_recovery_is_retried_before_a_start() {
    let r = rig(config());
    orphan_session(&r, "2026-01-01T00-00-00-000Z");
    r.fake.stop_codes.lock().push_back(5);
    let report = r.capture.recover_on_boot(None).await;
    assert!(report.orphan_suspected && !report.pktmon_stopped);
    assert!(r.capture.status().borrow().cleanup_pending);
    assert!(marker_exists(&r));
    let st = r.capture.start(ctx("a")).await.unwrap();
    assert!(st.running && !st.cleanup_pending);
    assert_ne!(st.session_id.as_deref(), Some("2026-01-01T00-00-00-000Z"));
    assert_eq!(r.fake.calls("stop"), 2);
}

/// §7.5 legacy hints (changed): a hint saying "running" triggers one `pktmon stop` and never
/// blocks; a cleanly stopped hint does nothing.
#[tokio::test]
async fn legacy_hints_trigger_one_stop_and_never_block() {
    let legacy = TempDir::new("legacy-electron");
    let hint_dir = legacy.path().join("traffic-forensics");
    std::fs::create_dir_all(&hint_dir).unwrap();
    let hint = hint_dir.join("latest-session.json");

    std::fs::write(
        &hint,
        br#"{"running":false,"stoppedAt":1,"lastError":null}"#,
    )
    .unwrap();
    let r = rig(config());
    let report = r.capture.recover_on_boot(Some(legacy.path())).await;
    assert!(!report.orphan_suspected);
    assert_eq!(r.fake.calls("stop"), 0);

    std::fs::write(&hint, br#"{"running":true}"#).unwrap();
    let report = r.capture.recover_on_boot(Some(legacy.path())).await;
    assert!(report.orphan_suspected);
    assert_eq!(r.fake.calls("stop"), 1);
    assert!(r.capture.start(ctx("a")).await.unwrap().running);
    // The hint never changes, but its capture already had its stop: later boots leave pktmon
    // (possibly the user's own capture) alone.
    r.capture.stop(StopReason::VpnStop).await.unwrap();
    let report = r.capture.recover_on_boot(Some(legacy.path())).await;
    assert!(!report.orphan_suspected);
    assert_eq!(r.fake.calls("stop"), 2, "only the session's own stop");
}

/// pktmon refusing (e.g. the user's own capture runs) leaves an ETW-only session that never
/// stops a capture it does not own; both failing is "start-failed".
#[tokio::test]
async fn pktmon_refusal_runs_etw_only() {
    let r = rig(config());
    r.fake.start_code.store(1, Ordering::SeqCst);
    let st = r.capture.start(ctx("a")).await.unwrap();
    assert!(st.running && matches!(st.pktmon, PktmonState::Unavailable(_)));
    assert!(
        st.warnings
            .iter()
            .any(|w| w.key == "forensics.capture.warn.pktmonUnavailable")
    );
    assert!(!marker_exists(&r));
    r.capture.stop(StopReason::VpnStop).await.unwrap();
    assert_eq!(r.fake.calls("stop"), 0);

    r.fake.etw_fails.store(true, Ordering::SeqCst);
    let err = r.capture.start(ctx("a")).await.unwrap_err();
    assert!(matches!(err, CaptureError::StartFailed(_)));
    let st = r.capture.status().borrow().clone();
    assert!(!st.running);
    assert_eq!(st.stop_reason.as_deref(), Some(START_FAILED));
    assert_eq!(
        st.last_error.unwrap().key,
        "forensics.capture.error.startFailed"
    );
}

/// §3.4.1: over quota the session runs ETW-only with a warning; nothing is deleted.
#[tokio::test]
async fn quota_reached_runs_etw_only() {
    let r = rig(CaptureConfig {
        max_size_mb: 2048,
        quota_mb: 1024,
        ..config()
    });
    let st = r.capture.start(ctx("a")).await.unwrap();
    assert!(st.running);
    assert_eq!(
        st.pktmon,
        PktmonState::Unavailable("storage quota reached".into())
    );
    assert_eq!(
        st.warnings.last().unwrap().key,
        "forensics.capture.warn.quota"
    );
    assert_eq!(r.fake.calls("start"), 0);
    assert!(!marker_exists(&r));
}

/// App events go to the running session only, typed (B-33), capped at 10 000 rows (B-15).
#[tokio::test]
async fn app_events_are_typed_and_capped() {
    let r = rig(config());
    let ev = |user| ForensicEvent {
        kind: ForensicEventKind::EngineExited {
            user_initiated: user,
        },
        details: serde_json::json!({"code": 0}),
    };
    r.capture.record(ev(true));
    let st = r.capture.start(ctx("a")).await.unwrap();
    for _ in 0..APP_EVENTS_MAX {
        r.capture.record(ev(true));
    }
    r.capture.record(ev(false));
    r.capture.stop(StopReason::VpnStop).await.unwrap();
    r.capture.record(ev(false));
    let dir = st.session_dir.unwrap();
    let text = std::fs::read_to_string(dir.join(APP_EVENTS_FILE)).unwrap();
    assert_eq!(text.lines().count(), APP_EVENTS_MAX as usize);
    let first: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(first["event"], "engine-exited");
    assert_eq!(first["userInitiated"], true);
    assert_eq!(first["source"], "tun");
    assert_eq!(first["details"]["code"], 0);
    assert!(first["timestamp"].as_str().unwrap().ends_with('Z'));
    assert_eq!(manifest::read_manifest(&dir).unwrap().app_events_dropped, 1);
}

/// Old sessions are not surfaced while capture is off; a new process shows no stale live data;
/// «clear» removes every session.
#[tokio::test]
async fn visibility_and_clear() {
    let r = rig(config());
    r.capture.start(ctx("a")).await.unwrap();
    let st = r.capture.stop(StopReason::VpnStop).await.unwrap();
    assert!(
        st.digest.is_some(),
        "a session stopped in this process keeps its final digest"
    );

    r.cfg.send_modify(|c| c.enabled = false);
    r.capture.refresh().await;
    let st = r.capture.status().borrow().clone();
    assert!(!st.enabled && !st.running);
    assert!(st.session_id.is_none() && st.digest.is_none());
    assert_eq!(st.health.artifact_count, 0);
    // Hidden, but its files still count in the size shown next to «clear».
    let on_disk: u64 = r.capture.sessions().iter().map(|s| s.bytes).sum();
    assert!(on_disk > 0);
    assert_eq!(st.total_bytes, on_disk);

    r.cfg.send_modify(|c| c.enabled = true);
    let (_tx, rx) = watch::channel(config());
    let fresh = Capture::new(r.root.path().to_path_buf(), rx, r.fake.clone());
    fresh.refresh().await;
    let st = fresh.status().borrow().clone();
    assert!(st.session_id.is_none() && st.digest.is_none() && st.total_bytes > 0);
    assert_eq!(fresh.sessions().len(), 1);

    let report = r.capture.clear().await.unwrap();
    assert_eq!(report.removed.len(), 1);
    assert!(r.capture.sessions().is_empty());
    assert_eq!(r.capture.status().borrow().total_bytes, 0);
}

/// Real pktmon + ETW: start and a confirmed stop with the artefacts in place. CI runs it on its
/// elevated runner (`--ignored elevated_`); the stop comes before every check, so a failed check
/// never leaves pktmon capturing.
#[tokio::test]
#[ignore = "needs elevation"]
async fn elevated_capture_start_and_stop() {
    let root = TempDir::new("capture-elevated");
    let (_tx, rx) = watch::channel(config());
    let capture = Capture::new(root.path().to_path_buf(), rx, Arc::new(WindowsSystem));
    let started = capture.start(ctx("127.0.0.1:1080")).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let stopped = capture.stop(StopReason::VpnStop).await;
    let st = started.unwrap();
    assert!(st.running);
    assert_eq!(st.pktmon, PktmonState::Running, "{st:?}");
    assert_eq!(st.etw, EtwState::Running, "{st:?}");
    let st = stopped.unwrap();
    assert!(!st.running && !st.cleanup_pending);
    let dir = st.session_dir.unwrap();
    for f in [
        pktmon::ETL_FILE,
        crate::etw::EVENTS_FILE,
        "network-start.json",
        "sockets-stop.json",
    ] {
        assert!(dir.join(f).exists(), "{f}");
    }
    assert!(!root.path().join(manifest::MARKER_FILE).exists());
}

/// B-26: the live refresh takes counters and snapshots, never an ETL copy; idle does nothing.
#[tokio::test]
async fn live_refresh_takes_counters_and_snapshots_only() {
    let r = rig(config());
    assert_eq!(r.capture.live_refresh().await, None);
    let st = r.capture.start(ctx("a")).await.unwrap();
    let dir = r.capture.live_refresh().await.unwrap();
    assert_eq!(Some(&dir), st.session_dir.as_ref());
    assert!(dir.join(LIVE_COUNTERS_FILE).exists());
    assert_eq!(r.fake.calls("snapshot-live"), 1);
    assert!(!dir.join("pktmon-live.etl").exists());
}

/// AT-08-009: the consent timestamp is stored in `forensics.json` and feeds the config.
#[test]
fn consent_is_persisted_and_mapped() {
    use vpnte_core::store::Store;
    let data = TempDir::new("prefs");
    let prefs = Store::<CapturePrefs>::open(data.path());
    assert_eq!(prefs.snapshot().consent_at, None);
    prefs
        .update(|p| p.consent_at = Some(1_781_827_200_000))
        .unwrap();
    let reopened = Store::<CapturePrefs>::open(data.path()).snapshot();
    assert_eq!(reopened.consent_at, Some(1_781_827_200_000));
    assert_eq!(reopened.quota_mb, store::DEFAULT_QUOTA_MB);
    let settings = Settings {
        deep_inspection: true,
        deep_inspection_max_mb: 99_999,
        ..Default::default()
    };
    let cfg = CaptureConfig::new(&settings, &reopened);
    assert!(cfg.enabled);
    assert_eq!(cfg.consent_at, Some(1_781_827_200_000));
    assert_eq!(cfg.max_size_mb, 2048);
    assert_eq!(CaptureConfig::default().max_size_mb, 512);
}
