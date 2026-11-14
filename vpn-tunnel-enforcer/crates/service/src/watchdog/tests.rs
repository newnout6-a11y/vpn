//! The watchdog follows what the capture holds, not the runtime's status (review service-a6).
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppError, ErrorKind};
use vpnte_engine::singbox_config::TunStack;
use vpnte_tunnel::runtime::tun_form;

use super::*;

/// A capture whose `begin` and `release` fail while `fail` is set.
#[derive(Default)]
struct Fake {
    fail: AtomicBool,
    /// The programs of the last `begin`.
    programs: Mutex<Vec<PathBuf>>,
}

impl Fake {
    fn outcome(&self) -> AppResult<()> {
        if self.fail.load(Ordering::SeqCst) {
            Err(AppError::new(ErrorKind::Internal))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl Capture for Fake {
    async fn prepare(&self, _: &StartRequest, _: &[String]) -> AppResult<CapturePlan> {
        unreachable!("not used by the watchdog")
    }
    fn config(&self, _: &CapturePlan, _: &EngineParts) -> Result<(Value, [u8; 32]), ConfigError> {
        unreachable!("not used by the watchdog")
    }
    async fn begin(&self, _: &CapturePlan, programs: &[PathBuf]) -> AppResult<()> {
        *self.programs.lock() = programs.to_vec();
        self.outcome()
    }
    async fn ready(
        &self,
        _: &CapturePlan,
        _: Duration,
        _: &CancellationToken,
    ) -> AppResult<CaptureProof> {
        unreachable!("not used by the watchdog")
    }
    async fn routes_ok(&self, _: &CaptureProof) -> bool {
        unreachable!("not used by the watchdog")
    }
    async fn lost(&self) -> AppResult<()> {
        Ok(())
    }
    async fn release(&self) -> AppResult<()> {
        self.outcome()
    }
    async fn wait_gone(&self, _: &CapturePlan, _: Duration, _: &CancellationToken) -> bool {
        unreachable!("not used by the watchdog")
    }
    async fn check(&self, _: &CaptureProof) -> CaptureCheck {
        unreachable!("not used by the watchdog")
    }
}

fn plan() -> CapturePlan {
    CapturePlan {
        alias: None,
        form: tun_form(KillSwitchLevel::Standard, false),
        stack: TunStack::default(),
        mtu: 1500,
        guard: KillSwitchLevel::Standard,
        warnings: Vec::new(),
    }
}

/// A crash keeps the hold (the block stays and must survive a BFE restart); only a release that
/// succeeded ends it.
#[tokio::test]
async fn a_crash_keeps_the_hold_and_only_a_release_ends_it() {
    let engaged = Engaged::new(Fake::default());
    let holds = engaged.holds();
    engaged.inner.fail.store(true, Ordering::SeqCst);
    assert!(engaged.begin(&plan(), &[]).await.is_err());
    assert!(!*holds.borrow(), "a failed first begin holds nothing");
    engaged.inner.fail.store(false, Ordering::SeqCst);
    engaged.begin(&plan(), &[]).await.expect("begin");
    assert!(*holds.borrow());
    engaged.lost().await.expect("lost");
    assert!(*holds.borrow(), "the block stays after a crash");
    engaged.inner.fail.store(true, Ordering::SeqCst);
    assert!(engaged.release().await.is_err());
    assert!(*holds.borrow(), "filters in doubt stay watched");
    engaged.inner.fail.store(false, Ordering::SeqCst);
    engaged.release().await.expect("release");
    assert!(!*holds.borrow());
}

async fn settle() {
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

/// No timer while idle; one watchdog from the hold to its end.
#[tokio::test]
async fn the_watchdog_runs_exactly_while_held() {
    let (tx, rx) = watch::channel(false);
    let started: Arc<Mutex<Vec<CancellationToken>>> = Arc::default();
    let stop = CancellationToken::new();
    let record = started.clone();
    let task = tokio::spawn(run(rx, move |t| record.lock().push(t), stop.clone()));
    settle().await;
    assert!(started.lock().is_empty(), "idle: no watchdog");
    tx.send_replace(true);
    settle().await;
    tx.send_replace(true);
    settle().await;
    assert_eq!(started.lock().len(), 1, "one watchdog per hold");
    assert!(!started.lock()[0].is_cancelled());
    tx.send_replace(false);
    settle().await;
    assert!(started.lock()[0].is_cancelled());
    stop.cancel();
    task.await.expect("watchdog loop");
}

/// p-svc-update: a session permits the engine files current at its start that the protection
/// does not permit anyway (a version the updater installed while the service runs).
#[tokio::test]
async fn a_session_permits_the_engines_it_starts() {
    let bundled = |name: &str| PathBuf::from(r"C:\Service").join(name);
    let downloaded = PathBuf::from(r"C:\Service\engines\sing-box\1.14.5\sing-box.exe");
    let (tx, rx) = watch::channel(EngineExes {
        singbox: bundled("sing-box.exe"),
        xray: bundled("xray.exe"),
    });
    let permitted = vec![bundled("sing-box.exe"), bundled("xray.exe")];
    let engaged = Engaged::new(Fake::default()).with_engines(rx, permitted);
    let owner = PathBuf::from(r"C:\Proxy\owner.exe");
    engaged
        .begin(&plan(), std::slice::from_ref(&owner))
        .await
        .expect("begin");
    assert_eq!(*engaged.inner.programs.lock(), vec![owner.clone()]);
    tx.send_modify(|e| e.singbox = downloaded.clone());
    engaged
        .begin(&plan(), std::slice::from_ref(&owner))
        .await
        .expect("begin");
    assert_eq!(*engaged.inner.programs.lock(), vec![owner, downloaded]);
}
