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

/// A capture whose methods with a trait default all answer something the default would not.
struct Answers;

#[async_trait]
impl Capture for Answers {
    async fn prepare(&self, _: &StartRequest, _: &[String]) -> AppResult<CapturePlan> {
        unreachable!("not asked")
    }
    fn config(&self, _: &CapturePlan, _: &EngineParts) -> Result<(Value, [u8; 32]), ConfigError> {
        unreachable!("not asked")
    }
    async fn begin(&self, _: &CapturePlan, _: &[PathBuf]) -> AppResult<()> {
        unreachable!("not asked")
    }
    async fn ready(
        &self,
        _: &CapturePlan,
        _: Duration,
        _: &CancellationToken,
    ) -> AppResult<CaptureProof> {
        unreachable!("not asked")
    }
    async fn routes_ok(&self, _: &CaptureProof) -> bool {
        unreachable!("not asked")
    }
    async fn lost(&self) -> AppResult<()> {
        unreachable!("not asked")
    }
    async fn release(&self) -> AppResult<()> {
        unreachable!("not asked")
    }
    async fn wait_gone(&self, _: &CapturePlan, _: Duration, _: &CancellationToken) -> bool {
        unreachable!("not asked")
    }
    async fn check(&self, _: &CaptureProof) -> CaptureCheck {
        unreachable!("not asked")
    }
    fn guard(&self, _: &CapturePlan) -> KillSwitchLevel {
        KillSwitchLevel::Strict
    }
    fn ports(&self, _: &CapturePlan) -> Vec<u16> {
        vec![4242]
    }
    fn probe(&self) -> Option<PassProbe> {
        Some(Box::pin(async { true }))
    }
}

/// Lab live-12: the wrapper left the trait's defaults in place, so in Tunnel mode the TUN's own
/// answers never reached the runtime: no packet probe before «Подключено» (L11-1), no server
/// exclusions (L11-2), the crash policy on the start's level instead of the live one (fix-ks a1).
#[tokio::test]
async fn the_wrapper_answers_with_the_inner_capture() {
    let engaged = Engaged::new(Answers);
    let plan = plan();
    assert_eq!(
        engaged.guard(&plan),
        KillSwitchLevel::Strict,
        "the live level"
    );
    assert_eq!(engaged.ports(&plan), vec![4242]);
    let probe = engaged.probe().expect("the inner capture's probe");
    assert!(probe.await);
}

/// The names of the `fn`s inside the block that starts at `head`, up to its closing line. CI's
/// Windows checkout has CRLF line ends (core.autocrlf): read as LF.
fn methods(source: &str, head: &str) -> Vec<String> {
    let source = source.replace("\r\n", "\n");
    let start = source.find(head).expect("block head");
    let body = &source[start..];
    let end = body.find("\n}\n").expect("block end");
    body[..end]
        .split("fn ")
        .skip(1)
        .filter_map(|rest| {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// Every method of `Capture`, including the ones a later change adds with a default, is
/// implemented by the wrapper: a default there answers for the TUN capture without a word.
#[test]
fn the_wrapper_implements_every_capture_method() {
    let trait_source = include_str!("../../../tunnel/src/runtime/capture/mod.rs");
    let wrapper_source = include_str!("../watchdog.rs");
    let wanted = methods(trait_source, "pub trait Capture: Send + Sync {");
    let wrapped = methods(wrapper_source, "impl<C: Capture> Capture for Engaged<C> {");
    assert!(wanted.len() >= 14, "the trait was read: {wanted:?}");
    let missing: Vec<_> = wanted.iter().filter(|m| !wrapped.contains(m)).collect();
    assert!(missing.is_empty(), "Engaged does not forward {missing:?}");
}
