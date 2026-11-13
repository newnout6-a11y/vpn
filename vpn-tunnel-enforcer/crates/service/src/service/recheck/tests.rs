//! The service's re-checks against fakes: a counting filter check, a fake curl / adapter
//! environment, a hand-driven wake counter and network-change stream.
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::KillSwitchLevel;
use vpnte_probes::leak::{
    CurlOutcome, LeakEnv, PhysicalAddr, SelfTestResult, SelfTestVerdict, SelfTester, WatchConfig,
    verdict,
};
use vpnte_winnet::adapters::NetChange;

use super::Recheck;

/// Curl answers: the default route reaches the internet; a probe bound to the physical adapter
/// reaches it only when `leaky` (the filters let it out).
struct FakeEnv {
    leaky: AtomicBool,
}

impl LeakEnv for FakeEnv {
    fn curl(&self, args: Vec<String>, _: Duration) -> BoxFuture<'static, CurlOutcome> {
        let bound = args.iter().any(|a| a == "--interface");
        let reached = !bound || self.leaky.load(Ordering::SeqCst);
        let outcome = CurlOutcome {
            exit: Some(if reached { 0 } else { 7 }),
            stdout: if reached {
                "198.51.100.7".into()
            } else {
                String::new()
            },
            stderr: String::new(),
            launched: true,
        };
        async move { outcome }.boxed()
    }

    fn physical_addresses(&self) -> BoxFuture<'static, Result<Vec<PhysicalAddr>, ()>> {
        let ip: IpAddr = "192.0.2.10".parse().expect("ip");
        async move {
            Ok(vec![PhysicalAddr {
                alias: "Ethernet".into(),
                ip,
            }])
        }
        .boxed()
    }
}

struct Rig {
    ticks: Arc<AtomicUsize>,
    results: watch::Receiver<Option<SelfTestResult>>,
    wakes: watch::Sender<u64>,
    changes: mpsc::Sender<NetChange>,
    cancel: CancellationToken,
}

/// A running re-check: `gate` open or closed, `leaky` adapters, background runs every `every`.
fn rig(gate: bool, leaky: bool, every: Duration) -> Rig {
    let ticks = Arc::new(AtomicUsize::new(0));
    let counted = ticks.clone();
    let env = Arc::new(FakeEnv {
        leaky: AtomicBool::new(leaky),
    });
    let results = watch::channel(None).0;
    let recheck = Arc::new(Recheck {
        tick: Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        }),
        tester: Arc::new(SelfTester::new(env)),
        config: WatchConfig {
            every,
            coalesce: Duration::from_millis(10),
        },
        gate: Arc::new(move || gate),
        level: Arc::new(|| KillSwitchLevel::Standard),
        results: results.clone(),
        settle: Duration::from_millis(50),
    });
    let wakes = watch::channel(0).0;
    let (changes, rx) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    tokio::spawn(recheck.run(wakes.subscribe(), Some(rx), cancel.clone()));
    Rig {
        ticks,
        results: results.subscribe(),
        wakes,
        changes,
        cancel,
    }
}

const QUIET: Duration = Duration::from_secs(3600);

/// Waits up to 5 s for `done`.
async fn until(done: impl Fn() -> bool) -> bool {
    for _ in 0..500 {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

fn latest(r: &Rig) -> Option<SelfTestVerdict> {
    r.results.borrow().as_ref().map(verdict)
}

/// RU audit item 11: a wake re-verifies the filters at once, then the self-test runs and its
/// result is published for the pipe status.
#[tokio::test]
async fn a_wake_reverifies_the_filters_at_once_then_self_tests() {
    let r = rig(true, false, QUIET);
    r.wakes.send_modify(|n| *n += 1);
    assert!(until(|| r.ticks.load(Ordering::SeqCst) == 1).await);
    assert!(until(|| latest(&r) == Some(SelfTestVerdict::Ok)).await);
    r.cancel.cancel();
}

/// RU audit item 11: a network change does the same.
#[tokio::test]
async fn a_network_change_reverifies_the_filters_too() {
    let r = rig(true, false, QUIET);
    let change = NetChange {
        before: 2,
        after: 3,
    };
    r.changes.send(change).await.expect("watch running");
    assert!(until(|| r.ticks.load(Ordering::SeqCst) == 1).await);
    assert!(until(|| latest(&r) == Some(SelfTestVerdict::Ok)).await);
    r.cancel.cancel();
}

/// A periodic run that finds a leak is published, and the filters are re-verified at once.
#[tokio::test]
async fn a_leak_is_published_and_repaired_at_once() {
    let r = rig(true, true, Duration::from_millis(100));
    assert!(until(|| latest(&r) == Some(SelfTestVerdict::Leak)).await);
    assert!(until(|| r.ticks.load(Ordering::SeqCst) >= 1).await);
    r.cancel.cancel();
}

/// With the kill switch off (gate closed) no self-test runs; the filter check still does.
#[tokio::test]
async fn no_self_test_while_the_gate_is_closed() {
    let r = rig(false, true, Duration::from_millis(50));
    r.wakes.send_modify(|n| *n += 1);
    assert!(until(|| r.ticks.load(Ordering::SeqCst) == 1).await);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(latest(&r), None);
    assert_eq!(
        r.ticks.load(Ordering::SeqCst),
        1,
        "no leak, no second check"
    );
    r.cancel.cancel();
}

/// Released filters clear the published result: it described filters that are gone.
#[tokio::test]
async fn a_release_clears_the_result() {
    let r = rig(true, false, Duration::from_millis(50));
    assert!(until(|| latest(&r).is_some()).await);
    r.cancel.cancel();
    assert!(until(|| latest(&r).is_none()).await);
}
