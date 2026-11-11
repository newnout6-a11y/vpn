use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use parking_lot::Mutex;

use super::*;
use crate::leak::SelfTestResult;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Answers reads from a queue (`None` = every provider failed), optionally slowly.
#[derive(Default)]
struct Script {
    answers: Mutex<VecDeque<Option<IpAddr>>>,
    families: Mutex<Vec<Family>>,
    calls: AtomicUsize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    delay_ms: u64,
}

impl Script {
    fn new(answers: &[Option<&str>]) -> Arc<Self> {
        Self::slow(answers, 0)
    }
    fn slow(answers: &[Option<&str>], delay_ms: u64) -> Arc<Self> {
        Arc::new(Script {
            answers: Mutex::new(answers.iter().map(|a| a.map(ip)).collect()),
            delay_ms,
            ..Default::default()
        })
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Sampler for Script {
    fn sample<'a>(
        &'a self,
        _route: &'a IpRoute,
        family: Family,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Option<IpSample>> {
        async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.families.lock().push(family);
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = tokio::time::sleep(Duration::from_millis(self.delay_ms)) => {}
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            if cancel.is_cancelled() {
                return None;
            }
            let answer = self.answers.lock().pop_front().flatten()?;
            Some(IpSample {
                ip: answer,
                provider: 0,
                at: 1,
            })
        }
        .boxed()
    }
}

const TUN: IpRoute = IpRoute::Tun {
    v4: Ipv4Addr::new(192, 168, 250, 253),
    v6: None,
};

fn monitor(script: &Arc<Script>) -> IpMonitor {
    let sampler: Arc<dyn Sampler> = script.clone();
    IpMonitor::new(sampler)
}

/// AT-07-001/005/006: the verdict table, including the honest `Failed` (B-IP-1).
#[test]
fn verdict_table() {
    let base = Some(ip("198.51.100.1"));
    let real = Some(ip("203.0.113.7"));
    assert_eq!(verdict(ip("198.51.100.1"), base, real), IpVerdict::Passed);
    assert_eq!(
        verdict(ip("13.143.217.2"), base, real),
        IpVerdict::Indeterminate
    );
    assert_eq!(verdict(ip("203.0.113.7"), base, real), IpVerdict::Failed);
    assert_eq!(verdict(ip("203.0.113.7"), None, real), IpVerdict::Failed);
    assert_eq!(
        verdict(ip("13.143.217.2"), None, real),
        IpVerdict::NotChecked
    );
    assert_eq!(
        verdict(ip("13.143.217.2"), base, None),
        IpVerdict::Indeterminate
    );
    assert_eq!(IpVerdict::Indeterminate.verdict(), Verdict::Warn);
    assert_eq!(IpVerdict::NotChecked.verdict(), Verdict::NotChecked);
    assert_eq!(
        serde_json::to_string(&IpVerdict::NotChecked).unwrap(),
        "\"not-checked\""
    );
}

/// AT-07-001/005/006 (publicIpEvidence): a different exit stays indeterminate on reads;
/// only an adoption moves the baseline.
#[tokio::test]
async fn mismatch_is_indeterminate_until_adopted() {
    let script = Script::new(&[
        Some("198.51.100.1"),
        Some("13.143.217.2"),
        Some("13.143.217.2"),
        Some("198.51.100.2"),
    ]);
    let m = monitor(&script);
    let mut rx = m.subscribe();
    m.start(7, TUN, DEFAULT_INTERVAL);
    let cancel = CancellationToken::new();
    assert_eq!(
        m.adopt_baseline(7, None, &cancel).await,
        Ok(ip("198.51.100.1"))
    );
    assert_eq!(m.evidence().verdict, IpVerdict::Passed);
    assert!(
        m.last_alive().is_some(),
        "a TUN-bound read of the baseline is liveness"
    );
    let e = m.refresh(7).await;
    assert_eq!(
        (e.verdict, e.last.map(|s| s.ip)),
        (IpVerdict::Indeterminate, Some(ip("13.143.217.2")))
    );
    assert_eq!(e.baseline, Some(ip("198.51.100.1")));
    assert!(rx.has_changed().unwrap());
    assert_eq!(rx.borrow_and_update().verdict, IpVerdict::Indeterminate);
    assert_eq!(m.refresh(7).await.verdict, IpVerdict::Indeterminate);
    assert_eq!(
        m.adopt_baseline(7, None, &cancel).await,
        Ok(ip("198.51.100.2"))
    );
    let e = m.evidence();
    assert_eq!(
        (e.baseline, e.verdict),
        (Some(ip("198.51.100.2")), IpVerdict::Passed)
    );
    m.stop();
}

/// B-IP-7 (publicIpEvidence "providers offline"): a failed read is `NotChecked` with the old
/// sample kept but marked stale; a failed adoption keeps the old baseline.
#[tokio::test]
async fn failed_reads_are_not_checked_never_cached_verdicts() {
    let script = Script::new(&[Some("198.51.100.1"), None, None]);
    let m = monitor(&script);
    m.start(1, TUN, DEFAULT_INTERVAL);
    let cancel = CancellationToken::new();
    m.adopt_baseline(1, None, &cancel).await.unwrap();
    let e = m.refresh(1).await;
    assert_eq!(e.verdict, IpVerdict::NotChecked);
    assert!(!e.fresh);
    assert_eq!(e.last.map(|s| s.ip), Some(ip("198.51.100.1")));
    assert_eq!(
        m.adopt_baseline(1, None, &cancel).await,
        Err(AdoptError::NoSample)
    );
    assert_eq!(m.evidence().baseline, Some(ip("198.51.100.1")));
    m.stop();
    let e = m.evidence();
    assert_eq!(
        (e.baseline, e.verdict, e.fresh),
        (None, IpVerdict::NotChecked, false)
    );
}

/// AT-07-006/011: adoption pins the family to the expected exit; background reads pin it to
/// the baseline (B-IP-3).
#[tokio::test]
async fn reads_pin_the_family() {
    let script = Script::new(&[
        Some("2001:4860::1"),
        Some("2001:4860::1"),
        Some("198.51.100.1"),
    ]);
    let m = monitor(&script);
    m.start(1, TUN, DEFAULT_INTERVAL);
    let cancel = CancellationToken::new();
    let v6 = ip("2001:4860::1");
    assert_eq!(m.adopt_baseline(1, Some(v6), &cancel).await, Ok(v6));
    m.inner.tick(1).await;
    assert_eq!(m.evidence().verdict, IpVerdict::Passed);
    assert_eq!(
        m.adopt_baseline(1, Some(ip("198.51.100.1")), &cancel).await,
        Ok(ip("198.51.100.1"))
    );
    assert_eq!(
        *script.families.lock(),
        vec![Family::V6, Family::V6, Family::V4]
    );
    m.stop();
}

/// B-IP-2: the user's real IP is never adopted and reads as `Failed`.
#[tokio::test]
async fn real_ip_is_refused_as_baseline() {
    let script = Script::new(&[
        Some("203.0.113.7"),
        Some("198.51.100.1"),
        Some("203.0.113.7"),
    ]);
    let m = monitor(&script);
    m.set_real_ip(Some(ip("203.0.113.7")));
    m.start(1, IpRoute::Direct, DEFAULT_INTERVAL);
    let cancel = CancellationToken::new();
    assert_eq!(
        m.adopt_baseline(1, None, &cancel).await,
        Err(AdoptError::RealIp)
    );
    let e = m.evidence();
    assert_eq!((e.baseline, e.verdict), (None, IpVerdict::Failed));
    assert_eq!(
        m.adopt_baseline(1, None, &cancel).await,
        Ok(ip("198.51.100.1"))
    );
    assert!(
        m.last_alive().is_none(),
        "a direct read is no tunnel liveness"
    );
    assert_eq!(m.refresh(1).await.verdict, IpVerdict::Failed);
    assert_eq!(
        AppError::from(AdoptError::RealIp).user_msg().key,
        "probes.ip.adopt.realIp"
    );
    m.stop();
}

/// AT-07-001 (auto-verify monitor integration): an expected exit that does not show up is
/// not adopted; the verdict stays indeterminate until the expected exit is read.
#[tokio::test]
async fn expected_exit_must_match() {
    let script = Script::new(&[
        Some("198.51.100.1"),
        Some("13.143.214.3"),
        Some("198.51.100.88"),
        Some("13.143.214.3"),
    ]);
    let m = monitor(&script);
    m.start(1, TUN, DEFAULT_INTERVAL);
    let cancel = CancellationToken::new();
    m.adopt_baseline(1, None, &cancel).await.unwrap();
    assert_eq!(m.refresh(1).await.verdict, IpVerdict::Indeterminate);
    let candidate = ip("13.143.214.3");
    assert_eq!(
        m.adopt_baseline(1, Some(candidate), &cancel).await,
        Err(AdoptError::Mismatch {
            seen: ip("198.51.100.88")
        })
    );
    let e = m.evidence();
    assert_eq!(
        (e.baseline, e.verdict),
        (Some(ip("198.51.100.1")), IpVerdict::Indeterminate)
    );
    assert_eq!(
        m.adopt_baseline(1, Some(candidate), &cancel).await,
        Ok(candidate)
    );
    let e = m.evidence();
    assert_eq!(
        (e.baseline, e.verdict),
        (Some(candidate), IpVerdict::Passed)
    );
    m.stop();
}

/// AT-00-003 / AT-02-005: reads of another (or no) connection make no request; a read that
/// goes stale in flight (stop, suspend, new connection) publishes nothing.
#[tokio::test]
async fn stale_reads_publish_nothing() {
    let script = Script::slow(&[Some("198.51.100.1"), Some("198.51.100.9")], 200);
    let m = monitor(&script);
    let cancel = CancellationToken::new();
    assert_eq!(
        m.adopt_baseline(1, None, &cancel).await,
        Err(AdoptError::Stale)
    );
    m.start(1, TUN, DEFAULT_INTERVAL);
    assert_eq!(m.refresh(2).await.last, None);
    assert_eq!(script.calls(), 0);

    let read = tokio::spawn({
        let m = m.clone();
        async move { m.refresh(1).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(m.suspend());
    let e = read.await.unwrap();
    assert_eq!(e.last, None, "a read aborted by suspend is dropped");

    let m2 = m.clone();
    let adopt =
        tokio::spawn(async move { m2.adopt_baseline(1, None, &CancellationToken::new()).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    m.start(2, TUN, DEFAULT_INTERVAL);
    assert_eq!(adopt.await.unwrap(), Err(AdoptError::Stale));
    assert_eq!(m.evidence().baseline, None);
    m.stop();
}

/// AT-07-007 / B-IP-8: suspended means no reads (background or refresh); guards nest;
/// adoption still works (it ends the transition); invalidation publishes `NotChecked`.
#[tokio::test]
async fn suspend_silences_reads_until_every_guard_drops() {
    let script = Script::new(&[Some("198.51.100.1"), Some("198.51.100.1")]);
    let m = monitor(&script);
    m.start(1, TUN, DEFAULT_INTERVAL);
    let outer = m.suspend();
    let inner = m.suspend();
    m.inner.tick(1).await;
    assert_eq!(m.refresh(1).await.last, None);
    assert_eq!(script.calls(), 0);
    drop(inner);
    assert!(m.is_suspended());
    let cancel = CancellationToken::new();
    assert_eq!(
        m.adopt_baseline(1, None, &cancel).await,
        Ok(ip("198.51.100.1"))
    );
    let mut rx = m.subscribe();
    rx.borrow_and_update();
    m.invalidate_baseline();
    assert!(rx.has_changed().unwrap());
    let e = rx.borrow_and_update().clone();
    assert_eq!((e.baseline, e.verdict), (None, IpVerdict::NotChecked));
    drop(outer);
    assert!(!m.is_suspended());
    m.inner.tick(1).await;
    assert_eq!(script.calls(), 2);
    m.stop();
}

/// Rebaselines never overlap (the second write would win with a stale value).
#[tokio::test]
async fn adoptions_are_serialised() {
    let script = Script::slow(&[Some("198.51.100.1"), Some("198.51.100.2")], 100);
    let m = monitor(&script);
    m.start(1, TUN, DEFAULT_INTERVAL);
    let cancel = CancellationToken::new();
    let (a, b) = tokio::join!(
        m.adopt_baseline(1, None, &cancel),
        m.adopt_baseline(1, None, &cancel)
    );
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(script.max_in_flight.load(Ordering::SeqCst), 1);
    assert_eq!(m.evidence().baseline, Some(ip("198.51.100.2")));
    cancel.cancel();
    assert_eq!(
        m.adopt_baseline(1, None, &cancel).await,
        Err(AdoptError::Cancelled)
    );
    m.stop();
}

/// AT-07-012: the same period does not reschedule, a new one does (once); the background
/// read runs after one period.
#[tokio::test]
async fn interval_changes_and_background_reads() {
    let script = Script::new(&[Some("198.51.100.1")]);
    let m = monitor(&script);
    assert!(!m.set_interval(DEFAULT_INTERVAL));
    assert!(
        m.set_interval(Duration::from_secs(1)),
        "clamped to 5 s, a change"
    );
    assert!(!m.set_interval(MIN_INTERVAL));
    assert!(m.set_interval(Duration::from_secs(3600)));
    assert_eq!(*m.inner.interval.borrow(), MAX_INTERVAL);
    m.start(1, TUN, MIN_INTERVAL);
    tokio::time::sleep(Duration::from_millis(4500)).await;
    assert_eq!(script.calls(), 0, "no immediate read on start");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(script.calls(), 1);
    assert_eq!(
        m.evidence().verdict,
        IpVerdict::NotChecked,
        "no baseline yet"
    );
    m.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!m.inner.timer_armed());
}

/// Protected transition: no proven routes → 3 waits, then the baseline is invalidated;
/// proven routes → one fresh adoption.
#[tokio::test]
async fn adoption_after_a_protected_transition() {
    let script = Script::new(&[Some("198.51.100.1"), Some("198.51.100.5")]);
    let m = monitor(&script);
    m.start(1, TUN, DEFAULT_INTERVAL);
    let cancel = CancellationToken::new();
    m.adopt_baseline(1, None, &cancel).await.unwrap();
    let started = Instant::now();
    assert_eq!(
        m.adopt_after_transition(1, || false, &cancel).await,
        Err(AdoptError::NoSample)
    );
    assert!(started.elapsed() >= Duration::from_millis(1400));
    assert_eq!(m.evidence().baseline, None);
    assert_eq!(script.calls(), 1);
    assert_eq!(
        m.adopt_after_transition(1, || true, &cancel).await,
        Ok(ip("198.51.100.5"))
    );
    m.stop();
}

/// Tunnel side of auto-verify: scripted connection id, route answers and self-test.
struct Env {
    current: Mutex<ConnId>,
    routes: Mutex<VecDeque<bool>>,
    leak: SelfTestResult,
    /// Connection id to switch to while the self-test runs.
    switch_to: Option<ConnId>,
    self_tests: AtomicUsize,
}

impl Env {
    fn new(leak: SelfTestResult) -> Env {
        Env {
            current: Mutex::new(1),
            routes: Mutex::new(VecDeque::new()),
            leak,
            switch_to: None,
            self_tests: AtomicUsize::new(0),
        }
    }
}

impl VerifyEnv for Env {
    fn is_current(&self, conn: ConnId) -> bool {
        *self.current.lock() == conn
    }
    fn routes_active(&self) -> bool {
        self.routes.lock().pop_front().unwrap_or(true)
    }
    fn self_test(&self) -> BoxFuture<'_, SelfTestResult> {
        async move {
            self.self_tests.fetch_add(1, Ordering::SeqCst);
            if let Some(conn) = self.switch_to {
                *self.current.lock() = conn;
            }
            self.leak.clone()
        }
        .boxed()
    }
}

fn clean(default: &str) -> SelfTestResult {
    let mut r = crate::leak::self_test::tests::complete();
    r.default_v4 = default.parse().ok();
    r
}

/// Baseline 198.51.100.1 adopted, then the exit changed: verdict indeterminate.
async fn indeterminate(script: &Arc<Script>) -> IpMonitor {
    let m = monitor(script);
    m.start(1, TUN, DEFAULT_INTERVAL);
    m.adopt_baseline(1, None, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(m.refresh(1).await.verdict, IpVerdict::Indeterminate);
    m
}

/// AT-07-001/005/006 (indeterminateIpAutoVerify): a clean self-test plus a confirming sample
/// adopts the self-test's exit; the sample is pinned to its family.
#[tokio::test]
async fn auto_verify_adopts_the_measured_exit() {
    let script = Script::new(&[
        Some("198.51.100.1"),
        Some("13.143.214.3"),
        Some("13.143.214.3"),
    ]);
    let m = indeterminate(&script).await;
    let env = Env::new(clean("13.143.214.3"));
    let cancel = CancellationToken::new();
    assert_eq!(
        m.auto_verify(1, &env, &cancel).await,
        VerifyOutcome::Adopted(ip("13.143.214.3"))
    );
    let e = m.evidence();
    assert_eq!(
        (e.baseline, e.verdict),
        (Some(ip("13.143.214.3")), IpVerdict::Passed)
    );
    assert_eq!(script.families.lock().last(), Some(&Family::V4));
    m.stop();
}

/// AT-00-008: incomplete or leaking self-tests never adopt (no extra read).
#[tokio::test]
async fn auto_verify_safety_gate() {
    let script = Script::new(&[Some("198.51.100.1"), Some("13.143.214.3")]);
    let m = indeterminate(&script).await;
    let cancel = CancellationToken::new();
    let mut cases = Vec::new();
    let mut r = clean("13.143.214.3");
    r.probes.clear();
    cases.push(r);
    let mut r = clean("13.143.214.3");
    r.probes[0].reach = crate::leak::Reach::Inconclusive {
        curl_exit: Some(-1),
        why: crate::leak::Why::Curl,
    };
    cases.push(r);
    cases.push(clean("999.1.2.3"));
    let mut r = clean("13.143.214.3");
    r.inspection_complete = false;
    cases.push(r);
    let mut r = clean("13.143.214.3");
    r.probes[0].reach = crate::leak::Reach::Reached { ip: ip("5.6.7.8") };
    cases.push(r);
    let mut r = clean("13.143.214.3");
    r.services_disagree = Some(crate::leak::Disagreement {
        other_service_ip: ip("5.6.7.8"),
        default_ip: ip("13.143.214.3"),
    });
    cases.push(r);
    for leak in cases {
        let outcome = m.auto_verify(1, &Env::new(leak), &cancel).await;
        assert!(
            matches!(outcome, VerifyOutcome::SafetyGate(_)),
            "{outcome:?}"
        );
    }
    assert_eq!(script.calls(), 2, "no rebaseline read");
    assert_eq!(m.evidence().verdict, IpVerdict::Indeterminate);
    m.stop();
}

/// Routes lost during the self-test, the connection changing, a mismatching sample, or a
/// verdict that is not indeterminate: no adoption; early returns do not latch.
#[tokio::test]
async fn auto_verify_guards() {
    let script = Script::new(&[
        Some("198.51.100.1"),
        Some("13.143.214.3"),
        Some("198.51.100.99"),
        Some("13.143.214.3"),
    ]);
    let m = indeterminate(&script).await;
    let cancel = CancellationToken::new();
    let env = Env::new(clean("13.143.214.3"));
    env.routes.lock().extend([true, false]);
    assert_eq!(
        m.auto_verify(1, &env, &cancel).await,
        VerifyOutcome::RoutesInactive
    );
    let mut env = Env::new(clean("13.143.214.3"));
    env.switch_to = Some(2);
    assert_eq!(m.auto_verify(1, &env, &cancel).await, VerifyOutcome::Stale);
    assert_eq!(script.calls(), 2);
    let env = Env::new(clean("13.143.214.3"));
    assert_eq!(
        m.auto_verify(1, &env, &cancel).await,
        VerifyOutcome::Rejected
    );
    assert_eq!(m.evidence().baseline, Some(ip("198.51.100.1")));
    assert_eq!(
        m.auto_verify(1, &env, &cancel).await,
        VerifyOutcome::Adopted(ip("13.143.214.3"))
    );
    assert_eq!(
        m.auto_verify(1, &env, &cancel).await,
        VerifyOutcome::NotNeeded,
        "verdict is passed now"
    );
    assert_eq!(env.self_tests.load(Ordering::SeqCst), 2);
    m.inner.verifying.store(true, Ordering::SeqCst);
    assert_eq!(m.auto_verify(1, &env, &cancel).await, VerifyOutcome::Busy);
    m.stop();
}
