//! The public-IP monitor: one evidence store (adopted VPN exit, the user's home IP, the latest
//! sample, the verdict) and the periodic task that keeps it current.
//!
//! Field lessons kept from the old monitor:
//! - a different exit than the baseline is NOT a leak (rotation, anycast, split routes): it is
//!   `Indeterminate` and gets verified independently (leak self-test + family-pinned rebaseline);
//! - the one thing a public-IP read can prove is the user's real ISP address showing up while
//!   connected: that is `Failed` (B-IP-1), and such a sample is never adopted as baseline (B-IP-2);
//! - a read that fails is `NotChecked`, never a reused cached verdict (B-IP-7);
//! - during a protected transition (stop, profile swap) reads are aborted and the monitor stays
//!   silent, otherwise the user's real IP read while tearing down would raise a false alarm;
//!   only the tunnel suspends it, through an RAII guard (B-IP-8);
//! - rebaselines are serialised: two concurrent adopters would race on the baseline.
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Verdict;
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::redact;

use crate::leak::{SelfTestResult, SelfTestVerdict};
use crate::public_ip::{Family, IpReader, IpRoute, IpSample, WAVE_BUDGET};

/// Identifies one tunnel connection (any value the tunnel never reuses).
pub type ConnId = u64;

/// Default period of the background read.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);
/// Allowed period range (settings field in seconds, 5–300).
pub const MIN_INTERVAL: Duration = Duration::from_secs(5);
/// See [`MIN_INTERVAL`].
pub const MAX_INTERVAL: Duration = Duration::from_secs(300);

/// What the latest public-IP read says about the protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpVerdict {
    /// The read through the tunnel shows the adopted VPN exit.
    Passed,
    /// Another exit than the adopted one: not proof of a leak, to be verified.
    Indeterminate,
    /// No baseline yet, the read failed, or the monitor is stopped.
    #[default]
    NotChecked,
    /// The read shows the user's real (pre-connect) public IP.
    Failed,
}

impl IpVerdict {
    /// The app-wide verdict scale (`Indeterminate` is a warning, never `Ok`).
    pub fn verdict(self) -> Verdict {
        match self {
            IpVerdict::Passed => Verdict::Ok,
            IpVerdict::Indeterminate => Verdict::Warn,
            IpVerdict::NotChecked => Verdict::NotChecked,
            IpVerdict::Failed => Verdict::Fail,
        }
    }

    /// Short user-facing label.
    pub fn label(self) -> Msg {
        Msg::new(match self {
            IpVerdict::Passed => "probes.ip.verdict.passed",
            IpVerdict::Indeterminate => "probes.ip.verdict.indeterminate",
            IpVerdict::NotChecked => "probes.ip.verdict.notChecked",
            IpVerdict::Failed => "probes.ip.verdict.failed",
        })
    }
}

/// Verdict of one sample: equal to the baseline → `Passed`; equal to the user's real IP (and
/// not the baseline) → `Failed`; no baseline → `NotChecked`; any other exit → `Indeterminate`.
pub fn verdict(sample: IpAddr, baseline: Option<IpAddr>, real_ip: Option<IpAddr>) -> IpVerdict {
    if baseline == Some(sample) {
        IpVerdict::Passed
    } else if real_ip == Some(sample) {
        IpVerdict::Failed
    } else if baseline.is_none() {
        IpVerdict::NotChecked
    } else {
        IpVerdict::Indeterminate
    }
}

/// Snapshot of the monitor for the UI, the tray and the tunnel.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpEvidence {
    /// Adopted VPN exit of the current connection.
    pub baseline: Option<IpAddr>,
    /// The user's public IP measured before the tunnel came up (home IP).
    pub real_ip: Option<IpAddr>,
    /// Latest successful read; may be older than the latest attempt (see `fresh`).
    pub last: Option<IpSample>,
    /// True when the latest attempt produced `last`.
    pub fresh: bool,
    pub verdict: IpVerdict,
}

impl IpEvidence {
    /// Equal for subscribers: everything but the time and provider of the same address.
    fn same_view(&self, other: &IpEvidence) -> bool {
        self.baseline == other.baseline
            && self.real_ip == other.real_ip
            && self.last.map(|s| s.ip) == other.last.map(|s| s.ip)
            && self.fresh == other.fresh
            && self.verdict == other.verdict
    }
}

/// Source of public-IP samples: the provider race in production, a script in tests.
pub trait Sampler: Send + Sync + 'static {
    /// One read of `family` over `route` (see [`IpReader::wave`]).
    fn sample<'a>(
        &'a self,
        route: &'a IpRoute,
        family: Family,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Option<IpSample>>;
}

impl Sampler for IpReader {
    fn sample<'a>(
        &'a self,
        route: &'a IpRoute,
        family: Family,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Option<IpSample>> {
        self.wave(route, family, WAVE_BUDGET, cancel).boxed()
    }
}

/// Why a baseline was not adopted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdoptError {
    #[error("no provider answered")]
    NoSample,
    #[error("the sample differs from the expected exit")]
    Mismatch { seen: IpAddr },
    #[error("the sample is the user's real IP")]
    RealIp,
    #[error("cancelled")]
    Cancelled,
    #[error("the connection or the read went stale")]
    Stale,
}

impl From<AdoptError> for AppError {
    fn from(err: AdoptError) -> Self {
        match err {
            AdoptError::Cancelled => AppError::cancelled(),
            AdoptError::NoSample => {
                AppError::msg(ErrorKind::Network, Msg::new("probes.ip.adopt.noSample"))
            }
            AdoptError::Mismatch { .. } => AppError::conflict(Msg::new("probes.ip.adopt.mismatch")),
            AdoptError::RealIp => AppError::conflict(Msg::new("probes.ip.adopt.realIp")),
            AdoptError::Stale => AppError::conflict(Msg::new("probes.ip.adopt.stale")),
        }
    }
}

/// The current connection: who the reads belong to and how they leave.
#[derive(Debug, Clone)]
struct Session {
    conn: ConnId,
    route: IpRoute,
}

struct State {
    session: Option<Session>,
    evidence: IpEvidence,
    suspended: u32,
    /// Cancelled (and replaced) to abort every in-flight read.
    reads: CancellationToken,
    /// Bumped with `reads`: a read that started in an older epoch is dropped.
    epoch: u64,
    timer: Option<CancellationToken>,
    last_alive: Option<Instant>,
}

impl State {
    fn abort_reads(&mut self) {
        self.reads.cancel();
        self.reads = CancellationToken::new();
        self.epoch += 1;
    }

    fn family(&self) -> Family {
        self.evidence.baseline.map_or(Family::V4, Family::of)
    }
}

struct Inner {
    sampler: Arc<dyn Sampler>,
    state: Mutex<State>,
    tx: watch::Sender<IpEvidence>,
    interval: watch::Sender<Duration>,
    adopt: tokio::sync::Mutex<()>,
    verifying: AtomicBool,
}

/// Outcome of one read attempt as seen by the monitor.
enum Read {
    Sampled(IpSample),
    Failed,
    Stale,
    Cancelled,
}

impl Inner {
    /// Publishes the evidence when it changed for subscribers.
    fn publish(&self, evidence: &IpEvidence) {
        self.tx.send_if_modified(|current| {
            if current.same_view(evidence) {
                false
            } else {
                *current = evidence.clone();
                true
            }
        });
    }

    async fn read(&self, conn: ConnId, family: Family, cancel: &CancellationToken) -> Read {
        let (route, reads, epoch) = {
            let state = self.state.lock();
            match &state.session {
                Some(session) if session.conn == conn => {}
                _ => return Read::Stale,
            }
            let route = state.session.as_ref().map(|s| s.route.clone());
            (route, state.reads.clone(), state.epoch)
        };
        let Some(route) = route else {
            return Read::Stale;
        };
        let sample = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Read::Cancelled,
            _ = reads.cancelled() => return Read::Stale,
            sample = self.sampler.sample(&route, family, &reads) => sample,
        };
        let state = self.state.lock();
        let current =
            state.epoch == epoch && state.session.as_ref().is_some_and(|s| s.conn == conn);
        match (current, sample) {
            (false, _) => Read::Stale,
            (true, Some(sample)) => Read::Sampled(sample),
            (true, None) => Read::Failed,
        }
    }

    /// Records a sample read over the session's route and recomputes the verdict.
    fn observe(&self, sample: IpSample) -> IpEvidence {
        let mut state = self.state.lock();
        let via_tun = state.session.as_ref().is_some_and(|s| s.route.is_tun());
        let e = &mut state.evidence;
        e.last = Some(sample);
        e.fresh = true;
        e.verdict = verdict(sample.ip, e.baseline, e.real_ip);
        // Liveness only from a proven tunnel path showing the adopted exit (B-IP-4).
        if via_tun && e.verdict == IpVerdict::Passed {
            state.last_alive = Some(Instant::now());
        }
        let snapshot = state.evidence.clone();
        drop(state);
        self.publish(&snapshot);
        snapshot
    }

    /// The attempt failed: the verdict is unknown again, the old sample stays but is stale.
    fn unknown(&self) -> IpEvidence {
        let mut state = self.state.lock();
        state.evidence.fresh = false;
        state.evidence.verdict = IpVerdict::NotChecked;
        let snapshot = state.evidence.clone();
        drop(state);
        self.publish(&snapshot);
        snapshot
    }

    fn snapshot(&self) -> IpEvidence {
        self.state.lock().evidence.clone()
    }

    /// One background read: skipped while suspended, family pinned to the baseline (B-IP-3).
    async fn tick(&self, conn: ConnId) {
        let (family, reads) = {
            let state = self.state.lock();
            if state.suspended > 0 {
                return;
            }
            (state.family(), state.reads.clone())
        };
        match self.read(conn, family, &reads).await {
            Read::Sampled(sample) => {
                self.observe(sample);
            }
            Read::Failed => {
                self.unknown();
            }
            Read::Stale | Read::Cancelled => {}
        }
    }
}

/// The public-IP monitor (cheap to clone; one per app).
#[derive(Clone)]
pub struct IpMonitor {
    inner: Arc<Inner>,
}

impl IpMonitor {
    /// A stopped monitor reading through `sampler` (production: `Arc::new(IpReader::new())`).
    pub fn new(sampler: Arc<dyn Sampler>) -> Self {
        let state = State {
            session: None,
            evidence: IpEvidence::default(),
            suspended: 0,
            reads: CancellationToken::new(),
            epoch: 0,
            timer: None,
            last_alive: None,
        };
        Self {
            inner: Arc::new(Inner {
                sampler,
                state: Mutex::new(state),
                tx: watch::Sender::new(IpEvidence::default()),
                interval: watch::Sender::new(DEFAULT_INTERVAL),
                adopt: tokio::sync::Mutex::new(()),
                verifying: AtomicBool::new(false),
            }),
        }
    }

    /// Starts monitoring connection `conn` over `route`, reading every `every` (clamped to
    /// 5–300 s; the first background read after one period). Drops the previous baseline;
    /// the tunnel adopts a new one with [`IpMonitor::adopt_baseline`]. Runtime.
    pub fn start(&self, conn: ConnId, route: IpRoute, every: Duration) {
        let token = CancellationToken::new();
        let snapshot = {
            let mut state = self.inner.state.lock();
            if let Some(old) = state.timer.replace(token.clone()) {
                old.cancel();
            }
            state.abort_reads();
            state.session = Some(Session { conn, route });
            state.evidence.baseline = None;
            state.evidence.fresh = false;
            state.evidence.verdict = IpVerdict::NotChecked;
            state.evidence.clone()
        };
        self.set_interval(every);
        self.inner.publish(&snapshot);
        tokio::spawn(timer(
            Arc::downgrade(&self.inner),
            conn,
            token,
            self.inner.interval.subscribe(),
        ));
    }

    /// Stops the background reads, aborts reads in flight and drops the baseline. The home IP
    /// and the last sample stay (the sample is marked stale).
    pub fn stop(&self) {
        let snapshot = {
            let mut state = self.inner.state.lock();
            if let Some(timer) = state.timer.take() {
                timer.cancel();
            }
            state.abort_reads();
            state.session = None;
            state.evidence.baseline = None;
            state.evidence.fresh = false;
            state.evidence.verdict = IpVerdict::NotChecked;
            state.evidence.clone()
        };
        self.inner.publish(&snapshot);
    }

    /// Changes the background period (clamped to 5–300 s). Returns true when the timer was
    /// rescheduled; the same period changes nothing (AT-07-012).
    pub fn set_interval(&self, every: Duration) -> bool {
        let every = every.clamp(MIN_INTERVAL, MAX_INTERVAL);
        self.inner.interval.send_if_modified(|current| {
            let changed = *current != every;
            *current = every;
            changed
        })
    }

    /// User "refresh": one read of the current connection (family pinned to the baseline),
    /// never adopts (B-LT-8). While suspended or for another connection it returns the stored
    /// evidence without a read.
    pub async fn refresh(&self, conn: ConnId) -> IpEvidence {
        let (family, reads) = {
            let state = self.inner.state.lock();
            if state.suspended > 0 {
                return state.evidence.clone();
            }
            (state.family(), state.reads.clone())
        };
        match self.inner.read(conn, family, &reads).await {
            Read::Sampled(sample) => self.inner.observe(sample),
            Read::Failed => self.inner.unknown(),
            Read::Stale | Read::Cancelled => self.inner.snapshot(),
        }
    }

    /// Adopts a fresh sample of connection `conn` as its VPN exit. Serialised with other
    /// adoptions and allowed while suspended (it ends a protected transition). With `expected`
    /// the read is pinned to its family and must equal it. A sample equal to the user's real
    /// IP is refused and turns the verdict `Failed` (B-IP-2). Only the tunnel calls this, after
    /// it proved the TUN routes.
    pub async fn adopt_baseline(
        &self,
        conn: ConnId,
        expected: Option<IpAddr>,
        cancel: &CancellationToken,
    ) -> Result<IpAddr, AdoptError> {
        let _serial = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(AdoptError::Cancelled),
            guard = self.inner.adopt.lock() => guard,
        };
        let family = expected.map_or(Family::V4, Family::of);
        let sample = match self.inner.read(conn, family, cancel).await {
            Read::Sampled(sample) => sample,
            Read::Failed => {
                self.inner.unknown();
                return Err(AdoptError::NoSample);
            }
            Read::Stale => return Err(AdoptError::Stale),
            Read::Cancelled => return Err(AdoptError::Cancelled),
        };
        let (result, snapshot) = {
            let mut state = self.inner.state.lock();
            let via_tun = state.session.as_ref().is_some_and(|s| s.route.is_tun());
            let e = &mut state.evidence;
            e.last = Some(sample);
            e.fresh = true;
            let result = if e.real_ip == Some(sample.ip) {
                e.verdict = IpVerdict::Failed;
                Err(AdoptError::RealIp)
            } else if expected.is_some_and(|ip| ip != sample.ip) {
                e.verdict = IpVerdict::Indeterminate;
                Err(AdoptError::Mismatch { seen: sample.ip })
            } else {
                e.baseline = Some(sample.ip);
                e.verdict = IpVerdict::Passed;
                Ok(sample.ip)
            };
            if result.is_ok() && via_tun {
                state.last_alive = Some(Instant::now());
            }
            (result, state.evidence.clone())
        };
        self.inner.publish(&snapshot);
        result
    }

    /// Records the user's public IP measured before the tunnel came up (tunnel lifecycle).
    pub fn set_real_ip(&self, ip: Option<IpAddr>) {
        let snapshot = {
            let mut state = self.inner.state.lock();
            state.evidence.real_ip = ip;
            state.evidence.clone()
        };
        self.inner.publish(&snapshot);
    }

    /// Forgets the baseline (the exit is about to change) and aborts reads in flight.
    pub fn invalidate_baseline(&self) {
        let snapshot = {
            let mut state = self.inner.state.lock();
            state.abort_reads();
            state.evidence.baseline = None;
            state.evidence.verdict = IpVerdict::NotChecked;
            state.evidence.clone()
        };
        self.inner.publish(&snapshot);
    }

    /// Silences the monitor for a protected transition: aborts reads in flight, skips
    /// background reads and refreshes until every guard is dropped. Guards nest.
    pub fn suspend(&self) -> SuspendGuard {
        let mut state = self.inner.state.lock();
        state.suspended += 1;
        state.abort_reads();
        SuspendGuard {
            inner: self.inner.clone(),
        }
    }

    /// True while at least one [`SuspendGuard`] lives.
    pub fn is_suspended(&self) -> bool {
        self.inner.state.lock().suspended > 0
    }

    /// Current evidence.
    pub fn evidence(&self) -> IpEvidence {
        self.inner.snapshot()
    }

    /// Evidence changes (address, verdict, baseline, home IP or freshness).
    pub fn subscribe(&self) -> watch::Receiver<IpEvidence> {
        self.inner.tx.subscribe()
    }

    /// When a read through the TUN-bound route last showed the adopted exit: the only public-IP
    /// evidence the watchdog may count as "the tunnel carries traffic" (B-IP-4).
    pub fn last_alive(&self) -> Option<Instant> {
        self.inner.state.lock().last_alive
    }

    /// After a protected restart (server swap): up to 3 rounds of "routes proven? adopt a fresh
    /// sample (no expected IP: never wait for the dead old exit, never adopt a cached one)",
    /// 500 ms apart while the routes are not proven. Gives up with the baseline invalidated
    /// (`NotChecked`). `routes_active` errors must read as false.
    pub async fn adopt_after_transition(
        &self,
        conn: ConnId,
        routes_active: impl Fn() -> bool,
        cancel: &CancellationToken,
    ) -> Result<IpAddr, AdoptError> {
        let mut last = AdoptError::NoSample;
        for _ in 0..3 {
            if routes_active() {
                match self.adopt_baseline(conn, None, cancel).await {
                    Ok(ip) => return Ok(ip),
                    Err(err @ (AdoptError::Cancelled | AdoptError::Stale | AdoptError::RealIp)) => {
                        return Err(err);
                    }
                    Err(err) => last = err,
                }
            } else {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Err(AdoptError::Cancelled),
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                }
            }
        }
        tracing::warn!("protected transition IP baseline not checked");
        self.invalidate_baseline();
        Err(last)
    }

    /// Indeterminate-exit verification (exit changed: rotation, anycast): adopts the new exit
    /// only with independent evidence that the physical adapters cannot reach the Internet.
    /// Every step is bound to connection `conn` (after a restart the tunnel runs again, but its
    /// exit belongs to another connection). The adopted address is the one the self-test saw
    /// through the default route, confirmed by a fresh sample pinned to its family — never the
    /// candidate the monitor saw. One verification at a time; early returns do not latch.
    pub async fn auto_verify(
        &self,
        conn: ConnId,
        env: &dyn VerifyEnv,
        cancel: &CancellationToken,
    ) -> VerifyOutcome {
        if self.inner.verifying.swap(true, Ordering::AcqRel) {
            return VerifyOutcome::Busy;
        }
        let _reset = ResetOnDrop(&self.inner.verifying);
        if !env.is_current(conn) || self.evidence().verdict != IpVerdict::Indeterminate {
            return VerifyOutcome::NotNeeded;
        }
        if !env.routes_active() || !env.is_current(conn) {
            return VerifyOutcome::RoutesInactive;
        }
        let leak = tokio::select! {
            biased;
            _ = cancel.cancelled() => return VerifyOutcome::Cancelled,
            result = env.self_test() => result,
        };
        if !env.is_current(conn) {
            return VerifyOutcome::Stale;
        }
        let gate = crate::leak::verdict(&leak);
        let Some(verified) = leak.default_v4.filter(|_| gate == SelfTestVerdict::Ok) else {
            tracing::warn!(verdict = ?gate, complete = leak.inspection_complete,
                "indeterminate IP failed the leak self-test safety gate");
            return VerifyOutcome::SafetyGate(gate);
        };
        if !env.routes_active() || !env.is_current(conn) {
            tracing::warn!("TUN routes no longer active after leak self-test; aborting rebaseline");
            return VerifyOutcome::RoutesInactive;
        }
        let verified = IpAddr::V4(verified);
        match self.adopt_baseline(conn, Some(verified), cancel).await {
            Ok(ip) if ip == verified && env.is_current(conn) => {
                tracing::info!(verified = %redact::ip_pseudonym(ip), "indeterminate IP verified and adopted");
                VerifyOutcome::Adopted(ip)
            }
            Ok(_) | Err(AdoptError::Stale) => VerifyOutcome::Stale,
            Err(AdoptError::Cancelled) => VerifyOutcome::Cancelled,
            Err(err) => {
                tracing::warn!(reason = %err, "indeterminate IP sample mismatch; rejecting adoption");
                VerifyOutcome::Rejected
            }
        }
    }
}

/// What auto-verification needs from the tunnel runtime (the app implements it).
pub trait VerifyEnv: Send + Sync {
    /// True while connection `conn` is the running one.
    fn is_current(&self, conn: ConnId) -> bool;
    /// True when the TUN routes are proven active (errors read as false).
    fn routes_active(&self) -> bool;
    /// One leak self-test run (normally [`crate::leak::SelfTester::run`]).
    fn self_test(&self) -> BoxFuture<'_, SelfTestResult>;
}

/// How an auto-verification ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The self-test's default-route exit was confirmed by a fresh sample and adopted.
    Adopted(IpAddr),
    /// Another verification is running.
    Busy,
    /// Nothing to verify (verdict not indeterminate) or the connection is not running.
    NotNeeded,
    /// TUN routes not proven, before or after the self-test.
    RoutesInactive,
    /// The self-test did not prove the physical adapters blocked (or the exit unknown).
    SafetyGate(SelfTestVerdict),
    /// The fresh sample did not confirm the measured exit.
    Rejected,
    /// The connection changed meanwhile.
    Stale,
    Cancelled,
}

struct ResetOnDrop<'a>(&'a AtomicBool);

impl Drop for ResetOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Keeps the monitor suspended while alive; dropping it resumes (without an immediate read).
#[must_use = "the monitor resumes when the guard is dropped"]
pub struct SuspendGuard {
    inner: Arc<Inner>,
}

impl Drop for SuspendGuard {
    fn drop(&mut self) {
        let mut state = self.inner.state.lock();
        state.suspended = state.suspended.saturating_sub(1);
    }
}

/// Background reads of connection `conn` until `token` is cancelled or the monitor is gone.
async fn timer(
    inner: Weak<Inner>,
    conn: ConnId,
    token: CancellationToken,
    mut interval: watch::Receiver<Duration>,
) {
    let mut every = *interval.borrow_and_update();
    loop {
        tokio::select! {
            biased;
            _ = token.cancelled() => return,
            changed = interval.changed() => {
                if changed.is_err() {
                    return;
                }
                // A new period restarts the wait (AT-07-012).
                every = *interval.borrow_and_update();
            }
            _ = tokio::time::sleep(every) => {
                let Some(inner) = inner.upgrade() else { return };
                tokio::select! {
                    biased;
                    _ = token.cancelled() => return,
                    _ = inner.tick(conn) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicUsize;

    use super::*;

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
            tokio::spawn(
                async move { m2.adopt_baseline(1, None, &CancellationToken::new()).await },
            );
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
        assert!(m.inner.state.lock().timer.is_none());
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
}
