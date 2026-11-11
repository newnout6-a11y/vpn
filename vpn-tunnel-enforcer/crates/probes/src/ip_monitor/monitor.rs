//! The running monitor: one state behind a lock, the periodic read task, rebaselines and the
//! suspend guard of protected transitions.
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_core::redact;

use crate::leak::{SelfTestResult, SelfTestVerdict};
use crate::public_ip::{Family, IpRoute, IpSample};

use super::{
    AdoptError, ConnId, DEFAULT_INTERVAL, IpEvidence, IpVerdict, MAX_INTERVAL, MIN_INTERVAL,
    Sampler, verdict,
};

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

/// Shared by the handle and the timer task; the tests drive it directly (`pub(super)`).
pub(super) struct Inner {
    sampler: Arc<dyn Sampler>,
    state: Mutex<State>,
    tx: watch::Sender<IpEvidence>,
    pub(super) interval: watch::Sender<Duration>,
    adopt: tokio::sync::Mutex<()>,
    pub(super) verifying: AtomicBool,
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
    /// Whether the periodic read task is armed (tests).
    #[cfg(test)]
    pub(super) fn timer_armed(&self) -> bool {
        self.state.lock().timer.is_some()
    }

    pub(super) async fn tick(&self, conn: ConnId) {
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
    pub(super) inner: Arc<Inner>,
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
