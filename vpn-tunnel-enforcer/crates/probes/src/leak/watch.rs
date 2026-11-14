//! Background scheduling of the leak self-test: a periodic run, event-triggered runs (network
//! changes, the tunnel's own triggers) coalesced to one per 5 s, suppression around tunnel
//! transitions, and a gate ("protection is expected now") checked before a run starts and
//! again before its result is reported.
//!
//! WHY coalescing: re-associating to Wi-Fi flaps the network several times a second and would
//! queue a dozen redundant runs. WHY suppression: during a start or stop the bound probes race
//! the adapter and route changes and report garbage. Manual runs ([`SelfTester::run`]) are not
//! gated: diagnostics stay available while disconnected.
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::KillSwitchLevel;
use vpnte_winnet::adapters::NetChange;

use super::self_test::{SelfTestResult, SelfTestVerdict, SelfTester, verdict};

/// Timing of the background runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchConfig {
    /// Period of the background run; the first one comes after a full period.
    pub every: Duration,
    /// Minimum gap between two accepted event triggers.
    pub coalesce: Duration,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            every: Duration::from_secs(30),
            coalesce: Duration::from_secs(5),
        }
    }
}

/// A finished background run, delivered only while the gate is still open. The tunnel reacts:
/// `Leak` → alarm; `PossibleLeak` → amber notice; `Ok` → may auto-verify an indeterminate exit;
/// `Inconclusive` → nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakEvent {
    /// `periodic`, `network-change` or the trigger's reason.
    pub reason: &'static str,
    pub verdict: SelfTestVerdict,
    pub result: SelfTestResult,
}

type Gate = Box<dyn Fn() -> bool + Send + Sync>;
type Level = Box<dyn Fn() -> KillSwitchLevel + Send + Sync>;

struct Shared {
    tester: Arc<SelfTester>,
    config: WatchConfig,
    gate: Gate,
    kill_switch: Level,
    suppressed_until: Mutex<Option<Instant>>,
    events: broadcast::Sender<LeakEvent>,
}

impl Shared {
    fn suppressed(&self) -> bool {
        self.suppressed_until
            .lock()
            .is_some_and(|until| Instant::now() < until)
    }
}

/// Handle of the background loop; dropping it stops the loop and any run in flight.
pub struct LeakWatch {
    shared: Arc<Shared>,
    triggers: mpsc::UnboundedSender<&'static str>,
    stop: CancellationToken,
}

impl LeakWatch {
    /// Starts the loop. `gate` answers "is protection expected now?"; `kill_switch` the level
    /// the runs are judged against; `net_changes` (winnet `watch_network`, already debounced)
    /// triggers a run per change. Runtime.
    pub fn spawn(
        tester: Arc<SelfTester>,
        config: WatchConfig,
        gate: impl Fn() -> bool + Send + Sync + 'static,
        kill_switch: impl Fn() -> KillSwitchLevel + Send + Sync + 'static,
        net_changes: Option<mpsc::Receiver<NetChange>>,
    ) -> LeakWatch {
        let (triggers, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            tester,
            config,
            gate: Box::new(gate),
            kill_switch: Box::new(kill_switch),
            suppressed_until: Mutex::new(None),
            events: broadcast::channel(16).0,
        });
        let stop = CancellationToken::new();
        tokio::spawn(run_loop(shared.clone(), rx, net_changes, stop.clone()));
        LeakWatch {
            shared,
            triggers,
            stop,
        }
    }

    /// Finished background runs.
    pub fn subscribe(&self) -> broadcast::Receiver<LeakEvent> {
        self.shared.events.subscribe()
    }

    /// Asks for a run soon (ignored while suppressed, gated off, or within 5 s of the last).
    pub fn trigger(&self, reason: &'static str) {
        let _ = self.triggers.send(reason);
    }

    /// No background run for `duration` (extends, never shortens); stops the run in flight.
    pub fn suppress(&self, duration: Duration) {
        {
            let mut until = self.shared.suppressed_until.lock();
            let candidate = Instant::now() + duration;
            *until = Some(until.map_or(candidate, |u| u.max(candidate)));
        }
        self.shared.tester.stop_all();
    }
}

impl Drop for LeakWatch {
    fn drop(&mut self) {
        self.stop.cancel();
        self.shared.tester.stop_all();
    }
}

async fn run_loop(
    shared: Arc<Shared>,
    mut triggers: mpsc::UnboundedReceiver<&'static str>,
    mut net_changes: Option<mpsc::Receiver<NetChange>>,
    stop: CancellationToken,
) {
    let mut next_periodic = Instant::now() + shared.config.every;
    let mut last_trigger: Option<Instant> = None;
    loop {
        let net_next = async {
            match net_changes.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        let (reason, triggered, net_closed) = tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            reason = triggers.recv() => match reason {
                Some(reason) => (reason, true, false),
                None => return,
            },
            change = net_next => match change {
                Some(change) => {
                    tracing::debug!(kind = ?change.kind(), "leak self-test: network changed");
                    ("network-change", true, false)
                }
                None => ("", false, true),
            },
            _ = tokio::time::sleep_until(next_periodic) => {
                next_periodic = Instant::now() + shared.config.every;
                ("periodic", false, false)
            }
        };
        if net_closed {
            net_changes = None;
            continue;
        }
        if shared.suppressed() {
            tracing::debug!(reason, "leak self-test: run suppressed during transition");
            continue;
        }
        if !(shared.gate)() {
            continue;
        }
        if triggered {
            let now = Instant::now();
            if last_trigger.is_some_and(|t| now.duration_since(t) < shared.config.coalesce) {
                tracing::debug!(reason, "leak self-test: trigger coalesced");
                continue;
            }
            last_trigger = Some(now);
        }
        let result = shared.tester.run((shared.kill_switch)(), &stop).await;
        // A run stopped by a transition, or finished after protection was disarmed, must not
        // raise an alarm against a user who is tearing the tunnel down.
        if result.cancelled || stop.is_cancelled() || shared.suppressed() || !(shared.gate)() {
            continue;
        }
        let verdict = verdict(&result);
        let reached = result.reached().count();
        match verdict {
            SelfTestVerdict::Ok => {
                tracing::info!(
                    reason,
                    ?verdict,
                    probes = result.probes.len(),
                    "leak self-test"
                )
            }
            _ => tracing::warn!(
                reason,
                ?verdict,
                probes = result.probes.len(),
                reached,
                complete = result.inspection_complete,
                "leak self-test"
            ),
        }
        let _ = shared.events.send(LeakEvent {
            reason,
            verdict,
            result,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::super::self_test::tests::{FakeEnv, exit};
    use super::*;

    fn watch(env: &Arc<FakeEnv>, every_ms: u64, gate: &Arc<AtomicBool>) -> LeakWatch {
        let tester = Arc::new(SelfTester::new(Arc::new(env.clone())));
        let config = WatchConfig {
            every: Duration::from_millis(every_ms),
            coalesce: Duration::from_millis(300),
        };
        let gate = gate.clone();
        LeakWatch::spawn(
            tester,
            config,
            move || gate.load(Ordering::SeqCst),
            || KillSwitchLevel::Standard,
            None,
        )
    }

    fn runs(env: &FakeEnv) -> usize {
        // default read + one cross-check + one bound probe per run on the clean fixture
        env.calls.load(Ordering::SeqCst) / 3
    }

    /// AT-07-002: with the gate closed nothing runs (periodic or triggered); open, the periodic
    /// run reports its verdict.
    #[tokio::test]
    async fn gate_controls_background_runs() {
        let env = Arc::new(FakeEnv::clean());
        let gate = Arc::new(AtomicBool::new(false));
        let w = watch(&env, 100, &gate);
        let mut events = w.subscribe();
        w.trigger("network-change");
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert_eq!(env.calls.load(Ordering::SeqCst), 0);
        gate.store(true, Ordering::SeqCst);
        let event = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (event.reason, event.verdict),
            ("periodic", SelfTestVerdict::Ok)
        );
        drop(w);
        let after = env.calls.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            env.calls.load(Ordering::SeqCst),
            after,
            "a dropped watch runs nothing"
        );
    }

    /// Triggers within the coalescing window collapse into one run; suppression skips runs.
    #[tokio::test]
    async fn triggers_coalesce_and_suppression_skips() {
        let env = Arc::new(FakeEnv::clean());
        let gate = Arc::new(AtomicBool::new(true));
        let w = watch(&env, 60_000, &gate);
        let mut events = w.subscribe();
        w.trigger("network-change");
        w.trigger("network-change");
        let first = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.reason, "network-change");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(runs(&env), 1);
        tokio::time::sleep(Duration::from_millis(300)).await;
        w.suppress(Duration::from_secs(5));
        w.trigger("test-start");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(runs(&env), 1, "suppressed");
    }

    /// AT-07-002: an event run that finds a reach reports a leak once.
    #[tokio::test]
    async fn leak_is_reported() {
        let env = Arc::new(FakeEnv::clean());
        env.by_bind
            .lock()
            .insert("192.168.1.2".parse().unwrap(), exit(Some(0), "ip=5.6.7.8"));
        let gate = Arc::new(AtomicBool::new(true));
        let w = watch(&env, 60_000, &gate);
        let mut events = w.subscribe();
        w.trigger("network-change");
        let event = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.verdict, SelfTestVerdict::Leak);
        assert_eq!(event.result.reached().count(), 1);
    }
}
