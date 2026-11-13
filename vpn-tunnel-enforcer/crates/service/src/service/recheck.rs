//! Re-checks of a held kill switch (RU audit item 11). On resume from sleep and on a network
//! change the watchdog's filter check runs at once instead of at its next 30 s tick (it repairs
//! what Windows dropped), and the leak self-test follows once routes have settled; while the kill
//! switch is on the self-test also runs every 30 s, and a leak triggers the filter check too.
//! Here and not in the app: with "Always" the session runs before any app does. One run lives
//! exactly while a session's filters are held, so an idle service keeps no timer and no network
//! watch.
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::KillSwitchLevel;
use vpnte_probes::leak::{
    LeakEvent, LeakWatch, SelfTestResult, SelfTestVerdict, SelfTester, WatchConfig,
};
use vpnte_winnet::adapters::NetChange;

/// Routes and adapter addresses settle after a wake or a network change before the probes run.
pub(super) const SETTLE: Duration = Duration::from_secs(3);

/// What one re-check run uses; shared by every run of the service.
pub(super) struct Recheck {
    /// The watchdog's filter check: blocking WFP work, run on the blocking pool.
    pub tick: Arc<dyn Fn() + Send + Sync>,
    pub tester: Arc<SelfTester>,
    pub config: WatchConfig,
    /// Self-tests run while this holds: a TUN session runs and the kill switch is on (with it
    /// off every run would read "possible leak").
    pub gate: Arc<dyn Fn() -> bool + Send + Sync>,
    /// The level a run is judged against.
    pub level: Arc<dyn Fn() -> KillSwitchLevel + Send + Sync>,
    /// The latest result of the held session (the pipe status carries it).
    pub results: watch::Sender<Option<SelfTestResult>>,
    pub settle: Duration,
}

impl Recheck {
    /// Runs until `cancel` (the filters were released): `resumes` counts wakes, `changes` is the
    /// debounced network-change stream.
    pub async fn run(
        self: Arc<Self>,
        mut resumes: watch::Receiver<u64>,
        mut changes: Option<mpsc::Receiver<NetChange>>,
        cancel: CancellationToken,
    ) {
        let (gate, level) = (self.gate.clone(), self.level.clone());
        let leaks = LeakWatch::spawn(
            self.tester.clone(),
            self.config,
            move || gate(),
            move || level(),
            None,
        );
        let mut events = leaks.subscribe();
        self.results.send_replace(None);
        loop {
            let why = tokio::select! {
                () = cancel.cancelled() => break,
                Ok(()) = resumes.changed() => "resume",
                Some(_) = next_change(&mut changes) => "network change",
                event = events.recv() => {
                    self.take(event).await;
                    continue;
                }
            };
            self.tick_now(why).await;
            tokio::select! {
                () = cancel.cancelled() => break,
                () = tokio::time::sleep(self.settle) => {}
            }
            leaks.trigger(why);
        }
        // Released: the result described filters that are gone now.
        self.results.send_replace(None);
    }

    /// A finished background run: published; a leak re-verifies the filters at once.
    async fn take(&self, event: Result<LeakEvent, broadcast::error::RecvError>) {
        let Ok(event) = event else {
            return;
        };
        match event.verdict {
            SelfTestVerdict::Leak => {
                tracing::error!(
                    reason = event.reason,
                    "leak self-test: traffic left outside the tunnel"
                );
                self.tick_now("leak").await;
            }
            SelfTestVerdict::PossibleLeak => {
                tracing::warn!(reason = event.reason, "leak self-test: possible leak");
            }
            verdict => tracing::debug!(reason = event.reason, ?verdict, "leak self-test"),
        }
        self.results.send_replace(Some(event.result));
    }

    /// The watchdog's filter check now, off the runtime.
    async fn tick_now(&self, why: &'static str) {
        tracing::info!(why, "kill-switch filters re-verified now");
        let tick = self.tick.clone();
        if tokio::task::spawn_blocking(move || tick()).await.is_err() {
            tracing::warn!("kill-switch filter check did not finish");
        }
    }
}

async fn next_change(changes: &mut Option<mpsc::Receiver<NetChange>>) -> Option<NetChange> {
    match changes {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests;
