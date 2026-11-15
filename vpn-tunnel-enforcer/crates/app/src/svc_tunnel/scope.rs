//! The app scope the running session started with (appsplit-b4/b5, p-follow3): «Только
//! выбранные приложения» applies from the next connection, so whatever labels or judges this run
//! (the background leak watch, the Maintenance self-test, the Apps page's pending line) reads
//! the scope the run started with, never the saved one. The run reports it (`TunStatus::
//! listed_only`, live2-a3: a crash restart of the helper service reuses its stored inputs); the
//! saved setting stands in only for a run that reports none (a service before protocol 5). The
//! tunnel service keeps the one copy (`Built::run_scope`).
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::watch;
use vpnte_base::types::UnixMs;
use vpnte_core::settings::{AppScope, Settings};
use vpnte_core::store::Store;
use vpnte_tunnel::api::TunStatus;

/// The run that started at `held.0` (`None`: nothing runs) and whether only the listed apps use
/// it.
#[derive(Clone, Default)]
pub struct RunScope {
    held: Arc<Mutex<(Option<UnixMs>, bool)>>,
    /// The runtime's status, where a run reports the scope it was built with.
    status: Option<watch::Receiver<TunStatus>>,
}

impl RunScope {
    /// A scope kept on the runs `status` shows, read the moment each run appears, until
    /// `status` closes.
    pub fn follow(status: watch::Receiver<TunStatus>, settings: Arc<Store<Settings>>) -> Self {
        let scope = Self {
            held: Arc::default(),
            status: Some(status.clone()),
        };
        tokio::spawn(follow(status, settings, scope.clone()));
        scope
    }

    /// The run that started at `started` (`None`: nothing runs): the scope it reports wins;
    /// a run that reports none reads `saved` when it is first seen and keeps it. Whoever sees a
    /// run first records it, so a reader woken by the same status change never reads the
    /// previous run's scope.
    pub fn observe(&self, started: Option<UnixMs>, saved: impl FnOnce() -> bool) {
        let reported = self.reported(started);
        let mut held = self.held.lock();
        match reported {
            Some(listed) => *held = (started, listed),
            None if held.0 != started => *held = (started, started.is_some() && saved()),
            None => {}
        }
    }

    /// Only the listed apps use the running session's VPN (`false` while nothing runs).
    pub fn listed(&self) -> bool {
        self.held.lock().1
    }

    /// The scope the run that started at `started` reports (`None`: nothing runs, another run
    /// shows by now, or the run reports none).
    fn reported(&self, started: Option<UnixMs>) -> Option<bool> {
        let status = self.status.as_ref()?.borrow();
        let same = started.is_some() && run_start(&status) == started;
        status.listed_only.filter(|_| same)
    }
}

/// The start of the run `status` shows (`None` while nothing runs).
pub fn run_start(status: &TunStatus) -> Option<UnixMs> {
    status.started_at.filter(|_| status.running)
}

/// The saved scope is «Только выбранные приложения».
pub fn saved_listed(settings: &Store<Settings>) -> bool {
    settings.read(|s| s.app_scope) == AppScope::OnlyListed
}

async fn follow(
    mut status: watch::Receiver<TunStatus>,
    settings: Arc<Store<Settings>>,
    scope: RunScope,
) {
    loop {
        let started = run_start(&status.borrow_and_update());
        scope.observe(started, || saved_listed(&settings));
        if status.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// appsplit-b4 (p-live2): a run keeps the scope it started with; a flip of the switch
    /// applies to the next run only.
    #[test]
    fn a_run_keeps_the_scope_it_started_with() {
        let scope = RunScope::default();
        assert!(!scope.listed());
        scope.observe(Some(1_000), || true);
        assert!(scope.listed());
        scope.observe(Some(1_000), || false);
        assert!(scope.listed(), "the switch flipped mid-run");
        scope.observe(None, || true);
        assert!(!scope.listed(), "nothing runs");
        scope.observe(Some(2_000), || false);
        assert!(!scope.listed(), "the next run reads the new scope");
    }

    /// live2-a3 (p-wire5): the scope a run reports it was built with wins over the saved one,
    /// also when another reader saw the run first; a run that reports none (a service before
    /// protocol 5) keeps the saved scope it was first seen with.
    #[test]
    fn a_reported_scope_wins_over_the_saved_one() {
        let run = |listed_only| TunStatus {
            running: true,
            started_at: Some(1_000),
            listed_only,
            ..TunStatus::default()
        };
        let (tx, rx) = watch::channel(run(Some(false)));
        let scope = RunScope {
            held: Arc::default(),
            status: Some(rx),
        };
        scope.observe(Some(1_000), || true);
        assert!(
            !scope.listed(),
            "the run reports every app; the saved scope says listed"
        );
        tx.send_replace(run(Some(true)));
        scope.observe(Some(1_000), || false);
        assert!(scope.listed(), "the run's own report");
        tx.send_replace(TunStatus {
            started_at: Some(2_000),
            ..run(None)
        });
        scope.observe(Some(2_000), || true);
        scope.observe(Some(2_000), || false);
        assert!(
            scope.listed(),
            "no report: the saved scope it was first seen with"
        );
        // A reader of an older status never takes the newer run's report for its own.
        tx.send_replace(TunStatus {
            started_at: Some(3_000),
            ..run(Some(false))
        });
        scope.observe(Some(2_000), || false);
        assert!(scope.listed());
    }

    /// A stopped run that left its start time behind counts as nothing running.
    #[test]
    fn only_a_running_session_has_a_start() {
        let mut status = TunStatus {
            running: true,
            started_at: Some(1_000),
            ..TunStatus::default()
        };
        assert_eq!(run_start(&status), Some(1_000));
        status.running = false;
        assert_eq!(run_start(&status), None);
    }
}
