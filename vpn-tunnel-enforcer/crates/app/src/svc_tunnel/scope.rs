//! The app scope the running session started with (appsplit-b4/b5, p-follow3): «Только
//! выбранные приложения» applies from the next connection, so whatever labels or judges this run
//! (the background leak watch, the Maintenance self-test, the Apps page's pending line) reads
//! the scope the run started with, never the saved one. The tunnel service keeps the one copy
//! (`Built::run_scope`).
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::watch;
use vpnte_base::types::UnixMs;
use vpnte_core::settings::{AppScope, Settings};
use vpnte_core::store::Store;
use vpnte_tunnel::api::TunStatus;

/// The run that started at `.0` (`None`: nothing runs) and whether only the listed apps use it.
#[derive(Clone, Default)]
pub struct RunScope(Arc<Mutex<(Option<UnixMs>, bool)>>);

impl RunScope {
    /// A scope kept on the runs `status` shows, read the moment each run appears, until
    /// `status` closes.
    pub fn follow(status: watch::Receiver<TunStatus>, settings: Arc<Store<Settings>>) -> Self {
        let scope = Self::default();
        tokio::spawn(follow(status, settings, scope.clone()));
        scope
    }

    /// The run that started at `started` (`None`: nothing runs): a new run reads its scope
    /// now, the same run keeps the one it read. Whoever sees a run first records it, so a
    /// reader woken by the same status change never reads the previous run's scope.
    pub fn observe(&self, started: Option<UnixMs>, listed: impl FnOnce() -> bool) {
        let mut held = self.0.lock();
        if held.0 != started {
            *held = (started, started.is_some() && listed());
        }
    }

    /// Only the listed apps use the running session's VPN (`false` while nothing runs).
    pub fn listed(&self) -> bool {
        self.0.lock().1
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
