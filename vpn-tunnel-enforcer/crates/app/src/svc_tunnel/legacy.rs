//! The old version's network cleanup at start (crate `cleanup`, "Usage (app)"): elevated only,
//! after `Protection::startup()`, so that with `strict` the old blocks go only once ours are in
//! place (firewall-recovery §6.6 step 0).
use std::sync::Arc;

use vpnte_cleanup::legacy::{self, Context, Mode, Run};

use crate::services::Backend;
use crate::setup::system::machine_wide_installed;

/// Runs the start-up cleanup (blocking work off the runtime) and shows its notices. Skipped while
/// the old per-machine version is still installed: its boot-recovery task and firewall rules are
/// its working parts then (the per-user installer leaves it in place). A skip leaves the marker
/// untouched, so the first elevated start after that version is gone runs the cleanup.
pub(super) async fn startup(backend: Arc<Backend>, strict_ready: bool) {
    let b = backend.clone();
    let run = tokio::task::spawn_blocking(move || {
        if machine_wide_installed() {
            return None;
        }
        let ctx = Context {
            resources: b.dirs.resources.clone(),
            level: b.protection.read(|d| d.settings.level),
            strict_ready,
        };
        Some(legacy::run(&b.cleanup, &ctx, Mode::Startup))
    })
    .await;
    match run {
        Ok(None) => {
            tracing::info!(
                "startup: legacy cleanup skipped, the per-machine 1.x is still installed"
            );
        }
        Ok(Some(Ok(Run::Finished(report)))) => {
            for notice in report.notices() {
                backend.notifier.notify(notice, None);
            }
        }
        Ok(Some(Ok(Run::NotDue | Run::Deferred))) => {}
        Ok(Some(Err(e))) => tracing::warn!(error = %e, "startup: legacy cleanup not run"),
        Err(e) => tracing::warn!(error = %e, "startup: legacy cleanup panicked"),
    }
}
