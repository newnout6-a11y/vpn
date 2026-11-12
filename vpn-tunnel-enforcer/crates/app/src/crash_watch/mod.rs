//! The proxy-mode crash guardian (research killswitch §5.5). While a proxy-mode session holds the
//! per-user tweaks (system proxy, variables, dev tools), a copy of the app waits on the app's
//! process handle. If the app dies without rolling back (a crash, "End task"), the copy rolls the
//! session back from the tweak journal (per-user, no admin), so browsing does not stay pointed at
//! a dead port until the next start. A normal stop or exit rolls back in the app first and stops
//! the copy; one that is still around finds nothing of its app left and exits.
mod spawn;
#[cfg(test)]
mod tests;
mod watch;

use parking_lot::Mutex;

pub use spawn::{Child, spawn};
pub use watch::{EXIT_INCOMPLETE, EXIT_NOT_WATCHED, run};

/// The argument that makes the exe a watcher: `--crash-watch <pid>`.
pub const FLAG: &str = "--crash-watch";

/// The watcher of this process: one per process, like the proxy session it guards.
static WATCHER: Mutex<Option<Child>> = Mutex::new(None);

/// Starts this process's watcher unless it runs. Blocking (a process start). Best effort: without
/// it the next start's recovery still rolls back, so a failure is only logged.
pub fn arm() {
    let mut slot = WATCHER.lock();
    if slot.as_ref().is_some_and(Child::running) {
        return;
    }
    let args = format!("{FLAG} {}", std::process::id());
    match std::env::current_exe().and_then(|exe| spawn(&exe, &args)) {
        Ok(child) => {
            tracing::info!(pid = child.pid(), "crash watcher started");
            *slot = Some(child);
        }
        Err(e) => tracing::warn!(error = %e, "crash watcher not started"),
    }
}

/// Stops this process's watcher once the session's tweaks are rolled back. Blocking (at most
/// about 2 s).
pub fn disarm() {
    let child = WATCHER.lock().take();
    if let Some(child) = child {
        child.stop();
        tracing::info!("crash watcher stopped");
    }
}
