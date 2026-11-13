//! The logon restore of a proxy-mode session (RU-2026 re-check item 14c). The crash guardian
//! ([`crate::crash_watch`]) covers a crash of the running app, not a logoff or a power loss:
//! then the per-user system proxy, the opted-in variables and dev tools stay pointed at a dead
//! loopback port until the app starts again, and with autostart off nothing starts it. So,
//! while the tweak journal holds a Soft session:
//! - a [`LogonValue`] (`HKCU\…\RunOnce`) runs `"<exe>" --restore-proxy` at the next sign-in;
//!   that process ([`run`]) rolls back what the journal's last writer left once that process is
//!   gone, with the crash guardian's code (journal lock, idempotent: a newer session is never
//!   undone), and exits before any UI;
//! - a hidden window rolls back at `WM_ENDSESSION` while the app still runs ([`at_start`]).
//!
//! The value goes on every complete rollback (Windows deletes it itself before it starts the
//! restore) and at a normal start ([`at_start`]); every process on an overridden data dir leaves
//! it alone ([`LogonValue::current`]).
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use vpnte_automation::hardening;
use vpnte_automation::tweaks::journal::TweakDoc;
use vpnte_automation::tweaks::{Journal, RollbackReport, Soft, SoftSystem};
use vpnte_core::paths::DataDirs;
use vpnte_core::store::Document;

use crate::crash_watch::EXIT_INCOMPLETE;

mod logon;
mod session_end;
#[cfg(test)]
mod tests;

pub use logon::{LogonValue, VALUE};

/// The argument of the logon restore process.
pub const FLAG: &str = "--restore-proxy";

/// The `--restore-proxy` process. Writes no log: the app started at the same sign-in rotates
/// it and must not find a second writer in it. Leaves the `RunOnce` key alone: Windows deleted
/// the value before starting it, and a program started from that key must not write to it
/// while Windows works through it (it may start the new value at once: a loop on a value that
/// keeps failing). What a failed rollback leaves waits for the next start's recovery.
pub fn run() -> ExitCode {
    let Ok(dirs) = DataDirs::resolve() else {
        return ExitCode::from(EXIT_INCOMPLETE);
    };
    match roll_back_orphaned(&dirs.root, SoftSystem::current_user()) {
        Some(report) if !report.is_complete() => ExitCode::from(EXIT_INCOMPLETE),
        _ => ExitCode::SUCCESS,
    }
}

/// A normal start (the primary instance, before the start-up recovery): an earlier run's value
/// is stale (the recovery rolls back what that run left; a new session registers its own), and
/// this run gets its end-session rollback of the journal under `root`.
pub fn at_start(root: PathBuf) {
    disarm();
    let started = session_end::start(move || {
        // Everything is ending: nobody needs the environment broadcast, and Explorer reads the
        // variables again at the next sign-in.
        let sys = SoftSystem {
            broadcast: false,
            ..SoftSystem::current_user()
        };
        let report = roll_back_at_end(&root, sys, LogonValue::current().as_ref());
        tracing::info!(
            restored = report.restored.len(),
            failed = report.failed.len(),
            "session end: soft rollback"
        );
    });
    if let Err(e) = started {
        tracing::warn!(error = %e, "session-end rollback not armed");
    }
}

/// Registers this process's logon value, with the crash watcher before the first write of a
/// proxy session. Blocking (one registry write); a failure is only logged.
pub fn arm() {
    if let Some(value) = LogonValue::current()
        && let Err(e) = value.set()
    {
        tracing::warn!(error = %e, "logon restore value not set");
    }
}

/// Removes the logon value once nothing of the session is journalled any more. Blocking.
pub fn disarm() {
    if let Some(value) = LogonValue::current()
        && let Err(e) = value.clear()
    {
        tracing::warn!(error = %e, "logon restore value not removed");
    }
}

/// Rolls back the Soft session the journal under `root` holds for a writer that is gone.
/// `None`: no journal (nothing is created then), or its last writer still runs.
pub(super) fn roll_back_orphaned(root: &Path, sys: SoftSystem) -> Option<RollbackReport> {
    if !root.join(TweakDoc::FILE).is_file() {
        return None;
    }
    // The hardening allow-list, as the app opens it: a narrower one would drop the browser
    // records from the file.
    let journal = Arc::new(Journal::open(root, hardening::admit));
    Soft::new(journal, sys).rollback_orphaned()
}

/// The end-session rollback of every Soft value under `root`, as the app's own exit does
/// (empty when nothing is journalled).
pub(super) fn roll_back_at_end(
    root: &Path,
    sys: SoftSystem,
    logon: Option<&LogonValue>,
) -> RollbackReport {
    let soft = Soft::new(Arc::new(Journal::open(root, hardening::admit)), sys);
    if !soft.is_applied() {
        return RollbackReport::default();
    }
    let report = soft.rollback_blocking();
    if let Some(value) = logon {
        value.follow(&report);
    }
    report
}
