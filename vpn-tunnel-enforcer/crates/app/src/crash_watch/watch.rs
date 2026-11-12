//! The watcher process (`--crash-watch <pid>`): one wait on the app's process handle, then the
//! rollback of what the dead app left in the tweak journal.
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use vpnte_automation::hardening;
use vpnte_automation::tweaks::{Journal, RollbackReport, Soft, SoftSystem, Writer};
use vpnte_core::paths::DataDirs;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::ProcessStatus::K32EmptyWorkingSet;
use windows::Win32::System::Threading::{
    GetCurrentProcess, INFINITE, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, WaitForSingleObject,
};
use windows::core::Owned;

/// Exit code: some values could not be restored (they stay journalled for the next start).
pub const EXIT_INCOMPLETE: u8 = 1;
/// Exit code: the app could not be watched (already gone, or not the process that started us).
pub const EXIT_NOT_WATCHED: u8 = 2;

/// The watcher's whole life. Writes no log: the next start rotates the app log and must not find
/// a second writer in it.
pub fn run(pid: u32) -> ExitCode {
    ExitCode::from(watch(pid))
}

/// [`run`] as a plain exit code.
pub(super) fn watch(pid: u32) -> u8 {
    let Some(app) = open_app(pid) else {
        return EXIT_NOT_WATCHED;
    };
    trim();
    // SAFETY: a valid handle with SYNCHRONIZE; the only wait, for as long as the app lives.
    if unsafe { WaitForSingleObject(*app.handle, INFINITE) } != WAIT_OBJECT_0 {
        return EXIT_NOT_WATCHED;
    }
    let Ok(dirs) = DataDirs::resolve() else {
        return EXIT_INCOMPLETE;
    };
    match roll_back(&dirs.root, SoftSystem::current_user(), app.writer) {
        Some(report) if !report.is_complete() => EXIT_INCOMPLETE,
        _ => 0,
    }
}

pub(super) struct App {
    handle: Owned<HANDLE>,
    writer: Writer,
}

/// Opens the app by `pid` and makes sure it is the process that started us: a PID reused after
/// a very early exit belongs to a process that started after this one.
pub(super) fn open_app(pid: u32) -> Option<App> {
    let access = PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
    // SAFETY: plain call; the handle is owned at once.
    let handle = unsafe { Owned::new(OpenProcess(access, false, pid).ok()?) };
    let writer = Writer::of_process(pid, *handle).ok()?;
    (writer.started <= Writer::current().started).then_some(App { handle, writer })
}

/// The wait may last all day: hand the pages back now; Windows maps them again on wake-up.
fn trim() {
    // SAFETY: the pseudo handle of this process.
    let _ = unsafe { K32EmptyWorkingSet(GetCurrentProcess()) }.ok();
}

/// Rolls back the Soft session the dead app `writer` left under the data `root`. `None`: the
/// journal is no longer that app's (the next start or a helper changed it since). Opened with
/// the hardening allow-list, as the app does: a narrower one would drop the browser records.
pub(super) fn roll_back(root: &Path, sys: SoftSystem, writer: Writer) -> Option<RollbackReport> {
    let journal = Arc::new(Journal::open(root, hardening::admit));
    Soft::new(journal, sys).rollback_left_by(writer)
}
