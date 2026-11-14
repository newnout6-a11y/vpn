//! The order of install / uninstall and what follows a failed step, over [`Machine`] (real:
//! `install::System`; tests: a recording fake). Reviews 4555679947 (an install that fails after
//! stopping the old service starts it again) and 4555679938 (an uninstall whose WFP clean-up
//! failed keeps the service, so strict filters left behind can still be removed).
use std::path::PathBuf;

use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

/// `uninstall` / the last user's removal could not remove our WFP filters: the service stays
/// (registration, files, automatic start) so a retry or its own start-up can remove them.
pub const FILTERS_KEPT: &str = "service.uninstall.filtersKept";
/// `install` failed after stopping the old service and could not start it again.
pub const NOT_RESTARTED: &str = "service.install.notRestarted";

/// The machine effects of install / uninstall, each one step.
pub(crate) trait Machine {
    /// Start type: `false` = disabled, so the SCM's recovery cannot start the old exe while its
    /// files change; `true` = automatic again. Nothing to do when the service is not installed.
    fn set_enabled(&self, on: bool) -> AppResult<()>;
    /// Stops the service and waits for `STOPPED` (`Ok` also when it is not installed).
    fn stop(&self) -> AppResult<()>;
    /// Starts the service and waits for `RUNNING`.
    fn start(&self) -> AppResult<()>;
    /// Everything between the stop and the start of an install: the files, the trusted-folder
    /// check, the data folder, the installing user, the registration. Returns the installed exe.
    fn place(&self) -> AppResult<PathBuf>;
    /// Removes every WFP object of ours, strict filters included.
    fn remove_wfp(&self) -> AppResult<()>;
    /// Removes the Windows Firewall rules sing-box made for the engines (lab F-8).
    fn remove_rules(&self) -> AppResult<()>;
    /// Marks the service for deletion.
    fn delete(&self) -> AppResult<()>;
    /// Deletes the program and the data folders.
    fn remove_folders(&self) -> AppResult<()>;
}

/// Stop, place, start. A stop that did not finish only gives the old service its start type back
/// (it may still be stopping). After any later failure the service is started again — the old
/// files when nothing was replaced yet, otherwise what is there (a mixed folder refuses Tunnel
/// mode with its own reason) — so a kept "Always" block stays managed, never silently stuck; the
/// original error is returned, or [`NOT_RESTARTED`] (with the original as its source) when even
/// that start failed: then the service is stopped until Windows starts it again.
pub(crate) fn install(m: &dyn Machine) -> AppResult<PathBuf> {
    m.set_enabled(false)?;
    if let Err(err) = m.stop() {
        let _ = m.set_enabled(true);
        return Err(err);
    }
    let exe = match m.place() {
        Ok(exe) => exe,
        Err(err) => return Err(start_again(m, err)),
    };
    m.start()?;
    Ok(exe)
}

fn start_again(m: &dyn Machine, err: AppError) -> AppError {
    if let Err(e) = m.set_enabled(true) {
        tracing::warn!(error = ?e.source, "start type not restored");
    }
    match m.start() {
        Ok(()) => {
            tracing::info!("install failed; the service runs again");
            err
        }
        Err(e) => {
            tracing::error!(error = ?e.source, "install failed and the service did not start again");
            AppError::msg(ErrorKind::Internal, Msg::new(NOT_RESTARTED)).with_source(cause(err))
        }
    }
}

/// Disable, stop, remove the WFP objects and the engines' firewall rules, delete, remove the
/// folders. Every step is tried even
/// when one before it failed (the first failure is returned: a rerun finishes what is left),
/// except a failed WFP clean-up: strict filters left behind would block traffic with nothing
/// left to remove them, so the registration and the files stay, the service runs again (its
/// start-up removes leftovers of a level no longer in force) and [`FILTERS_KEPT`] is returned.
pub(crate) fn uninstall(m: &dyn Machine) -> AppResult<()> {
    let mut first = None;
    let mut step = |done: AppResult<()>| {
        if let Err(err) = done {
            tracing::warn!(error = ?err.source, key = %err.user_msg().key, "uninstall step failed");
            first.get_or_insert(err);
        }
    };
    step(m.set_enabled(false));
    step(m.stop());
    if let Err(err) = m.remove_wfp() {
        let _ = m.set_enabled(true);
        if let Err(e) = m.start() {
            tracing::warn!(error = ?e.source, "service not started again after the kept filters");
        }
        return Err(filters_kept(err));
    }
    step(m.remove_rules());
    step(m.delete());
    step(m.remove_folders());
    first.map_or(Ok(()), Err)
}

/// The kept-filters error, with the WFP failure as its source.
pub fn filters_kept(err: AppError) -> AppError {
    AppError::msg(ErrorKind::Internal, Msg::new(FILTERS_KEPT)).with_source(cause(err))
}

/// The replaced error as a source: its key and its own source, as log text.
fn cause(err: AppError) -> std::io::Error {
    let key = err.user_msg().key;
    match err.source {
        Some(source) => std::io::Error::other(format!("{key}: {source:#}")),
        None => std::io::Error::other(key.to_string()),
    }
}

#[cfg(test)]
mod tests;
