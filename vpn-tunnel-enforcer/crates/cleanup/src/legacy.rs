//! One-shot cleanup of what the old Electron app may have left in the system (firewall-recovery
//! spec §6.6 / §6.7): its Windows Firewall rules and profile defaults, sing-box's `sing-tun`
//! inbound rules, the old WFP IPv6 sublayer, the boot-recovery tasks, adapter IPv6 / DNS
//! leftovers recorded in its journals, orphaned engines and staged files under
//! `%ProgramData%\VPNTE`. Every step is independent and reports into one [`CleanupReport`]; the
//! per-user marker [`CleanupMarker`] records completion and retries.
//!
//! Everything here is blocking (COM, BFE, INetCfg, process waits): call it from
//! `tokio::task::spawn_blocking`. Acting needs elevation; unelevated calls return
//! `ErrorKind::Permission` before touching anything.

mod adapters;
mod com;
mod files;
mod firewall;
mod journal;
mod marker;
mod netcfg;
mod policy;
mod procs;
mod report;
mod tasks;
mod trust;
mod wfp;

use std::path::{Path, PathBuf};

use vpnte_base::types::{KillSwitchLevel, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::store::Store;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

pub use marker::{CleanupMarker, MAX_ATTEMPTS};
pub use report::{CleanupReport, Outcome, StepId, StepRecord};

use journal::Journals;

/// Inputs of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// Resources dir of the running install (`DataDirs::resources`); its `sing-box.exe` names
    /// the `sing-tun` firewall rule that uninstall deletes.
    pub resources: PathBuf,
    /// The kill-switch level after the settings import.
    pub level: KillSwitchLevel,
    /// `Protection::startup()` succeeded. With `Strict` the old firewall / WFP blocks are only
    /// removed once the persistent WFP set is in place, so removing them never opens a gap
    /// (spec §6.6 step 0); otherwise those two steps fail and are retried.
    pub strict_ready: bool,
}

/// Which trigger runs the cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The elevated start-up: honours the marker (completed, or 3 failed attempts).
    Startup,
    /// The maintenance action "run legacy cleanup again": ignores the marker.
    Again,
}

/// What [`run`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Run {
    /// Completed earlier, or retries exhausted (see [`CleanupMarker::gave_up`]).
    NotDue,
    /// An old Electron instance is running, or could not be ruled out (process list or a
    /// candidate's image unreadable): nothing was done and no attempt was counted.
    Deferred,
    /// The steps ran; the marker holds their records.
    Finished(CleanupReport),
}

fn needs_admin() -> AppError {
    AppError::msg(ErrorKind::Permission, Msg::new("cleanup.legacy.needsAdmin"))
}

/// The one-shot cleanup at start-up (after the settings import and, for `Strict`, after
/// `Protection::startup()`), or again from the maintenance page. The attempt is recorded in
/// the marker before anything is changed, so a crash mid-run still counts.
pub fn run(marker: &Store<CleanupMarker>, ctx: &Context, mode: Mode) -> AppResult<Run> {
    if !vpnte_winnet::elevation::is_elevated() {
        return Err(needs_admin());
    }
    if mode == Mode::Startup && !marker.read(CleanupMarker::is_due) {
        return Ok(Run::NotDue);
    }
    if procs::old_app_running() {
        tracing::info!("legacy cleanup deferred: the old app is running");
        return Ok(Run::Deferred);
    }
    let root = vpnte_root()?;
    marker.update(|m| m.begin(now_ms()))?;
    let report = startup_steps(&root, ctx);
    if let Err(e) = marker.update(|m| m.finish(&report, now_ms())) {
        tracing::warn!(error = %e, "legacy cleanup marker not saved");
    }
    Ok(Run::Finished(report))
}

/// `--cleanup` / uninstall (spec §6.7): old engine orphans (so their staged folders can go),
/// journals, Windows Firewall, `sing-tun` rules of this install and the old copies, legacy
/// WFP, boot tasks and files. Our own WFP provider (`wfp::remove_all`) and the proxy baseline
/// are the app's. Exit code: [`CleanupReport::exit_code`].
pub fn uninstall(ctx: &Context) -> AppResult<CleanupReport> {
    if !vpnte_winnet::elevation::is_elevated() {
        return Err(needs_admin());
    }
    let root = vpnte_root()?;
    let runtime = root.join("runtime");
    let mut report = CleanupReport::default();
    report.push(procs::stop_orphans(&runtime));
    let journals = Journals::read(&root, &trust::check);
    report.push(journals.record());
    let firewall = firewall::clean_kill_switch(&journals, &mut report);
    report.push(firewall);
    report.push(wfp::clean());
    let engines = [ctx.resources.join(firewall::ENGINE_EXE)];
    report.push(firewall::clean_singtun(&engines, &runtime));
    report.push(tasks::clean());
    let finished = finished_journals(&journals, &report, false, false);
    report.push(files::clean(&root, &finished, &trust::check));
    Ok(report)
}

/// `%ProgramData%\VPNTE` from the known folder (not the environment variable, which any
/// process can set for us).
fn vpnte_root() -> AppResult<PathBuf> {
    // SAFETY: no token; the returned string is freed with CoTaskMemFree below.
    let raw = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
        .map_err(AppError::internal)?;
    // SAFETY: a NUL-terminated string allocated by the call.
    let path = unsafe { raw.to_string() };
    // SAFETY: allocated with CoTaskMemAlloc by SHGetKnownFolderPath, freed once.
    unsafe { CoTaskMemFree(Some(raw.0 as *const _)) };
    Ok(PathBuf::from(path.map_err(AppError::internal)?).join("VPNTE"))
}

/// Spec §6.6 steps 1-10 in order; each step is independent and only adds its record.
fn startup_steps(root: &Path, ctx: &Context) -> CleanupReport {
    let runtime = root.join("runtime");
    let mut report = CleanupReport::default();
    report.push(procs::stop_orphans(&runtime));
    let journals = Journals::read(root, &trust::check);
    report.push(journals.record());
    if ctx.level == KillSwitchLevel::Strict && !ctx.strict_ready {
        let detail = "strict protection is not in place yet: the old blocks are kept";
        report.push(StepRecord::new(StepId::Firewall, Outcome::Failed, detail));
        report.push(StepRecord::new(StepId::LegacyWfp, Outcome::Failed, detail));
    } else {
        let firewall = firewall::clean_kill_switch(&journals, &mut report);
        report.push(firewall);
        report.push(wfp::clean());
    }
    // The running install's own rule stays (sing-box re-adds it on every TUN start anyway);
    // uninstall removes it.
    report.push(firewall::clean_singtun(&[], &runtime));
    let adapters = adapters::restore(&journals);
    report.push(adapters.record);
    report.push(policy::restore(&journals, &policy::Hklm));
    let tun = adapters::tun_leftover(&journals);
    report.push(tun.record);
    report.push(tasks::clean());
    let finished = finished_journals(&journals, &report, adapters.journal_done, tun.journal_done);
    report.push(files::clean(root, &finished, &trust::check));
    report
}

/// Journals that were used and whose replay finished in this run: only those are deleted (the
/// journals are machine-wide, a skipped or failed replay stays for a later run or user).
fn finished_journals(
    journals: &Journals,
    report: &CleanupReport,
    adapters_done: bool,
    tun_done: bool,
) -> Vec<&'static str> {
    let done = |step| report.outcome(step) == Some(Outcome::Done);
    let firewall = done(StepId::Firewall);
    let wfp_ok = matches!(
        report.outcome(StepId::LegacyWfp),
        Some(Outcome::Done | Outcome::Skipped)
    );
    // A salvaged journal whose saved values were used stays, like the adapter journal.
    let firewall_complete = journals
        .firewall
        .valid()
        .is_some_and(|f| f.skipped.is_empty() || journals.strict_evidence());
    let candidates = [
        (journal::FIREWALL, firewall_complete && firewall && wfp_ok),
        (
            journal::POLICY,
            journals.policy.valid().is_some() && firewall,
        ),
        (
            journal::ADAPTERS,
            journals.adapters.valid().is_some() && adapters_done && done(StepId::DnsPolicy),
        ),
        (
            journal::TUN_OWNER,
            journals.tun_owner.valid().is_some() && tun_done,
        ),
    ];
    candidates
        .into_iter()
        .filter_map(|(name, finished)| finished.then_some(name))
        .collect()
}

#[cfg(test)]
mod tests;
