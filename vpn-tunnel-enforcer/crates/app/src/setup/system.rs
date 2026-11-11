//! What the app put into the system, removed again: `--cleanup` (the user's emergency exit) and
//! the network, tweak and autostart part of `--setup uninstall` (installer contract). Privileged
//! parts (our WFP objects, the old version's leftovers including the `sing-tun` firewall rule)
//! run only in an elevated process (NOADMIN §0); unelevated they are reported as needing
//! administrator rights, never as done.
use std::fmt;
use std::path::Path;

use vpnte_automation::hardening::{self, WinSystem};
use vpnte_automation::tweaks::journal::RegHive;
use vpnte_automation::tweaks::soft::SOFT_FEATURES;
use vpnte_automation::tweaks::{Feature, Journal, RollbackReport, SoftSystem, Target};
use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppError, ErrorKind};
use vpnte_cleanup::legacy;
use vpnte_core::paths::DataDirs;
use vpnte_winnet::autostart::{self, AutostartState, RunValue};
use windows::Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, WIN32_ERROR};
use windows::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};
use windows::core::HSTRING;

/// How one area ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Removed, or nothing was there; the text says which (ASCII).
    Done(String),
    /// Not (completely) removed; the text says what is left (ASCII).
    Failed(String),
    /// Not checked: only an elevated process may do it.
    NeedsAdmin,
}

/// One area of a cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub area: &'static str,
    pub outcome: Outcome,
}

impl Step {
    fn new(area: &'static str, outcome: Outcome) -> Self {
        Self { area, outcome }
    }

    /// Removed or nothing to remove.
    pub fn is_done(&self) -> bool {
        matches!(self.outcome, Outcome::Done(_))
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.outcome {
            Outcome::Done(text) => write!(f, "{}: done ({text})", self.area),
            Outcome::Failed(text) => write!(f, "{}: FAILED ({text})", self.area),
            Outcome::NeedsAdmin => {
                write!(f, "{}: not checked (needs administrator rights)", self.area)
            }
        }
    }
}

/// Area names as they appear in the output.
pub const AREA_FILTERS: &str = "network filters";
pub const AREA_LEGACY: &str = "old version leftovers";
pub const AREA_TWEAKS: &str = "proxy and tool settings";
pub const AREA_AUTOSTART: &str = "autostart";

/// Every journalled feature: the Soft session (system proxy, variables, dev tools), browser
/// policies and location privacy.
const HARDENING: [Feature; 2] = [Feature::BrowserWebRtc, Feature::LocationPrivacy];

/// An `AppError` as ASCII: kind and message key; the source may carry localized OS text.
pub fn app_err(err: &AppError) -> String {
    format!("{:?} [{}]", err.kind, err.user_msg().key)
}

/// True while any instance of the app runs, for any user and from any location (its machine-wide
/// single-instance mutex exists). Its WFP session, system proxy and journal belong to it.
pub fn app_running() -> bool {
    let name = HSTRING::from(vpnte_winnet::single_instance::MUTEX_NAME);
    // SAFETY: plain call with a NUL-terminated name that outlives it.
    match unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, false, &name) } {
        Ok(handle) => {
            // SAFETY: the handle was just opened by us and is closed once.
            let _ = unsafe { CloseHandle(handle) };
            true
        }
        // Created by another account with a stricter DACL: it exists all the same.
        Err(err) => WIN32_ERROR::from_error(&err) != Some(ERROR_FILE_NOT_FOUND),
    }
}

/// Our WFP objects (persistent `strict` filters included, then sublayer and provider) and the
/// old version's system leftovers: firewall rules and profiles, its WFP sublayer, tasks, files
/// and the `sing-tun` rules of `<resources>\sing-box.exe` (crate `cleanup`). Elevated only.
pub fn network(resources: &Path, elevated: bool) -> Vec<Step> {
    if !elevated {
        return vec![
            Step::new(AREA_FILTERS, Outcome::NeedsAdmin),
            Step::new(AREA_LEGACY, Outcome::NeedsAdmin),
        ];
    }
    let filters = match vpnte_winnet::wfp::remove_all() {
        Ok(r) => Outcome::Done(format!(
            "{} filters removed, sublayer {}, provider {}",
            r.filters,
            gone(r.sublayer),
            gone(r.provider)
        )),
        Err(err) => Outcome::Failed(err.to_string()),
    };
    let ctx = legacy::Context {
        resources: resources.to_path_buf(),
        // Read by the start-up run only; uninstall has no strict gate (the app is going away).
        level: KillSwitchLevel::Off,
        strict_ready: false,
    };
    let leftovers = match legacy::uninstall(&ctx) {
        Ok(report) => {
            let failed: Vec<&str> = report
                .steps
                .iter()
                .filter(|r| r.outcome == legacy::Outcome::Failed)
                .map(|r| r.step.key())
                .collect();
            if failed.is_empty() {
                let changed = report.steps.iter().filter(|r| r.changed).count();
                Outcome::Done(format!(
                    "{changed} of {} steps changed something",
                    report.steps.len()
                ))
            } else {
                Outcome::Failed(format!("failed: {}", failed.join(", ")))
            }
        }
        Err(err) => Outcome::Failed(app_err(&err)),
    };
    vec![
        Step::new(AREA_FILTERS, filters),
        Step::new(AREA_LEGACY, leftovers),
    ]
}

fn gone(removed: bool) -> &'static str {
    if removed { "removed" } else { "absent" }
}

/// Rolls back the journalled tweaks of this user: the Soft session (system proxy, variables,
/// Git / Gradle / Android Studio), browser policies and location privacy. A value someone changed
/// since is kept; what fails stays journalled for the next attempt. Runs under the data-dir lock
/// (a running app owns its journal); a missing data dir means nothing was ever applied.
pub fn tweaks(dirs: &DataDirs, elevated: bool) -> Step {
    if !dirs.root.is_dir() {
        return Step::new(AREA_TWEAKS, Outcome::Done("nothing applied".into()));
    }
    let _lock = match dirs.lock() {
        Ok(lock) => lock,
        Err(err) if err.kind == ErrorKind::Conflict => {
            return Step::new(AREA_TWEAKS, Outcome::Failed("the app is running".into()));
        }
        Err(err) => return Step::new(AREA_TWEAKS, Outcome::Failed(app_err(&err))),
    };
    let journal = Journal::open(&dirs.root, hardening::admit);
    let lost = journal.notice().map(|notice| notice.key);
    let applied = SOFT_FEATURES
        .iter()
        .chain(&HARDENING)
        .any(|f| journal.is_applied(*f));
    let mut report = RollbackReport::default();
    if applied {
        report = journal.rollback(&SoftSystem::current_user(), &SOFT_FEATURES);
        report.merge(journal.rollback(&WinSystem::new(), &HARDENING));
    }
    Step::new(AREA_TWEAKS, judge(&report, lost.as_deref(), elevated))
}

/// The outcome of a rollback. Unelevated, machine-wide policy values (HKLM) cannot be written:
/// when only those are left the step needs administrator rights.
fn judge(report: &RollbackReport, lost: Option<&str>, elevated: bool) -> Outcome {
    if let Some(key) = lost {
        // The journal was unreadable: obligations recorded in it are unknown.
        return Outcome::Failed(format!(
            "journal unreadable [{key}]; check proxy settings by hand"
        ));
    }
    if report.failed.is_empty() {
        return Outcome::Done(format!(
            "{} restored, {} kept as changed since",
            report.restored.len(),
            report.kept_user_value.len()
        ));
    }
    let machine_wide = |t: &Target| {
        matches!(
            t,
            Target::Reg {
                hive: RegHive::Hklm,
                ..
            }
        )
    };
    if !elevated && report.failed.iter().all(machine_wide) {
        Outcome::NeedsAdmin
    } else {
        Outcome::Failed(format!("{} value(s) not restored", report.failed.len()))
    }
}

/// Deletes this user's autostart `Run` value whatever it points at (its name is ours), and the
/// 1.x logon task when the process may (it was created elevated); then reads the value back.
pub fn autostart_value(exe: &Path) -> Step {
    let os = RunValue {
        exe: exe.to_path_buf(),
    };
    let outcome = match autostart::sync(&os, false).and_then(|_| autostart::state(exe)) {
        Ok(AutostartState::Absent) => Outcome::Done("Run value absent".into()),
        Ok(_) => Outcome::Failed("Run value still present".into()),
        Err(err) => Outcome::Failed(super::gate::os_code(&err.into())),
    };
    Step::new(AREA_AUTOSTART, outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(hive: RegHive) -> Target {
        Target::Reg {
            hive,
            key: r"Software\Policies\X".into(),
            name: "V".into(),
        }
    }

    /// AT-11-005 (delivery §7.5): an empty journal changes nothing; failed records are reported;
    /// unelevated, machine-wide policy values alone mean "needs administrator rights".
    #[test]
    fn rollback_reports_are_judged_honestly() {
        let empty = RollbackReport::default();
        assert_eq!(
            judge(&empty, None, false),
            Outcome::Done("0 restored, 0 kept as changed since".into())
        );
        let hkcu = RollbackReport {
            restored: vec![Target::SystemProxy],
            failed: vec![reg(RegHive::Hkcu)],
            ..RollbackReport::default()
        };
        assert_eq!(
            judge(&hkcu, None, true),
            Outcome::Failed("1 value(s) not restored".into())
        );
        let hklm = RollbackReport {
            failed: vec![reg(RegHive::Hklm)],
            ..RollbackReport::default()
        };
        assert_eq!(judge(&hklm, None, false), Outcome::NeedsAdmin);
        assert!(matches!(judge(&hklm, None, true), Outcome::Failed(_)));
        let lost = judge(&empty, Some("automation.tweaks.journalCorrupt"), true);
        assert!(matches!(lost, Outcome::Failed(text) if text.contains("journalCorrupt")));
    }

    /// Without a data folder nothing was ever applied; an empty one has an empty journal. Both
    /// stay inside a throw-away directory.
    #[test]
    fn tweaks_without_a_journal_change_nothing() {
        let base = std::env::temp_dir().join(format!("vpnte-setup-tweaks-{}", std::process::id()));
        let dirs = DataDirs::new(base.join("data"), base.join("legacy"), base.join("res"));
        let step = tweaks(&dirs, false);
        assert_eq!(step.outcome, Outcome::Done("nothing applied".into()));
        assert!(!dirs.root.exists(), "no data folder is created");
        std::fs::create_dir_all(&dirs.root).expect("temp data dir");
        let step = tweaks(&dirs, false);
        assert!(step.is_done(), "{step}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Output lines are plain ASCII and say what happened.
    #[test]
    fn steps_print_as_ascii_lines() {
        let lines = [
            Step::new(AREA_FILTERS, Outcome::NeedsAdmin).to_string(),
            Step::new(
                AREA_TWEAKS,
                Outcome::Failed("2 value(s) not restored".into()),
            )
            .to_string(),
            Step::new(AREA_AUTOSTART, Outcome::Done("Run value absent".into())).to_string(),
        ];
        assert_eq!(
            lines[0],
            "network filters: not checked (needs administrator rights)"
        );
        assert_eq!(
            lines[1],
            "proxy and tool settings: FAILED (2 value(s) not restored)"
        );
        assert_eq!(lines[2], "autostart: done (Run value absent)");
        assert!(lines.iter().all(|l| l.is_ascii()));
    }
}
