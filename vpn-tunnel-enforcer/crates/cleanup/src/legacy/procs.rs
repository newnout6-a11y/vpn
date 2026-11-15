//! Old processes (spec §6.6 preconditions and step 1, §3.11): a running old Electron build
//! defers the whole cleanup; engines the old app staged under `%ProgramData%\VPNTE\runtime`
//! and left running are stopped.
use std::path::Path;

use vpnte_winnet::process::{self, ImageError, SweepReport, UnknownReason};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::core::Owned;

use super::report::{Outcome, StepId, StepRecord};

/// Image name of the old Electron app.
pub(crate) const OLD_APP_EXE: &str = "VPN Tunnel Enforcer.exe";
/// The old runtime images in stop order: the TUN consumer before its upstreams. The external
/// proxy was only orphan-swept by PID files in the old app; it must go before its folder can.
pub(crate) const RUNTIME_NAMES: [&str; 4] = [
    "vpnte-sing-box.exe",
    "vpnte-xray.exe",
    "vpnte-etw-sidecar.exe",
    "vpnte-external-proxy.exe",
];

/// An Electron install: `resources\app.asar` next to the exe.
pub(crate) fn is_electron_install(exe: &Path) -> bool {
    exe.parent()
        .is_some_and(|dir| dir.join("resources").join("app.asar").is_file())
}

/// An old Electron instance other than us is running (or the process list is unreadable, or
/// a candidate's image cannot be read: then the cleanup waits for a later start).
pub(crate) fn old_app_running() -> bool {
    let Some(pids) = pids_named(OLD_APP_EXE) else {
        return true;
    };
    pids.into_iter()
        .filter(|&pid| pid != std::process::id())
        .any(|pid| match process::image_path(pid) {
            Ok(path) => is_electron_install(&path),
            Err(ImageError::Gone) => false,
            Err(_) => true,
        })
}

/// PIDs whose image name is `name` (case-insensitive); `None` when the snapshot fails.
fn pids_named(name: &str) -> Option<Vec<u32>> {
    // SAFETY: plain snapshot call; the handle is owned (closed on drop) right below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.ok()?;
    // SAFETY: a valid handle we own.
    let snapshot = unsafe { Owned::new(snapshot) };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut out = Vec::new();
    // SAFETY: valid snapshot handle and a sized entry.
    let mut more = unsafe { Process32FirstW(*snapshot, &mut entry) }.is_ok();
    while more {
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        if String::from_utf16_lossy(&entry.szExeFile[..len]).eq_ignore_ascii_case(name) {
            out.push(entry.th32ProcessID);
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(*snapshot, &mut entry) }.is_ok();
    }
    Some(out)
}

/// Step 1: stops old engines running from `runtime` (terminating an elevated orphan needs
/// elevation; one that survives is a failure, retried on a later start).
pub(crate) fn stop_orphans(runtime: &Path) -> StepRecord {
    if !runtime.is_dir() {
        return StepRecord::new(StepId::Processes, Outcome::Done, "no old runtime folder");
    }
    match process::sweep_orphans(&[runtime.to_path_buf()], &RUNTIME_NAMES) {
        Ok(sweep) => sweep_record(&sweep),
        Err(e) => StepRecord::new(
            StepId::Processes,
            Outcome::Failed,
            format!("process sweep failed: {e:?}"),
        ),
    }
}

/// An engine that survived, or one whose image could not be read (not checked), fails the
/// step; a candidate that exited meanwhile does not.
fn sweep_record(sweep: &SweepReport) -> StepRecord {
    let unreadable = sweep
        .unknown
        .iter()
        .filter(|p| p.reason != UnknownReason::Vanished)
        .count();
    let detail = format!(
        "stopped {}, survived {}, unreadable {unreadable}",
        sweep.stopped.len(),
        sweep.survived.len(),
    );
    let outcome = match sweep.survived.is_empty() && unreadable == 0 {
        true => Outcome::Done,
        false => Outcome::Failed,
    };
    StepRecord::new(StepId::Processes, outcome, detail).changed(!sweep.stopped.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    /// Read-only: lists processes, stops nothing. This test binary is not an Electron app.
    #[test]
    fn detects_no_old_app_in_tests() {
        let me = std::env::current_exe().unwrap();
        assert!(!is_electron_install(&me));
        let name = me.file_name().unwrap().to_str().unwrap();
        let pids = pids_named(name).expect("process snapshot");
        assert!(pids.contains(&std::process::id()));
        assert!(pids_named("no-such-image-vpnte.exe").unwrap().is_empty());
    }

    #[test]
    fn electron_install_layout() {
        let dir = TempDir::new("asar");
        std::fs::create_dir_all(dir.path().join("resources")).unwrap();
        let exe = dir.path().join(OLD_APP_EXE);
        assert!(!is_electron_install(&exe));
        dir.write(r"resources\app.asar", b"x");
        assert!(is_electron_install(&exe));
    }

    /// Without the old runtime folder nothing is scanned.
    #[test]
    fn missing_runtime_folder_is_done() {
        let record = stop_orphans(Path::new(r"C:\vpnte-test-no-such-folder\runtime"));
        assert_eq!(record.outcome, Outcome::Done);
        assert!(!record.changed);
    }

    /// An engine that exited meanwhile is not "unreadable"; one that could not be read is
    /// not checked, so the step fails (retried) instead of reporting success.
    #[test]
    fn unreadable_engines_are_not_a_success() {
        use vpnte_winnet::process::{OwnedProc, UnknownProc};
        let gone = |reason| UnknownProc {
            pid: 7,
            name: RUNTIME_NAMES[0].into(),
            reason,
        };
        let mut sweep = SweepReport {
            stopped: vec![OwnedProc {
                pid: 5,
                path: r"C:\ProgramData\VPNTE\runtime\x\tun-runtime\vpnte-sing-box.exe".into(),
            }],
            survived: Vec::new(),
            unknown: vec![gone(UnknownReason::Vanished)],
        };
        let record = sweep_record(&sweep);
        assert_eq!(record.outcome, Outcome::Done);
        assert!(record.changed);
        assert_eq!(record.detail, "stopped 1, survived 0, unreadable 0");
        sweep.unknown.push(gone(UnknownReason::PathUnreadable));
        assert_eq!(sweep_record(&sweep).outcome, Outcome::Failed);
    }
}
