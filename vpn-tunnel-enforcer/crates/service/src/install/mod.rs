//! Install and uninstall (verbs of the binary, run elevated by the installer) and the service's
//! own removal when its last user left.
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use windows::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
use windows::core::{HSTRING, PCWSTR};

use crate::paths::{self, EXE_NAME};
use crate::scm::manage;

pub mod pins;

/// The description Services shows (system text, English like Windows' own entries).
pub const DESCRIPTION: &str = "Runs the Tunnel mode of VPN Tunnel Enforcer: the virtual adapter, \
the VPN engines and the kill switch. The app works in proxy mode without it.";

/// How long install / uninstall wait for the SCM.
const SCM_WAIT: Duration = Duration::from_secs(30);

/// Where the files come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The service exe to install (this binary).
    pub exe: PathBuf,
    /// The folder with the pinned engine files (the app's `resources`).
    pub resources: PathBuf,
}

impl Source {
    /// This binary, and `resources` or else `<exe dir>\resources` (the app's layout).
    pub fn current(resources: Option<PathBuf>) -> AppResult<Self> {
        let exe = std::env::current_exe().map_err(AppError::internal)?;
        let resources = match resources {
            Some(dir) => dir,
            None => exe
                .parent()
                .map(|d| d.join("resources"))
                .ok_or_else(|| AppError::new(ErrorKind::Internal))?,
        };
        Ok(Self { exe, resources })
    }
}

fn require_elevation() -> AppResult<()> {
    if vpnte_winnet::elevation::is_elevated() {
        Ok(())
    } else {
        Err(AppError::msg(
            ErrorKind::Permission,
            Msg::new("service.install.notElevated"),
        ))
    }
}

fn failed(err: impl std::error::Error + Send + Sync + 'static) -> AppError {
    AppError::msg(ErrorKind::Internal, Msg::new("service.install.failed")).with_source(err)
}

/// Installs or upgrades: stops a running service, copies the exe and the pinned engine files into
/// the admin-only Program Files folder, secures the data folder, registers the service
/// (LocalSystem, automatic start, service SID, restricted DACL, recovery) and starts it.
pub fn install(source: &Source) -> AppResult<PathBuf> {
    require_elevation()?;
    let dir = paths::install_dir().map_err(failed)?;
    manage::stop(SCM_WAIT).map_err(failed)?;
    paths::secure_dir(&dir).map_err(failed)?;
    for name in pins::FILES {
        pins::copy_verified(&source.resources, &dir, name)?;
    }
    let exe = dir.join(EXE_NAME);
    let bytes = std::fs::read(&source.exe).map_err(failed)?;
    // The stopped service's process may still be exiting for a moment: retry the replace.
    retry(|| pins::write_replacing(&exe, &bytes))?;
    // The service runs Tunnel mode only from a folder users cannot change: checked here too, so a
    // folder it would refuse fails the install with the file and the reason.
    crate::service::trusted_install(&dir, &exe)
        .map_err(|reason| failed(std::io::Error::other(reason)))?;
    let data = paths::data_dir().map_err(failed)?;
    paths::secure_dir(&data).map_err(failed)?;
    manage::create_or_update(&exe, DESCRIPTION).map_err(failed)?;
    if !manage::start(SCM_WAIT).map_err(failed)? {
        return Err(failed(std::io::Error::other(
            "the service did not reach RUNNING",
        )));
    }
    Ok(exe)
}

/// Stops and deletes the service, removes every WFP object of ours (strict filters included) and
/// deletes the program and data folders.
pub fn uninstall() -> AppResult<()> {
    require_elevation()?;
    manage::stop(SCM_WAIT).map_err(failed)?;
    manage::delete().map_err(failed)?;
    if let Err(err) = vpnte_winnet::wfp::remove_all() {
        tracing::warn!(error = %err, "WFP objects not removed");
    }
    for dir in [paths::install_dir(), paths::data_dir()] {
        let dir = dir.map_err(failed)?;
        if dir.exists() {
            retry(|| std::fs::remove_dir_all(&dir).map_err(AppError::internal))?;
        }
    }
    Ok(())
}

fn retry(mut op: impl FnMut() -> AppResult<()>) -> AppResult<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match op() {
            Ok(()) => return Ok(()),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            Err(err) => return Err(err),
        }
    }
}

/// Inside the service, after its last user left (no UAC: the service is SYSTEM): unregisters,
/// removes our WFP objects, deletes the engine files and the data folder; what is in use (the
/// running exe, its folder, the open service log) is deleted by Windows at the next restart.
pub fn remove_self(exe: &Path) {
    if let Err(err) = manage::delete() {
        tracing::warn!(error = %err, "service registration not deleted");
    }
    if let Err(err) = vpnte_winnet::wfp::remove_all() {
        tracing::warn!(error = %err, "WFP objects not removed");
    }
    if let Ok(data) = paths::data_dir() {
        remove_or_schedule(&data);
    }
    if let Some(dir) = exe.parent() {
        remove_or_schedule(dir);
    }
}

/// Deletes `dir` bottom-up; every entry that cannot go now (in use) is queued for deletion at
/// the next restart, files before their folders (Windows processes the queue in order).
fn remove_or_schedule(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            // Never descend into a link: it is removed itself, not its target.
            let is_dir = entry
                .file_type()
                .is_ok_and(|t| t.is_dir() && !t.is_symlink());
            if is_dir {
                remove_or_schedule(&path);
            } else if std::fs::remove_file(&path).is_err() {
                schedule(&path);
            }
        }
    }
    if std::fs::remove_dir(dir).is_err() {
        schedule(dir);
    }
}

fn schedule(path: &Path) {
    // SAFETY: valid path; a null target with DELAY_UNTIL_REBOOT means "delete at restart".
    let queued = unsafe {
        MoveFileExW(
            &HSTRING::from(path.as_os_str()),
            PCWSTR::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        )
    };
    if let Err(err) = queued {
        tracing::warn!(path = %path.display(), error = %err, "not queued for deletion");
    }
}
