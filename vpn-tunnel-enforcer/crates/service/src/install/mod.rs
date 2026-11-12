//! Install and uninstall (verbs of the binary, run elevated by the installer) and the service's
//! own removal when its last user left.
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use windows::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
use windows::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};
use windows::core::{HSTRING, PCWSTR};

use crate::paths::{self, DataFiles, EXE_NAME};
use crate::scm::manage;
use crate::users::Users;

pub mod flow;
pub mod image;
pub mod pins;

/// The description Services shows (system text, English like Windows' own entries).
pub const DESCRIPTION: &str = "Runs the Tunnel mode of VPN Tunnel Enforcer: the virtual adapter, \
the VPN engines and the kill switch. The app works in proxy mode without it.";

/// How long install / uninstall wait for the SCM.
const SCM_WAIT: Duration = Duration::from_secs(30);

/// Where the files come from.
pub struct Source {
    /// The service exe to install: this binary's bytes, read through a locked handle proven to be
    /// the running image ([`image::read_running_exe`]), never read by path later.
    pub exe: Vec<u8>,
    /// The folder with the pinned engine files (the app's `resources`).
    pub resources: PathBuf,
}

impl Source {
    /// This binary (read now: call it first, see [`image`]), and `resources` or else
    /// `<exe dir>\resources` (the app's layout).
    pub fn current(resources: Option<PathBuf>) -> AppResult<Self> {
        let exe = image::read_running_exe().map_err(|e| match e {
            image::ImageError::Replaced => AppError::msg(
                ErrorKind::Validation,
                Msg::new("service.install.imageChanged"),
            )
            .with_source(e),
            other => failed(other),
        })?;
        let resources = match resources {
            Some(dir) => dir,
            None => std::env::current_exe()
                .map_err(failed)?
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

/// The elevated verbs run from the per-user app folder: a DLL loaded by name from here on comes
/// from System32, never from that folder. (The exe's own imports are resolved at process start:
/// like the exe itself, the folder as it was at the UAC prompt is what the administrator approved.)
pub fn system_dlls_only() {
    // SAFETY: a process-wide loader setting with a valid flag.
    if let Err(err) = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } {
        eprintln!("DLL search not restricted to System32: {err}");
    }
}

/// Installs or upgrades: stops a running service, copies the exe and the pinned engine files into
/// the admin-only Program Files folder, secures the data folder, registers the service
/// (LocalSystem, automatic start, service SID, restricted DACL, recovery) and starts it. A failure
/// after the stop starts the service again ([`flow::install`]).
pub fn install(source: &Source) -> AppResult<PathBuf> {
    require_elevation()?;
    // Everything is read and checked before anything changes: a missing or changed file fails the
    // install while the old service still runs on its own, untouched files.
    let files = pins::read_all(&source.resources)?;
    flow::install(&System {
        files: &files,
        exe: &source.exe,
    })
}

/// Stops and deletes the service, removes every WFP object of ours (strict filters included) and
/// deletes the program and data folders ([`flow::uninstall`]: a failed WFP clean-up keeps the
/// service, every other step is tried even when one before it failed).
pub fn uninstall() -> AppResult<()> {
    require_elevation()?;
    flow::uninstall(&System {
        files: &[],
        exe: &[],
    })
}

/// The real machine: the SCM, the files and WFP. `files` / `exe` are what an install copies.
struct System<'a> {
    files: &'a [(&'static str, Vec<u8>)],
    exe: &'a [u8],
}

impl flow::Machine for System<'_> {
    fn set_enabled(&self, on: bool) -> AppResult<()> {
        manage::set_enabled(on).map_err(failed)
    }

    fn stop(&self) -> AppResult<()> {
        stopped(manage::stop(SCM_WAIT))
    }

    fn start(&self) -> AppResult<()> {
        match manage::start(SCM_WAIT) {
            Ok(true) => Ok(()),
            Ok(false) => Err(failed(std::io::Error::other(
                "the service did not reach RUNNING",
            ))),
            Err(e) => Err(failed(e)),
        }
    }

    fn place(&self) -> AppResult<PathBuf> {
        place(self.files, self.exe)
    }

    fn remove_wfp(&self) -> AppResult<()> {
        vpnte_winnet::wfp::remove_all().map(drop).map_err(failed)
    }

    fn delete(&self) -> AppResult<()> {
        manage::delete().map_err(failed)
    }

    fn remove_folders(&self) -> AppResult<()> {
        let mut first = Ok(());
        for dir in [paths::install_dir(), paths::data_dir()] {
            let removed = dir.map_err(failed).and_then(|dir| {
                if dir.exists() {
                    retry(|| std::fs::remove_dir_all(&dir).map_err(AppError::internal))
                } else {
                    Ok(())
                }
            });
            if first.is_ok() {
                first = removed;
            }
        }
        first
    }
}

/// The files in place, the data folder and the installing user ready, the service registered
/// (automatic start again). Runs after the old service stopped for good.
fn place(files: &[(&str, Vec<u8>)], service_exe: &[u8]) -> AppResult<PathBuf> {
    let dir = paths::install_dir().map_err(failed)?;
    let dir = dir.as_path();
    paths::secure_dir(dir).map_err(failed)?;
    // The stopped service's process and its engines may still be exiting for a moment: every
    // replace is retried.
    for (name, bytes) in files {
        let to = dir.join(name);
        retry(|| pins::write_replacing(&to, bytes))?;
    }
    let exe = dir.join(EXE_NAME);
    retry(|| pins::write_replacing(&exe, service_exe))?;
    // The service runs Tunnel mode only from a folder users cannot change: checked here too, so a
    // folder it would refuse fails the install with the file and the reason.
    crate::service::trusted_install(dir, &exe)
        .map_err(|fault| failed(std::io::Error::other(fault.to_string())))?;
    let data = paths::data_dir().map_err(failed)?;
    let files = DataFiles::new(&data);
    files.secure().map_err(failed)?;
    // The person installing counts as a user from now on, also if he only ever uses proxy mode:
    // another account's uninstall must not remove the service under him (review service-b5).
    if let Some(sid) = crate::users::session_user()
        && let Err(err) = Users::open(&files.users).add(&sid)
    {
        tracing::warn!(error = %err, "installing user not recorded");
    }
    manage::create_or_update(&exe, DESCRIPTION).map_err(failed)?;
    Ok(exe)
}

/// A stop that did not reach `STOPPED` in time is a failure: files of a running service are not
/// replaced or removed under it (review service-a13).
fn stopped(stop: windows::core::Result<bool>) -> AppResult<()> {
    match stop {
        Ok(true) => Ok(()),
        Ok(false) => Err(failed(std::io::Error::other(
            "the service did not stop in time",
        ))),
        Err(e) => Err(failed(e)),
    }
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
        remove_or_schedule(&data, &mut schedule);
    }
    if let Some(dir) = exe.parent() {
        remove_or_schedule(dir, &mut schedule);
    }
}

/// Deletes `dir` bottom-up. A file in use (the running exe, the open service log) is renamed to a
/// tombstone next to it, and the tombstone goes to `queue` (deletion at the next restart): queuing
/// the file's own path would delete whatever is there at boot, such as the exe of a reinstall made
/// before that restart (review service-a3). Folders are queued by path, after their files
/// (Windows processes the queue in order and never deletes a folder that is not empty).
fn remove_or_schedule(dir: &Path, queue: &mut dyn FnMut(&Path)) {
    // Listed first: a tombstone made below must not show up in this same listing.
    let entries: Vec<_> = std::fs::read_dir(dir)
        .map(|list| list.flatten().collect())
        .unwrap_or_default();
    for entry in entries {
        let path = entry.path();
        // Never descend into a link: it is removed itself, not its target.
        let is_dir = entry
            .file_type()
            .is_ok_and(|t| t.is_dir() && !t.is_symlink());
        if is_dir {
            remove_or_schedule(&path, queue);
        } else if std::fs::remove_file(&path).is_err() {
            let tombstone = tombstone(&path);
            match std::fs::rename(&path, &tombstone) {
                Ok(()) => queue(&tombstone),
                Err(err) => {
                    tracing::warn!(path = %path.display(), error = %err, "in use: left in place");
                }
            }
        }
    }
    if std::fs::remove_dir(dir).is_err() {
        queue(dir);
    }
}

/// `<name>.<time>.deleted` next to `path`: a name no install writes.
fn tombstone(path: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{stamp}.deleted"));
    path.with_file_name(name)
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

#[cfg(test)]
mod tests;
