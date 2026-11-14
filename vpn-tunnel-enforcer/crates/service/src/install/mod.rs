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

pub mod entry;
mod firewall;
pub mod flow;
pub mod image;
pub mod pins;

/// The description Services shows (system text, English like Windows' own entries).
pub const DESCRIPTION: &str = "Runs the Tunnel mode of VPN Tunnel Enforcer: the virtual adapter, \
the VPN engines and the kill switch. The app works in proxy mode without it.";

/// How long install / uninstall wait for the SCM.
const SCM_WAIT: Duration = Duration::from_secs(30);
/// How long the sweep waits for the service process it follows to end.
const SWEEP_WAIT: Duration = Duration::from_secs(60);

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

    fn remove_rules(&self) -> AppResult<()> {
        let dir = paths::install_dir().map_err(failed)?;
        firewall::remove_for(&dir);
        Ok(())
    }

    fn delete(&self) -> AppResult<()> {
        manage::delete().map_err(failed)?;
        unlist();
        Ok(())
    }

    fn remove_folders(&self) -> AppResult<()> {
        let mut first = Ok(());
        for dir in [paths::install_dir(), paths::data_dir()] {
            let removed = dir.map_err(failed).and_then(|dir| {
                if !dir.exists() {
                    Ok(())
                } else if runs_from(&dir) {
                    // Settings > Apps runs the installed exe (`request-uninstall`, then this
                    // verb): its file goes at the next restart, as after the last user's leave.
                    let left = remove_or_schedule(&dir, &mut schedule);
                    log_held(&left);
                    Ok(())
                } else {
                    retry(|| std::fs::remove_dir_all(&dir).map_err(AppError::internal))
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
    let bytes = files.iter().map(|(_, bytes)| bytes.len()).sum::<usize>() + service_exe.len();
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
    // The installer's exe is never on trial, and nothing the feed staged outlives it: a rollback
    // to an older release must not take the newer one back at its next start (svcupd-a7).
    crate::update::swap::forget(&crate::update::swap::SwapFiles::new(&exe));
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
    list(&exe, bytes as u64);
    Ok(exe)
}

/// Lists the registered service in Settings > Apps. A failed write costs only that line: the
/// service works, and the `uninstall` verb or the last user's leave still remove it.
fn list(exe: &Path, bytes: u64) {
    let listed = entry::Entry {
        exe,
        version: env!("CARGO_PKG_VERSION"),
        bytes,
        lang: entry::system_lang(),
    };
    if let Err(err) = entry::write(&entry::Place::machine(), &listed) {
        tracing::warn!(error = %err, "Settings > Apps entry not written");
    }
}

/// Takes the service off Settings > Apps, once its registration is deleted.
fn unlist() {
    if let Err(err) = entry::remove(&entry::Place::machine()) {
        tracing::warn!(error = %err, "Settings > Apps entry not removed");
    }
}

/// At the service's start: Settings > Apps names the running version. The service's own update
/// (a swap, or its rollback) changes the exe under the entry, and a service an older build
/// installed has none yet. Runs before the service log: a failure only leaves the old line.
pub fn relist() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    if !entry::names(&entry::Place::machine(), env!("CARGO_PKG_VERSION")) {
        list(&exe, exe.parent().map_or(0, bytes_under));
    }
}

/// Bytes of the files under `dir`: what the service's folder takes (links are not followed).
fn bytes_under(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    (entries.flatten())
        .map(|item| match item.file_type() {
            Ok(kind) if kind.is_dir() => bytes_under(&item.path()),
            Ok(kind) if kind.is_file() => item.metadata().map_or(0, |meta| meta.len()),
            _ => 0,
        })
        .sum()
}

/// This process runs an exe inside `dir`.
fn runs_from(dir: &Path) -> bool {
    std::env::current_exe().is_ok_and(|exe| inside(&exe, dir))
}

/// `path` lies in `dir` or below it (Windows paths: any case).
fn inside(path: &Path, dir: &Path) -> bool {
    let (exe, dir) = (path.to_string_lossy(), dir.to_string_lossy());
    let dir = dir.trim_end_matches('\\');
    exe.len() > dir.len()
        && exe.as_bytes()[dir.len()] == b'\\'
        && exe
            .get(..dir.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(dir))
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
/// removes our WFP objects and the firewall rules sing-box made for the engines, deletes the
/// engine files and the data folder; what is in use (the running exe, its folder, the open
/// service log) is deleted by Windows at the next restart. The engine files stay open in this
/// process until it exits (the engine pins hold them against a swap): a sweep started from the
/// exe's tombstone deletes them once this process is gone (lab F-8).
pub fn remove_self(exe: &Path) {
    match manage::delete() {
        Ok(()) => unlist(),
        Err(err) => tracing::warn!(error = %err, "service registration not deleted"),
    }
    if let Err(err) = vpnte_winnet::wfp::remove_all() {
        tracing::warn!(error = %err, "WFP objects not removed");
    }
    if let Ok(data) = paths::data_dir() {
        remove_or_schedule(&data, &mut schedule);
    }
    let Some(dir) = exe.parent() else {
        return;
    };
    firewall::remove_for(dir);
    let left = remove_or_schedule(dir, &mut schedule);
    if left.held.is_empty() {
        return;
    }
    match left.tombstone_of(exe) {
        Some(tombstone) => start_sweep(tombstone),
        None => log_held(&left),
    }
}

/// The `sweep <pid>` verb: the service's own removal starts it (as SYSTEM, from the tombstone of
/// its exe) for the engine files its process held open. It waits for that process to end, then
/// removes what is left of the service's folder, unless a service is registered again by then
/// (a reinstall's files are never touched).
pub fn sweep(parent: &str) -> AppResult<()> {
    require_elevation()?;
    let pid: u32 = parent
        .parse()
        .map_err(|_| failed(std::io::Error::other("sweep: not a process id")))?;
    wait_for_exit(pid, SWEEP_WAIT);
    if manage::installed_binary().map_err(failed)?.is_some() {
        tracing::info!("sweep: a service is registered again; its folder stays");
        return Ok(());
    }
    let dir = paths::install_dir().map_err(failed)?;
    if dir.exists() {
        let left = remove_or_schedule(&dir, &mut schedule);
        log_held(&left);
    }
    Ok(())
}

/// Starts `<tombstone> sweep <this pid>` detached: it outlives this process by design.
fn start_sweep(tombstone: &Path) {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    let started = Command::new(tombstone)
        .args(["sweep", &std::process::id().to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
        .spawn();
    match started {
        Ok(_) => tracing::info!("engine files held by this process: a sweep follows its exit"),
        Err(err) => tracing::warn!(error = %err, "sweep not started: engine files stay"),
    }
}

/// Waits up to `limit` for process `pid` to end (gone already: at once).
fn wait_for_exit(pid: u32, limit: Duration) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };
    // SAFETY: SYNCHRONIZE only; the handle is closed below.
    let Ok(process) = (unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }) else {
        return;
    };
    let ms = u32::try_from(limit.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: a live process handle; waiting has no other effect.
    unsafe {
        WaitForSingleObject(process, ms);
        let _ = CloseHandle(process);
    }
}

fn log_held(left: &Left) {
    for path in &left.held {
        tracing::warn!(path = %path.display(), "in use: left in place");
    }
}

/// What [`remove_or_schedule`] could not delete at once.
#[derive(Debug, Default)]
pub(crate) struct Left {
    /// Files in use renamed to tombstones (queued for the next restart): `(path, tombstone)`.
    pub renamed: Vec<(PathBuf, PathBuf)>,
    /// Files neither deleted nor renamed: open in a process without delete sharing.
    pub held: Vec<PathBuf>,
}

impl Left {
    /// The tombstone `exe` went to.
    fn tombstone_of(&self, exe: &Path) -> Option<&Path> {
        let name = exe.file_name()?.to_str()?;
        self.renamed
            .iter()
            .find(|(from, _)| {
                (from.file_name().and_then(|n| n.to_str()))
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            })
            .map(|(_, to)| to.as_path())
    }
}

/// Deletes `dir` bottom-up. A file in use (the running exe, the open service log) is renamed to a
/// tombstone next to it, and the tombstone goes to `queue` (deletion at the next restart): queuing
/// the file's own path would delete whatever is there at boot, such as the exe of a reinstall made
/// before that restart (review service-a3). Folders are queued by path, after their files
/// (Windows processes the queue in order and never deletes a folder that is not empty). A file
/// open without delete sharing can be neither: it is reported as held.
fn remove_or_schedule(dir: &Path, queue: &mut dyn FnMut(&Path)) -> Left {
    let mut left = Left::default();
    sweep_dir(dir, queue, &mut left);
    left
}

fn sweep_dir(dir: &Path, queue: &mut dyn FnMut(&Path), left: &mut Left) {
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
            sweep_dir(&path, queue, left);
        } else if std::fs::remove_file(&path).is_err() {
            let tombstone = tombstone(&path);
            match std::fs::rename(&path, &tombstone) {
                Ok(()) => {
                    queue(&tombstone);
                    left.renamed.push((path, tombstone));
                }
                Err(_) => left.held.push(path),
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
