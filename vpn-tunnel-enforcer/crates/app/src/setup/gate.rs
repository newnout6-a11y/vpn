//! `--setup await-shutdown` (delivery §6.6, `installer/PROGRESS.md`): asks the installed client
//! to clean up and exit, waits for its acknowledgement, then makes sure nothing of ours still runs
//! from the installation before the installer replaces or deletes a file. The OS sits behind
//! [`ProcessOs`], so every decision runs against a fake in the unit tests.
use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use windows::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

/// The client's file name in the installation directory.
pub const MAIN_EXE: &str = "VPN Tunnel Enforcer.exe";
/// Exit code of a client that cleaned up for the installer (lifecycle-app §3.13).
pub const EXIT_ACK: u32 = 73;
/// The argument that asks a running client to clean up and exit with [`EXIT_ACK`].
pub const ARG_SHUTDOWN_FOR_UPDATE: &str = "--shutdown-for-update";
/// Images of this version that run from the installation directory.
const INSTALLED: [&str; 4] = [MAIN_EXE, "vpnte-proxy.exe", "sing-box.exe", "xray.exe"];
/// Images of the Electron generation: under the installation or its old runtime directory.
const LEGACY: [&str; 4] = [
    "vpnte-sing-box.exe",
    "vpnte-xray.exe",
    "vpnte-etw-sidecar.exe",
    "vpnte-external-proxy.exe",
];
/// The drain after the acknowledgement: 25 polls 200 ms apart (5 s).
const DRAIN_POLLS: u32 = 25;
const DRAIN_STEP: Duration = Duration::from_millis(200);
/// How long a leftover may take to die after it was terminated.
const KILL_WAIT: Duration = Duration::from_secs(3);

/// One row of a process snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcRow {
    pub pid: u32,
    pub ppid: u32,
    /// Image file name as the snapshot reports it (`VPN Tunnel Enforcer.exe`).
    pub name: String,
    /// Windows session; `None` when the session list did not report the process.
    pub session: Option<u32>,
}

/// Why a process could not be opened or read.
#[derive(Debug)]
pub enum ProcError {
    /// It exited since the snapshot (`OpenProcess` answers ERROR_INVALID_PARAMETER).
    Gone,
    /// The OS refused access.
    Denied,
    /// Anything else.
    Other(io::Error),
}

/// A process handle bound before the client is signalled: a later PID reuse cannot replace the
/// process whose exit code is read.
pub trait Waitable {
    /// Image path read through this handle.
    fn image_path(&self) -> io::Result<PathBuf>;
    /// `true` when the process ended within `timeout`.
    fn wait(&self, timeout: Duration) -> io::Result<bool>;
    /// Exit code of the ended process.
    fn exit_code(&self) -> io::Result<u32>;
}

/// The process layer of the gate.
pub trait ProcessOs {
    /// Every process: PID, parent PID, image file name.
    fn snapshot(&self) -> io::Result<Vec<ProcRow>>;
    /// Full Win32 image path of `pid`.
    fn image_path(&self, pid: u32) -> Result<PathBuf, ProcError>;
    /// Creation time of `pid` (FILETIME ticks); `None` when unreadable.
    fn created(&self, pid: u32) -> Option<u64>;
    /// Opens `pid` for waiting and reading its exit code.
    fn open_waitable(&self, pid: u32) -> Result<Box<dyn Waitable>, ProcError>;
    /// Starts `exe args` without waiting for it.
    fn spawn_detached(&self, exe: &Path, args: &[&str]) -> io::Result<()>;
    /// Terminates `pid` if it still runs `image`; `true` when it is gone within `wait`.
    fn terminate(&self, pid: u32, image: &Path, wait: Duration) -> io::Result<bool>;
    /// Pauses between drain polls.
    fn sleep(&self, duration: Duration);
}

/// Why the gate refused; `Display` is the one stderr line the installer shows.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    #[error("Installation path is missing; update refused.")]
    PathMissing,
    #[error(
        "Cannot identify the installed primary client. Close VPNTE normally and retry; no processes were killed."
    )]
    CannotIdentify,
    #[error("Primary process identity changed; update refused.")]
    IdentityChanged,
    #[error("Client cleanup timed out; update refused.")]
    Timeout,
    #[error("Client exited without cleanup acknowledgement; update refused.")]
    NoAck(u32),
    #[error("VPNTE background processes remain; update refused.")]
    Remaining,
    /// A process call failed: what was attempted, and the OS error number.
    #[error("Cannot {0} ({1}); update refused.")]
    Os(&'static str, String),
}

impl Refusal {
    fn os(what: &'static str, err: &io::Error) -> Self {
        Refusal::Os(what, os_code(err))
    }
}

/// An OS error as ASCII: the installer decodes our output as ANSI, and the system's message text
/// is localized (Cyrillic on a Russian Windows), so only the number goes out.
pub fn os_code(err: &io::Error) -> String {
    match err.raw_os_error() {
        // An HRESULT carried through `io::Error`.
        Some(code) if code < 0 => format!("0x{:08X}", code.cast_unsigned()),
        Some(code) => format!("os error {code}"),
        None => format!("{:?}", err.kind()),
    }
}

/// Which processes are ours: decided by image path, never by name alone (the user's own
/// `xray.exe` / `sing-box.exe` elsewhere is not ours, nor is a copy of the client elsewhere).
#[derive(Debug, Clone)]
pub struct Scope {
    /// The installation directory: full path, UTF-16, no trailing separator.
    dir: Vec<u16>,
    /// `<dir>\VPN Tunnel Enforcer.exe`.
    exe: Vec<u16>,
    /// `%ProgramData%\VPNTE\runtime` of the Electron generation.
    legacy_runtime: Option<Vec<u16>>,
    /// The helper itself (a copy of the client exe) is never a candidate.
    own_pid: u32,
}

impl Scope {
    /// `install_dir` as the installer passed it (`GetFullPathNameW`, compared ignoring case).
    pub fn new(install_dir: &Path, legacy_runtime: Option<&Path>, own_pid: u32) -> Self {
        let dir = full(install_dir);
        let mut exe = dir.clone();
        exe.push(u16::from(b'\\'));
        exe.extend(MAIN_EXE.encode_utf16());
        Self {
            dir,
            exe,
            legacy_runtime: legacy_runtime.map(full),
            own_pid,
        }
    }

    /// The installed client exe.
    pub fn exe(&self) -> PathBuf {
        PathBuf::from(OsString::from_wide(&self.exe))
    }

    fn is_exe(&self, path: &Path) -> bool {
        same(&full(path), &self.exe)
    }

    /// Where `path` makes a process ours: one of our images under the installation, or an
    /// Electron engine image under the old runtime directory; `None` = not ours.
    fn place(&self, path: &Path) -> Option<Place> {
        let name = path.file_name()?.to_str()?;
        let is = |list: &[&str]| list.iter().any(|n| n.eq_ignore_ascii_case(name));
        let path = full(path);
        let legacy = is(&LEGACY);
        if (is(&INSTALLED) || legacy) && under(&path, &self.dir) {
            Some(Place::Installed)
        } else if legacy
            && self
                .legacy_runtime
                .as_ref()
                .is_some_and(|d| under(&path, d))
        {
            Some(Place::LegacyRuntime)
        } else {
            None
        }
    }
}

/// How a process belongs to the installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// Its image lies under the installation directory.
    Installed,
    /// An Electron engine under `%ProgramData%\VPNTE\runtime`: shared by every old installation,
    /// so it is ours only while no client runs from anywhere else.
    LegacyRuntime,
}

/// A path as Windows compares it: full (`GetFullPathNameW`), UTF-16, without a `\\?\X:` prefix
/// or trailing separators.
fn full(path: &Path) -> Vec<u16> {
    let path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.starts_with(&[92, 92, 63, 92]) && wide.get(5) == Some(&u16::from(b':')) {
        wide.drain(..4);
    }
    while wide.last() == Some(&u16::from(b'\\')) {
        wide.pop();
    }
    wide
}

/// Ordinal comparison ignoring case, as the file system compares names.
fn same(a: &[u16], b: &[u16]) -> bool {
    // SAFETY: plain call over two valid slices.
    unsafe { CompareStringOrdinal(a, b, true) == CSTR_EQUAL }
}

/// Two paths name the same file as Windows compares them (full form, case ignored).
pub fn same_path(a: &Path, b: &Path) -> bool {
    same(&full(a), &full(b))
}

/// `path` lies below `dir` (`C:\X\runtime-evil\a.exe` is not below `C:\X\runtime`).
fn under(path: &[u16], dir: &[u16]) -> bool {
    path.len() > dir.len() + 1
        && path[dir.len()] == u16::from(b'\\')
        && same(&path[..dir.len()], dir)
}

/// One of our processes in a snapshot.
#[derive(Debug, Clone)]
struct Owned {
    pid: u32,
    ppid: u32,
    path: PathBuf,
    /// A client process (`VPN Tunnel Enforcer.exe`), not an engine or helper.
    main: bool,
    /// Runs in another Windows session than the gate: the signal cannot reach it (one instance
    /// per session, each with its own pipe).
    elsewhere: bool,
}

/// The acknowledged client: Electron left helper children of it behind (crashpad).
struct Client {
    pid: u32,
    created: Option<u64>,
}

/// The gate: nothing of ours runs from `install_dir` when it returns `Ok`. A client is only ever
/// asked to exit (`--shutdown-for-update`, acknowledged with exit code 73), never terminated;
/// engines without a client and the leftovers of an acknowledged client are terminated.
pub fn await_shutdown(
    os: &dyn ProcessOs,
    install_dir: Option<&Path>,
    legacy_runtime: Option<&Path>,
    timeout: Duration,
) -> Result<(), Refusal> {
    let dir = install_dir.ok_or(Refusal::PathMissing)?;
    let scope = Scope::new(dir, legacy_runtime, std::process::id());
    gate(os, &scope, timeout)
}

/// [`await_shutdown`] for a given scope.
pub fn gate(os: &dyn ProcessOs, scope: &Scope, timeout: Duration) -> Result<(), Refusal> {
    let owned = scan(os, scope)?;
    if owned.is_empty() {
        return Ok(());
    }
    let primaries: Vec<&Owned> = owned
        .iter()
        .filter(|p| p.main && scope.is_exe(&p.path))
        // A parent counts only if it is older: a recycled parent PID never hides the primary.
        .filter(|p| {
            !owned
                .iter()
                .any(|parent| parent.main && parent.pid == p.ppid && older(os, parent.pid, p.pid))
        })
        .collect();
    let client = match primaries.as_slice() {
        [primary] if !primary.elsewhere => stop_client(os, scope, primary, timeout)?,
        // A client we cannot address (two of them, one in another session, or one elsewhere
        // under the directory).
        [] if owned.iter().any(|p| p.main) => return Err(Refusal::CannotIdentify),
        [] => {
            // Engines without any client (B-08): they only lock our files.
            for p in &owned {
                let _ = os.terminate(p.pid, &p.path, KILL_WAIT);
            }
            None
        }
        _ => return Err(Refusal::CannotIdentify),
    };
    drain(os, scope, client.as_ref())
}

/// Our processes now. A row that exited since the snapshot is skipped; a client whose image
/// cannot be read refuses the gate (it may be ours and could not be addressed) unless it runs in
/// another Windows session: one copy runs per session, and another user's own copy is unreadable
/// to a standard user. An engine-named process that cannot be read is not provably ours and is
/// left alone. While a client runs from another directory, the Electron runtime engines may be
/// its own: they are left alone too.
fn scan(os: &dyn ProcessOs, scope: &Scope) -> Result<Vec<Owned>, Refusal> {
    let rows = os
        .snapshot()
        .map_err(|e| Refusal::os("list processes", &e))?;
    let own_session = rows
        .iter()
        .find(|r| r.pid == scope.own_pid)
        .and_then(|r| r.session);
    let mut owned = Vec::new();
    let mut runtime = Vec::new();
    let mut foreign_client = false;
    for row in rows {
        let named = |list: &[&str]| list.iter().any(|n| n.eq_ignore_ascii_case(&row.name));
        if row.pid == scope.own_pid || !(named(&INSTALLED) || named(&LEGACY)) {
            continue;
        }
        let main = row.name.eq_ignore_ascii_case(MAIN_EXE);
        // An unknown session counts as ours.
        let elsewhere = matches!((own_session, row.session), (Some(a), Some(b)) if a != b);
        let path = match os.image_path(row.pid) {
            Ok(path) => path,
            Err(ProcError::Gone) => continue,
            Err(ProcError::Denied | ProcError::Other(_)) if main => {
                if !elsewhere {
                    return Err(Refusal::CannotIdentify);
                }
                // It may be the user of the shared Electron runtime engines.
                foreign_client = true;
                continue;
            }
            Err(_) => continue,
        };
        let is_main = path
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case(MAIN_EXE));
        let place = scope.place(&path);
        foreign_client |= is_main && place.is_none();
        let process = Owned {
            pid: row.pid,
            ppid: row.ppid,
            path,
            main: is_main,
            elsewhere,
        };
        match place {
            Some(Place::Installed) => owned.push(process),
            Some(Place::LegacyRuntime) => runtime.push(process),
            None => {}
        }
    }
    if !foreign_client {
        owned.extend(runtime);
    }
    Ok(owned)
}

/// `parent` was created before `child` (both readable).
fn older(os: &dyn ProcessOs, parent: u32, child: u32) -> bool {
    matches!((os.created(parent), os.created(child)), (Some(a), Some(b)) if a < b)
}

/// Binds a handle to the client, asks it through the installed exe to clean up and exit, and
/// waits for the acknowledgement. `None`: it exited on its own before it could be bound.
fn stop_client(
    os: &dyn ProcessOs,
    scope: &Scope,
    primary: &Owned,
    timeout: Duration,
) -> Result<Option<Client>, Refusal> {
    let created = os.created(primary.pid);
    let handle = match os.open_waitable(primary.pid) {
        Ok(handle) => handle,
        Err(ProcError::Gone) => return Ok(None),
        Err(ProcError::Denied) => return Err(Refusal::CannotIdentify),
        Err(ProcError::Other(e)) => return Err(Refusal::os("open the client process", &e)),
    };
    if !handle.image_path().is_ok_and(|path| scope.is_exe(&path)) {
        return Err(Refusal::IdentityChanged);
    }
    os.spawn_detached(&scope.exe(), &[ARG_SHUTDOWN_FOR_UPDATE])
        .map_err(|e| Refusal::os("signal the client", &e))?;
    match handle.wait(timeout) {
        Ok(true) => {}
        Ok(false) => return Err(Refusal::Timeout),
        Err(e) => return Err(Refusal::os("wait for the client", &e)),
    }
    match handle.exit_code() {
        Ok(EXIT_ACK) => Ok(Some(Client {
            pid: primary.pid,
            created,
        })),
        Ok(code) => Err(Refusal::NoAck(code)),
        Err(e) => Err(Refusal::os("read the client exit code", &e)),
    }
}

/// Waits up to 5 s until nothing of ours runs any more. Then the leftovers are terminated:
/// engines, and helper children of the acknowledged client (created after it); a second client
/// is never terminated and refuses the gate.
fn drain(os: &dyn ProcessOs, scope: &Scope, client: Option<&Client>) -> Result<(), Refusal> {
    for poll in 0..DRAIN_POLLS {
        if poll > 0 {
            os.sleep(DRAIN_STEP);
        }
        if scan(os, scope)?.is_empty() {
            return Ok(());
        }
    }
    let left = scan(os, scope)?;
    let helper = |p: &Owned| {
        client.is_some_and(|c| {
            p.ppid == c.pid && matches!((c.created, os.created(p.pid)), (Some(a), Some(b)) if a < b)
        })
    };
    if left.iter().any(|p| p.main && !helper(p)) {
        return Err(Refusal::Remaining);
    }
    for p in &left {
        let _ = os.terminate(p.pid, &p.path, KILL_WAIT);
    }
    if scan(os, scope)?.is_empty() {
        Ok(())
    } else {
        Err(Refusal::Remaining)
    }
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod tests;
