//! The real process layer of the installer gate: Toolhelp snapshot with session ids, image
//! paths, creation times, bound handles, a detached start and termination (delivery §6.6
//! `ProcessOs`).
use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES,
    FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT, WIN32_ERROR,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_PROCESS_INFOW, WTSEnumerateProcessesW, WTSFreeMemory,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_ACCESS_RIGHTS,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
};
use windows::core::{Owned, PWSTR};

use super::gate::{ProcError, ProcRow, ProcessOs, Waitable};

/// The Windows process layer.
pub struct RealProcesses;

impl ProcessOs for RealProcesses {
    fn snapshot(&self) -> io::Result<Vec<ProcRow>> {
        // Before the snapshot: a process started in between has no session (counts as ours).
        let sessions = sessions();
        // SAFETY: plain call; the handle is owned right below.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
        // SAFETY: the snapshot handle is ours and closed only by `Owned`.
        let snap = unsafe { Owned::new(snap) };
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut rows = Vec::new();
        // SAFETY: `entry` is a valid PROCESSENTRY32W with `dwSize` set, for both calls.
        let mut step = unsafe { Process32FirstW(*snap, &mut entry) };
        loop {
            if let Err(err) = step {
                // Any other end than "no more" leaves the list incomplete: refuse rather than
                // miss a client.
                return match WIN32_ERROR::from_error(&err) {
                    Some(ERROR_NO_MORE_FILES) => Ok(rows),
                    _ => Err(err.into()),
                };
            }
            let len = entry
                .szExeFile
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(entry.szExeFile.len());
            rows.push(ProcRow {
                pid: entry.th32ProcessID,
                ppid: entry.th32ParentProcessID,
                name: String::from_utf16_lossy(&entry.szExeFile[..len]),
                session: sessions.get(&entry.th32ProcessID).copied(),
            });
            // SAFETY: as above.
            step = unsafe { Process32NextW(*snap, &mut entry) };
        }
    }

    fn image_path(&self, pid: u32) -> Result<PathBuf, ProcError> {
        let process = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        query_image(*process).map_err(classify)
    }

    fn created(&self, pid: u32) -> Option<u64> {
        let process = open(pid, PROCESS_QUERY_LIMITED_INFORMATION).ok()?;
        let mut created = FILETIME::default();
        let (mut exited, mut kernel, mut user) = (created, created, created);
        // SAFETY: four valid out pointers for the duration of the call.
        unsafe { GetProcessTimes(*process, &mut created, &mut exited, &mut kernel, &mut user) }
            .ok()?;
        let FILETIME {
            dwLowDateTime: low,
            dwHighDateTime: high,
        } = created;
        Some((u64::from(high) << 32) | u64::from(low))
    }

    fn open_waitable(&self, pid: u32) -> Result<Box<dyn Waitable>, ProcError> {
        let process = open(pid, PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)?;
        Ok(Box::new(Bound(process)))
    }

    fn spawn_detached(&self, exe: &Path, args: &[&str]) -> io::Result<()> {
        // Our stdout / stderr are the installer's capture pipes: the child must not hold them.
        Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW.0)
            .spawn()
            .map(drop)
    }

    fn terminate(&self, pid: u32, image: &Path, wait: Duration) -> io::Result<bool> {
        let rights = PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
        let process = match open(pid, rights) {
            Ok(process) => process,
            Err(ProcError::Gone) => return Ok(true),
            Err(ProcError::Denied) => return Err(io::ErrorKind::PermissionDenied.into()),
            Err(ProcError::Other(err)) => return Err(err),
        };
        // The PID may have been reused since the snapshot: only the process that still runs
        // `image` is ours, and the one we meant is gone otherwise.
        if !query_image(*process).is_ok_and(|path| path == image) {
            return Ok(true);
        }
        // SAFETY: the handle is open with PROCESS_TERMINATE.
        unsafe { TerminateProcess(*process, 1) }?;
        wait_for(*process, wait)
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// A handle bound to the client before it is signalled.
struct Bound(Owned<HANDLE>);

impl Waitable for Bound {
    fn image_path(&self) -> io::Result<PathBuf> {
        Ok(query_image(*self.0)?)
    }
    fn wait(&self, timeout: Duration) -> io::Result<bool> {
        wait_for(*self.0, timeout)
    }
    fn exit_code(&self) -> io::Result<u32> {
        let mut code = 0u32;
        // SAFETY: `code` is a valid out pointer for the duration of the call.
        unsafe { GetExitCodeProcess(*self.0, &mut code) }?;
        Ok(code)
    }
}

/// `true` when the process ended within `timeout`.
fn wait_for(process: HANDLE, timeout: Duration) -> io::Result<bool> {
    // u32::MAX would be INFINITE.
    let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
    // SAFETY: the handle is open with SYNCHRONIZE.
    match unsafe { WaitForSingleObject(process, ms) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Opens a process; the handle closes on drop.
fn open(pid: u32, rights: PROCESS_ACCESS_RIGHTS) -> Result<Owned<HANDLE>, ProcError> {
    if pid == 0 {
        return Err(ProcError::Gone);
    }
    // SAFETY: plain call without pointers.
    let handle = unsafe { OpenProcess(rights, false, pid) }.map_err(classify)?;
    // SAFETY: the handle was just returned to us and is closed only by `Owned`.
    Ok(unsafe { Owned::new(handle) })
}

/// Session id of every process from the session list. Unlike `ProcessIdToSessionId` it opens no
/// process, so it covers another user's processes, which a standard user cannot open. Empty when
/// the list is unavailable: then no process counts as another session's.
fn sessions() -> HashMap<u32, u32> {
    let mut info: *mut WTS_PROCESS_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: two valid out pointers; on success `info` is freed with WTSFreeMemory below.
    let listed = unsafe {
        WTSEnumerateProcessesW(Some(WTS_CURRENT_SERVER_HANDLE), 0, 1, &mut info, &mut count)
    };
    if listed.is_err() || info.is_null() {
        return HashMap::new();
    }
    // SAFETY: on success `info` points to `count` initialised entries owned by wtsapi32 until
    // the free below.
    let map = unsafe { std::slice::from_raw_parts(info, count as usize) }
        .iter()
        .map(|p| (p.ProcessId, p.SessionId))
        .collect();
    // SAFETY: `info` came from WTSEnumerateProcessesW and is freed exactly once.
    unsafe { WTSFreeMemory(info.cast()) };
    map
}

/// ERROR_INVALID_PARAMETER from `OpenProcess` means the PID no longer exists.
fn classify(err: windows::core::Error) -> ProcError {
    match WIN32_ERROR::from_error(&err) {
        Some(ERROR_INVALID_PARAMETER) => ProcError::Gone,
        Some(ERROR_ACCESS_DENIED) => ProcError::Denied,
        _ => ProcError::Other(err.into()),
    }
}

/// Image path of an open process (`PROCESS_QUERY_LIMITED_INFORMATION` suffices).
fn query_image(process: HANDLE) -> windows::core::Result<PathBuf> {
    // Long-path installs exceed MAX_PATH: grow up to the 32K Win32 limit.
    let mut buf = vec![0u16; 1024];
    loop {
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` UTF-16 units; on success `len` is the length written.
        let res = unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        };
        match res {
            Ok(()) => return Ok(PathBuf::from(OsString::from_wide(&buf[..len as usize]))),
            Err(e)
                if WIN32_ERROR::from_error(&e) == Some(ERROR_INSUFFICIENT_BUFFER)
                    && buf.len() < 32_768 =>
            {
                buf.resize(buf.len() * 4, 0);
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bound handle reports exactly the exit code of a real child (delivery §7.3, the
    /// real-process row): `cmd /c exit 73` stands in for the acknowledging client.
    #[test]
    fn bound_handle_reads_the_real_exit_code() {
        let os = RealProcesses;
        for code in [0u32, 73] {
            let child = Command::new("cmd.exe")
                .args(["/d", "/c", &format!("exit {code}")])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW.0)
                .spawn()
                .expect("cmd.exe starts");
            let handle = os.open_waitable(child.id()).expect("bound");
            assert!(handle.wait(Duration::from_secs(10)).expect("waited"));
            assert_eq!(handle.exit_code().expect("exit code"), code);
            drop(child);
        }
    }

    /// The snapshot lists this test process with its image path and creation time.
    #[test]
    fn snapshot_sees_this_process() {
        let os = RealProcesses;
        let me = std::process::id();
        let rows = os.snapshot().expect("snapshot");
        let row = rows.iter().find(|r| r.pid == me);
        assert!(row.is_some_and(|r| r.name.ends_with(".exe")));
        let path = os.image_path(me).expect("own image");
        assert_eq!(path, std::env::current_exe().expect("current exe"));
        assert!(os.created(me).is_some());
        assert!(matches!(os.image_path(0), Err(ProcError::Gone)));

        // The session ids come without opening a process: our own matches the kernel's, and an
        // interactive session also sees the services of session 0, which it cannot open.
        let mut own = u32::MAX;
        // SAFETY: valid out pointer.
        unsafe { windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(me, &mut own) }
            .expect("own session");
        assert_eq!(row.and_then(|r| r.session), Some(own));
        if own != 0 {
            assert!(rows.iter().any(|r| r.session == Some(0) && r.pid > 4));
        }
    }
}
