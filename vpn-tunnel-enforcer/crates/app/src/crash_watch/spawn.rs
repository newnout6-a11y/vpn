//! Starting and stopping the watcher process: CreateProcessW by hand, because std's `Command`
//! always lets the child inherit every inheritable handle of the app (engine pipes of the
//! moment), and the watcher must hold nothing of ours but the wait on our process.
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW, CreateProcessW, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows::core::{Owned, PCWSTR, PWSTR};

/// How long a stop waits for the watcher to be gone (it holds the exe open: an update that
/// replaces the exe right after must not find it running).
const STOP_WAIT_MS: u32 = 2_000;

/// A started watcher. Dropping it leaves the process running on purpose: a panic unwinding
/// the app must not take its guardian down.
#[derive(Debug)]
pub struct Child {
    process: Owned<HANDLE>,
    pid: u32,
}

// SAFETY: a process handle may be waited on, terminated and closed from any thread.
unsafe impl Send for Child {}

/// Starts `exe` with `args` (one command-line string): no window, no inherited handle, out of
/// the app's job when the job allows it (a launcher's kill-on-close job would end the watcher
/// together with a crashed app), in the exe's directory (not the app's current directory, which
/// may be a drive the user wants to eject).
pub fn spawn(exe: &Path, args: &str) -> io::Result<Child> {
    let flags = CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB;
    match create(exe, args, flags) {
        Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => {
            // The job forbids breakaway: inside it is still better than no watcher.
            create(exe, args, CREATE_NO_WINDOW)
        }
        other => other,
    }
    .map_err(io::Error::from)
}

fn create(exe: &Path, args: &str, flags: PROCESS_CREATION_FLAGS) -> windows::core::Result<Child> {
    let app = wide(exe.as_os_str());
    // The exe path goes in as it is (no lossy display form): `"<exe>" <args>`.
    let mut line: Vec<u16> = "\""
        .encode_utf16()
        .chain(exe.as_os_str().encode_wide())
        .chain("\" ".encode_utf16())
        .chain(args.encode_utf16())
        .chain([0])
        .collect();
    let dir = exe.parent().map(|d| wide(d.as_os_str()));
    let dir = dir.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr()));
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every string is NUL-terminated and outlives the call; the command line buffer is
    // writable as CreateProcessW requires; `info` is a valid out-pointer.
    unsafe {
        CreateProcessW(
            PCWSTR(app.as_ptr()),
            Some(PWSTR(line.as_mut_ptr())),
            None,
            None,
            false,
            flags,
            None,
            dir,
            &startup,
            &mut info,
        )
    }?;
    // SAFETY: both handles are fresh and ours; the thread handle is not needed.
    let (process, _thread) = unsafe { (Owned::new(info.hProcess), Owned::new(info.hThread)) };
    Ok(Child {
        process,
        pid: info.dwProcessId,
    })
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain([0]).collect()
}

impl Child {
    /// Process id.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Still running (`false` also when Windows cannot tell).
    pub fn running(&self) -> bool {
        // SAFETY: a valid process handle; a zero timeout only polls.
        unsafe { WaitForSingleObject(*self.process, 0) == WAIT_TIMEOUT }
    }

    /// Waits up to `ms` for the exit; `true` once it has exited.
    pub fn wait(&self, ms: u32) -> bool {
        // SAFETY: a valid process handle.
        unsafe { WaitForSingleObject(*self.process, ms) == WAIT_OBJECT_0 }
    }

    /// Ends the process (the app started it, so the app may) and waits briefly for its exit.
    pub fn stop(&self) {
        if !self.running() {
            return;
        }
        // SAFETY: a valid handle with terminate rights (we created the process).
        if let Err(e) = unsafe { TerminateProcess(*self.process, 0) } {
            tracing::warn!(error = %e, pid = self.pid, "crash watcher not stopped");
            return;
        }
        if !self.wait(STOP_WAIT_MS) {
            tracing::warn!(pid = self.pid, "crash watcher still running after stop");
        }
    }
}
