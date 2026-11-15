//! Which process saved the journal last. A crash watcher rolls back only what its own app left:
//! once another process (the next start, an uninstall helper) has written the journal, the
//! obligations are that process's to handle, and a late watcher must not undo a session it
//! did not see start.
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{FILETIME, HANDLE, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};
use windows::core::Owned;

/// A process across PID reuse: its id and its start time (FILETIME ticks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Writer {
    pub pid: u32,
    pub started: u64,
}

impl Writer {
    /// This process (`started` = 0 if Windows cannot tell: never equal to a real start).
    pub fn current() -> Self {
        // SAFETY: plain calls; the pseudo handle of the current process needs no closing.
        let (pid, handle) = unsafe { (GetCurrentProcessId(), GetCurrentProcess()) };
        Self {
            pid,
            started: started(handle).unwrap_or(0),
        }
    }

    /// The process `pid` behind `handle` (opened with at least
    /// `PROCESS_QUERY_LIMITED_INFORMATION`).
    pub fn of_process(pid: u32, handle: HANDLE) -> windows::core::Result<Self> {
        Ok(Self {
            pid,
            started: started(handle)?,
        })
    }

    /// Whether this process still runs: its PID opens, started at the same time (a PID reused
    /// by a later process is not it, the usual case after a reboot) and not exited. A PID
    /// Windows will not open for us belongs to another account (our app runs as this user): gone.
    pub fn is_running(self) -> bool {
        let access = PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
        // SAFETY: plain call; the handle is owned at once.
        let Ok(handle) = (unsafe { OpenProcess(access, false, self.pid) }) else {
            return false;
        };
        // SAFETY: a fresh handle of ours.
        let handle = unsafe { Owned::new(handle) };
        let same = started(*handle).is_ok_and(|s| s == self.started);
        // An exited process stays openable while anyone holds a handle to it (its crash
        // watcher does): the wait tells it apart.
        // SAFETY: a valid handle with SYNCHRONIZE; a zero timeout only polls.
        same && unsafe { WaitForSingleObject(*handle, 0) } == WAIT_TIMEOUT
    }
}

fn started(handle: HANDLE) -> windows::core::Result<u64> {
    let mut times = [FILETIME::default(); 4];
    let [created, exited, kernel, user] = &mut times;
    // SAFETY: four valid out-pointers for the duration of the call.
    unsafe { GetProcessTimes(handle, created, exited, kernel, user)? };
    Ok(u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_has_a_start_time() {
        let me = Writer::current();
        assert_eq!(me.pid, std::process::id());
        assert_ne!(me.started, 0);
        // SAFETY: the pseudo handle of the current process.
        let again = Writer::of_process(me.pid, unsafe { GetCurrentProcess() }).unwrap();
        assert_eq!(again, me);
    }

    /// A live process is running; the same PID with another start time (PID reuse), a PID that
    /// was never used and an exited child are not.
    #[test]
    fn only_the_live_process_itself_is_running() {
        let me = Writer::current();
        assert!(me.is_running());
        assert!(
            !Writer {
                started: me.started + 1,
                ..me
            }
            .is_running()
        );
        assert!(
            !Writer {
                pid: u32::MAX - 3,
                started: 1
            }
            .is_running()
        );

        // This test binary again, with a filter that matches nothing: it exits at once.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "no-such-test", "--quiet"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let handle = HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(&child));
        let it = Writer::of_process(child.id(), handle).unwrap();
        child.wait().unwrap();
        // Still openable (we hold its handle), but exited.
        assert!(!it.is_running());
    }
}
