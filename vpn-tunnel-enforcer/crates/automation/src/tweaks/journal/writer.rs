//! Which process saved the journal last. A crash watcher rolls back only what its own app left:
//! once another process (the next start, an uninstall helper) has written the journal, the
//! obligations are that process's to handle, and a late watcher must not undo a session it
//! did not see start.
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetProcessTimes};

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
}
