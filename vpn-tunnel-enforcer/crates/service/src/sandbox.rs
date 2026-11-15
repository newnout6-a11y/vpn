//! Engines may not start programs (research §3.5): every engine process running from the
//! service's folder is confined in a job of its own with `ActiveProcessLimit = 1`. The engine
//! crate already holds each engine in a kill-on-close job; Windows 8+ nests the new job inside it
//! (a process already in a job may join an empty one, which becomes its child), so lifetime and
//! crash handling stay the engine crate's while any process the engine tries to create fails
//! with a quota error. A seat belt, not a wall: an engine runs for a moment before it is confined.
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_tunnel::api::{TunStatus, TunnelEvent};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOBOBJECT_BASIC_LIMIT_INFORMATION, JobObjectBasicLimitInformation, SetInformationJobObject,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
};
use windows::core::{BOOL, PCWSTR};

/// Engine images the service runs.
const ENGINES: [&str; 2] = ["sing-box.exe", "xray.exe"];

/// While a session runs, Xray slots may restart without a runtime event: look again this often.
const SESSION_SWEEP: Duration = Duration::from_secs(10);

/// An owned handle.
struct Owned(HANDLE);

// SAFETY: a kernel handle may be used and closed from any thread; this value is its only owner.
unsafe impl Send for Owned {}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value and closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// The confining job of one process (closing it neither kills nor frees the process).
pub struct Confined(Owned);

/// Puts process `pid` into a new job that allows no further process.
pub fn confine(pid: u32) -> windows::core::Result<Confined> {
    // SAFETY: plain handle-returning calls; both handles are owned at once.
    let (job, process) = unsafe {
        let job = Owned(CreateJobObjectW(None, PCWSTR::null())?);
        let rights = PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION;
        (job, Owned(OpenProcess(rights, false, pid)?))
    };
    let limit = JOBOBJECT_BASIC_LIMIT_INFORMATION {
        LimitFlags: JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        ActiveProcessLimit: 1,
        ..Default::default()
    };
    // SAFETY: valid job and process handles; `limit` is the structure the class names.
    unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectBasicLimitInformation,
            (&raw const limit).cast(),
            size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
        )?;
        AssignProcessToJobObject(job.0, process.0)?;
    }
    Ok(Confined(job))
}

fn still_confined(pid: u32, confined: &Confined) -> bool {
    // SAFETY: plain query on a freshly opened handle.
    unsafe {
        let Ok(process) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let process = Owned(process);
        let mut inside = BOOL(0);
        IsProcessInJob(process.0, Some(confined.0.0), &mut inside).is_ok() && inside.as_bool()
    }
}

/// The engine processes of one folder and their confining jobs.
pub struct Sandbox {
    dir: PathBuf,
    confined: HashMap<u32, Confined>,
}

impl Sandbox {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            confined: HashMap::new(),
        }
    }

    /// Confines every engine running from the folder that is not confined yet (a reused PID
    /// is noticed: its process is not in the old job) and forgets ended ones. Blocking.
    pub fn sweep(&mut self) {
        let scan =
            match vpnte_winnet::process::find_under(std::slice::from_ref(&self.dir), &ENGINES) {
                Ok(scan) => scan,
                Err(err) => return tracing::warn!(error = %err, "engine scan failed"),
            };
        let running: Vec<u32> = scan.owned.iter().map(|p| p.pid).collect();
        self.confined
            .retain(|pid, job| running.contains(pid) && still_confined(*pid, job));
        for pid in running {
            if self.confined.contains_key(&pid) {
                continue;
            }
            match confine(pid) {
                Ok(job) => {
                    self.confined.insert(pid, job);
                }
                Err(err) => tracing::warn!(pid, error = %err, "engine not confined"),
            }
        }
    }
}

/// Sweeps after every runtime status change or event, and every [`SESSION_SWEEP`] while a
/// session runs; with no session it only waits (no timer).
pub async fn run(
    sandbox: Sandbox,
    mut status: watch::Receiver<TunStatus>,
    mut events: broadcast::Receiver<TunnelEvent>,
    stop: CancellationToken,
) {
    let mut sandbox = Some(sandbox);
    loop {
        let session = status.borrow_and_update().capture.is_some();
        let go_on = tokio::select! {
            () = stop.cancelled() => false,
            changed = status.changed() => changed.is_ok(),
            e = events.recv() => !matches!(e, Err(broadcast::error::RecvError::Closed)),
            () = tokio::time::sleep(SESSION_SWEEP), if session => true,
        };
        let Some(mut current) = sandbox.take().filter(|_| go_on) else {
            break;
        };
        sandbox = tokio::task::spawn_blocking(move || {
            current.sweep();
            current
        })
        .await
        .ok();
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    use super::*;

    /// Runs `hostname` through `cmd` (a stand-in that starts programs on request), confined or
    /// not; returns stdout (lowercase) and whether stderr said anything.
    fn hostname_via_cmd(system: &std::path::Path, confined: bool) -> (String, bool) {
        let mut child = Command::new(system.join("cmd.exe"))
            .args(["/q", "/d", "/k", "prompt $s"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("cmd");
        let job = confined.then(|| confine(child.id()).expect("confined"));
        if let Some(job) = &job {
            assert!(still_confined(child.id(), job));
        }
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(b"hostname\r\nexit 0\r\n")
            .expect("commands");
        drop(stdin);
        // cmd writes in the console code page: compare bytes, not UTF-8 text.
        let (mut out, mut err) = (Vec::new(), Vec::new());
        child
            .stdout
            .take()
            .expect("out")
            .read_to_end(&mut out)
            .expect("read out");
        child
            .stderr
            .take()
            .expect("err")
            .read_to_end(&mut err)
            .expect("read err");
        let _ = child.wait();
        (
            String::from_utf8_lossy(&out).to_lowercase(),
            !err.trim_ascii().is_empty(),
        )
    }

    /// A confined process cannot start another one; the same commands unconfined can.
    #[test]
    fn a_confined_process_cannot_start_programs() {
        let system = std::env::var_os("SystemRoot").map(PathBuf::from);
        let Some(system) = system.map(|s| s.join("System32")) else {
            return eprintln!("skipped: no SystemRoot");
        };
        let host = std::env::var("COMPUTERNAME")
            .unwrap_or_default()
            .to_lowercase();
        if host.is_empty() {
            return eprintln!("skipped: no COMPUTERNAME");
        }
        let (free, _) = hostname_via_cmd(&system, false);
        assert!(free.contains(&host), "control run: {free}");
        let (out, complained) = hostname_via_cmd(&system, true);
        assert!(!out.contains(&host), "hostname ran: {out}");
        assert!(complained, "cmd reports the refused start");
    }
}
