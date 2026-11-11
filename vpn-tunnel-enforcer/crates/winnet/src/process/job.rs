//! Kill-on-close Job Object and the hidden spawn used for every child process.
use std::io;
use std::process::Stdio;
use std::sync::OnceLock;

use tokio::process::{Child, Command};
use windows::Win32::Foundation::{CloseHandle, ERROR_INVALID_HANDLE, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Threading::CREATE_NO_WINDOW;
use windows::core::PCWSTR;

/// A Job Object whose members are killed when its last handle closes: on drop, and by the OS
/// when our process ends for any reason (crash, kill from Task Manager, logoff).
#[derive(Debug)]
pub struct Job(HANDLE);

// SAFETY: a job handle is a process-wide kernel handle and the Job API is thread-safe.
unsafe impl Send for Job {}
// SAFETY: as above; `&Job` only allows assign/terminate, which the kernel serialises.
unsafe impl Sync for Job {}

impl Job {
    /// Creates an anonymous job with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
    pub fn kill_on_close() -> windows::core::Result<Self> {
        // SAFETY: default security, no name; the returned handle is owned by the `Job` at once.
        let job = Job(unsafe { CreateJobObjectW(None, PCWSTR::null())? });
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // DIE_ON_UNHANDLED_EXCEPTION: a crashing engine must exit at once instead of hanging in an
        // error-reporting dialog nobody can see (CREATE_NO_WINDOW) while looking alive to us.
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        // SAFETY: `info` is a valid JOBOBJECT_EXTENDED_LIMIT_INFORMATION and the length is its size.
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )?;
        }
        Ok(job)
    }

    /// Puts a running child into the job (fails if the child was already reaped).
    pub fn assign(&self, child: &Child) -> windows::core::Result<()> {
        let process = child
            .raw_handle()
            .ok_or_else(|| windows::core::Error::from(ERROR_INVALID_HANDLE))?;
        // SAFETY: both handles stay valid for the call: the job is owned, the child is borrowed.
        unsafe { AssignProcessToJobObject(self.0, HANDLE(process)) }
    }

    /// Kills every process of the job with `exit_code` (the job itself stays usable).
    pub fn terminate(&self, exit_code: u32) -> windows::core::Result<()> {
        // SAFETY: `self.0` is a valid job handle owned by `self`.
        unsafe { TerminateJobObject(self.0, exit_code) }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and closed exactly once; closing it kills the members.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Process-wide job for children that should simply die with the app (tools, one-shot checks).
/// It is never dropped: the OS closes its handle, and so kills its members, when we exit.
pub fn app_job() -> io::Result<&'static Job> {
    static JOB: OnceLock<Job> = OnceLock::new();
    if let Some(job) = JOB.get() {
        return Ok(job);
    }
    let job = Job::kill_on_close()?;
    // A racing initialiser wins; our spare job has no members and is just closed.
    Ok(JOB.get_or_init(|| job))
}

/// Spawns `cmd` without a console window, with piped stdin/stdout/stderr (overriding any stdio
/// set before) and `kill_on_drop`, and puts it into `job` right away. A child that cannot be
/// put into the job is killed and the spawn fails: outside the job it could outlive the app.
///
/// The child runs unconfined for the microseconds between spawn and assignment; the engines
/// and tools we start create no children of their own, so nothing can escape the job.
pub fn spawn_hidden(cmd: &mut Command, job: &Job) -> io::Result<Child> {
    cmd.creation_flags(CREATE_NO_WINDOW.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn()?;
    if let Err(err) = job.assign(&child) {
        let _ = child.start_kill();
        return Err(err.into());
    }
    Ok(child)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use super::*;

    /// A harmless long-running child: `ping -n 30 127.0.0.1` (about 30 s, loopback only).
    pub(crate) fn long_ping(exe: &std::path::Path) -> Command {
        let mut cmd = Command::new(exe);
        cmd.args(["-n", "30", "127.0.0.1"]);
        cmd
    }

    pub(crate) fn system_ping() -> std::path::PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        std::path::Path::new(&root)
            .join("System32")
            .join("PING.EXE")
    }

    /// AT-02-001: a child in a kill-on-close job dies when the job handle closes.
    #[tokio::test]
    async fn dropping_the_job_kills_its_members() {
        let job = Job::kill_on_close().unwrap();
        let mut child = spawn_hidden(&mut long_ping(&system_ping()), &job).unwrap();
        assert!(child.stdout.is_some() && child.stderr.is_some() && child.stdin.is_some());
        assert!(child.try_wait().unwrap().is_none(), "ping runs for ~30 s");
        drop(job);
        // Closing the job kills with exit code 0, so only the prompt exit proves the kill.
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("child must exit once the job closes")
            .unwrap();
    }

    /// AT-02-001: terminating the job ends its members with the given exit code.
    #[tokio::test]
    async fn terminate_kills_with_the_exit_code() {
        let job = Job::kill_on_close().unwrap();
        let mut child = spawn_hidden(&mut long_ping(&system_ping()), &job).unwrap();
        job.terminate(7).unwrap();
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.code(), Some(7));
    }

    #[test]
    fn app_job_is_created_once() {
        let a = app_job().unwrap() as *const Job;
        let b = app_job().unwrap() as *const Job;
        assert_eq!(a, b);
    }
}
