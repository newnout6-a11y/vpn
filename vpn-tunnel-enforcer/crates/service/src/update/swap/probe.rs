//! A staged exe must start on this Windows before it takes the service's place (svcupd-a9): its
//! trial counts inside the new exe, so one that never reaches its own code (an import this
//! Windows lacks, an antivirus that refuses the new file) would never roll back. It runs once,
//! with an argument no build accepts: the usage exit code shows that the loader and `main` ran.
use std::io;
use std::os::windows::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// `vpnte-service.exe`'s exit code for bad arguments (main.rs).
const USAGE_EXIT: i32 = 2;
/// The usage line takes milliseconds; an antivirus may scan a new file for some seconds first.
const WAIT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(50);
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `Ok` when `exe` started and answered a bad argument with its usage exit code. Blocking.
pub fn probe(exe: &Path) -> io::Result<()> {
    let mut child = Command::new(exe)
        .arg("--start-probe")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()?;
    let deadline = Instant::now() + WAIT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() > deadline {
            // Our own child: it goes with the probe.
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::ErrorKind::TimedOut.into());
        }
        std::thread::sleep(POLL);
    };
    match status.code() {
        Some(USAGE_EXIT) => Ok(()),
        code => Err(io::Error::other(format!("exit code {code:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::testkit::TempDir;

    /// A file that is not a program on this Windows never passes; neither does one that
    /// answers a bad argument with another code than the service's usage code.
    #[test]
    fn only_an_exe_that_starts_and_answers_with_its_usage_code_passes() {
        let dir = TempDir::new("probe");
        let fake = dir.path().join("vpnte-service-9.9.9.exe");
        std::fs::write(&fake, b"not a program").expect("fake");
        assert!(probe(&fake).is_err());
        // The test binary itself starts, but its harness refuses the argument with code 101.
        let me = std::env::current_exe().expect("test exe");
        let err = probe(&me).expect_err("not the usage code");
        assert!(err.to_string().contains("exit code"), "{err}");
    }
}
