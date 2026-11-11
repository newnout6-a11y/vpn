//! `pktmon.exe` spawned directly (no shell, no generated PowerShell): argument lists, the runner
//! and the ETL-release check used as a second stop confirmation.
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::etw::classify::truncate_chars;

/// Packet capture file of a session.
pub const ETL_FILE: &str = "pktmon.etl";
/// Wireshark export written after a confirmed stop (local only, never exported).
pub const PCAPNG_FILE: &str = "pktmon.pcapng";
/// `pktmon counters --json` taken after a confirmed stop.
pub const COUNTERS_FILE: &str = "pktmon-counters.json";
/// `pktmon counters --json --drop-reason` taken after a confirmed stop.
pub const DROP_COUNTERS_FILE: &str = "pktmon-drop-counters.json";
/// Deadline of `pktmon start` (a timeout keeps the marker: the capture may have started).
pub const START_TIMEOUT: Duration = Duration::from_secs(45);
/// Deadline of `pktmon stop`.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(30);
/// Deadline of `pktmon counters` / `etl2pcap`.
pub const COLLECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Trace providers recorded next to the packets: name, keywords, level (TF:35-42).
pub const TRACE_PROVIDERS: [(&str, &str, &str); 4] = [
    ("Microsoft-Windows-TCPIP", "0x7FFFFFFFFFFFFFFF", "17"),
    ("Microsoft-Windows-WFP", "0x7FFFFFFFFFFFFFFF", "255"),
    ("Microsoft-Windows-Winsock-AFD", "0x3FFFFFFFFFFF", "255"),
    ("Microsoft-Windows-WebIO", "0xFFFFFFFFFFFFFFFF", "255"),
];

/// `pktmon start …`: whole packets on the NICs (`--pkt-size 0`, owner decision §10.6 «B», shown
/// with a warning before consent), circular ETL of `max_size_mb`. No `filter remove` / `reset`
/// before it: those destroyed the user's own pktmon setup (B-27).
pub fn start_args(etl: &Path, max_size_mb: u32) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "start",
        "--capture",
        "--trace",
        "--comp",
        "nics",
        "--pkt-size",
        "0",
        "--flags",
        "0x01A",
    ]
    .map(OsString::from)
    .into();
    for (name, keywords, level) in TRACE_PROVIDERS {
        for a in ["--provider", name, "--keywords", keywords, "--level", level] {
            args.push(a.into());
        }
    }
    args.push("--file-name".into());
    args.push(etl.as_os_str().to_owned());
    args.push("--file-size".into());
    args.push(max_size_mb.to_string().into());
    args.push("--log-mode".into());
    args.push("circular".into());
    args
}

/// `pktmon stop`.
pub fn stop_args() -> Vec<OsString> {
    vec!["stop".into()]
}

/// `pktmon counters --json [--drop-reason]`.
pub fn counters_args(drop_reason: bool) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["counters".into(), "--json".into()];
    if drop_reason {
        args.push("--drop-reason".into());
    }
    args
}

/// `pktmon etl2pcap <etl> --out <pcapng>`.
pub fn etl2pcap_args(etl: &Path, out: &Path) -> Vec<OsString> {
    vec![
        "etl2pcap".into(),
        etl.as_os_str().to_owned(),
        "--out".into(),
        out.as_os_str().to_owned(),
    ]
}

/// Exit status and output of one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// `None` when the process ended without an exit code.
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Outcome {
    /// `true` when pktmon exited 0.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Last non-empty output line (stderr first), at most 200 characters, for logs.
    pub fn detail(&self) -> String {
        let pick = |b: &[u8]| {
            String::from_utf8_lossy(b)
                .lines()
                .map(str::trim)
                .rfind(|l| !l.is_empty())
                .map(|l| truncate_chars(l, 200))
        };
        pick(&self.stderr)
            .or_else(|| pick(&self.stdout))
            .unwrap_or_else(|| format!("exit code {:?}", self.code))
    }
}

/// `%SystemRoot%\System32\pktmon.exe`, located through `GetSystemDirectoryW` (an inherited
/// environment variable could point elsewhere, and the caller runs privileged).
pub fn exe() -> PathBuf {
    use std::os::windows::ffi::OsStringExt;
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = [0u16; 260];
    // SAFETY: the buffer is valid for its length; the return value is the number of characters
    // written (0 on failure, larger than the buffer when it is too small).
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    let dir = if n > 0 && n < buf.len() {
        PathBuf::from(OsString::from_wide(&buf[..n]))
    } else {
        PathBuf::from(r"C:\Windows\System32")
    };
    dir.join("pktmon.exe")
}

/// Runs `pktmon.exe <args>` hidden, in the app job, and waits up to `timeout` (the child is
/// killed on timeout).
pub async fn run(args: Vec<OsString>, timeout: Duration) -> io::Result<Outcome> {
    let mut cmd = tokio::process::Command::new(exe());
    cmd.args(&args);
    let job = vpnte_winnet::process::app_job()?;
    let child = vpnte_winnet::process::spawn_hidden(&mut cmd, job)?;
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(out) => {
            let out = out?;
            Ok(Outcome {
                code: out.status.code(),
                stdout: out.stdout,
                stderr: out.stderr,
            })
        }
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("pktmon {:?} timed out", args.first()),
        )),
    }
}

/// `true` when no writer holds the ETL any more (or it does not exist): the kernel logger keeps
/// the file open for writing while the capture runs, so an open that refuses sharing succeeds
/// only after the capture stopped. A positive observation independent of pktmon's exit codes.
pub fn etl_released(path: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(path)
    {
        Ok(_) => true,
        Err(e) => e.kind() == io::ErrorKind::NotFound,
    }
}
