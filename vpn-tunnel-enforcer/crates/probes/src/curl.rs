//! Windows' own `curl.exe` as a probe child: the one launcher of the leak self-test and the
//! diagnostics endpoint checks.
//!
//! WHY curl and not our own sockets: the kill switch permits our own executable, so a probe from
//! our process proves nothing; `curl.exe` is deliberately left unpermitted and measures what an
//! arbitrary unprivileged app experiences (B-LT-4, B-SD-5). It is started by absolute path
//! (`%SystemRoot%\System32\curl.exe`): a PATH search from an elevated process would run any
//! planted `curl.exe` as admin (B-LT-3).
use std::path::PathBuf;
use std::time::Duration;

/// Characters of stderr kept as evidence.
pub(crate) const STDERR_TAIL: usize = 200;

/// Proxy variables curl would honour; removed from the child's environment (curl also gets
/// `--noproxy *`).
const PROXY_VARS: [&str; 6] = [
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
];

/// What one curl run produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CurlOutcome {
    /// Exit code; `None` when the process was killed (deadline) or could not be waited for.
    pub exit: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// False when the process could not be started at all.
    pub launched: bool,
}

impl CurlOutcome {
    /// The process could not be started.
    pub fn not_launched() -> Self {
        Self::default()
    }

    /// Last [`STDERR_TAIL`] characters of stderr, trimmed; `None` when empty.
    pub fn stderr_tail(&self) -> Option<String> {
        let text = self.stderr.trim();
        if text.is_empty() {
            return None;
        }
        let skip = text.chars().count().saturating_sub(STDERR_TAIL);
        Some(text.chars().skip(skip).collect())
    }
}

/// `%SystemRoot%\System32\curl.exe`, from `GetSystemDirectoryW` (never a PATH search).
pub fn curl_path() -> Option<PathBuf> {
    let mut buf = [0u16; 260];
    // SAFETY: the buffer is valid for its length; the call writes at most that many UTF-16 units.
    let len =
        unsafe { windows::Win32::System::SystemInformation::GetSystemDirectoryW(Some(&mut buf)) };
    let len = usize::try_from(len)
        .ok()
        .filter(|&n| n > 0 && n < buf.len())?;
    Some(PathBuf::from(String::from_utf16_lossy(&buf[..len])).join("curl.exe"))
}

/// Runs `curl.exe` hidden, in the app's kill-on-close job, without proxy variables, and kills it
/// after `timeout` (dropping the future kills it too).
pub async fn run_curl(args: Vec<String>, timeout: Duration) -> CurlOutcome {
    let Some(exe) = curl_path().filter(|p| p.is_file()) else {
        return CurlOutcome::not_launched();
    };
    let Ok(job) = vpnte_winnet::process::app_job() else {
        return CurlOutcome::not_launched();
    };
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(&args);
    for var in PROXY_VARS {
        cmd.env_remove(var);
    }
    let Ok(mut child) = vpnte_winnet::process::spawn_hidden(&mut cmd, job) else {
        return CurlOutcome::not_launched();
    };
    // curl never reads stdin here; closing it avoids any wait on input.
    drop(child.stdin.take());
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(out)) => CurlOutcome {
            exit: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            launched: true,
        },
        // Deadline (the dropped child is killed: `kill_on_drop`) or a failed wait.
        Ok(Err(_)) | Err(_) => CurlOutcome {
            launched: true,
            ..CurlOutcome::default()
        },
    }
}
