//! sing-box process supervision: spawn with the config on stdin (`run -c stdin --disable-color`),
//! readiness from the `sing-box started (` line, exit watch with [`ExitInfo`], terminate with an
//! observed exit, the outbound fault classifier, the version gate and the config check.
//!
//! The process lives in its own kill-on-close Job: dropping a [`SingBoxProcess`] (or the app
//! dying for any reason) ends the engine. A reaped process handle is the exit proof.
use std::io;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use regex::Regex;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Engine, OutboundFault};
use vpnte_base::{AppError, ErrorKind, Msg};

pub(crate) mod child;
#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

use crate::pin::NotPinned;
use child::{EngineChild, Scrubber, Spec, exited};
pub use child::{ExitInfo, GRACEFUL_STOP, KILL_CODE};

/// Emitted by `Box.Start()` after every start stage, e.g.
/// `+0300 2026-09-02 10:54:30 INFO sing-box started (0.40s)` (not `sing-box pre-started (`).
/// Printed only at `log.level` info or lower and without `log.output` (the config's duty).
pub const READY_MARKER: &str = "sing-box started (";
/// Log file stem under the logs dir: `sing-box.log` (this session), `sing-box.1.log` (previous).
pub const LOG_STEM: &str = "sing-box";
/// Readiness budget: the first Wintun driver installation takes seconds.
pub const READY_TIMEOUT: Duration = Duration::from_secs(20);
/// Exit wait after the kill (a stop first waits up to [`GRACEFUL_STOP`] for the engine's own exit).
pub const STOP_TIMEOUT: Duration = Duration::from_secs(3);
/// Deadline of `version` and `check`.
const TOOL_TIMEOUT: Duration = Duration::from_secs(10);
/// The classifier looks at this many recent lines and needs this many hits.
const FAULT_WINDOW: usize = 500;
const FAULT_THRESHOLD: usize = 3;

/// Why sing-box did not become ready.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("sing-box exited before it was ready (code {:?})", .0.code)]
    Exited(ExitInfo),
    #[error("sing-box did not report readiness in time")]
    Timeout,
    #[error("sing-box start cancelled")]
    Cancelled,
    #[error("sing-box could not be started")]
    Spawn(#[source] io::Error),
}

impl From<io::Error> for StartError {
    fn from(err: io::Error) -> Self {
        StartError::Spawn(err)
    }
}

/// The process did not exit within the stop budget; the stop can be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StopError {
    #[error("engine exit was not confirmed")]
    ExitNotConfirmed,
}

/// `sing-box check` refused the config, or could not be run.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// Redacted engine output explaining the refusal.
    #[error("sing-box rejected the config: {0}")]
    Rejected(String),
    #[error("sing-box check could not run")]
    Run(#[source] io::Error),
}

impl From<StartError> for AppError {
    fn from(err: StartError) -> Self {
        let (kind, msg) = match &err {
            StartError::Cancelled => return AppError::cancelled(),
            StartError::Exited(info) => (
                ErrorKind::Internal,
                Msg::new("engine.process.singboxExited").arg("code", code_text(info.code)),
            ),
            StartError::Timeout => (
                ErrorKind::Timeout,
                Msg::new("engine.process.singboxNotReady"),
            ),
            StartError::Spawn(io) => spawn_error("sing-box", io),
        };
        AppError::msg(kind, msg).with_source(err)
    }
}

impl From<StopError> for AppError {
    fn from(err: StopError) -> Self {
        let msg = Msg::new("engine.process.stopUnconfirmed").arg("engine", "sing-box");
        AppError::msg(ErrorKind::Internal, msg).with_source(err)
    }
}

impl From<CheckError> for AppError {
    fn from(err: CheckError) -> Self {
        let (kind, msg) = match &err {
            CheckError::Rejected(_) => (
                ErrorKind::Validation,
                Msg::new("engine.process.configRejected").arg("engine", "sing-box"),
            ),
            CheckError::Run(io) => spawn_error("sing-box", io),
        };
        AppError::msg(kind, msg).with_source(err)
    }
}

/// Kind and message of an engine process that could not be created: an engine file that differs
/// from its release pin (elevated only, `crate::pin`), access denied, a missing exe, a job failure.
pub(crate) fn spawn_error(engine: &'static str, err: &io::Error) -> (ErrorKind, Msg) {
    if let Some(refused) = err.get_ref().and_then(|e| e.downcast_ref::<NotPinned>()) {
        let key = if refused.missing {
            "engine.process.fileMissing"
        } else {
            "engine.process.notPinned"
        };
        return (
            ErrorKind::Internal,
            Msg::new(key).arg("file", &refused.file),
        );
    }
    let kind = match err.kind() {
        io::ErrorKind::PermissionDenied => ErrorKind::Permission,
        _ => ErrorKind::Internal,
    };
    (
        kind,
        Msg::new("engine.process.spawnFailed").arg("engine", engine),
    )
}

/// An exit code for a message argument (`?` when Windows reported none).
pub(crate) fn code_text(code: Option<i32>) -> String {
    code.map_or_else(|| "?".to_owned(), |c| c.to_string())
}

/// A sing-box run owned by handle. Dropping it kills the engine.
pub struct SingBoxProcess {
    child: EngineChild,
}

impl SingBoxProcess {
    /// Starts `exe run -c stdin --disable-color` with `config` on stdin (runtime). `logs` = the
    /// logs dir for `sing-box.log`; the previous session's file becomes `sing-box.1.log`.
    /// Errors only when the process cannot be created (elevated: also when an engine file
    /// differs from its release pin); a bad config shows up as an early exit.
    pub fn spawn(exe: &Path, config: &[u8], logs: Option<&Path>) -> io::Result<Self> {
        let child = EngineChild::spawn(Spec {
            engine: Engine::SingBox,
            exe,
            args: &["run", "-c", "stdin", "--disable-color"],
            config,
            log: logs.map(|dir| (dir, LOG_STEM)),
            marker: Some(child::Marker::Contains(READY_MARKER)),
            scrub: Scrubber::new(config, &[]),
        })?;
        tracing::info!(pid = child.pid(), "sing-box spawned");
        Ok(Self { child })
    }

    /// Ready = the `sing-box started (` line was read and the process has not exited. Does not
    /// kill on failure: the caller's compensation terminates (or drops) the process.
    pub async fn wait_ready(
        &self,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<(), StartError> {
        let mut ready = self.child.ready_watch();
        let mut exit = self.child.exit_watch();
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(StartError::Cancelled),
            Some(info) = exited(&mut exit) => Err(StartError::Exited(info)),
            Ok(_) = ready.wait_for(|r| *r) => match self.child.exited() {
                Some(info) => Err(StartError::Exited(info)),
                None => Ok(()),
            },
            () = tokio::time::sleep(timeout) => Err(StartError::Timeout),
        }
    }

    /// Stops the engine and waits for its exit (idempotent; an already exited process returns
    /// its exit at once): CTRL_BREAK, up to [`GRACEFUL_STOP`] for its own exit (sing-box then
    /// closes its TUN and Wintun removes the adapter; [`ExitInfo::graceful`]), else the kill and
    /// up to `within` more. The returned exit is the proof.
    pub async fn terminate(&self, within: Duration) -> Result<ExitInfo, StopError> {
        let info = self.child.stop_and_wait(GRACEFUL_STOP, within).await;
        info.ok_or(StopError::ExitNotConfirmed)
    }

    /// Process id (for logs and the orphan sweep; ownership is by handle, never by PID).
    pub fn pid(&self) -> u32 {
        self.child.pid()
    }

    /// `Some` once the process exited; owners `select!` on it to notice a crash.
    pub fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>> {
        self.child.exit_watch()
    }

    /// The exit, if the process has ended.
    pub fn exit_info(&self) -> Option<ExitInfo> {
        self.child.exited()
    }

    /// The dominant upstream fault of the recent output (§3.18), if any.
    pub fn recent_fault(&self) -> Option<OutboundFault> {
        let lines = self.child.raw_lines(None);
        classify_fault(lines.iter().map(|l| &**l))
    }

    /// The last `n` output lines, redacted, oldest first (live log view, diagnostics).
    pub fn tail(&self, n: usize) -> Vec<String> {
        self.child.tail(n)
    }

    /// Every output line as read, for in-process consumers (traffic history log parse). NOT
    /// redacted: never log or show these without `vpnte_core::redact::for_log`.
    pub fn subscribe_lines(&self) -> broadcast::Receiver<Arc<str>> {
        self.child.subscribe()
    }
}

static ERROR_LEVEL: LazyLock<Regex> = LazyLock::new(|| re(r"\bERROR\b"));
static REALITY: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)reality verification failed"));
static TLS: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\b(tls|x509|certificate|bad certificate|handshake failure|remote error)\b")
});
static UNREACHABLE: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?i)\b(connection refused|i/o timeout|no route to host|network is unreachable|",
        r"context deadline exceeded|dial tcp)\b",
    ))
});

pub(crate) fn re(pattern: &str) -> Regex {
    // Patterns are constants covered by the tests.
    Regex::new(pattern).expect("static regex")
}

/// Outbound fault of sing-box output (old `readRecentSingBoxOutboundFault`): of the last 500
/// lines only `ERROR` lines count, each as reality > tls > unreachable; the first kind with at
/// least 3 hits in that priority wins, so one transient error during startup never trips it.
pub fn classify_fault<'a>(lines: impl IntoIterator<Item = &'a str>) -> Option<OutboundFault> {
    let lines: Vec<&str> = lines.into_iter().collect();
    let (mut reality, mut tls, mut unreachable) = (0, 0, 0);
    for line in &lines[lines.len().saturating_sub(FAULT_WINDOW)..] {
        if !ERROR_LEVEL.is_match(line) {
            continue;
        }
        if REALITY.is_match(line) {
            reality += 1;
        } else if TLS.is_match(line) {
            tls += 1;
        } else if UNREACHABLE.is_match(line) {
            unreachable += 1;
        }
    }
    if reality >= FAULT_THRESHOLD {
        Some(OutboundFault::RealityKeyMismatch)
    } else if tls >= FAULT_THRESHOLD {
        Some(OutboundFault::TlsHandshakeFailed)
    } else if unreachable >= FAULT_THRESHOLD {
        Some(OutboundFault::UpstreamUnreachable)
    } else {
        None
    }
}

/// `exe version` → `(major, minor, patch)` (run once per app process; gate with
/// [`version_supported`]).
pub async fn engine_version(exe: &Path) -> io::Result<(u16, u16, u16)> {
    let out = child::run_once(Engine::SingBox, exe, &["version"], None, TOOL_TIMEOUT).await?;
    parse_version(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unrecognised sing-box version output",
        )
    })
}

/// Parses `sing-box version 1.14.4` (first line of `sing-box version`); a pre-release suffix
/// (`1.14.0-rc.2`) is ignored.
pub fn parse_version(text: &str) -> Option<(u16, u16, u16)> {
    let rest = text
        .lines()
        .next()?
        .trim()
        .strip_prefix("sing-box version ")?;
    let mut parts = rest.split(['.', '-', '+', ' ']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// The generated config uses 1.14-only fields (`dns_mode`) and ≤1.13 rejects unknown ones, so
/// only the compiled range is accepted: 1.14.x from the bundled release on
/// (`vpnte_update::policy::engine_range`, shared with the update channel and the pin check).
pub fn version_supported(version: (u16, u16, u16)) -> bool {
    vpnte_update::policy::engine_allowed(
        vpnte_update::policy::SINGBOX,
        vpnte_update::version::Version::from_triple(version),
    )
}

/// `exe check -c stdin`: decodes the config and builds every component without starting it
/// (no TUN, no listeners). For tests and diagnostics; the runtime relies on `run` failing fast.
pub async fn check_config(exe: &Path, config: &[u8]) -> Result<(), CheckError> {
    let args = ["check", "-c", "stdin", "--disable-color"];
    let out = child::run_once(Engine::SingBox, exe, &args, Some(config), TOOL_TIMEOUT)
        .await
        .map_err(CheckError::Run)?;
    if out.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&out.stderr);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    Err(CheckError::Rejected(
        Scrubber::new(config, &[]).tail(&lines),
    ))
}
