//! Opt-in packet capture session ("Глубокий захват трафика"): `pktmon.exe` spawned directly plus
//! the in-process ETW consumer, one session per protection session.
//!
//! All transitions (start, stop, restart, clear, boot recovery) run under one async mutex, so an
//! old session's finalisation can never overwrite a newer one (TF:47-54). The ownership marker is
//! written before pktmon starts and removed only after a confirmed stop: a crash at any point
//! leaves something `recover_on_boot` can act on (B-11). A stop that is not observed stays
//! `cleanup_pending` and is never reported as stopped.
use std::io;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vpnte_base::types::UnixMs;
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::settings::{ConnectionMode, DEEP_INSPECTION_MAX_MB, Settings};

pub mod manifest;
pub mod pktmon;
mod service;
mod snapshot;
pub mod status;
pub mod store;
mod system;
mod transitions;

pub use manifest::{EtwState, PktmonState, SessionManifest};
pub use pktmon::Outcome;
pub use service::Capture;
pub use status::{CaptureStatus, Health};
pub use store::{ArtifactFile, ClearReport, SessionEntry};
pub use system::{Etw, System, WindowsSystem};

/// App events kept per session in `app-events.ndjson`; later ones are only counted.
pub const APP_EVENTS_MAX: u32 = 10_000;
/// App events of a session.
pub const APP_EVENTS_FILE: &str = "app-events.ndjson";
/// Failures of the best-effort collection after a stop.
pub const STOP_ERRORS_FILE: &str = "stop-errors.txt";
/// pktmon counters taken by [`Capture::live_refresh`] while a session runs.
pub const LIVE_COUNTERS_FILE: &str = "pktmon-live-counters.json";

/// What the capture needs from settings ([`Settings`] + [`CapturePrefs`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    pub enabled: bool,
    /// When the user accepted the full-payload warning (§10.6 «B»); `None` refuses to start.
    pub consent_at: Option<UnixMs>,
    /// Ring size of the ETL (128..=2048).
    pub max_size_mb: u32,
    /// Quota of all sessions together (1024..=65536).
    pub quota_mb: u32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            consent_at: None,
            max_size_mb: 512,
            quota_mb: store::DEFAULT_QUOTA_MB,
        }
    }
}

impl CaptureConfig {
    /// From the settings document and the capture preferences, clamped.
    pub fn new(settings: &Settings, prefs: &CapturePrefs) -> Self {
        let (lo, hi) = DEEP_INSPECTION_MAX_MB;
        let (qlo, qhi) = store::QUOTA_MB;
        Self {
            enabled: settings.deep_inspection,
            consent_at: prefs.consent_at,
            max_size_mb: settings.deep_inspection_max_mb.clamp(lo, hi),
            quota_mb: prefs.quota_mb.clamp(qlo, qhi),
        }
    }
}

/// `forensics.json`: capture preferences `Settings` does not carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CapturePrefs {
    /// Set when the user accepts the consent dialog that comes with switching capture on.
    pub consent_at: Option<UnixMs>,
    pub quota_mb: u32,
}

impl Default for CapturePrefs {
    fn default() -> Self {
        Self {
            consent_at: None,
            quota_mb: store::DEFAULT_QUOTA_MB,
        }
    }
}

impl vpnte_core::store::Document for CapturePrefs {
    const FILE: &'static str = "forensics.json";
    const VERSION: u32 = 1;
}

/// The protection session a capture belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCtx {
    pub mode: ConnectionMode,
    /// Proxy address (local proxy mode) or profile name (direct VPN mode).
    pub target: String,
}

/// Why a session ended (strings as recorded by the old app; the summary matches on them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    VpnStop,
    Shutdown,
    ManualRestart,
    ManualClear,
    KillSwitch,
    Other(String),
}

impl StopReason {
    /// The recorded string (the summary and the old app match on it).
    pub fn as_str(&self) -> &str {
        match self {
            StopReason::VpnStop => "vpn-stop",
            StopReason::Shutdown => "shutdown",
            StopReason::ManualRestart => "manual-ui-restart",
            StopReason::ManualClear => "manual diagnostics artifact clear",
            StopReason::KillSwitch => "killswitch-active",
            StopReason::Other(s) => s,
        }
    }
}

/// Recorded when neither pktmon nor ETW started.
pub const START_FAILED: &str = "start-failed";
/// Recorded for a session found running at boot.
pub const RECOVERED_AT_STARTUP: &str = "recovered-at-startup";

/// Why a capture operation failed.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// Capture is on but the full-payload consent was never recorded (AT-08-009).
    #[error("capture consent not recorded")]
    ConsentRequired,
    /// `pktmon stop` was not confirmed; the session stays `cleanup_pending`.
    #[error("CaptureStopUnconfirmed: {detail}")]
    StopUnconfirmed { code: Option<i32>, detail: String },
    /// Neither pktmon nor ETW started.
    #[error("start failed: {0}")]
    StartFailed(String),
    #[error("forensics storage: {0}")]
    Io(#[from] io::Error),
}

impl From<CaptureError> for AppError {
    fn from(e: CaptureError) -> Self {
        let (kind, msg) = match &e {
            CaptureError::ConsentRequired => (
                ErrorKind::Conflict,
                Msg::new("forensics.capture.error.consentRequired"),
            ),
            CaptureError::StopUnconfirmed { .. } => (
                ErrorKind::Conflict,
                Msg::new("forensics.capture.error.stopUnconfirmed"),
            ),
            CaptureError::StartFailed(_) => (
                ErrorKind::Internal,
                Msg::new("forensics.capture.error.startFailed"),
            ),
            CaptureError::Io(io) => (
                if io.kind() == io::ErrorKind::PermissionDenied {
                    ErrorKind::Permission
                } else {
                    ErrorKind::Internal
                },
                Msg::new("forensics.capture.error.storage"),
            ),
        };
        AppError::msg(kind, msg).with_source(e)
    }
}

/// An app event recorded into the running session (§2.16 producers, typed).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ForensicEvent {
    #[serde(flatten)]
    pub kind: ForensicEventKind,
    /// The producer's payload, written as is (redacted at export).
    pub details: Value,
}

/// Kinds of [`ForensicEvent`]; `engine-exited` always says whether the user asked for it (B-33).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(
    tag = "event",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum ForensicEventKind {
    TunStartRequested,
    EngineStartFailed,
    EngineExited { user_initiated: bool },
    EngineCrashRestart,
    EngineRestartExhausted,
    EngineExitedKillswitchActive,
    KillSwitchEngaged,
    TunStarted,
    EngineStartTimeout,
    TunStopRequested,
    TunStopped,
    LeakDiagnosticsResult,
    LeakSelfTestResult,
}

impl ForensicEventKind {
    /// `source` of the row (old producers: `tun`, `leak-diagnostics`, `leak-self-test`).
    pub fn source(self) -> &'static str {
        match self {
            ForensicEventKind::LeakDiagnosticsResult => "leak-diagnostics",
            ForensicEventKind::LeakSelfTestResult => "leak-self-test",
            _ => "tun",
        }
    }
}

/// What [`Capture::recover_on_boot`] found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReport {
    /// Our marker or an old app's hint said a capture may still run.
    pub orphan_suspected: bool,
    /// `pktmon stop` ran and was confirmed.
    pub pktmon_stopped: bool,
    /// Manifests left "running" by a crash, now closed.
    pub sessions_closed: u32,
    /// An orphaned `VPNTE-ETW` session was stopped.
    pub etw_reclaimed: bool,
}

#[cfg(test)]
mod tests;
