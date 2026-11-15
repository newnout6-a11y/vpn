//! Registry of long-running feature operations (refresh, speed test, import / export, health
//! check, ...): per-resource single flight, owner-priority pre-emption, monotonic deadlines that
//! pause while the user decides, cancellation that is prompt for the caller while physical
//! effects keep their resource until they settle, a bounded history and a broadcast of every
//! metadata change for the UI.
//!
//! Feature code awaits its I/O through the [`Lease`] (`wait`, `wait_for_user`), calls
//! [`Lease::assert_active`] before publishing anything (a cancelled operation never reports late
//! results) and makes its final persistence a [`Lease::commit`]:
//!
//! ```
//! # async fn export(ops: &vpnte_core::ops::OperationRegistry) -> vpnte_base::AppResult<usize> {
//! use vpnte_core::ops::{FeatureKind, RunOpts};
//! ops.run(FeatureKind::Export, RunOpts::default(), |lease| async move {
//!     let doc = lease.wait(async { String::from("{}") }).await?; // tracked, cancellable
//!     lease.commit(|| Ok(doc.len())) // persist: success is final from here on
//! })
//! .await
//! # }
//! ```
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vpnte_base::ErrorKind;
use vpnte_base::types::UnixMs;

pub use tokio_util::sync::CancellationToken;
pub use vpnte_base::types::Owner;

mod lease;
mod registry;
mod state;
mod supervisor;
#[cfg(test)]
mod tests;

pub use lease::Lease;
pub use registry::{OperationRegistry, RunOpts};

/// Where a user action came from (provenance in logs and connection history).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// The app window (the Electron app called it `ipc`; old records are read as `Ui`).
    #[serde(alias = "ipc")]
    Ui,
    Tray,
    #[default]
    Lifecycle,
    Runtime,
    Unknown,
}

/// Opaque id shared by every log line of one user action: `op_` + a dash-less UUID v4.
///
/// The version / variant bits are kept so the Electron-era history validator (and our reader of
/// old records) accepts the ids we write.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CorrelationId(String);

impl CorrelationId {
    /// A fresh random id.
    pub fn new() -> Self {
        let mut b = [0u8; 16];
        // The OS RNG does not fail on supported Windows versions; a weaker id still correlates.
        if getrandom::fill(&mut b).is_err() {
            b = fastrand::u128(..).to_le_bytes();
        }
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        Self(format!("op_{}", hex::encode(b)))
    }

    /// Accepts the persisted forms: `op_` or `ipc_` (case-sensitive) followed by a dash-less
    /// UUID v4 (hex in either case), exactly as the old validator did.
    pub fn parse(s: &str) -> Option<Self> {
        let hex = s
            .strip_prefix("op_")
            .or_else(|| s.strip_prefix("ipc_"))?
            .as_bytes();
        let ok = hex.len() == 32
            && hex.iter().all(u8::is_ascii_hexdigit)
            && hex[12] == b'4'
            && matches!(hex[16].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b');
        ok.then(|| Self(s.to_owned()))
    }

    /// The id as written to logs and history.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for CorrelationId {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s).ok_or("invalid correlation id")
    }
}

impl From<CorrelationId> for String {
    fn from(id: CorrelationId) -> String {
        id.0
    }
}

/// Process-wide operation id (registry and connection lane share the counter); log key `op_<hex>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpId(u64);

impl OpId {
    /// Allocates the next id.
    pub fn next() -> OpId {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        OpId(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

impl fmt::Display for OpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "op_{:x}", self.0)
    }
}

/// Lifecycle of one operation record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpStatus {
    Running,
    Success,
    Cancelled,
    Error,
}

/// Long feature operations managed by [`OperationRegistry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FeatureKind {
    Refresh,
    SpeedTest,
    Import,
    Export,
    Rotation,
    HealthCheck,
    AvailabilityCheck,
    RoutingCheck,
    ServerProbe,
    LeakCheck,
    Snapshot,
}

impl FeatureKind {
    /// Every kind, in the order of the deadline table.
    pub const ALL: [FeatureKind; 11] = [
        FeatureKind::Refresh,
        FeatureKind::SpeedTest,
        FeatureKind::Import,
        FeatureKind::Export,
        FeatureKind::Rotation,
        FeatureKind::HealthCheck,
        FeatureKind::AvailabilityCheck,
        FeatureKind::RoutingCheck,
        FeatureKind::ServerProbe,
        FeatureKind::LeakCheck,
        FeatureKind::Snapshot,
    ];

    /// Default work budget of the kind (user decision time is not counted).
    pub const fn deadline(self) -> Duration {
        Duration::from_secs(match self {
            FeatureKind::SpeedTest | FeatureKind::HealthCheck => 600,
            FeatureKind::Refresh
            | FeatureKind::Import
            | FeatureKind::Export
            | FeatureKind::Rotation => 120,
            FeatureKind::AvailabilityCheck
            | FeatureKind::RoutingCheck
            | FeatureKind::LeakCheck
            | FeatureKind::Snapshot => 60,
            FeatureKind::ServerProbe => 9,
        })
    }

    /// Wire name; also the default resource of an operation of this kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            FeatureKind::Refresh => "refresh",
            FeatureKind::SpeedTest => "speed-test",
            FeatureKind::Import => "import",
            FeatureKind::Export => "export",
            FeatureKind::Rotation => "rotation",
            FeatureKind::HealthCheck => "health-check",
            FeatureKind::AvailabilityCheck => "availability-check",
            FeatureKind::RoutingCheck => "routing-check",
            FeatureKind::ServerProbe => "server-probe",
            FeatureKind::LeakCheck => "leak-check",
            FeatureKind::Snapshot => "snapshot",
        }
    }
}

impl fmt::Display for FeatureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Kind of any published operation: the connection lane's own kinds plus the feature kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OpKind {
    Connect,
    Disconnect,
    Rotation,
    Refresh,
    SpeedTest,
    Import,
    Export,
    HealthCheck,
    AvailabilityCheck,
    RoutingCheck,
    ServerProbe,
    LeakCheck,
    Snapshot,
}

impl From<FeatureKind> for OpKind {
    fn from(kind: FeatureKind) -> Self {
        match kind {
            FeatureKind::Refresh => OpKind::Refresh,
            FeatureKind::SpeedTest => OpKind::SpeedTest,
            FeatureKind::Import => OpKind::Import,
            FeatureKind::Export => OpKind::Export,
            FeatureKind::Rotation => OpKind::Rotation,
            FeatureKind::HealthCheck => OpKind::HealthCheck,
            FeatureKind::AvailabilityCheck => OpKind::AvailabilityCheck,
            FeatureKind::RoutingCheck => OpKind::RoutingCheck,
            FeatureKind::ServerProbe => OpKind::ServerProbe,
            FeatureKind::LeakCheck => OpKind::LeakCheck,
            FeatureKind::Snapshot => OpKind::Snapshot,
        }
    }
}

/// Published metadata of one operation (UI, logs, tunnel snapshot). Never carries payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpMeta {
    /// Process-wide id (cancel by it).
    pub id: OpId,
    /// The user action this operation belongs to.
    pub correlation: CorrelationId,
    /// Who asked; decides pre-emption.
    pub owner: Owner,
    /// Where the request came from.
    pub source: Source,
    /// What the operation does.
    pub kind: OpKind,
    /// Wall-clock admission time.
    pub started_at: UnixMs,
    /// Wall-clock end of the work budget; `None` while the user decides (budget paused).
    pub deadline: Option<UnixMs>,
    /// Running, or how it ended.
    pub status: OpStatus,
    /// Error category of a `Cancelled` / `Error` outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<ErrorKind>,
}
