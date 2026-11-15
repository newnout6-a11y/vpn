//! Live server check ("Живая проверка", live-probe spec §3.20-§3.23, §6): for one saved profile or
//! a raw `host:port`, run the direct stages of [`crate::live_stages`], an end-to-end probe through
//! a temporary engine built from the profile (or through the running tunnel's own probe inbound),
//! turn everything into typed findings, compare with the previous good check and keep the
//! sanitised result in a 20-per-target history.
//!
//! One job runner executes checks one at a time (a batch of ≤ 12 profiles is one job, its checks
//! sequential): probe engines and throughput samples share the uplink, so concurrent checks would
//! make a ranking noisy (old comment, liveServerProbe.ts:3614-3619). Jobs are cancellable by their
//! token; progress is a `watch` of a per-stage snapshot, so no transition is lost between UI polls.
use std::time::Duration;

use serde::{Deserialize, Serialize};

mod check;
mod diff;
mod engine_probe;
mod env;
mod findings;
mod history;
mod model;
mod reflect;
mod runner;
mod sanitize;
mod split;
mod throughput;
pub(crate) mod wire;

#[cfg(test)]
mod tests;

pub use diff::{HistoryDiff, diff, is_baseline};
pub use env::{EngineSetup, LiveEnv, ProfileTarget, SplitTunnelRules, TunnelState, TunnelView};
pub use findings::evaluate_findings;
pub use history::{HistoryStore, LiveHistory, target_key};
pub use model::{
    Egress, EgressStatus, EngineRoute, Evidence, Finding, FindingCode, Handshake,
    HandshakeEvidence, HandshakeStatus, Ipv6Status, LiveCheck, MediaEndpoint, MediaStatus,
    MediaStream, Reflector, ReflectorStatus, Severity, SplitTunnel, SplitTunnelStatus, Throughput,
    ThroughputSample, ThroughputStatus, TunnelContext,
};
pub use runner::{
    BatchError, BatchResult, ItemProgress, ItemState, JobHandle, JobId, JobOutcome, JobState,
    LiveCheckService, ProgressSnapshot, ProgressStatus, StageId,
};
pub use sanitize::sanitize;
pub use split::summarize_split_tunnel;
pub use throughput::summarize_throughput;

/// Most profiles one batch accepts (old IPC limit, kept as the API contract).
pub const MAX_BATCH: usize = 12;
/// Rows kept per target, newest first.
pub const HISTORY_PER_TARGET: usize = 20;
/// Whole-check deadline in basic mode without throughput samples.
pub const BASIC_DEADLINE: Duration = Duration::from_secs(25);
/// Whole-check deadline in extended mode and of every check that measures throughput.
pub const EXTENDED_DEADLINE: Duration = Duration::from_secs(60);

/// Whole milliseconds of `d`, saturating.
pub(crate) fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Check depth: basic = 5 TCP samples, known port + 443, no traceroute, no DoH, no split-tunnel
/// snapshot; extended = 10 samples, 8 CDN ports, traceroute, DoH comparison, direct TLS / HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckMode {
    #[default]
    Basic,
    Extended,
}

impl CheckMode {
    /// True for [`CheckMode::Extended`].
    pub fn extended(self) -> bool {
        self == CheckMode::Extended
    }
}

/// What one check looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckTarget {
    /// A saved profile by id: host, port, TLS facts and the engine probe come from it.
    Profile(String),
    /// A raw endpoint (`host`, `host:port`, `[v6]:port`); only the direct stages run.
    Endpoint { host: String, port: Option<u16> },
}

/// One check. The mode is explicit (B-27); `throughput` adds the 3 × 4 MiB download through the
/// profile (the UI default: on in extended mode and for batches).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRequest {
    pub target: CheckTarget,
    pub mode: CheckMode,
    pub throughput: bool,
}

/// A job for the runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobRequest {
    Single(CheckRequest),
    /// 1..=12 profile ids (duplicates dropped, first occurrence wins), checked sequentially.
    Batch {
        profiles: Vec<String>,
        mode: CheckMode,
        throughput: bool,
    },
}
