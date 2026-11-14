//! Forensic summary of a capture session: typed, tri-state, evidence-linked verdicts computed by
//! streaming the session's own artefacts (§3.7).
//!
//! Field experience behind the rules (B-03..B-07, B-32, B-33): the old summary read every file whole
//! (captures included), turned configuration text into "leak" verdicts, inherited parser errors from
//! earlier runs and called every user stop an engine failure. Here a verdict is `Detected` only on a
//! real observation, `NotDetected` only when the source that could have observed it ran, and
//! `Unknown` otherwise: an empty capture confirms nothing. Captures (`*.etl`, `*.pcapng`) are never
//! opened; NDJSON is read line by line; insufficiency is computed per run, never inherited.
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use vpnte_base::Msg;
use vpnte_base::types::UnixMs;
use vpnte_core::settings::ConnectionMode;

use crate::etw::{Counted, classify::truncate_chars};

mod collect;
mod counters;

pub use counters::{MetricCategory, PacketMetric, flatten_counters};

/// `summary.json` inside the session directory (and the archive).
pub const SUMMARY_FILE: &str = "summary.json";
/// Flattened pktmon counters next to the summary.
pub const PACKET_METRICS_FILE: &str = "packet-metrics.json";
/// Schema of `summary.json` (v1 of the old app had booleans).
pub const SCHEMA_VERSION: u32 = 2;
/// Evidence references kept per verdict.
pub const EVIDENCE_MAX: usize = 20;
/// Characters of a matched line kept in an evidence reference.
pub const MATCH_MAX_CHARS: usize = 500;
/// TCP rows of one reason needed for a "likely" verdict: one reset or retransmit is normal on a
/// healthy link.
pub const TCP_MIN: u64 = 3;
/// Length of the top lists.
pub const TOP_N: usize = 20;

/// Outcome of one question about the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Finding {
    /// Observed in this session's artefacts.
    Detected,
    /// The source that would have observed it ran and saw nothing.
    NotDetected,
    /// No source could answer (never read as "fine").
    Unknown,
}

impl Finding {
    /// Label for the UI (`forensics.summary.finding.*`).
    pub fn label(self) -> Msg {
        Msg::new(match self {
            Finding::Detected => "forensics.summary.finding.detected",
            Finding::NotDetected => "forensics.summary.finding.notDetected",
            Finding::Unknown => "forensics.summary.finding.unknown",
        })
    }
}

/// The questions the summary answers (old verdict keys, `localResetLikely` removed: no source can
/// tell a local from a remote RST, F-099).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Check {
    TrafficLeakDetected,
    DnsLeakDetected,
    TunPathConfirmed,
    KillSwitchBlockedTraffic,
    WindowsFirewallBlockedTraffic,
    RemoteResetLikely,
    TimeoutOrPacketLossLikely,
    MtuIssueLikely,
    SingBoxFailureLikely,
}

impl Check {
    /// Every check, in report order.
    pub const ALL: [Check; 9] = [
        Check::TrafficLeakDetected,
        Check::DnsLeakDetected,
        Check::TunPathConfirmed,
        Check::KillSwitchBlockedTraffic,
        Check::WindowsFirewallBlockedTraffic,
        Check::RemoteResetLikely,
        Check::TimeoutOrPacketLossLikely,
        Check::MtuIssueLikely,
        Check::SingBoxFailureLikely,
    ];

    /// Label for the UI (`forensics.summary.check.<camelCase name>`).
    pub fn label(self) -> Msg {
        Msg::new(match self {
            Check::TrafficLeakDetected => "forensics.summary.check.trafficLeakDetected",
            Check::DnsLeakDetected => "forensics.summary.check.dnsLeakDetected",
            Check::TunPathConfirmed => "forensics.summary.check.tunPathConfirmed",
            Check::KillSwitchBlockedTraffic => "forensics.summary.check.killSwitchBlockedTraffic",
            Check::WindowsFirewallBlockedTraffic => {
                "forensics.summary.check.windowsFirewallBlockedTraffic"
            }
            Check::RemoteResetLikely => "forensics.summary.check.remoteResetLikely",
            Check::TimeoutOrPacketLossLikely => "forensics.summary.check.timeoutOrPacketLossLikely",
            Check::MtuIssueLikely => "forensics.summary.check.mtuIssueLikely",
            Check::SingBoxFailureLikely => "forensics.summary.check.singBoxFailureLikely",
        })
    }

    /// Whether this build can answer the check both ways. The block checks need a WFP drop
    /// enumeration nobody records yet (the stop reason can only say "detected"), so their
    /// `unknown` does not mark every summary insufficient.
    pub fn answerable(self) -> bool {
        !matches!(
            self,
            Check::KillSwitchBlockedTraffic | Check::WindowsFirewallBlockedTraffic
        )
    }
}

/// A pointer to the line that supports a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// File name inside the session directory.
    pub artifact: String,
    /// 1-based line for NDJSON artefacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    /// Machine-readable reason (`engine-start-failed`, `reset-observed`, ...).
    pub reason: String,
    /// The matched text, at most [`MATCH_MAX_CHARS`] characters.
    #[serde(rename = "match", default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<String>,
}

/// Counters over the session's artefacts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    /// ETW rows read (lifecycle and health rows included).
    pub events: u64,
    /// ETW rows that are neither lifecycle nor health.
    pub data_events: u64,
    pub per_category: BTreeMap<String, u64>,
    pub dns_rows: u64,
    pub resets: u64,
    pub losses: u64,
    pub mtu: u64,
    /// WFP provider rows the consumer classified as `block` (filter activity, not packet drops).
    pub wfp_block_rows: u64,
    /// Rows without a decodable ETW schema.
    pub unparsed: u64,
    pub app_events: u64,
    pub packet_metrics: u64,
    /// NDJSON lines that are not JSON objects or not UTF-8.
    pub malformed_lines: u64,
    /// Events the kernel reported lost (ETW session query at stop).
    pub events_lost: u64,
    /// Rows dropped by a full writer queue or a failed write.
    pub rows_dropped: u64,
}

/// Most frequent names in the ETW rows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Top {
    /// DNS query names.
    pub domains: Vec<Counted>,
    /// `address[:port]` of remote ends.
    pub remotes: Vec<Counted>,
}

/// Why the summary may be incomplete (machine codes; `label` for the UI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SummaryWarning {
    /// The session manifest is missing or unreadable.
    ManifestMissing,
    /// No ETW rows at all.
    EtwNotRun,
    /// ETW ran but produced no data rows.
    EtwNoData,
    /// The kernel or the writer lost events: absence of a signal proves less.
    EtwEventsLost,
    /// The packet capture did not run or its stop was not confirmed.
    PktmonNotRun,
    /// No pktmon counters to confirm the TUN path from.
    NoCounters,
    /// Some NDJSON lines could not be read.
    MalformedLines,
    /// An artefact could not be read (or was too large to parse).
    ArtifactUnreadable,
    /// The app-event log was full and later events were only counted.
    AppEventsDropped,
    /// No leak test reported in this session.
    NoLeakTest,
    /// No WFP drop enumeration exists in this build.
    NoWfpDropSource,
}

impl SummaryWarning {
    /// Label for the UI (`forensics.summary.warning.*`).
    pub fn label(self) -> Msg {
        Msg::new(match self {
            SummaryWarning::ManifestMissing => "forensics.summary.warning.manifestMissing",
            SummaryWarning::EtwNotRun => "forensics.summary.warning.etwNotRun",
            SummaryWarning::EtwNoData => "forensics.summary.warning.etwNoData",
            SummaryWarning::EtwEventsLost => "forensics.summary.warning.etwEventsLost",
            SummaryWarning::PktmonNotRun => "forensics.summary.warning.pktmonNotRun",
            SummaryWarning::NoCounters => "forensics.summary.warning.noCounters",
            SummaryWarning::MalformedLines => "forensics.summary.warning.malformedLines",
            SummaryWarning::ArtifactUnreadable => "forensics.summary.warning.artifactUnreadable",
            SummaryWarning::AppEventsDropped => "forensics.summary.warning.appEventsDropped",
            SummaryWarning::NoLeakTest => "forensics.summary.warning.noLeakTest",
            SummaryWarning::NoWfpDropSource => "forensics.summary.warning.noWfpDropSource",
        })
    }
}

/// What the summary needs from outside the session directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SummaryCtx {
    /// Alias of the TUN adapter (disguised names such as `Ethernet 7`); pktmon names components
    /// by alias or description, so `Wintun` is matched as well.
    pub tun_alias: Option<String>,
}

/// `summary.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub schema_version: u32,
    pub generated_at: UnixMs,
    pub session_id: String,
    pub mode: Option<ConnectionMode>,
    pub target: Option<String>,
    /// `pktmon` when the packet capture ran, `None` for an ETW-only session.
    pub engine: Option<String>,
    /// The session was still running when the summary was computed.
    pub running: bool,
    pub verdicts: BTreeMap<Check, Finding>,
    /// A check with a source stayed unknown, ETW lost events, or the packet capture did not run.
    pub insufficient_evidence: bool,
    pub evidence: BTreeMap<Check, Vec<Evidence>>,
    pub counts: Counts,
    pub top: Top,
    pub warnings: Vec<SummaryWarning>,
    /// Written to [`PACKET_METRICS_FILE`], not into `summary.json`.
    #[serde(skip)]
    pub packet_metrics: Vec<PacketMetric>,
}

impl Summary {
    /// The verdict of `check` (`Unknown` when absent).
    pub fn finding(&self, check: Check) -> Finding {
        self.verdicts
            .get(&check)
            .copied()
            .unwrap_or(Finding::Unknown)
    }

    /// Checks found `Detected` (what system diagnostics prints).
    pub fn detected(&self) -> Vec<Check> {
        Check::ALL
            .into_iter()
            .filter(|c| self.finding(*c) == Finding::Detected)
            .collect()
    }

    /// `summary.json` bytes (pretty, trailing newline).
    pub fn to_json(&self) -> serde_json::Result<Vec<u8>> {
        crate::pretty_json(self)
    }

    /// `packet-metrics.json` bytes.
    pub fn metrics_json(&self) -> serde_json::Result<Vec<u8>> {
        crate::pretty_json(&self.packet_metrics)
    }
}

/// Computes the summary of the session in `dir`. Blocking (streams the event files); call it on a
/// blocking thread. Only an unreadable directory is an error: a missing artefact is a warning.
pub fn summarize(dir: &Path, ctx: &SummaryCtx) -> io::Result<Summary> {
    std::fs::metadata(dir)?;
    Ok(collect::run(dir, ctx))
}

/// Replaces `summary.json` and `packet-metrics.json` of the session atomically.
pub fn write(dir: &Path, summary: &Summary) -> io::Result<()> {
    let store = vpnte_core::store::write_atomic;
    store(&dir.join(SUMMARY_FILE), &summary.to_json()?)?;
    store(&dir.join(PACKET_METRICS_FILE), &summary.metrics_json()?)
}

/// Computes and writes the summary (the app calls this after a capture stopped). Blocking.
pub fn summarize_and_write(dir: &Path, ctx: &SummaryCtx) -> io::Result<Summary> {
    let summary = summarize(dir, ctx)?;
    write(dir, &summary)?;
    Ok(summary)
}

/// Evidence lists bounded by [`EVIDENCE_MAX`].
#[derive(Default)]
struct EvidenceSet(HashMap<Check, Vec<Evidence>>);

impl EvidenceSet {
    fn add(&mut self, check: Check, artifact: &str, line: Option<u64>, reason: &str, text: &str) {
        let list = self.0.entry(check).or_default();
        if list.len() < EVIDENCE_MAX {
            list.push(Evidence {
                artifact: artifact.to_string(),
                line,
                reason: reason.to_string(),
                matched: (!text.is_empty()).then(|| truncate_chars(text, MATCH_MAX_CHARS)),
            });
        }
    }

    fn has(&self, check: Check) -> bool {
        self.0.get(&check).is_some_and(|l| !l.is_empty())
    }
}

#[cfg(test)]
mod tests;
