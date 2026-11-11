//! Row types of `history/live-checks.json` owned by `live` (the direct stages' types live in
//! [`crate::live_stages`]). Field names and enum strings follow the Electron rows (camelCase,
//! old vocabularies) so imported history deserialises; unknown legacy fields are ignored and
//! never written; additions are optional fields.
use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use vpnte_base::types::UnixMs;

use super::CheckMode;
use crate::live_stages::dns::DnsDiagnostics;
use crate::live_stages::geo::{AsnInfo, Infrastructure};
use crate::live_stages::http::HttpInfo;
use crate::live_stages::icmp::{Pmtu, RouteTrace};
use crate::live_stages::path::PathInfo;
use crate::live_stages::tcp::{LatencyStats, PortItem, Reachability};
use crate::live_stages::tls::TlsInfo;
use crate::live_stages::{NotCheckedReason, Text};

/// How the probe engine's traffic reached the checked server (old `throughput.route` strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineRoute {
    /// Temporary engine bound to the physical adapter (our tunnel is down).
    PhysicalDirect,
    /// Temporary engine dialling the server through the running tunnel's bypass inbound.
    ActiveTunnelDirectDetour,
    /// The running tunnel itself (the checked profile is the active one).
    ActiveTunnel,
}

/// Verdict of the end-to-end handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeStatus {
    /// Bytes crossed the tunnel (an HTTP status line or body bytes through it, B-04).
    Ok,
    AuthFailed,
    TransportFailed,
    Timeout,
    Skipped,
    Unsupported,
    #[default]
    NotChecked,
}

/// Evidence of the handshake verdict.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandshakeEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// Failure class (`auth-failed`, `hy2-udp-blocked`, …); legacy rows may hold a sentence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_port: Option<u16>,
    /// A SOCKS CONNECT through the probe inbound succeeded (not proof of a handshake, B-04).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_connect_ok: Option<bool>,
}

/// `handshake` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Handshake {
    pub status: HandshakeStatus,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Technical cause (English, never localised).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Why the stage did not run, for the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NotCheckedReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<EngineRoute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<HandshakeEvidence>,
}

/// Egress verdict: `ok` = two reflectors agree, `partial` = some answer, `error` = none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressStatus {
    Ok,
    Partial,
    Error,
    Skipped,
    Timeout,
    #[default]
    NotChecked,
}

/// IPv6 exit verdict, derived once from all IPv6 evidence (B-34).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6Status {
    Ok,
    Unsupported,
    Error,
    Timeout,
}

/// Outcome of one reflector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReflectorStatus {
    Ok,
    Error,
    Timeout,
    Unsupported,
}

/// One egress reflector (`cloudflare-trace`, `ipify`, `ipify-v6`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reflector {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default)]
    pub duration_ms: u64,
    pub status: ReflectorStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `egress` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Egress {
    pub status: EgressStatus,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_ipv4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_ipv6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_status: Option<Ipv6Status>,
    /// Exit country (ISO2) from the Cloudflare trace `loc=`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default)]
    pub reflectors: Vec<Reflector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches_endpoint: Option<bool>,
    /// Two IPv4 reflectors disagreed (B-09: stored, and the reason of `partial`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discrepancy: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NotCheckedReason>,
}

/// Media (Twitch HLS / QUIC #2000) verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaStatus {
    Ok,
    Warning,
    Error,
    Skipped,
    #[default]
    NotChecked,
}

/// One media endpoint attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaEndpoint {
    pub endpoint: String,
    pub reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// Negotiated TLS version (B-16; old rows: the fixed label `TLS 1.3 / TCP`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `mediaStream` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaStream {
    pub status: MediaStatus,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub twitch_hls_reachable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_fallback_guarded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error2000_risk: Option<bool>,
    #[serde(default)]
    pub tested_endpoints: Vec<MediaEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NotCheckedReason>,
}

/// Throughput verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThroughputStatus {
    Ok,
    Warning,
    Error,
    Skipped,
    #[default]
    NotChecked,
}

/// One 4 MiB download sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThroughputSample {
    pub index: u32,
    pub bytes: u64,
    /// Whole sample: dial + TLS + request + body.
    pub duration_ms: u64,
    /// Over the body window (first to last body byte, B-10); old rows: over `durationMs`.
    pub throughput_mbps: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttfb_ms: Option<u64>,
    #[serde(default)]
    pub stall_count: u32,
    #[serde(default)]
    pub max_inter_chunk_gap_ms: u64,
    /// False when the sample stopped early (timeout, close): its bytes still count (B-11).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub complete: bool,
}

fn yes() -> bool {
    true
}

fn is_true(v: &bool) -> bool {
    *v
}

/// `throughput` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Throughput {
    pub status: ThroughputStatus,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<EngineRoute>,
    #[serde(default)]
    pub samples: Vec<ThroughputSample>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub median_mbps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_mbps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_mbps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variability_pct: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stall_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inter_chunk_gap_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NotCheckedReason>,
}

/// Split-tunnel snapshot verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelStatus {
    Ok,
    Warning,
    Error,
    #[default]
    Skipped,
}

/// `splitTunnel` section (extended mode; read-only view of the routing rules).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnel {
    pub status: SplitTunnelStatus,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub direct_process_names: Vec<String>,
    #[serde(default)]
    pub vpn_process_names: Vec<String>,
    #[serde(default)]
    pub duplicate_process_names: Vec<String>,
    #[serde(default)]
    pub direct_rule_count: u32,
    #[serde(default)]
    pub vpn_rule_count: u32,
    /// `proxy-out`, or `unknown` when the rules could not be read.
    #[serde(default)]
    pub default_outbound: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// Finding codes (old strings; `REVERSE_DNS_MISMATCH` only in imported rows, B-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingCode {
    PrivateTarget,
    DnsMultiIp,
    DnsChanged,
    ReverseDnsMismatch,
    TlsExpiring,
    TlsSanMismatch,
    TlsFingerprintChanged,
    TlsUntrusted,
    HttpRedirect,
    HttpUnexpectedStatus,
    PortOpen,
    TcpUnreachable,
    PacketLoss,
    LatencyHigh,
    JitterHigh,
    AsnChanged,
    CidrSharedWithProfile,
    EgressCountryMismatch,
    DnsResolverDiscrepancy,
    TunnelHandshakeFailed,
    EgressVerificationFailed,
    EgressPartial,
    EgressDiffersFromEndpoint,
    PmtuBlackholeSuspected,
    LowPmtu,
    ThroughputProbeFailed,
    ThroughputUnstable,
    ThroughputDegradedFromPrevious,
    #[serde(rename = "TWITCH_MEDIA_ERROR_2000_RISK")]
    TwitchMediaError2000Risk,
    TwitchHlsOk,
    TwitchMediaUnreachable,
    SplitTunnelRuleConflict,
    SplitTunnelDiagnosticsFailed,
    /// A code this version does not know (an imported row).
    #[serde(other)]
    Other,
}

/// An evidence value: text, finite number or flag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Evidence {
    Bool(bool),
    Num(f64),
    Str(String),
}

impl From<&str> for Evidence {
    fn from(v: &str) -> Self {
        Evidence::Str(v.to_owned())
    }
}

impl From<String> for Evidence {
    fn from(v: String) -> Self {
        Evidence::Str(v)
    }
}

impl From<bool> for Evidence {
    fn from(v: bool) -> Self {
        Evidence::Bool(v)
    }
}

impl From<f64> for Evidence {
    fn from(v: f64) -> Self {
        Evidence::Num(v)
    }
}

impl From<u64> for Evidence {
    fn from(v: u64) -> Self {
        Evidence::Num(v as f64)
    }
}

/// One finding: what the user should know, with the facts behind it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub code: FindingCode,
    pub severity: Severity,
    pub title: Text,
    pub detail: Text,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub evidence: BTreeMap<String, Evidence>,
}

/// Our tunnel when the check ran (new rows only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelContext {
    pub state: super::TunnelState,
}

/// One stored live check (a row of `history/live-checks.json`, newest first per target).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveCheck {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub mode: CheckMode,
    #[serde(deserialize_with = "timestamp")]
    pub started_at: UnixMs,
    #[serde(deserialize_with = "timestamp")]
    pub finished_at: UnixMs,
    #[serde(default)]
    pub duration_ms: u64,
    /// Only imported rows can be cancelled ones (new cancelled checks are never stored).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cancelled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelContext>,
    pub dns: DnsDiagnostics,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reverse_dns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<AsnInfo>,
    pub reachability: Reachability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<LatencyStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_ports: Option<Vec<PortItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<RouteTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infrastructure: Option<Infrastructure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake: Option<Handshake>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<Egress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_stream: Option<MediaStream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throughput: Option<Throughput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_diagnostics: Option<PathInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pmtu: Option<Pmtu>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_tunnel: Option<SplitTunnel>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

impl LiveCheck {
    /// Row invariants serde cannot express: non-empty id / host, a real port, finite numbers,
    /// address families 4 / 6 (the old validator's rules that still matter).
    pub fn is_valid(&self) -> bool {
        let finite = |v: f64| v.is_finite();
        let family_ok = |f: Option<u8>| f.is_none_or(|f| f == 4 || f == 6);
        !self.id.trim().is_empty()
            && !self.host.trim().is_empty()
            && self.port != 0
            && self.latency.as_ref().is_none_or(|l| finite(l.loss))
            && self.throughput.as_ref().is_none_or(|t| {
                t.samples.iter().all(|s| finite(s.throughput_mbps))
                    && [t.median_mbps, t.min_mbps, t.max_mbps]
                        .into_iter()
                        .flatten()
                        .all(finite)
            })
            && self
                .egress
                .as_ref()
                .is_none_or(|e| e.reflectors.iter().all(|r| family_ok(r.family)))
            && self.pmtu.as_ref().is_none_or(|p| family_ok(p.family))
            && self.findings.iter().all(|f| {
                f.evidence.values().all(|v| match v {
                    Evidence::Num(n) => finite(*n),
                    _ => true,
                })
            })
    }
}

/// `UnixMs`, or the ISO 8601 text of an imported row (`2026-09-20T10:00:00.000Z`).
fn timestamp<'de, D: Deserializer<'de>>(d: D) -> Result<UnixMs, D::Error> {
    use serde::de::Error;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Ms(i64),
        Iso(String),
    }
    match Raw::deserialize(d)? {
        Raw::Ms(ms) => Ok(ms),
        Raw::Iso(text) => text
            .parse::<jiff::Timestamp>()
            .map(|t| t.as_millisecond())
            .map_err(D::Error::custom),
    }
}
