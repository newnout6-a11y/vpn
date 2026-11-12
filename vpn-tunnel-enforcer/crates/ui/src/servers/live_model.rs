//! View models of the live check: one server's report (with history and progress) and the batch
//! comparison. Field meanings follow live-probe §2.7; display data only.
use vpnte_base::Msg;
use vpnte_base::types::UnixMs;

use super::model::{AsnInfo, LatencyStats};

/// Depth of a live check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LiveMode {
    #[default]
    Basic,
    /// Adds a port scan, CNAME chain, traceroute, PMTU and a short throughput test.
    Extended,
}

/// A probe stage (progress caption).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    Dns,
    Reachability,
    Tls,
    Http,
    Ports,
    Route,
    Infrastructure,
    Handshake,
    Egress,
    MediaStream,
    Throughput,
    Path,
    Pmtu,
}

impl Stage {
    /// Suffix of the `ui.servers.stage.*` caption key.
    pub fn key(self) -> &'static str {
        match self {
            Stage::Dns => "dns",
            Stage::Reachability => "reachability",
            Stage::Tls => "tls",
            Stage::Http => "http",
            Stage::Ports => "ports",
            Stage::Route => "route",
            Stage::Infrastructure => "infrastructure",
            Stage::Handshake => "handshake",
            Stage::Egress => "egress",
            Stage::MediaStream => "mediaStream",
            Stage::Throughput => "throughput",
            Stage::Path => "path",
            Stage::Pmtu => "pmtu",
        }
    }
}

/// State of a progress event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressStatus {
    Running,
    Completed,
    Failed,
    Skipped,
}

/// Progress of a single check, in channel order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveProgress {
    pub stage: Stage,
    pub status: ProgressStatus,
    pub completed: u8,
    pub total: u8,
    pub elapsed_ms: u32,
}

/// Generic outcome of a timed stage (old `unavailable` reads as `NotChecked`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StageStatus {
    Ok,
    Warning,
    Error,
    Timeout,
    Skipped,
    #[default]
    NotChecked,
}

/// Result of the tunnel handshake through the checked server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStatus {
    Ok,
    AuthFailed,
    TransportFailed,
    Timeout,
    Skipped,
    Unsupported,
}

/// Result of the path-MTU ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmtuStatus {
    Ok,
    /// The DF ladder proved at least `pmtu` bytes pass.
    LowerBound,
    BlackholeSuspected,
    IcmpBlocked,
    Skipped,
    Error,
}

/// How the PMTU was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PmtuMethod {
    IcmpDf,
    InterfaceMtu,
    Other(String),
}

/// Which path the throughput request took (always through the checked profile's SOCKS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThroughputRoute {
    PhysicalDirect,
    ActiveTunnel,
    ActiveProfileSelf,
    DirectDetour,
}

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// One diagnostic finding of a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub title: Msg,
    pub detail: Msg,
}

/// One resolver's answer in the DNS comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverAnswer {
    pub name: String,
    /// `Warning` = a partial answer.
    pub status: StageStatus,
    /// AD flag (DNSSEC) set in the answer.
    pub authenticated: bool,
    pub duration_ms: u32,
    pub records: Vec<String>,
    pub error: Option<String>,
}

/// DNS stage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsDiag {
    pub status: StageStatus,
    pub duration_ms: u32,
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub cname_chain: Vec<String>,
    pub ttl: Option<u32>,
    pub reverse_dns: Vec<String>,
    pub resolvers: Vec<ResolverAnswer>,
    /// Resolvers disagree: possible DNS tampering.
    pub discrepancies: Vec<String>,
}

/// TCP reachability of the endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reachability {
    pub status: StageStatus,
    pub duration_ms: u32,
    pub tcp_reachable: bool,
    pub error: Option<String>,
}

/// Direct TLS facts (Reality servers show the camouflage site's certificate).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsDiag {
    pub status: StageStatus,
    pub duration_ms: u32,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    /// `YYYY-MM-DD` or an ISO timestamp.
    pub valid_to: Option<String>,
    pub days_remaining: Option<i64>,
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub alpn: Option<String>,
    pub hostname_verified: Option<bool>,
    pub authorized: Option<bool>,
    pub authorization_error: Option<String>,
    pub fingerprint: Option<String>,
}

/// HTTP(S) diagnostic probe (a hint, never proof of anything).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpDiag {
    pub status: StageStatus,
    pub duration_ms: u32,
    pub status_code: Option<u16>,
    pub target_port: Option<u16>,
    pub is_tls: bool,
    pub server_header: Option<String>,
    pub via_header: Option<String>,
    pub location_header: Option<String>,
}

/// State of a scanned port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    Timeout,
}

/// One scanned port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortProbe {
    pub port: u16,
    pub service: Option<String>,
    pub state: PortStatus,
}

/// Traceroute to the endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouteDiag {
    pub status: StageStatus,
    pub duration_ms: u32,
    pub hops: Option<u32>,
    /// `Some(false)`: tracert finished without reaching the target.
    pub reached_target: Option<bool>,
    /// One line per hop (legacy history: raw tracert text, sanitised on display).
    pub hop_lines: Vec<String>,
    pub error: Option<String>,
}

/// What changed since the previous check of the same endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Changes {
    pub ip: bool,
    pub tls_cert: bool,
    pub asn: bool,
    pub country: bool,
    pub latency_spike: bool,
    pub ports: bool,
    pub handshake: bool,
    pub egress: bool,
    pub pmtu: bool,
    pub throughput: bool,
}

impl Changes {
    /// Any network difference at all (the «Diff» mark of history entries).
    pub fn any(&self) -> bool {
        let Changes {
            ip,
            tls_cert,
            asn,
            country,
            latency_spike,
            ports,
            handshake,
            egress,
            pmtu,
            throughput,
        } = *self;
        ip || tls_cert
            || asn
            || country
            || latency_spike
            || ports
            || handshake
            || egress
            || pmtu
            || throughput
    }
}

/// ASN, countries and diffs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Infrastructure {
    pub asn: Option<AsnInfo>,
    pub endpoint_country: Option<String>,
    /// From the stored profile (time of measurement unknown), shown only when the active tunnel
    /// runs this profile.
    pub egress_country: Option<String>,
    pub active_tunnel_matches_profile: bool,
    /// Other saved servers in the same /24: one block takes them all down.
    pub shared_cidr: Vec<String>,
    pub changes: Changes,
    pub error: Option<String>,
}

/// Tunnel handshake through the checked profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub status: HandshakeStatus,
    /// From the probe start to the first proxied TCP CONNECT (not the VPN start time).
    pub duration_ms: Option<u32>,
    pub protocol: Option<String>,
    pub evidence: Option<String>,
    pub error: Option<String>,
}

/// One "what is my IP" reflector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reflector {
    pub source: String,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub error: Option<String>,
}

/// Fresh exit IP through the checked profile.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Egress {
    pub status: StageStatus,
    pub duration_ms: u32,
    pub exit_ipv4: Option<String>,
    pub exit_ipv6: Option<String>,
    pub ipv6_unsupported: bool,
    pub country: Option<String>,
    /// `Some(false)`: dual-hop / NAT (normal for relays).
    pub matches_endpoint: Option<bool>,
    /// `route-selected`, `direct`, `nested` (`unknown` is not shown).
    pub underlay: Option<String>,
    pub reflectors: Vec<Reflector>,
    pub error: Option<String>,
}

/// Windows route to the VPN endpoint (outside the tunnel).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathDiag {
    pub status: StageStatus,
    pub interface_alias: Option<String>,
    pub interface_index: Option<u32>,
    pub is_tun: bool,
    pub next_hop: Option<String>,
    pub local_ip: Option<String>,
    pub error: Option<String>,
}

/// Path MTU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PmtuDiag {
    pub status: PmtuStatus,
    pub pmtu: Option<u32>,
    pub min_tested: Option<u32>,
    pub max_tested: Option<u32>,
    pub method: PmtuMethod,
    pub detail: Option<String>,
    pub error: Option<String>,
}

/// One media CDN endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaEndpoint {
    pub endpoint: String,
    pub reachable: bool,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
}

/// Twitch HLS reachability and the QUIC black-hole guard (player error #2000).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MediaDiag {
    pub status: StageStatus,
    pub hls_reachable: bool,
    pub quic_guarded: bool,
    pub error_2000_risk: bool,
    pub endpoints: Vec<MediaEndpoint>,
    pub detail: Option<String>,
    pub error: Option<String>,
}

/// One download sample of the throughput test.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ThroughputSample {
    pub mbps: f64,
    pub bytes: u64,
    pub duration_ms: u32,
    pub ttfb_ms: Option<u32>,
    pub stalls: u32,
    pub max_gap_ms: u32,
}

/// Short throughput / stability test through the profile.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Throughput {
    pub status: StageStatus,
    pub route: Option<ThroughputRoute>,
    pub median_mbps: Option<f64>,
    pub min_mbps: Option<f64>,
    pub max_mbps: Option<f64>,
    pub variability_pct: Option<f64>,
    pub stall_count: Option<u32>,
    pub max_gap_ms: Option<u32>,
    pub samples: Vec<ThroughputSample>,
    pub detail: Option<String>,
    pub error: Option<String>,
}

/// Split-tunnel rules as the engine sees them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SplitTunnelDiag {
    pub status: StageStatus,
    pub enabled: bool,
    pub direct: Vec<String>,
    pub vpn: Vec<String>,
    /// Programs listed both as direct and through the VPN.
    pub duplicates: Vec<String>,
    pub default_outbound: String,
    pub detail: Option<String>,
    pub error: Option<String>,
}

/// One live-check receipt.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LiveCheck {
    /// Unique per receipt (history entries merge by it).
    pub id: String,
    pub profile_id: Option<String>,
    pub host: String,
    pub port: u16,
    pub mode: LiveMode,
    pub started_at: UnixMs,
    pub finished_at: UnixMs,
    pub duration_ms: u32,
    /// Only imported legacy receipts can say so: an aborted check is never stored.
    pub cancelled: bool,
    /// Whether our tunnel ran during the measurement (`None`: not recorded).
    pub tunnel_running: Option<bool>,
    pub dns: DnsDiag,
    pub reachability: Reachability,
    pub latency: Option<LatencyStats>,
    pub tls: Option<TlsDiag>,
    pub http: Option<HttpDiag>,
    pub open_ports: Vec<PortProbe>,
    pub ports_error: Option<String>,
    pub route: Option<RouteDiag>,
    pub infrastructure: Option<Infrastructure>,
    pub handshake: Option<Handshake>,
    pub egress: Option<Egress>,
    pub path: Option<PathDiag>,
    pub pmtu: Option<PmtuDiag>,
    pub media: Option<MediaDiag>,
    pub throughput: Option<Throughput>,
    pub split_tunnel: Option<SplitTunnelDiag>,
    /// Requests through the server that its handshake budget left out (the rendered note): their
    /// rows are missing on purpose, not failed. `None`: nothing was left out.
    pub deferred: Option<String>,
    pub findings: Vec<Finding>,
}

/// Progress of a batch comparison, in channel order.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchProgress {
    pub profile_id: String,
    /// 0-based position in the batch.
    pub index: u16,
    pub total: u16,
    pub status: ProgressStatus,
    pub stage: Option<Stage>,
    pub median_mbps: Option<f64>,
}

/// Result of a batch comparison (partial with `cancelled` after a soft stop).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BatchResult {
    pub cancelled: bool,
    pub results: Vec<LiveCheck>,
    /// Servers that could not be checked (disabled, removed, failed).
    pub errors: Vec<(String, Msg)>,
}
