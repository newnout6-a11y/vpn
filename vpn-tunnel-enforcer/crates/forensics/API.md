# vpnte-forensics — API

The traffic sample type and its maths, the domain history («История трафика») with opt-in site names, the
opt-in deep packet capture (pktmon + in-process ETW consumer), the forensic session summary and the
diagnostics ZIP («Отправить логи разработчику»). Depends on `vpnte-base`, `vpnte-core`, `vpnte-winnet`.

Paths: `vpnte_forensics::{traffic, connections, domains, enrichment, etw, capture, summary, export}`
plus `vpnte_forensics::LOCALES`. Shared types from `vpnte_base`: `AppError` / `ErrorKind` /
`AppResult`, `Msg`, `types::{UnixMs, now_ms, ProxyKind, Level, Notice}`; from `vpnte_core`:
`store::{Store, Document}`, `settings::{Settings, ConnectionMode}`, `net::Route`,
`ops::{OperationRegistry, Source}`. The crate has no cargo features.

**Elevation.** Needs it: the packet capture (`pktmon start/stop/counters/etl2pcap`, writing session
dirs under the protected root), `Capture::recover_on_boot`'s `pktmon stop`, and the ETW consumer
(`etw::EtwConsumer::start`, `reclaim_orphan`: admin or membership in «Performance Log Users»).
Unelevated, `Capture::start` fails with `ErrorKind::Permission` (`forensics.capture.error.storage`):
session dirs cannot be created under the protected root (a root someone made user-writable is
accepted as is: then pktmon refuses and the session is ETW-only or `StartFailed`). Elevated, a
pktmon refusal leaves the session ETW-only (not an error). This build does not wire the capture
(NOADMIN: a later, service-hosted feature). Works without elevation: Clash polling, the domain
history, enrichment lookups, the summary (reads only) and the export (reads the forensics root:
the user has read access, never write).
**Runtime.** `ClashPoller::spawn`, `HistoryService::open`, `Enricher::{queue,
spawn_tick}`, `Capture` (its ticker) and `export::export` need a tokio runtime. Blocking calls (put
them on `spawn_blocking`): `EtwConsumer::{start, stop}`, `summary::{summarize, write,
summarize_and_write}`, `Capture::sessions`, everything in `capture::{store, manifest}`. `Capture`
itself moves the heavy work (ETW start / stop, snapshots, «clear») to blocking threads; its
transitions still write manifests and list session dirs on the runtime (small files, rare).
**Files.** Data dir (through `Store`): `history/traffic-domains.json` (`DomainsDoc`),
`cache/domain-info.json` (`EnrichmentDoc`), `forensics.json` (`CapturePrefs`). Capture root:
`%ProgramData%\VPN Tunnel Enforcer\forensics\` (`capture.owned` marker, `sessions\<id>\`).

## Locales (register at startup)
```rust
pub const LOCALES: &[(&str, &str)];   // (ru_json, en_json) per fragment, file-name order: capture, export, traffic
let layers = [vpnte_core::LOCALES, vpnte_forensics::LOCALES /* , … */].concat();
vpnte_ui::lang::init_locales(&layers);
```
Every `Msg` this crate returns has its key here (all under `forensics.`; `src/locale_tests.rs` checks
ru/en parity, placeholders and that every key named in the code exists):

| Keys | Args | Returned by |
| --- | --- | --- |
| `forensics.history.sourceUnavailable` | — | `SourceHealth::warning()` (history page banner) |
| `forensics.capture.error.{consentRequired,stopUnconfirmed,startFailed,storage}` | — | `From<CaptureError> for AppError`; `stopUnconfirmed` / `startFailed` also as `CaptureStatus::last_error` |
| `forensics.capture.warn.{onlyLifecycle,etlEmpty,etwFailed,quota,pktmonUnavailable}` | — | `CaptureStatus::warnings` |
| `forensics.capture.warn.{eventsLost,unparsed}` | `count` | `CaptureStatus::warnings` |
| `forensics.summary.check.<camelCase check>` | — | `summary::Check::label` |
| `forensics.summary.finding.{detected,notDetected,unknown}` | — | `summary::Finding::label` |
| `forensics.summary.warning.<camelCase warning>` | — | `summary::SummaryWarning::label` |
| `forensics.export.stage.{preparing,settings,logs,system,runtime,recovery,snapshots,forensics,finishing}` | — | `export::ExportStage::label` |
| `forensics.export.cleanupFailed.{title,body}` | — | the `Notice` sent to `ExportRequest::notices` |
| `forensics.export.{dialogTitle,zipFilter}` | — | not returned: for the UI's save dialog |

**Pushed state the app must forward** (all `tokio::sync::watch`, no broadcast events):
`HistoryService::{health(), changes()}`,
`Enricher::changes()`, `Capture::status()` (on transitions + every 5 s while running), the export's
`ExportRequest::progress` sender, plus `NoticeSink` notices of a failed export cleanup.

## traffic — the published traffic sample and its maths
```rust
pub const SAMPLE_INTERVAL: Duration;   // 1 s between samples
pub const SMOOTHING_ALPHA: f64;        // 0.35          pub const BURSTINESS_WINDOW: usize;   // 5
#[derive(Clone, Default, PartialEq, Serialize)] #[serde(rename_all = "camelCase")]
pub struct TrafficStats { pub ts_ms: UnixMs, pub running: bool, pub adapter: String, pub adapter_found: bool,
    pub down_bps: f64, pub up_bps: f64, pub smooth_down_bps: f64, pub smooth_up_bps: f64,
    pub down_burst_pct: u16, pub up_burst_pct: u16,          // 0..=999 %
    pub total_down: u64, pub total_up: u64,                  // totals of the current source (engine run)
    pub session_down: u64, pub session_up: u64,              // since the session start; survive restarts
    pub peak_down_bps: f64, pub peak_up_bps: f64, pub started_at_ms: Option<UnixMs> }
impl TrafficStats { pub fn empty(adapter: &str, now: UnixMs) -> Self; }
pub fn smooth(prev: f64, cur: f64, alpha: f64) -> f64;   pub fn burstiness(xs: &[f64]) -> u16;
```
The sampler itself lives in the app (`svc_tunnel::traffic::Meter`, engine Clash API totals for both
captures). The TUN-counter `RateSampler` / `TunIf` / `recent_traffic` /
`TrafficStats::shows_live_traffic` / `LIVE_TRAFFIC_BPS` were removed in the crate review
(2026-11-12): nothing used them, and a Soft session has no TUN adapter to read.

## connections — Clash API `/connections` client
```rust
pub const POLL_INTERVAL: Duration;  /* 1.5 s */  pub const REQUEST_TIMEOUT: Duration; /* 4 s */  pub const FAILURE_LIMIT: u32; /* 3 */
#[derive(Clone, PartialEq, Eq)] pub struct ClashEndpoint { pub port: u16, pub secret: String } // 127.0.0.1; Debug hides the secret
pub struct ClashSnapshot { pub connections: Vec<ClashConn> }
pub struct ClashConn { pub id: String, pub metadata: ClashMeta, pub upload: u64, pub download: u64, pub chains: Vec<String> }
pub struct ClashMeta { pub host: String, pub destination_ip: String }
pub enum PollError { Transport(reqwest::Error), Status(u16), Schema }     // thiserror
pub fn parse_snapshot(body: &[u8]) -> Result<ClashSnapshot, PollError>;   // `null` list = empty, bad elements skipped
pub struct ClashClient;
impl ClashClient { pub fn new(endpoint: &ClashEndpoint) -> AppResult<Self>;
                   pub async fn connections(&self) -> Result<ClashSnapshot, PollError>; }  // bearer secret, body ≤ 16 MiB
#[derive(Clone, Copy, Default, PartialEq, Serialize)] #[serde(rename_all = "kebab-case")]
pub enum SourceHealth { Idle, Ok, Unavailable }      // Idle until the first success, Unavailable after 3 failures
impl SourceHealth { pub fn warning(self) -> Option<Msg>; }       // Some only for Unavailable
pub struct FailureCounter;  // Default
impl FailureCounter { pub fn record(&mut self, ok: bool) -> Option<SourceHealth>; }
pub struct ClashPoller;     // stops on stop() or drop
impl ClashPoller { pub fn spawn(endpoint: &ClashEndpoint, interval: Duration,
                       on_poll: impl FnMut(Result<ClashSnapshot, PollError>) + Send + 'static) -> AppResult<Self>;
                   pub fn stop(&self); }
```

## domains — domain history
```rust
pub const MAX_DOMAINS: usize;  /* 2000 */  pub const PERSIST_DELAY: Duration;  /* 10 s */
pub const DOH_INFRA_HOSTS: &[&str];        // DoH / DoT resolvers, never recorded
#[serde(rename_all = "camelCase")]
pub struct DomainRecord { pub domain: String, pub first_seen: UnixMs, pub last_seen: UnixMs, pub connections: u32,
    pub lookups: u32, pub bytes_up: u64, pub bytes_down: u64, pub outbound: Option<String> }
impl DomainRecord { pub fn visits(&self) -> u32; }                 // connections if > 0, else lookups
pub struct DomainsDoc { pub domains: BTreeMap<String, DomainRecord> }   // Document "history/traffic-domains.json" v1
impl DomainsDoc { pub fn from_legacy(old: &serde_json::Value) -> Self; } // old traffic-domains.json
pub fn normalize_host(raw: &str) -> Option<String>;
pub fn should_record(raw: &str, infra: &HashSet<String>) -> Option<String>;  // None: IPs, local, DoH, servers, junk
pub struct History;   // pure state (the service wraps it)
impl History { pub fn new(doc: DomainsDoc) -> Self;
    pub fn set_infra<S: AsRef<str>>(&mut self, server_hosts: impl IntoIterator<Item = S>);
    pub fn merge_snapshot(&mut self, s: &ClashSnapshot, now: UnixMs, new_hosts: &mut Vec<String>) -> bool;
    pub fn observe_log_line(&mut self, line: &str, now: UnixMs) -> bool;   // sing-box INFO DNS answers
    pub fn list(&self) -> Vec<DomainRecord>;  pub fn clear(&mut self);  pub fn take_doc(&mut self) -> Option<DomainsDoc>; }
pub type NewConnectionHook = Arc<dyn Fn(&str) + Send + Sync>;   // host of every new connection (domain-rule hits)
pub struct HistoryService;
impl HistoryService {
    pub fn open(store: Arc<Store<DomainsDoc>>, on_new: Option<NewConnectionHook>) -> Self;  // spawns the delayed writer
    pub fn set_server_hosts<S: AsRef<str>>(&self, hosts: impl IntoIterator<Item = S>);
    pub fn start_polling(&self, endpoint: &ClashEndpoint) -> AppResult<()>;   // engine run up (replaces the poller)
    pub async fn stop_polling(&self) -> AppResult<()>;                       // engine stopped: Idle + flush
    pub fn observe_log_line(&self, line: &str);                              // every engine stdout/stderr line
    pub fn list(&self) -> Vec<DomainRecord>;                                 // newest first, side-effect free
    pub fn health(&self) -> watch::Receiver<SourceHealth>;
    pub fn changes(&self) -> watch::Receiver<u64>;                           // revision counter
    pub async fn clear(&self) -> AppResult<()>;                              // saves at once; logs untouched
    pub async fn flush(&self) -> AppResult<()>;                              // app exit
}
```

## enrichment — opt-in site names (off by default)
```rust
pub const READY_TTL_MS: i64; /* 30 d */  pub const FAILURE_TTL_MS: i64; /* 24 h */  pub const MAX_ENTRIES: usize; /* 1000 */
pub const MAX_CONCURRENT: usize; /* 2 */ pub const MAX_PENDING: usize;  /* 8 */
pub const LOOKUP_TIMEOUT: Duration; /* 8 s */  pub const TICK: Duration; /* 15 s */
#[serde(rename_all = "lowercase")] pub enum EnrichStatus { Pending, Ready, Unavailable }   // Pending never stored
#[serde(rename_all = "camelCase")]
pub struct DomainEnrichment { pub status: EnrichStatus, pub site_name: Option<String>, pub title: Option<String>,
    pub description: Option<String>, pub canonical_url: Option<String>, pub favicon_url: Option<String>, pub fetched_at: UnixMs }
impl DomainEnrichment { pub fn is_fresh(&self, now: UnixMs) -> bool; }
pub struct EnrichmentDoc { pub entries: BTreeMap<String, DomainEnrichment> }   // Document "cache/domain-info.json" v1
impl EnrichmentDoc { pub fn from_legacy(old: &serde_json::Value) -> Self; }     // old domain-intelligence.json
pub fn normalize_domain(input: &str) -> Option<String>;
pub fn registrable(host: &str) -> Option<String>;          // cache key: contacts.google.com → google.com
pub fn allowed_url(url: &Url) -> bool;                     // https, default port, no user info
pub fn proxy_route(addr: &str, kind: ProxyKind) -> Option<Route>;   // local proxy "host:port" / "<kind>://host:port"
#[derive(Serialize)] #[serde(rename_all = "camelCase")]
pub struct HistoryEntry { #[serde(flatten)] pub record: DomainRecord, pub enrichment: Option<DomainEnrichment> }
#[derive(Clone, Default, PartialEq, Eq)] pub struct EnrichInputs { pub enabled: bool, pub route: Option<Route> }
#[derive(Clone)] pub struct Enricher;
impl Enricher {
    pub fn open(store: Arc<Store<EnrichmentDoc>>) -> Self;
    pub fn get(&self, domain: &str) -> Option<DomainEnrichment>;     // Pending while queued, fresh cache hit, else None
    pub fn entries(&self, records: Vec<DomainRecord>, inputs: &EnrichInputs) -> Vec<HistoryEntry>; // never queues
    pub fn changes(&self) -> watch::Receiver<u64>;
    pub fn queue(&self, domains: &[String], route: &Route);         // runtime; normally only the tick calls it
    pub fn disable(&self);                                          // drops the queue, aborts lookups, keeps the cache
    pub async fn clear(&self) -> AppResult<()>;
    pub fn spawn_tick(&self, history: Arc<HistoryService>, inputs: watch::Receiver<EnrichInputs>, cancel: CancellationToken);
}
```
Lookups: every hop's host must resolve to public addresses only (`vpnte_core::net::is_public_ip`); the
direct route is pinned to them (F-177); ≤ 4 redirects; only a 2xx `text/html` / xhtml answer is
scanned (≤ 512 KiB). `EnrichInputs::route`: `proxy_route(..)` (or `ProxyOverride::route`) in local-proxy
mode, `Some(Route::Direct)` while the TUN runs, `None` otherwise (no lookups, nothing attached).

## etw — in-process ETW consumer (ex-sidecar)
```rust
pub const ENGINE: &str;  /* "etw-inproc" */  pub const STOP_TIMEOUT: Duration;  /* 5 s */
pub use session::{SESSION_NAME /* "VPNTE-ETW" */, PROVIDERS /* [(name, guid u128); 5] */, LossStats, reclaim_orphan};
pub use writer::{EVENTS_FILE /* events.ndjson */, EVENTS_PREV_FILE /* events.prev.ndjson */, WriterStats};
pub use digest::{Counted, DigestSnapshot, LiveDigest};
pub enum EtwError { Io(io::Error), Start(String) }
pub struct EtwStopStats { pub writer: WriterStats, pub digest: DigestSnapshot, pub loss: Option<LossStats>, pub clean: bool }
pub struct LossStats { pub events_lost: u32, pub buffers_lost: u32 }
pub struct WriterStats { pub rows_written: u64, pub bytes_written: u64, pub write_errors: u64, pub rotations: u32, pub rotated_bytes: u64 }
pub struct EtwConsumer;
impl EtwConsumer {
    pub fn start(dir: &Path, session_id: &str) -> Result<Self, EtwError>;  // blocking: reclaim orphan, writer, trace
    pub fn digest(&self) -> Arc<LiveDigest>;
    pub fn is_running(&self) -> bool;                                      // false once processing ended on its own
    pub fn stop(self, reason: &str) -> EtwStopStats;                       // blocking ≤ ~5 s; final row written last
}
pub fn reclaim_orphan() -> bool;            // stop a left-over "VPNTE-ETW" session; true = one existed
pub fn session::query_loss() -> Option<LossStats>;
pub struct Counted { pub name: String, pub count: u64 }
pub struct DigestSnapshot { engine: Option<String>, events, data_events, observed, filtered, unparsed,
    backpressure_dropped, write_errors, overflow: u64, categories: BTreeMap<String, u64>, wfp_blocks: u64,
    top_domains: Vec<Counted>, top_remotes: Vec<Counted>, last_data_at: Option<UnixMs> }   // all pub, camelCase
impl LiveDigest { pub fn observe(&self, row: &Map<String, Value>); pub fn snapshot(&self) -> DigestSnapshot;
    pub fn note_{observed,filtered,unparsed,backpressure,write_error}(&self); }
pub mod classify { provider_category, canonical_provider, known_guid, derive_event_and_reason, is_significant,
    default_event, parse_sockaddr, first_ip, le_uint, port_value, truncate_chars }   // verbatim port of the sidecar rules
pub mod writer { ROTATE_BYTES /* 64 MiB */, QUEUE_ROWS /* 65 536 */, HEARTBEAT_EVERY /* 30 s */, SIDECAR,
    Heartbeat, RowSender, RowWriter, fn rfc3339_ms(ms: i64) -> String /* 2026-06-19T00:00:00.000Z */ }
```
Rows (`events.ndjson`, schema of the old sidecar): `provider`, `category` (data rows `tcp|dns|wfp|afd|
webio|event`; consumer rows `lifecycle|health`), `event`, `reason`, `remoteAddress` / `remotePort`, `localAddress` / `localPort`, `queryName`,
`queryResults`, `resolver`, `ts` (RFC 3339 ms). Rotation at 64 MiB keeps the tail in `events.prev.ndjson`.

## capture — opt-in deep packet capture («Глубокий захват трафика»)
```rust
pub const APP_EVENTS_MAX: u32;  /* 10 000 */  pub const APP_EVENTS_FILE: &str;  /* app-events.ndjson */
pub const STOP_ERRORS_FILE: &str;  /* stop-errors.txt */  pub const LIVE_COUNTERS_FILE: &str;  /* pktmon-live-counters.json */
pub const START_FAILED: &str; /* "start-failed" */  pub const RECOVERED_AT_STARTUP: &str; /* "recovered-at-startup" */
pub struct CaptureConfig { pub enabled: bool, pub consent_at: Option<UnixMs>, pub max_size_mb: u32 /* 128..=2048 */,
    pub quota_mb: u32 /* 1024..=65536 */ }                                   // Default: off, 512 MB ring, 8192 MB quota
impl CaptureConfig { pub fn new(settings: &Settings, prefs: &CapturePrefs) -> Self; }   // deep_inspection*, clamped
#[serde(rename_all = "camelCase", default)]
pub struct CapturePrefs { pub consent_at: Option<UnixMs>, pub quota_mb: u32 }   // Document "forensics.json" v1
pub struct SessionCtx { pub mode: ConnectionMode, pub target: String }         // proxy address / profile name
pub enum StopReason { VpnStop, Shutdown, ManualRestart, ManualClear, KillSwitch, Other(String) }
impl StopReason { pub fn as_str(&self) -> &str; }   // "vpn-stop", "shutdown", "manual-ui-restart", …, "killswitch-active"
pub enum CaptureError { ConsentRequired, StopUnconfirmed { code: Option<i32>, detail: String }, StartFailed(String), Io(io::Error) }
impl From<CaptureError> for AppError;   // Conflict / Conflict / Internal / Permission|Internal + forensics.capture.error.*
#[derive(Serialize)] pub struct ForensicEvent { #[serde(flatten)] pub kind: ForensicEventKind, pub details: serde_json::Value }
#[serde(tag = "event", rename_all = "kebab-case", rename_all_fields = "camelCase")]
pub enum ForensicEventKind { TunStartRequested, EngineStartFailed, EngineExited { user_initiated: bool }, EngineCrashRestart,
    EngineRestartExhausted, EngineExitedKillswitchActive, KillSwitchEngaged, TunStarted, EngineStartTimeout,
    TunStopRequested, TunStopped, LeakDiagnosticsResult, LeakSelfTestResult }
impl ForensicEventKind { pub fn source(self) -> &'static str; }   // "tun" | "leak-diagnostics" | "leak-self-test"
pub trait System: Send + Sync + 'static {        // the OS side; tests use a fake
    fn pktmon(&self, args: Vec<OsString>, timeout: Duration) -> BoxFuture<'static, io::Result<Outcome>>;
    fn etl_released(&self, etl: &Path) -> bool;
    fn start_etw(&self, dir: PathBuf, session: String) -> BoxFuture<'static, Result<Box<dyn Etw>, String>>;
    fn reclaim_etw(&self) -> bool;
    fn snapshot(&self, dir: PathBuf, phase: &'static str) -> BoxFuture<'static, ()>; }
pub trait Etw: Send + Sync { fn digest(&self) -> DigestSnapshot; fn is_running(&self) -> bool;
    fn loss(&self) -> Option<LossStats>; fn stop(self: Box<Self>, reason: &str) -> EtwStopStats; }  // impl for EtwConsumer
pub struct WindowsSystem;                         // the real System
#[derive(Clone)] pub struct Capture;
impl Capture {
    pub fn new(root: PathBuf, cfg: watch::Receiver<CaptureConfig>, system: Arc<dyn System>) -> Self;
    pub fn root(&self) -> &Path;
    pub fn status(&self) -> watch::Receiver<CaptureStatus>;
    pub async fn start(&self, ctx: SessionCtx) -> Result<CaptureStatus, CaptureError>;  // disabled → Ok(enabled: false)
    pub async fn stop(&self, reason: StopReason) -> Result<CaptureStatus, CaptureError>; // StopUnconfirmed → call again
    pub async fn restart(&self) -> Result<CaptureStatus, CaptureError>;                 // «Перезапустить сбор»
    pub async fn recover_on_boot(&self, legacy_electron: Option<&Path>) -> RecoveryReport;
    pub fn record(&self, ev: ForensicEvent);            // into the running session only; dropped when none runs
    pub async fn clear(&self) -> Result<ClearReport, CaptureError>;   // «Очистить диагностику»: stops, deletes all
                                                        // sessions; Err(StopUnconfirmed) while the stop stays unconfirmed
    pub async fn refresh(&self);
    pub async fn live_refresh(&self) -> Option<PathBuf>; // counters + snapshots of the running session (export)
    pub fn sessions(&self) -> Vec<SessionEntry>;         // blocking, oldest first
}
pub struct RecoveryReport { pub orphan_suspected: bool, pub pktmon_stopped: bool, pub sessions_closed: u32, pub etw_reclaimed: bool }
#[serde(rename_all = "camelCase")]
pub struct CaptureStatus { pub enabled: bool, pub running: bool, pub cleanup_pending: bool, pub session_id: Option<String>,
    pub session_dir: Option<PathBuf>, pub mode: Option<ConnectionMode>, pub target: Option<String>,
    pub started_at: Option<UnixMs>, pub stopped_at: Option<UnixMs>, pub max_size_mb: u32, pub stop_reason: Option<String>,
    pub last_error: Option<Msg>, pub pktmon: PktmonState, pub etw: EtwState, pub digest: Option<DigestSnapshot>,
    pub health: Health, pub warnings: Vec<Msg> /* most important first */, pub total_bytes: u64 }
pub struct Health { pub artifact_count: usize, pub etl_bytes: u64, pub events_bytes: u64,
    pub etw_warming_up: bool, pub etw_only_lifecycle: bool }
#[serde(tag = "state", content = "detail", rename_all = "kebab-case")]
pub enum PktmonState { NotStarted, Running, Unavailable(String), Stopped, StopUnconfirmed(String) }
#[serde(tag = "state", content = "detail", rename_all = "kebab-case")]
pub enum EtwState { NotStarted, Running, Failed(String), Stopped }
pub mod manifest { MANIFEST_FILE, MARKER_FILE, SESSIONS_DIR, SCHEMA_VERSION /* 2 */, SessionManifest, session_id(now),
    valid_session_id, session_dir, read_manifest, write_manifest, read_marker, write_marker, remove_marker,
    legacy_hint_paths, legacy_hint_pending }
pub mod store { DEFAULT_QUOTA_MB /* 8192 */, QUOTA_MB /* (1024, 65536) */, fn default_root() -> Option<PathBuf>
    /* %ProgramData%\VPN Tunnel Enforcer\forensics */, ensure_root, list_sessions, list_artifacts, total_bytes, free_bytes,
    quota_reached, remove_sessions, ArtifactFile { name, size, mtime_ms }, SessionEntry { id, dir, bytes, files, manifest },
    ClearReport { removed, failed, freed_bytes } }
pub mod pktmon { ETL_FILE, PCAPNG_FILE, COUNTERS_FILE, DROP_COUNTERS_FILE, START/STOP/COLLECT_TIMEOUT, TRACE_PROVIDERS,
    start_args, stop_args, counters_args, etl2pcap_args, exe(), run(args, timeout), etl_released,
    Outcome { code: Option<i32>, stdout, stderr } + success() / detail() }
pub mod status { WARM_UP_MS, HealthInput, liveness_and_warnings }   // engine names are labelled by the UI
```
Session dir: `session-manifest.json`, `pktmon.etl` (whole packets, never exported), `events.ndjson`
(+ `.prev`), `network-{start,stop,live}.json`, `sockets-{start,stop,live}.json`, `app-events.ndjson`,
`pktmon-counters.json`, `pktmon-drop-counters.json`, `pktmon.pcapng` (local only),
`pktmon-live-counters.json`, `stop-errors.txt`, and after the app ran the summary: `summary.json`,
`packet-metrics.json`. A stop counts as confirmed only when `pktmon stop` exits 0 or the ETL is
observed released; otherwise the status stays `cleanup_pending` and the marker is kept.

## summary — tri-state, evidence-linked session summary
```rust
pub const SUMMARY_FILE: &str; /* summary.json */  pub const PACKET_METRICS_FILE: &str; /* packet-metrics.json */
pub const SCHEMA_VERSION: u32; /* 2 */  pub const EVIDENCE_MAX: usize; /* 20 */  pub const MATCH_MAX_CHARS: usize; /* 500 */
pub const TCP_MIN: u64; /* 3 rows of one reason for a "likely" */  pub const TOP_N: usize; /* 20 */
#[serde(rename_all = "kebab-case")] pub enum Finding { Detected, NotDetected, Unknown }   // label() -> Msg
#[serde(rename_all = "camelCase")] pub enum Check { TrafficLeakDetected, DnsLeakDetected, TunPathConfirmed,
    KillSwitchBlockedTraffic, WindowsFirewallBlockedTraffic, RemoteResetLikely, TimeoutOrPacketLossLikely,
    MtuIssueLikely, SingBoxFailureLikely }       // Check::ALL (report order), label() -> Msg, answerable() -> bool
pub struct Evidence { pub artifact: String, pub line: Option<u64>, pub reason: String, pub matched: Option<String> /* "match" */ }
pub struct Counts { pub events, data_events: u64, pub per_category: BTreeMap<String, u64>, pub dns_rows, resets, losses, mtu,
    wfp_block_rows, unparsed, app_events, packet_metrics, malformed_lines, events_lost, rows_dropped: u64 }
pub struct Top { pub domains: Vec<etw::Counted>, pub remotes: Vec<etw::Counted> }
#[serde(rename_all = "kebab-case")] pub enum SummaryWarning { ManifestMissing, EtwNotRun, EtwNoData, EtwEventsLost,
    PktmonNotRun, NoCounters, MalformedLines, ArtifactUnreadable, AppEventsDropped, NoLeakTest, NoWfpDropSource } // label()
#[derive(Default)] pub struct SummaryCtx { pub tun_alias: Option<String> }
pub struct Summary { pub schema_version: u32, pub generated_at: UnixMs, pub session_id: String,
    pub mode: Option<ConnectionMode>, pub target: Option<String>, pub engine: Option<String>, pub running: bool,
    pub verdicts: BTreeMap<Check, Finding>, pub insufficient_evidence: bool, pub evidence: BTreeMap<Check, Vec<Evidence>>,
    pub counts: Counts, pub top: Top, pub warnings: Vec<SummaryWarning>,
    #[serde(skip)] pub packet_metrics: Vec<PacketMetric> }   // camelCase
impl Summary { pub fn finding(&self, c: Check) -> Finding; pub fn detected(&self) -> Vec<Check>;
    pub fn to_json(&self) -> serde_json::Result<Vec<u8>>; pub fn metrics_json(&self) -> serde_json::Result<Vec<u8>>; }
pub fn summarize(dir: &Path, ctx: &SummaryCtx) -> io::Result<Summary>;            // blocking; Err only: dir unreadable
pub fn write(dir: &Path, summary: &Summary) -> io::Result<()>;                     // atomic, both files
pub fn summarize_and_write(dir: &Path, ctx: &SummaryCtx) -> io::Result<Summary>;   // the app: after a capture stop
#[serde(rename_all = "lowercase")] pub enum MetricCategory { Drop, Byte, Packet, Error, Counter }
pub struct PacketMetric { pub artifact: String, pub path: String, pub name: String, pub value: f64, pub category: MetricCategory }
pub fn flatten_counters(root: &serde_json::Value, artifact: &str) -> Vec<PacketMetric>;
```
`Detected` only on a real observation, `NotDetected` only when the source that could see it ran,
else `Unknown` (never read as "fine"). Leak verdicts come only from leak-test app events
(`LeakSelfTestResult` / `LeakDiagnosticsResult` details); configuration is never evidence.

## export — the diagnostics ZIP
```rust
pub const RESOURCE: &str; /* "diagnostics:export": one at a time (Conflict core.ops.busy) */  pub const BUDGET: Duration; /* 600 s */
pub type NoticeSink = Arc<dyn Fn(Notice) + Send + Sync>;
pub enum RecoveryRead { Trusted(serde_json::Value), Absent, Untrusted }
pub struct RecoveryArtifact { pub artifact: String, pub file: String, pub read: RecoveryRead }
#[derive(Clone, Default)] pub struct ExportInputs { pub app_version: String, pub engine_versions: Vec<(String, String)>,
    pub settings: Settings, pub logs_dir: Option<PathBuf>, pub system_diagnostics: Option<serde_json::Value>,
    pub engine_configs: Vec<(String, serde_json::Value)>, pub recovery: Vec<RecoveryArtifact>,
    pub snapshots_dir: Option<PathBuf>, pub capture: Option<Capture>, pub summary_ctx: SummaryCtx,
    pub user_name: Option<String> /* None = %USERNAME% */ }
#[derive(Clone, Copy, Default)] pub enum ExportStage { Preparing, Settings, Logs, System, Runtime, Recovery, Snapshots,
    Forensics, Finishing }       // COUNT = 9, step() -> u8 (1-based), label() -> Msg
#[derive(Clone, Copy, Default)] pub struct ExportProgress { pub stage: ExportStage, pub entries: u32, pub bytes: u64 }
pub struct ExportRequest { pub dest: PathBuf, pub inputs: ExportInputs, pub source: Source,
    pub progress: watch::Sender<ExportProgress>, pub notices: Option<NoticeSink> }
pub struct ExportResult { pub path: PathBuf, pub entries: usize, pub excluded: Vec<String>, pub forensics_session: Option<String> }
pub fn default_file_name(now: UnixMs) -> String;   // vpn-tunnel-enforcer-diagnostics-2026-11-11T07-20-30-123Z.zip
pub async fn export(ops: &OperationRegistry, request: ExportRequest) -> AppResult<ExportResult>;
```
Errors: `Conflict` (another export), `Cancelled` (`ops.cancel(id)` or dropping the future), `Timeout`,
I/O kinds (`Permission` for an unwritable destination). The ZIP is streamed into
`.<dest>.<random>.partial` next to `dest` and renamed over it only when complete: on any failure the
previous file stays. Layout: `settings.json`, `app-log.json`, `system-info.json`,
`system-diagnostics.json`, `runtime-<engine>.json`, `runtime-<engine log>`, recovery files +
`recovery-artifacts-status.json`, `snapshots/*.json`, `traffic-forensics/sessions/<latest id>/…`
(raw captures only listed as excluded), `traffic-forensics/{latest-session.json,REDACTION.txt}`,
`README.txt`, `diagnostics-manifest.json`. Every entry is redacted with `vpnte_core::redact` (config /
data / log policies; forensic host names become per-archive `<domain-N>` pseudonyms); the Windows user
name becomes `<user>`.

## Main flows (app wiring)
```rust
// start-up (inside the runtime)
let history = Arc::new(HistoryService::open(Arc::new(Store::<DomainsDoc>::open(&dirs.root)), Some(rule_hit_hook)));
let enricher = Enricher::open(Arc::new(Store::<EnrichmentDoc>::open(&dirs.root)));
enricher.spawn_tick(history.clone(), enrich_inputs_rx, app_cancel.clone()); // inputs: setting + route (see enrichment)
let prefs = Arc::new(Store::<CapturePrefs>::open(&dirs.root));      // consent dialog: prefs.update(|p| p.consent_at = Some(now_ms()))
let (cfg_tx, cfg_rx) = watch::channel(CaptureConfig::new(&settings, &prefs.snapshot())); // re-send on settings / prefs change
let Some(root) = capture::store::default_root() else { /* no %ProgramData%: capture unavailable */ };
let capture = Capture::new(root, cfg_rx, Arc::new(WindowsSystem));
if elevated { capture.recover_on_boot(Some(&dirs.legacy_electron)).await; }   // before any new capture
// legacy import (once, by the app): DomainsDoc::from_legacy(&old_traffic_domains), EnrichmentDoc::from_legacy(&old_domain_intelligence)

// protection established (not on engine auto-restarts)
history.set_server_hosts(all_server_hosts);              // also whenever the server list changes
history.start_polling(&ClashEndpoint { port, secret })?; // each sing-box run; feed every engine line:
history.observe_log_line(line);
capture.start(SessionCtx { mode, target }).await?;       // Ok(enabled: false) when the setting is off
capture.record(ForensicEvent { kind: ForensicEventKind::TunStarted, details: json!({ /* … */ }) });

// protection ends
let st = capture.stop(StopReason::VpnStop).await?;       // BEFORE engine teardown; StopUnconfirmed → retry later
history.stop_polling().await?;
if let Some(dir) = st.session_dir.filter(|_| !st.running) {
    tokio::task::spawn_blocking(move || summary::summarize_and_write(&dir, &SummaryCtx { tun_alias }));
}
// shutdown: tokio::time::timeout(10 s, capture.stop(StopReason::Shutdown)); history.flush().await

// history page / dashboard: enricher.entries(history.list(), &inputs) (top 300 / top 5);
// «Очистить историю»: history.clear().await?; enricher.clear().await?

// export (after the UI's save dialog; default name default_file_name(now_ms()))
let (progress, progress_rx) = watch::channel(ExportProgress::default());
let req = ExportRequest { dest, inputs, source: Source::Ui, progress, notices: Some(notice_sink) };
let done = export::export(&ops, req).await?;             // UI: stage.label(), step()/ExportStage::COUNT
```
Engine requirement (engine crate): sing-box `log.level = "info"`, `timestamp: true`, `disable_color:
true`, output on the pipe; Clash API on 127.0.0.1 with a per-run secret.

## Not implemented / not verified
- Not implemented (dropped on purpose): netsh trace fallback and `netsh wfp` state, WFP drop
  enumeration (`windowsFirewallBlockedTraffic` is always `unknown` + warning `no-wfp-drop-source`),
  the ETW "physical address → public remote" leak heuristic, the old re-projection files
  (timeline / flows / tcp-health), retention auto-prune (quota → ETW-only; the user clears),
  `vpnIp` / `sniffHost` per history entry, log-file tailing. `CaptureStatus` carries no summary: the
  app runs `summarize_and_write` after a stop.
- Not run here (need elevation; CI runs them with `-- --ignored elevated_`):
  `capture::tests::elevated_capture_start_and_stop` (real pktmon), `etw::tests::elevated_*` (run
  once by hand unelevated as a Performance Log User); the real `pktmon counters --json` layout
  (TUN-path search is structural); Clash polling against a real sing-box (mock server used).
  `enrichment::tests::live_lookup_of_example_com` needs internet (ignored).
- Not wired by the app in this build: `Capture` start / stop / `etw` / `summary` after a stop (no
  packet capture). Wired (w3-app-extras, 2026-11-12): `Enricher` (its tick runs only while the
  `domain_enrichment` setting is on; route Direct under the TUN, the session's mixed inbound in
  Soft, none idle), `HistoryService::observe_log_line` (every line of every sing-box core, through
  the tunnel runtime's `EngineFeed`), the Traffic page reads `HistoryService` (no file polling),
  and the export gets engine versions, the last engine config, the recovery state (protection,
  cleanup marker, tweak-journal summary) and an idle `Capture` over the default root.
