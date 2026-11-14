//! View models of the Maintenance page: display data only (no secrets, no Dioxus types). The app
//! fills them from the probes, protection, forensics, lifecycle and storage services.
use vpnte_base::Msg;
use vpnte_base::types::{KillSwitchLevel, UnixMs, Verdict};

/// What the page needs to know about the tunnel to gate its actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TunnelPhase {
    /// No session: repairs are allowed, the protection test is not.
    #[default]
    Off,
    /// Connecting, switching or disconnecting.
    Busy,
    /// A session is up: the protection test runs, repairs are refused.
    On,
}

/// Group of a diagnostics item (the probes report's categories).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagCategory {
    App,
    Tun,
    Proxy,
    Network,
    Internet,
    Windows,
    Logs,
    Routing,
    Profile,
}

impl DiagCategory {
    /// Report order of the groups.
    pub const ALL: [DiagCategory; 9] = [
        DiagCategory::App,
        DiagCategory::Tun,
        DiagCategory::Proxy,
        DiagCategory::Network,
        DiagCategory::Internet,
        DiagCategory::Routing,
        DiagCategory::Windows,
        DiagCategory::Logs,
        DiagCategory::Profile,
    ];

    /// The categories the page's summary counts (a failure there breaks connectivity).
    pub fn is_critical(self) -> bool {
        matches!(
            self,
            DiagCategory::App
                | DiagCategory::Tun
                | DiagCategory::Proxy
                | DiagCategory::Network
                | DiagCategory::Internet
                | DiagCategory::Routing
        )
    }

    /// Whether a warning here concerns the route (App warnings are not shown as important).
    pub fn is_route(self) -> bool {
        self.is_critical() && self != DiagCategory::App
    }

    /// Locale key of the group heading.
    pub fn label_key(self) -> &'static str {
        match self {
            DiagCategory::App => "ui.maintenance.category.app",
            DiagCategory::Tun => "ui.maintenance.category.tun",
            DiagCategory::Proxy => "ui.maintenance.category.proxy",
            DiagCategory::Network => "ui.maintenance.category.network",
            DiagCategory::Internet => "ui.maintenance.category.internet",
            DiagCategory::Windows => "ui.maintenance.category.windows",
            DiagCategory::Logs => "ui.maintenance.category.logs",
            DiagCategory::Routing => "ui.maintenance.category.routing",
            DiagCategory::Profile => "ui.maintenance.category.profile",
        }
    }
}

/// One row of the system diagnostics report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagItem {
    /// Stable id (`adapters`, `endpoint-google`, `routing-…`).
    pub id: String,
    pub category: DiagCategory,
    pub label: Msg,
    /// `None`: informational, nothing judged; `Some(NotChecked)`: the check could not run.
    pub verdict: Option<Verdict>,
    pub value: Msg,
    /// Technical rows (adapters, routes, log lines): redacted, not localized.
    pub details: Vec<String>,
    /// Localized remarks.
    pub notes: Vec<Msg>,
}

/// The system diagnostics report («Проверить»).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SystemReport {
    pub ran_at: UnixMs,
    pub items: Vec<DiagItem>,
}

/// State of the WFP kill switch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum KillSwitchState {
    #[default]
    Off,
    /// Standard level, no session: filters come with the next connection.
    Armed,
    /// Filters active and the tunnel up.
    Engaged,
    /// Filters active without a tunnel: traffic outside the VPN is blocked.
    Blocking,
    /// The filters could not be applied or read back.
    Failed(Msg),
    /// No filters here (no helper service, an unelevated app): the kill switch acts through the
    /// system proxy; the filters come with the service (p-noadmin-ui).
    ProxyOnly,
}

/// A Windows Firewall profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FwProfile {
    Domain,
    Private,
    Public,
}

impl FwProfile {
    /// Stable id (`domain`, `private`, `public`), also the last segment of its locale keys.
    pub fn id(self) -> &'static str {
        match self {
            FwProfile::Domain => "domain",
            FwProfile::Private => "private",
            FwProfile::Public => "public",
        }
    }
}

/// An enabled Windows Firewall profile whose default outbound action is Block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallBlock {
    pub profile: FwProfile,
    /// The profile applies to a connected network right now.
    pub active: bool,
}

/// Network protection as read back from Windows (own WFP provider and sublayer).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtectionView {
    pub level: KillSwitchLevel,
    pub kill_switch: KillSwitchState,
    pub leak_protection_active: bool,
    /// Our filters in the dynamic session (gone when the process exits).
    pub dynamic_filters: u32,
    /// Our persistent filters (only the strict level keeps them).
    pub persistent_filters: u32,
    /// Base Filtering Engine service: the kill switch and sing-box's strict route depend on it.
    pub bfe_running: bool,
    pub firewall_blocks: Vec<FirewallBlock>,
    pub last_verified: Option<UnixMs>,
}

/// A step of the auto-repair, in run order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RepairStep {
    /// Remove our WFP filters (persistent ones only when the level is not strict).
    Filters,
    /// Replay the old version's journals and remove its leftovers again.
    Legacy,
    /// Stop sing-box / xray processes that no session owns.
    Engines,
}

impl RepairStep {
    /// Run order.
    pub const ALL: [RepairStep; 3] = [RepairStep::Filters, RepairStep::Legacy, RepairStep::Engines];

    /// Stable id (logs, DOM).
    pub fn id(self) -> &'static str {
        match self {
            RepairStep::Filters => "filters",
            RepairStep::Legacy => "legacy",
            RepairStep::Engines => "engines",
        }
    }

    /// Locale key of the row label.
    pub fn label_key(self) -> &'static str {
        match self {
            RepairStep::Filters => "ui.maintenance.steps.filters",
            RepairStep::Legacy => "ui.maintenance.steps.legacy",
            RepairStep::Engines => "ui.maintenance.steps.engines",
        }
    }
}

/// What one repair step reported (an error is reported as `failed(msg)`, a refusal as
/// `blocked(msg)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepOutcome {
    /// False: the step failed or did only part of its job (`message` says what).
    pub success: bool,
    /// Refused (for example a session started meanwhile): a warning, never a failure.
    pub blocked: bool,
    /// Done, with something to look at.
    pub warning: bool,
    /// The step's own sentence; wins over everything else.
    pub message: Option<Msg>,
    /// What was changed (`Some(vec![])`: nothing needed changing; `None`: not reported).
    pub changes: Option<Vec<String>>,
}

impl StepOutcome {
    /// Done; `changes` lists what was changed.
    pub fn done(changes: Vec<String>) -> Self {
        Self {
            success: true,
            blocked: false,
            warning: false,
            message: None,
            changes: Some(changes),
        }
    }
    /// Failed (or only partly done) with an explanation.
    pub fn failed(message: Msg) -> Self {
        Self {
            success: false,
            blocked: false,
            warning: false,
            message: Some(message),
            changes: None,
        }
    }
    /// Refused with an explanation.
    pub fn blocked(message: Msg) -> Self {
        Self {
            success: false,
            blocked: true,
            warning: false,
            message: Some(message),
            changes: None,
        }
    }
}

/// Progress of one step of the current or last repair.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum StepState {
    /// Not run since the app started.
    #[default]
    Idle,
    /// Waiting for the earlier steps.
    Pending,
    Running,
    Done(StepOutcome),
}

/// The auto-repair as published by the backend operation (so it survives the page).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairView {
    pub running: bool,
    /// One entry per [`RepairStep::ALL`], in order.
    pub steps: Vec<(RepairStep, StepState)>,
}

impl Default for RepairView {
    fn default() -> Self {
        Self {
            running: false,
            steps: RepairStep::ALL
                .iter()
                .map(|s| (*s, StepState::Idle))
                .collect(),
        }
    }
}

/// Conclusion of the leak self-test, computed by the probes service from the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LeakVerdict {
    /// A physical address reached the Internet while the kill switch should block it.
    Leak,
    /// Reach with the kill switch off, or IP services that disagree.
    PossibleLeak,
    /// Every probe measured "no way out" and the tunnel's exit is known.
    Ok,
    /// Not proven either way (also: cancelled).
    #[default]
    Inconclusive,
}

impl LeakVerdict {
    /// Wire name (the panel's `data-verdict`).
    pub fn name(self) -> &'static str {
        match self {
            LeakVerdict::Leak => "leak",
            LeakVerdict::PossibleLeak => "possible-leak",
            LeakVerdict::Ok => "ok",
            LeakVerdict::Inconclusive => "inconclusive",
        }
    }
}

/// What the bound probe from one physical address proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeReach {
    /// An answer came back: this address reaches the Internet outside the tunnel.
    Reached { public_ip: String },
    /// curl measured no connection (exit 7 or 28).
    NotReached { curl_exit: i32 },
    /// Nothing established (DNS, TLS, launch, bind, garbage); `why` explains.
    Unknown { curl_exit: Option<i32>, why: Msg },
}

/// One probed physical address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterProbe {
    pub alias: String,
    /// The local address the probe was bound to.
    pub local: Option<String>,
    pub reach: ProbeReach,
    /// Last characters of curl's stderr (technical).
    pub stderr_tail: Option<String>,
}

/// The leak self-test result as the panel shows it (no legacy summary text exists here: every
/// sentence is derived from the evidence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakTestView {
    pub at: UnixMs,
    pub verdict: LeakVerdict,
    pub cancelled: bool,
    /// The verdict sentence with its evidence (addresses, reason of an inconclusive run).
    pub headline: Msg,
    /// Public IPv4 seen through the default route (the TUN when it works).
    pub tun_ip: Option<String>,
    pub adapters: Vec<AdapterProbe>,
    /// Two IP services saw different exits.
    pub disagreement: Option<Msg>,
}

/// Conclusion of the routing self-test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteVerdict {
    Ok,
    Partial,
    Leak,
    TunnelOff,
    #[default]
    Inconclusive,
}

/// The routing self-test result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTestView {
    pub verdict: RouteVerdict,
    pub message: Msg,
}

/// Both halves of «Проверить защиту».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionTest {
    pub leak: LeakTestView,
    pub route: RouteTestView,
}

/// A name with a count (ETW categories, top domains, top endpoints).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counted {
    pub name: String,
    pub count: u64,
}

/// The in-process ETW consumer of the current capture session.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EtwView {
    pub running: bool,
    /// Engine label of the session (`etw-inproc`; old imported sessions: `ferrisetw-realtime`,
    /// `powershell-poller`).
    pub engine: Option<String>,
    /// Started less than 30 s ago and no data event yet.
    pub warming_up: bool,
    /// Running past the warm-up with lifecycle events only.
    pub only_lifecycle: bool,
    pub data_events: u64,
    /// Data events per category (any order; the page sorts).
    pub categories: Vec<Counted>,
    pub wfp_blocks: u64,
    pub top_domains: Vec<Counted>,
    pub top_remotes: Vec<Counted>,
    pub last_event_at: Option<UnixMs>,
}

/// Packet capture / forensics status («Сбор пакетов»).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CaptureView {
    /// Capture can run in this process; otherwise «restart» is disabled up front and the first
    /// warning says why.
    pub available: bool,
    /// Deep inspection is switched on in Settings.
    pub enabled: bool,
    pub running: bool,
    /// The stop was not confirmed: the capture may still be writing (F-198).
    pub cleanup_pending: bool,
    /// The status could not be read: shown as "stop not confirmed", never as "stopped".
    pub status_unavailable: bool,
    /// The old client's capture still needs stopping (its own localized explanation).
    pub legacy_cleanup_required: bool,
    /// `stop_reason == start-failed`.
    pub start_failed: bool,
    /// Why the last start or stop failed.
    pub last_error: Option<Msg>,
    /// `pktmon` while it records; `None` when the session is ETW-only.
    pub engine: Option<String>,
    pub etl_bytes: Option<u64>,
    pub live_snapshot_at: Option<UnixMs>,
    pub artifact_count: u32,
    pub etw: Option<EtwView>,
    /// Most important first; the panel shows the first one.
    pub warnings: Vec<Msg>,
}

/// An error the app caught without crashing (lifecycle "faults").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultView {
    pub at: UnixMs,
    /// Short technical code (`engine-exit`, `panic`, …).
    pub code: String,
    /// Redacted technical summary (English), shown as is in this advanced-mode box.
    pub detail: String,
}

/// The diagnostics ZIP export: one at a time app-wide, published by the forensics service so
/// every button (Settings, Maintenance) shows the same state.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ExportView {
    pub running: bool,
    /// 0..=1; `None` while the amount of work is unknown.
    pub progress: Option<f64>,
    /// What is being packed right now.
    pub stage: Option<Msg>,
}

/// A finished export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDone {
    pub path: String,
    /// Temporary files could not be removed (owner §10.6 A: must be visible).
    pub cleanup_failed: bool,
}

/// The data directory of the old Electron version (never modified by the import).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyDir {
    pub path: String,
    pub bytes: Option<u64>,
    /// Plaintext copies that may hold keys (`settings.json.bak-*` and the like).
    pub plaintext_files: u32,
}

/// A document that is corrupt and holds secrets, so it was opened read-only and left untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorruptStore {
    /// Store id passed back to [`super::MaintenanceApi::set_aside_corrupt`].
    pub id: String,
    /// What it holds («Профили»).
    pub name: Msg,
    pub file: String,
}

/// Old-version leftovers and storage repair helpers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LegacyView {
    /// `None`: the old data directory is gone (or never existed).
    pub data_dir: Option<LegacyDir>,
    /// Keys could not be decrypted at import; they are still in the old files.
    pub secrets_pending: bool,
    pub corrupt: Vec<CorruptStore>,
    /// Steps of the one-shot network cleanup of the old version that did not finish.
    pub cleanup_failures: Vec<Msg>,
}

/// Outcome of «Повторить импорт ключей из старой версии».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretsImport {
    /// Keys filled in.
    pub restored: u32,
    /// Still not decryptable (DPAPI unavailable).
    pub pending: bool,
}

/// A stage of the network check, in the order it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetStepKind {
    Dns,
    Tcp,
    Tls,
    /// Bytes after 16 KB (the freeze).
    Bytes,
    Udp,
    /// The user's servers (address ban).
    Servers,
    /// The DNS canary: do the system's DNS queries reach our engine (TUN), or are they not
    /// captured at all (proxy mode).
    DnsCapture,
}

/// One stage line: its mark and its plain-words result.
#[derive(Debug, Clone, PartialEq)]
pub struct NetStepView {
    pub kind: NetStepKind,
    pub verdict: Verdict,
    pub detail: Msg,
}

/// A finished network check.
#[derive(Debug, Clone, PartialEq)]
pub struct NetCheckView {
    pub at: UnixMs,
    /// The probes left through the running session's direct-out (our TUN was up).
    pub via_session: bool,
    /// The overall colour: `Ok` only for a clean pass, `Warn` for a restriction, `Fail` for no
    /// internet, `NotChecked` when nothing was proven either way (never the success colour).
    pub verdict: Verdict,
    pub steps: Vec<NetStepView>,
    /// The restrictions found, most limiting first (empty: none).
    pub modes: Vec<vpnte_view::netmode::NetMode>,
    /// The verdict in one line.
    pub headline: Msg,
    /// What helps, one line per mode.
    pub advice: Vec<Msg>,
}

/// The network-mode check (RU networks): pushed by the backend, which also runs it on its own
/// at start and after a network change.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetworkView {
    /// A check runs now.
    pub running: bool,
    /// The latest check of the current network; `None` before one finished, and again after
    /// the network changed.
    pub last: Option<NetCheckView>,
}

/// Everything the backend pushes to the page (one snapshot, latest value).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MaintenanceState {
    pub tunnel: TunnelPhase,
    /// `None` until the first read.
    pub protection: Option<ProtectionView>,
    pub repair: RepairView,
    pub capture: CaptureView,
    pub fault: Option<FaultView>,
    pub export: ExportView,
    pub legacy: LegacyView,
    /// The network-mode check (also read by the start page's network banner).
    pub network: NetworkView,
}
