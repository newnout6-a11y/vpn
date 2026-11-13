//! View models of the Logs page and the [`LogsApi`] the app implements over the backend.
//! Display data only: no secrets, no Dioxus types.
use std::sync::Arc;

use tokio::sync::watch;
use vpnte_base::types::{Engine, OutboundFault, UnixMs};
use vpnte_base::{AppResult, ErrorKind, Msg};

use super::events::EventRow;
use crate::lang::Lang;
use crate::widgets::Load;

/// Data and actions of the «Журнал» page (tabs «События», «Подключения», «Технический»).
///
/// Implementations run destructive work (the clears) in their own task: the page may unmount
/// while a call is pending, and dropping the future must not stop a half-done clear.
#[async_trait::async_trait(?Send)]
pub trait LogsApi: 'static {
    /// The event journal and the whole connection history (any order; the page sorts), pushed on
    /// every change: an event, a session end, a clear, an import.
    fn snapshot(&self) -> watch::Receiver<LogsSnapshot>;
    /// Reads the history again after a failed read (the result arrives through `snapshot`).
    async fn reload_history(&self) -> AppResult<()>;
    /// Writes the WHOLE history (the on-screen filters are not applied) as CSV or JSON (the
    /// lifecycle formats): shows the native save dialog suggesting `file_name`, writes the file
    /// atomically and returns the saved file's name. `Err(Cancelled)` when the dialog was dismissed.
    async fn export_history(&self, format: ExportFormat, file_name: String) -> AppResult<String>;
    /// Empties the event journal; nothing else.
    async fn clear_events(&self) -> AppResult<()>;
    /// Empties the connection history; nothing else.
    async fn clear_history(&self) -> AppResult<()>;
    /// Empties the technical logs this user owns (app.log and the engine logs in the user's
    /// logs folder, previous generations deleted); nothing else.
    async fn clear_technical(&self) -> AppResult<ArtifactReport>;
    /// The last lines of a log (whole lines, redacted by their writer, oldest first).
    async fn read_log(&self, source: LogSource) -> AppResult<LogTail>;
    /// Opens the folder of the log `source` shows in Explorer.
    async fn open_log_folder(&self, source: LogSource) -> AppResult<()>;
    /// Puts `text` on the Windows clipboard.
    async fn copy_text(&self, text: String) -> AppResult<()>;
}

/// Pushed state of the page.
#[derive(Debug, Clone, PartialEq)]
pub struct LogsSnapshot {
    /// Every stored session (at most 1000), in any order.
    pub history: Load<Arc<[SessionRow]>>,
    /// The event journal, oldest first.
    pub events: Load<Arc<[EventRow]>>,
}

impl Default for LogsSnapshot {
    fn default() -> Self {
        Self {
            history: Load::Loading,
            events: Load::Loading,
        }
    }
}

/// One connection attempt of the history.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionRow {
    pub id: String,
    pub started_at: UnixMs,
    /// `None` while the session runs.
    pub ended_at: Option<UnixMs>,
    /// Monotonic elapsed time; absent on rows written before it was recorded.
    pub duration_ms: Option<u64>,
    pub profile_name: String,
    pub mode: Mode,
    pub bytes_down: u64,
    pub bytes_up: u64,
    /// Coarse five-bucket reason (filters, CSV).
    pub reason: DisconnectReason,
    /// Technical message stored with the row, if any.
    pub error_message: Option<String>,
    /// The explained outcome; absent on rows written before outcomes existed.
    pub outcome: Option<Outcome>,
}

/// Connection mode of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    Hard,
    Soft,
    Direct,
}

impl Mode {
    /// Wire name (`hard`), also what the text search matches.
    pub fn key(self) -> &'static str {
        match self {
            Mode::Hard => "hard",
            Mode::Soft => "soft",
            Mode::Direct => "direct",
        }
    }
    /// Key of the mode name shown in the table (`modes.hard` = «Туннель»).
    pub fn label_key(self) -> &'static str {
        match self {
            Mode::Hard => "modes.hard",
            Mode::Soft => "modes.soft",
            Mode::Direct => "modes.direct",
        }
    }
}

/// Coarse reason a session ended (the old five buckets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DisconnectReason {
    User,
    Error,
    Rotation,
    Schedule,
    Crash,
}

impl DisconnectReason {
    /// Filter chip order.
    pub const ALL: [DisconnectReason; 5] = [
        DisconnectReason::User,
        DisconnectReason::Error,
        DisconnectReason::Rotation,
        DisconnectReason::Schedule,
        DisconnectReason::Crash,
    ];
    /// Wire name (`user`).
    pub fn key(self) -> &'static str {
        match self {
            DisconnectReason::User => "user",
            DisconnectReason::Error => "error",
            DisconnectReason::Rotation => "rotation",
            DisconnectReason::Schedule => "schedule",
            DisconnectReason::Crash => "crash",
        }
    }
    /// Chip label key (`logs.reasonUser`).
    pub fn label_key(self) -> &'static str {
        match self {
            DisconnectReason::User => "logs.reasonUser",
            DisconnectReason::Error => "logs.reasonError",
            DisconnectReason::Rotation => "logs.reasonRotation",
            DisconnectReason::Schedule => "logs.reasonSchedule",
            DisconnectReason::Crash => "logs.reasonCrash",
        }
    }
}

/// Why a session ended, as explained by the lifecycle (15 kinds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutcomeKind {
    UserStop,
    AppQuit,
    ServerSwitch,
    Rotation,
    Schedule,
    ProxyUnreachable,
    ServerRejectedKey,
    ServerDown,
    SingboxCrash,
    Killswitch,
    TunSetupFailed,
    NetworkLost,
    SystemSleep,
    StartFailed,
    Unknown,
}

/// How loud an outcome chip is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeTone {
    /// The user or the app ended it on purpose.
    Intended,
    /// The network or the machine got in the way.
    Warn,
    /// Something broke.
    Bad,
    /// The cause is not known.
    Unknown,
}

impl OutcomeKind {
    pub const ALL: [OutcomeKind; 15] = [
        OutcomeKind::UserStop,
        OutcomeKind::AppQuit,
        OutcomeKind::ServerSwitch,
        OutcomeKind::Rotation,
        OutcomeKind::Schedule,
        OutcomeKind::ProxyUnreachable,
        OutcomeKind::ServerRejectedKey,
        OutcomeKind::ServerDown,
        OutcomeKind::SingboxCrash,
        OutcomeKind::Killswitch,
        OutcomeKind::TunSetupFailed,
        OutcomeKind::NetworkLost,
        OutcomeKind::SystemSleep,
        OutcomeKind::StartFailed,
        OutcomeKind::Unknown,
    ];

    /// Wire name (`user-stop`): the CSV value, the text-search token, the label key suffix.
    pub fn key(self) -> &'static str {
        match self {
            OutcomeKind::UserStop => "user-stop",
            OutcomeKind::AppQuit => "app-quit",
            OutcomeKind::ServerSwitch => "server-switch",
            OutcomeKind::Rotation => "rotation",
            OutcomeKind::Schedule => "schedule",
            OutcomeKind::ProxyUnreachable => "proxy-unreachable",
            OutcomeKind::ServerRejectedKey => "server-rejected-key",
            OutcomeKind::ServerDown => "server-down",
            OutcomeKind::SingboxCrash => "singbox-crash",
            OutcomeKind::Killswitch => "killswitch",
            OutcomeKind::TunSetupFailed => "tun-setup-failed",
            OutcomeKind::NetworkLost => "network-lost",
            OutcomeKind::SystemSleep => "system-sleep",
            OutcomeKind::StartFailed => "start-failed",
            OutcomeKind::Unknown => "unknown",
        }
    }

    /// Chip label: `logs.outcome.<kind>`.
    pub fn label(self) -> Msg {
        Msg::new(format!("logs.outcome.{}", self.key()))
    }

    /// Chip tone (the old ok/info → intended, warn → warn, bad → bad, muted unknown → unknown;
    /// app-quit was muted too, but it is a deliberate end).
    pub fn tone(self) -> OutcomeTone {
        match self {
            OutcomeKind::UserStop
            | OutcomeKind::AppQuit
            | OutcomeKind::ServerSwitch
            | OutcomeKind::Rotation
            | OutcomeKind::Schedule => OutcomeTone::Intended,
            OutcomeKind::ProxyUnreachable | OutcomeKind::NetworkLost | OutcomeKind::SystemSleep => {
                OutcomeTone::Warn
            }
            OutcomeKind::ServerRejectedKey
            | OutcomeKind::ServerDown
            | OutcomeKind::SingboxCrash
            | OutcomeKind::Killswitch
            | OutcomeKind::TunSetupFailed
            | OutcomeKind::StartFailed => OutcomeTone::Bad,
            OutcomeKind::Unknown => OutcomeTone::Unknown,
        }
    }
}

/// Text that is either a catalog message (re-rendered on a language switch) or verbatim stored
/// text (rows imported from the old version, engine output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Text {
    Msg(Msg),
    Plain(String),
}

impl Text {
    /// The text in `lang` (the global catalog).
    pub fn render(&self, lang: Lang) -> String {
        self.render_with(&|msg: &Msg| msg.render(lang))
    }
    /// The text with `tr` rendering catalog messages (pages pass `lang::tr`).
    pub fn render_with(&self, tr: &dyn Fn(&Msg) -> String) -> String {
        match self {
            Text::Msg(msg) => tr(msg),
            Text::Plain(text) => text.clone(),
        }
    }
}

impl From<Msg> for Text {
    fn from(msg: Msg) -> Self {
        Text::Msg(msg)
    }
}

impl From<String> for Text {
    fn from(text: String) -> Self {
        Text::Plain(text)
    }
}

/// The explained end of a session.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub kind: OutcomeKind,
    /// One sentence for the user.
    pub headline: Text,
    pub evidence: Evidence,
}

/// Facts recorded with an outcome; every field is optional and an absent one is not shown.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Evidence {
    pub singbox_exit_code: Option<i64>,
    /// Last lines of the engine output (redacted by the logger).
    pub singbox_stderr_tail: Option<String>,
    pub outbound_fault: Option<OutboundFault>,
    /// Adaptive bypass mode, wire name (`tls-compatibility`, `external-managed`, …).
    pub adaptive_mode: Option<String>,
    pub adaptive_attempts: Option<u32>,
    pub auto_restart_attempts: Option<u32>,
    pub kill_switch_engaged: Option<bool>,
    pub leak_detected_during_session: Option<bool>,
    pub network_transition: Option<String>,
    pub egress_country: Option<String>,
    pub egress_ip: Option<String>,
    pub proxy_engine: Option<Engine>,
    /// Why that engine ran the server (REALITY, chosen by the user, …).
    pub proxy_engine_reason: Option<Text>,
    /// What to do (start failures).
    pub hint: Option<Text>,
}

/// One field of [`Evidence`], in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKey {
    SingboxExitCode,
    SingboxStderrTail,
    OutboundFault,
    AdaptiveMode,
    AdaptiveAttempts,
    AutoRestartAttempts,
    KillSwitchEngaged,
    LeakDetectedDuringSession,
    NetworkTransition,
    EgressCountry,
    EgressIp,
    ProxyEngine,
    ProxyEngineReason,
    Hint,
}

impl EvidenceKey {
    pub const ALL: [EvidenceKey; 14] = [
        EvidenceKey::SingboxExitCode,
        EvidenceKey::SingboxStderrTail,
        EvidenceKey::OutboundFault,
        EvidenceKey::AdaptiveMode,
        EvidenceKey::AdaptiveAttempts,
        EvidenceKey::AutoRestartAttempts,
        EvidenceKey::KillSwitchEngaged,
        EvidenceKey::LeakDetectedDuringSession,
        EvidenceKey::NetworkTransition,
        EvidenceKey::EgressCountry,
        EvidenceKey::EgressIp,
        EvidenceKey::ProxyEngine,
        EvidenceKey::ProxyEngineReason,
        EvidenceKey::Hint,
    ];

    /// The old field name (`singboxExitCode`): label key suffix and copied-text key.
    pub fn name(self) -> &'static str {
        match self {
            EvidenceKey::SingboxExitCode => "singboxExitCode",
            EvidenceKey::SingboxStderrTail => "singboxStderrTail",
            EvidenceKey::OutboundFault => "outboundFault",
            EvidenceKey::AdaptiveMode => "adaptiveMode",
            EvidenceKey::AdaptiveAttempts => "adaptiveAttempts",
            EvidenceKey::AutoRestartAttempts => "autoRestartAttempts",
            EvidenceKey::KillSwitchEngaged => "killSwitchEngaged",
            EvidenceKey::LeakDetectedDuringSession => "leakDetectedDuringSession",
            EvidenceKey::NetworkTransition => "networkTransition",
            EvidenceKey::EgressCountry => "egressCountry",
            EvidenceKey::EgressIp => "egressIp",
            EvidenceKey::ProxyEngine => "proxyEngine",
            EvidenceKey::ProxyEngineReason => "proxyEngineReason",
            EvidenceKey::Hint => "hint",
        }
    }

    /// Label: `logs.outcomeEvidence.<name>`.
    pub fn label(self) -> Msg {
        Msg::new(format!("logs.outcomeEvidence.{}", self.name()))
    }
}

/// A present evidence value.
#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceValue {
    Number(i64),
    Flag(bool),
    Fault(OutboundFault),
    Engine(Engine),
    Text(Text),
}

/// Per-file result of clearing the technical logs (core's artifact names: `app-log`,
/// `sing-box-previous-log`, ...).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArtifactReport {
    pub cleared: Vec<String>,
    /// Nothing to delete (never created).
    pub absent: Vec<String>,
    pub failed: Vec<(String, ErrorKind)>,
}

/// File format of the history export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
    Json,
}

impl ExportFormat {
    pub fn extension(self) -> &'static str {
        match self {
            ExportFormat::Csv => "csv",
            ExportFormat::Json => "json",
        }
    }
}

/// A source of the technical tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum LogSource {
    /// `app.log`: backend and UI lines (JSON lines).
    #[default]
    App,
    /// The sing-box log of the current or last session, wherever it ran.
    SingBox,
    /// The Xray log of the current or last session, wherever it ran.
    Xray,
    /// The helper service's own log: the service-wide lines and this user's (JSON lines).
    Service,
}

impl LogSource {
    pub const ALL: [LogSource; 4] = [
        LogSource::App,
        LogSource::SingBox,
        LogSource::Xray,
        LogSource::Service,
    ];
}

/// One whole line of a log and its byte offset in the file (the row key: a re-read keeps the
/// expanded line and the scroll position).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailLine {
    pub offset: u64,
    pub text: String,
}

/// What the calm line over the lines says about where they come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TailNote {
    /// Nothing to say (app.log).
    #[default]
    None,
    /// Engine log of a session in Proxy mode (the user's logs folder).
    ProxySession,
    /// Engine log of a Tunnel session this app ran itself (elevated).
    TunnelSession,
    /// Engine log of a Tunnel session through the helper service (its logs folder).
    ServiceSession,
    /// The service's lines: service-wide ones and those of this user's sessions.
    ServiceLines,
    /// No helper service is installed (the service source has nothing to show).
    NoService,
    /// The installed service is older than the app and does not send its log.
    OldService,
}

/// The end of a log.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogTail {
    /// Whole lines, oldest first.
    pub lines: Vec<TailLine>,
    /// The log exists (an engine that never ran has no log yet).
    pub exists: bool,
    /// Older lines were left out.
    pub truncated: bool,
    pub note: TailNote,
}
