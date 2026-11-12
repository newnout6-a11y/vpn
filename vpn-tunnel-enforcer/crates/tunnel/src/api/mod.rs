//! Shared types of the tunnel runtime API and the [`Runtime`] trait: the runtime actor's handle
//! implements it, the lifecycle lane consumes it.
//!
//! Engine-side types (exit info, slots) are mirrored here as small plain structs so that crates
//! without the engine dependency (the lifecycle) can use them. User-facing text is always a
//! [`Msg`]; English strings in this module are for logs only.
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{
    AdaptiveMode, ClientDevice, Engine, EnginePref, KillSwitchLevel, OutboundFault, ProxyKind,
    UnixMs,
};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_profiles::model::Profile;

/// A server key ready to run: the typed profile, the server-list id and the device to imitate.
#[derive(Debug, Clone, PartialEq)]
pub struct VpnProfile {
    /// Stable id of the server entry (failover and history refer to it, never to the name).
    pub id: String,
    /// Shared and immutable: requests are cloned for "last start" and restarts.
    pub profile: Arc<Profile>,
    /// Client the subscription expects; drives the default uTLS fingerprint.
    pub device: Option<ClientDevice>,
    /// The server's own engine choice: sing-box / Xray win over [`StartRequest::engine`], `Auto`
    /// follows it (`vpnte_engine::xray_config::server_pref`).
    pub engine: EnginePref,
}

pub use vpnte_engine::xray_config::SelectReason;

/// The engine that carries a session's upstream and why it was chosen: shown beside the server
/// while connected, kept in the history row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineRun {
    pub kind: Engine,
    /// `None` for a local upstream proxy: sing-box forwards to it, no engine was chosen.
    pub reason: Option<SelectReason>,
}

/// What the tunnel carries.
#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    /// Everything through a local upstream proxy (e.g. Happ) behind the sing-box TUN.
    LocalProxy { addr: String, kind: ProxyKind },
    /// A VPN server driven by our own engines.
    DirectVpn { profile: VpnProfile },
}

impl Mode {
    /// The mode without its payload.
    pub fn kind(&self) -> ModeKind {
        match self {
            Mode::LocalProxy { .. } => ModeKind::LocalProxy,
            Mode::DirectVpn { .. } => ModeKind::DirectVpn,
        }
    }
}

/// Payload-free [`Mode`] (`"localProxy"` / `"directVpn"` on the wire, as in the old status).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ModeKind {
    LocalProxy,
    DirectVpn,
}

/// Why a start was requested. Every origin except `Recovery` resets the crash-restart budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    User,
    Schedule,
    Rotation,
    Adaptive,
    Recovery,
}

/// How a session takes traffic (NOADMIN.md §2; settings `routing_mode`: Hard = `Tun`, Soft =
/// `Proxy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CaptureKind {
    /// The whole machine through our TUN, guarded by WFP (needs an elevated process).
    Tun,
    /// A loopback `mixed` inbound the user-level system proxy points at (no privileges).
    Proxy,
}

/// Everything one start needs. Kept by the runtime as "last start" for restarts.
#[derive(Debug, Clone, PartialEq)]
pub struct StartRequest {
    pub mode: Mode,
    /// How traffic is captured; a strategy the host did not supply answers `Permission`.
    pub capture: CaptureKind,
    /// Kill-switch level for this run (`Off` = no WFP protection).
    pub kill_switch: KillSwitchLevel,
    /// Public Wi-Fi compatibility (TUN MTU 1380).
    pub public_wifi: bool,
    /// Stealth mode (MTU 1280 + TLS compatibility).
    pub stealth: bool,
    pub adaptive: AdaptiveMode,
    pub engine: EnginePref,
    pub origin: Origin,
}

/// A confirmed start: the runtime is up, its adapter, protection and selector are verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartReceipt {
    /// Native generation of this run (the one `StartBegan` / `StartFinished` carried).
    pub generation: u64,
    /// PID of our sing-box process.
    pub pid: u32,
    pub started_at: UnixMs,
    /// Engine that carries the upstream (`Xray` for slot upstreams behind the sing-box TUN) and
    /// why it was chosen.
    pub engine: EngineRun,
    /// Things the user should know about this run (never raw OS text).
    pub warnings: Vec<Msg>,
}

/// How to stop.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StopOptions {
    /// Keep the kill switch blocking with no tunnel behind it (protected restart, adaptive fallback).
    pub preserve_protection: bool,
    /// Keep the last start request and the crash-restart counter.
    pub preserve_last: bool,
}

/// What a stop actually achieved. Each cleanup step is independent and reported on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopReceipt {
    /// `stop_` + 32 lowercase hex.
    pub operation_id: String,
    pub ok: bool,
    /// Our engine processes are proven gone (process handle observed exiting).
    pub runtime_stopped: bool,
    /// The process had to be terminated instead of ending on its own.
    pub forced: bool,
    /// `None`: not attempted (preserved stop). A full stop reports `Some(true)` also when no
    /// protection was held.
    pub protection_released: Option<bool>,
    /// `None`: not attempted (preserved stop); like `protection_released` otherwise.
    pub baseline_restored: Option<bool>,
    /// Our TUN adapter was seen disappearing.
    pub adapter_gone: bool,
    pub warnings: Vec<Msg>,
}

impl StopReceipt {
    /// A full stop whose every rollback step is confirmed: the only receipt that may certify
    /// "disconnected" after a fault (absent steps count as unconfirmed).
    pub fn confirms_cleanup(&self) -> bool {
        self.ok
            && self.runtime_stopped
            && self.protection_released == Some(true)
            && self.baseline_restored == Some(true)
    }
}

/// Options of a protected restart (stop with protection kept, then start).
#[derive(Debug, Clone)]
pub struct RestartOptions {
    /// How long to wait for the old adapter to disappear before the new one is created.
    pub release_timeout: Duration,
    /// Cancels the restart; a cancelled restart ends in a full stop.
    pub cancel: CancellationToken,
}

impl Default for RestartOptions {
    fn default() -> Self {
        Self {
            release_timeout: Duration::from_secs(5),
            cancel: CancellationToken::new(),
        }
    }
}

/// How an engine process ended (plain mirror of the engine's exit record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInfo {
    pub at: UnixMs,
    /// Process exit code, when the OS reported one.
    pub code: Option<i32>,
    /// Last non-empty output lines, already redacted, at most 800 chars.
    pub stderr_tail: String,
    /// The app asked for this exit (stop, compensation): not a crash.
    pub user_initiated: bool,
}

/// Runtime status as published on the status watch.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunStatus {
    pub running: bool,
    pub mode: Option<ModeKind>,
    pub proxy_addr: Option<String>,
    pub proxy_type: Option<ProxyKind>,
    pub profile_name: Option<String>,
    /// Protocol label (`vless`, `hysteria2`, …).
    pub protocol: Option<String>,
    pub pid: Option<u32>,
    pub warning: Option<Msg>,
    /// `false` while the watchdog sees the upstream down (traffic is held inside the TUN).
    pub proxy_reachable: bool,
    /// Start of this run (UI uptime).
    pub started_at: Option<UnixMs>,
    pub restart_attempt: u8,
    /// How the running session takes traffic (`None` while nothing runs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureKind>,
    /// The engine of the running session and why (`None` while nothing runs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineRun>,
    /// What the app needs to observe the running session. Holds secrets: never serialized
    /// (the status keeps the old wire shape, which had no session).
    #[serde(skip)]
    pub session: Option<SessionEndpoints>,
}

impl Default for TunStatus {
    /// Nothing running; the upstream is not suspected (old initial status).
    fn default() -> Self {
        Self {
            running: false,
            mode: None,
            proxy_addr: None,
            proxy_type: None,
            profile_name: None,
            protocol: None,
            pid: None,
            warning: None,
            proxy_reachable: true,
            started_at: None,
            restart_attempt: 0,
            capture: None,
            engine: None,
            session: None,
        }
    }
}

/// An app-owned authenticated loopback listener of a session (`Debug` hides the credentials;
/// deliberately not `Serialize`).
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub port: u16,
    pub user: String,
    pub pass: String,
}

impl fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProxyEndpoint(127.0.0.1:{}, ..)", self.port)
    }
}

/// Plain data about a running session: where to read traffic and connections, which adapter
/// to count, which log files belong to it. Secrets inside: never logged (`Debug` hides them)
/// and deliberately not `Serialize`.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionEndpoints {
    /// Clash API controller on `127.0.0.1`.
    pub clash_port: u16,
    /// Bearer secret of the controller (32 lowercase hex).
    pub clash_secret: String,
    /// `mixed-direct-in`: leaves the machine directly (key checks, pings, URL availability).
    pub direct: ProxyEndpoint,
    /// `live-check-in`: through the tunnel's upstream (direct VPN modes only).
    pub probe: Option<ProxyEndpoint>,
    /// LUID of our TUN adapter (interface counters are read by LUID, never by alias).
    pub tun_luid: Option<u64>,
    pub tun_alias: Option<String>,
    /// Unauthenticated loopback `mixed` inbound of a proxy capture (`127.0.0.1:port`): where the
    /// Soft-mode system proxy points.
    pub proxy_port: Option<u16>,
    /// Engine log files of this session (`sing-box.log`, `xray-a.log`, ...).
    pub logs: Vec<std::path::PathBuf>,
}

impl fmt::Debug for SessionEndpoints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionEndpoints")
            .field("clash_port", &self.clash_port)
            .field("direct", &self.direct)
            .field("probe", &self.probe)
            .field("tun_luid", &self.tun_luid)
            .field("tun_alias", &self.tun_alias)
            .field("proxy_port", &self.proxy_port)
            .field("logs", &self.logs)
            .finish_non_exhaustive()
    }
}

/// Status changes the runtime announces (old status strings, now typed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunStatusKind {
    Stopping,
    /// Preserved stop: protection kept, no tunnel (may last until a start or a full stop).
    Adapting,
    Stopped,
    Running,
    /// TUN down, kill switch still blocking.
    KillSwitchActive,
    Restarting {
        attempt: u8,
        max: u8,
    },
    /// The upstream stopped answering; the TUN stays up and holds the traffic.
    ProxyDown {
        reason: Msg,
    },
    Error {
        warning: Msg,
    },
    /// Crash budget exhausted, switched to a live sibling key.
    PostTrialFailover {
        name: String,
    },
    /// A foreign TUN adapter appeared (`name` is a display label, may include its address).
    CompetingTun {
        name: String,
    },
    CompetingTunCleared,
}

impl fmt::Display for TunStatusKind {
    /// The old wire string, for logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunStatusKind::Stopping => f.write_str("stopping"),
            TunStatusKind::Adapting => f.write_str("adapting"),
            TunStatusKind::Stopped => f.write_str("stopped"),
            TunStatusKind::Running => f.write_str("running"),
            TunStatusKind::KillSwitchActive => f.write_str("killswitch-active"),
            TunStatusKind::Restarting { attempt, max } => write!(f, "restarting:{attempt}/{max}"),
            TunStatusKind::ProxyDown { .. } => f.write_str("proxy-down"),
            TunStatusKind::Error { .. } => f.write_str("error"),
            TunStatusKind::PostTrialFailover { name } => write!(f, "post-trial-failover:{name}"),
            TunStatusKind::CompetingTun { name } => write!(f, "competing-tun:{name}"),
            TunStatusKind::CompetingTunCleared => f.write_str("competing-tun-cleared"),
        }
    }
}

/// A non-fatal finding of a start or restart the user should see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunWarning {
    /// The adapter list could not be read, so a competing TUN was not ruled out before the start.
    ForeignTunUnverified,
    /// The previous TUN adapter did not disappear in time; the run uses a fresh adapter name.
    ReleaseUnverified,
    /// Any other warning, already phrased as a message of its producer (e.g. the engine's
    /// routing warnings such as Smart-RU being unavailable, tunnel-core B-15).
    Other(Msg),
}

impl TunWarning {
    /// The message to show.
    pub fn msg(&self) -> Msg {
        match self {
            TunWarning::ForeignTunUnverified => Msg::new("tunnel.warning.foreignTunUnverified"),
            TunWarning::ReleaseUnverified => Msg::new("tunnel.warning.releaseUnverified"),
            TunWarning::Other(msg) => msg.clone(),
        }
    }

    /// The warning a receipt message stands for: receipts carry plain messages, events stay
    /// typed for the variants above.
    pub fn from_msg(msg: Msg) -> Self {
        [
            TunWarning::ForeignTunUnverified,
            TunWarning::ReleaseUnverified,
        ]
        .into_iter()
        .find(|w| w.msg() == msg)
        .unwrap_or(TunWarning::Other(msg))
    }
}

/// Events on the runtime's broadcast channel, in the order they happened.
///
/// Generations: `StartBegan` / `StartFinished` / `StopFinished` carry the native generation
/// (one strictly increasing counter per runtime start, lane or auto-restart; a stop reports
/// the generation of the run it ended). `SwitchBegan` / `SwitchFinished` carry the upstream
/// generation, an independent counter of in-place upstream switches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelEvent {
    StartBegan {
        generation: u64,
    },
    /// Emitted exactly once per `StartBegan`.
    StartFinished {
        generation: u64,
        ok: bool,
    },
    StopFinished {
        generation: u64,
        preserved: bool,
        receipt: StopReceipt,
    },
    SwitchBegan {
        generation: u64,
    },
    SwitchFinished {
        generation: u64,
        verified: bool,
    },
    /// A protected restart begins while the tunnel is still up (history closes the session).
    /// `reason` is an English log tag such as `server switch` or `config change: <what>`.
    ProtectedRestart {
        reason: String,
    },
    Status(TunStatusKind),
    Warning(TunWarning),
}

/// Key prefix of the runtime's TUN bring-up failures (`.adapter`, `.protection`, `.routes`):
/// the lifecycle records a start that failed with such a key as `tun-setup-failed` (L-14).
pub const TUN_SETUP_KEY_PREFIX: &str = "tunnel.runtime.tunSetup";

/// A refused or failed runtime operation: category, user-facing message (on `error`), log cause
/// (`error.source`) and the warnings collected before the failure.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct TunError {
    pub error: AppError,
    pub warnings: Vec<Msg>,
}

impl TunError {
    /// Failure with a user-facing message.
    pub fn new(kind: ErrorKind, msg: Msg) -> Self {
        AppError::msg(kind, msg).into()
    }

    /// The error category.
    pub fn kind(&self) -> ErrorKind {
        self.error.kind
    }

    /// The message to show (the canonical text of the category when none was given).
    pub fn user_msg(&self) -> Msg {
        self.error.user_msg()
    }

    /// Adds a warning collected along the way (e.g. a compensation step that was not confirmed).
    #[must_use]
    pub fn with_warning(mut self, warning: Msg) -> Self {
        self.warnings.push(warning);
        self
    }
}

impl From<AppError> for TunError {
    fn from(error: AppError) -> Self {
        Self {
            error,
            warnings: Vec::new(),
        }
    }
}

impl From<TunError> for AppError {
    /// Drops the warnings: callers that show them read `warnings` first.
    fn from(err: TunError) -> Self {
        err.error
    }
}

/// One of the two Xray upstream slots behind the sing-box selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Slot {
    A,
    B,
}

impl Slot {
    /// The other slot.
    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }
}

/// How an in-place upstream switch ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SwitchOutcome {
    Success,
    Cancelled,
    Failed,
}

/// Step of the protected switch in which a failure happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SwitchPhase {
    Stage,
    Probe,
    Select,
    Confirm,
    Commit,
    Restore,
    ConfirmPrevious,
    StopCandidate,
    StopPrevious,
    Ownership,
}

/// A failed switch step; `message` is a redacted English diagnostic for the log, never shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchFailure {
    pub phase: SwitchPhase,
    pub message: String,
}

/// What an in-place upstream switch did to both slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchReceipt {
    pub outcome: SwitchOutcome,
    /// The candidate was published as the active upstream (never rolled back afterwards).
    pub committed: bool,
    pub active_slot: Option<Slot>,
    /// The previous upstream was re-selected and re-confirmed after a failed attempt.
    pub previous_preserved: bool,
    pub candidate_stopped: bool,
    pub previous_stopped: bool,
    /// The caller stopped owning the tunnel while the switch ran.
    pub ownership_lost: bool,
    pub failures: Vec<SwitchFailure>,
    /// The engine run the committed candidate uses (`None` until committed).
    pub engine: Option<EngineRun>,
    /// Things the user should know about the new upstream (Xray's dropped settings).
    pub warnings: Vec<Msg>,
}

impl Default for SwitchReceipt {
    /// Nothing done yet: a failure until proven otherwise.
    fn default() -> Self {
        Self {
            outcome: SwitchOutcome::Failed,
            committed: false,
            active_slot: None,
            previous_preserved: false,
            candidate_stopped: false,
            previous_stopped: false,
            ownership_lost: false,
            failures: Vec::new(),
            engine: None,
            warnings: Vec::new(),
        }
    }
}

impl SwitchReceipt {
    /// The tunnel ends on a proven upstream: the candidate, or the preserved previous one.
    pub fn verified(&self) -> bool {
        !self.ownership_lost && (self.previous_preserved || self.outcome == SwitchOutcome::Success)
    }
}

/// Asked during a switch: does the caller still own the tunnel?
pub type OwnerCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// The tunnel runtime as the lifecycle lane sees it. One owner task serialises every operation;
/// the lane decides who may call, the runtime guarantees how it runs.
#[async_trait]
pub trait Runtime: Send + Sync {
    /// Starts a tunnel. Queued behind the operation in flight (the lane pre-empts by cancelling
    /// it); when its turn comes it is `Cancelled` if a stop was requested after it, and refused
    /// with `Conflict` while a tunnel is up or a previous run's exit is still unproven.
    /// Cancellation compensates every effect before returning.
    async fn start(
        &self,
        req: StartRequest,
        cancel: CancellationToken,
    ) -> Result<StartReceipt, TunError>;

    /// Stops the tunnel (cancels an in-flight start or switch and waits for its compensation).
    /// Concurrent stops share one result; a full stop arriving during a preserved one runs after it.
    async fn stop(&self, opts: StopOptions) -> StopReceipt;

    /// Restarts with protection kept across the gap; a failure or cancellation ends in a full stop.
    async fn restart_protected(
        &self,
        reason: String,
        next: StartRequest,
        opts: RestartOptions,
    ) -> Result<StartReceipt, TunError>;

    /// Re-applies the last start with the current settings; `Ok(None)` when nothing is running.
    async fn restart_with_last(&self, reason: String) -> Result<Option<StartReceipt>, TunError>;

    /// Protected restart of the last start in another adaptive mode (optionally another profile).
    async fn restart_adaptive(
        &self,
        mode: AdaptiveMode,
        reason: String,
        profile: Option<VpnProfile>,
    ) -> Result<StartReceipt, TunError>;

    /// Swaps the upstream behind the running TUN; `None` means "not possible in place, use
    /// [`Runtime::restart_protected`]".
    async fn switch_upstream(
        &self,
        next: StartRequest,
        cancel: CancellationToken,
        is_owner: OwnerCheck,
    ) -> Option<SwitchReceipt>;

    /// Status watch (current value via `borrow()`).
    fn status(&self) -> watch::Receiver<TunStatus>;

    /// Event subscription; on `Lagged` resync from [`Runtime::status`].
    fn subscribe(&self) -> broadcast::Receiver<TunnelEvent>;

    /// How the last sing-box run ended.
    fn last_exit(&self) -> Option<ExitInfo>;

    /// Upstream fault classified from recent engine output.
    fn recent_fault(&self) -> Option<OutboundFault>;
}

#[cfg(test)]
mod tests;
