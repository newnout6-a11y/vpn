//! Shared types of the tunnel runtime API and the [`Runtime`] trait: the runtime actor's handle
//! implements it, the lifecycle lane consumes it.
//!
//! Engine-side types (exit info, slots) are mirrored here as small plain structs so that crates
//! without the engine dependency (the lifecycle) can use them. User-facing text is always a
//! [`Msg`]; English strings in this module are for logs only.
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

mod status;
mod switch;

pub use status::{ProxyEndpoint, SessionEndpoints, TunStatus, TunStatusKind, TunWarning};
pub use switch::{OwnerCheck, Slot, SwitchFailure, SwitchOutcome, SwitchPhase, SwitchReceipt};

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
    /// The engine ended by itself after our CTRL_BREAK, without the kill (sing-box then closed
    /// its TUN: Wintun removes the adapter only then).
    pub graceful: bool,
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
    /// Right after `Status(Restarting)`: the crash restart waits `delay` first (the backoff, or
    /// what is left of a frozen server's quiet window). A Soft session with the kill switch off
    /// must not leave the system proxy on a dead port for long (NOADMIN §2).
    RestartScheduled {
        delay: Duration,
    },
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
