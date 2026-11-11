//! The connection surface automation talks to. The app implements [`Coordinator`] over the tunnel
//! lifecycle; the scheduler, rotation, AutoPilot and adaptive bypass only ask through it, so every
//! tunnel mutation goes through one place that applies the owner priorities (`Owner` order).
use std::future::Future;

use tokio::sync::broadcast;
use vpnte_base::types::{AdaptiveMode, Creds, Notice, OutboundFault, Owner, ProxyKind};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::net::HostPort;

/// Identity of one engine run; a new value on every engine (re)start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuntimeId(pub u64);

/// A local proxy the tunnel routes through (Hard TUN or Soft mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub addr: HostPort,
    pub kind: ProxyKind,
    pub creds: Option<Creds>,
}

/// What automation asks the tunnel to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectRequest {
    /// Direct VPN through a stored server profile.
    Direct { profile_id: String },
    /// Hard TUN through a local proxy. `None`: the proxy a manual connect would use
    /// (settings override, else detection); none found → [`OpError::NoLocalProxy`].
    LocalProxyHard { endpoint: Option<ProxyEndpoint> },
    /// Soft mode (user-level proxy variables plus the user's enabled dev-tool targets). `None` as above.
    Soft { endpoint: Option<ProxyEndpoint> },
}

impl ConnectRequest {
    /// The kind of session this request produces.
    pub fn kind(&self) -> SessionKind {
        match self {
            ConnectRequest::Direct { .. } => SessionKind::Direct,
            ConnectRequest::LocalProxyHard { .. } => SessionKind::LocalProxyHard,
            ConnectRequest::Soft { .. } => SessionKind::Soft,
        }
    }
}

/// Route architecture of a running session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionKind {
    Direct,
    LocalProxyHard,
    Soft,
}

/// The running session as the coordinator sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub kind: SessionKind,
    /// Who holds the session. Restarts that continue it (crash auto-restart, settings restart,
    /// adaptive restart, profile switch) keep the owner; a connect by a higher owner takes it over.
    pub owner: Owner,
    /// Server profile of a `Direct` session.
    pub profile_id: Option<String>,
    pub runtime_id: RuntimeId,
    /// Adaptive compatibility mode the running engine was started with.
    pub mode: AdaptiveMode,
}

/// Successful [`Coordinator::connect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// A session was started or switched to the request.
    Connected,
    /// An equal session already ran; nothing was restarted (a higher caller now holds it).
    AlreadyConnected,
}

/// Why a coordinator operation did not happen.
#[derive(Debug, thiserror::Error)]
pub enum OpError {
    /// Refused: a session of a higher owner, or an operation of an equal / higher owner, is active.
    #[error("refused by a higher-priority session or operation")]
    Conflict,
    /// Cancelled by a higher-priority operation, the user, or shutdown.
    #[error("cancelled")]
    Cancelled,
    #[error("timed out")]
    Timeout,
    /// The requested server profile is missing, disabled or archived.
    #[error("profile unavailable")]
    ProfileUnavailable,
    /// No local proxy could be found for a Hard / Soft request.
    #[error("no local proxy found")]
    NoLocalProxy,
    /// Anything else, with its own user-facing message.
    #[error(transparent)]
    Failed(AppError),
}

impl OpError {
    /// The user-facing reason.
    pub fn reason(&self) -> Msg {
        match self {
            OpError::Conflict => Msg::new("automation.coordinator.conflict"),
            OpError::Cancelled => Msg::new(ErrorKind::Cancelled.i18n_key()),
            OpError::Timeout => Msg::new(ErrorKind::Timeout.i18n_key()),
            OpError::ProfileUnavailable => Msg::new("automation.coordinator.profileUnavailable"),
            OpError::NoLocalProxy => Msg::new("automation.coordinator.noLocalProxy"),
            OpError::Failed(e) => e.user_msg(),
        }
    }
}

impl From<OpError> for AppError {
    fn from(err: OpError) -> Self {
        let kind = match err {
            OpError::Failed(e) => return e,
            OpError::Conflict | OpError::ProfileUnavailable | OpError::NoLocalProxy => {
                ErrorKind::Conflict
            }
            OpError::Cancelled => ErrorKind::Cancelled,
            OpError::Timeout => ErrorKind::Timeout,
        };
        AppError::msg(kind, err.reason())
    }
}

/// Failure of [`Coordinator::switch_profile`].
#[derive(Debug, thiserror::Error)]
pub enum SwitchError {
    /// Refused or failed before the running tunnel was touched: the previous session runs on.
    #[error("switch not started: {0}")]
    NotStarted(OpError),
    /// The restart onto the new profile failed. `restored_previous`: the previous profile runs again
    /// under protection; `false`: the session was stopped with protection rolled back.
    #[error("switch failed (previous restored: {restored_previous}): {reason}")]
    Failed {
        reason: OpError,
        restored_previous: bool,
    },
}

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopCause {
    /// A deliberate stop asked for by this owner (`Owner::Manual` = the user).
    Requested(Owner),
    /// The engine failed and the session could not be kept (crash, restarts exhausted).
    Fault,
    /// The app is quitting.
    Shutdown,
}

/// What happened to the session, pushed by [`Coordinator::events`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// An engine (re)started: connect, switch, adaptive restart, crash auto-restart or settings
    /// restart. A switch emits only this (no `Stopped` in between); `owner` is the session's owner.
    Started {
        owner: Owner,
        runtime_id: RuntimeId,
        kind: SessionKind,
        profile_id: Option<String>,
        mode: AdaptiveMode,
    },
    /// The session ended; no session runs afterwards.
    Stopped {
        owner: Owner,
        runtime_id: RuntimeId,
        cause: StopCause,
    },
    /// The running engine reported an upstream fault (classified from its log).
    Fault {
        runtime_id: RuntimeId,
        fault: OutboundFault,
    },
    /// The physical network changed (other Wi-Fi, cable, gateway).
    NetworkChanged,
}

/// User-toggleable notification category of a [`Notice`] (settings `notifications.*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoticeCategory {
    ScheduleTriggered,
    ProfileRotation,
    ConnectionError,
}

/// The tunnel lifecycle as automation uses it; implemented by the app.
///
/// Every operation is admitted by owner priority (`Owner` order): a strictly higher owner pre-empts
/// a running lower one; an equal or lower one is refused with [`OpError::Conflict`]. Dropping a
/// returned future cancels the request; the implementation finishes or rolls back native work
/// itself. Futures are `Send` because automation tasks run under `tokio::spawn`.
pub trait Coordinator: Send + Sync + 'static {
    /// The running session, if any.
    fn session(&self) -> Option<SessionInfo>;

    /// A lifecycle operation (connect, stop, switch, restart) is in flight.
    fn busy(&self) -> bool;

    /// Starts `req`. An equal session → `AlreadyConnected` (a higher caller takes it over); a
    /// different one is switched only if `owner >= session.owner`, else `Conflict`.
    fn connect(
        &self,
        owner: Owner,
        req: ConnectRequest,
    ) -> impl Future<Output = Result<ConnectOutcome, OpError>> + Send;

    /// Stops the session; `Conflict` if `owner < session.owner`. No session → `Ok` without effects.
    fn disconnect(&self, owner: Owner) -> impl Future<Output = Result<(), OpError>> + Send;

    /// Moves a `Direct` session to another profile: protected restart (kill switch kept), egress
    /// and tunnel proof, the selection committed only on success; on failure the previous profile
    /// is restarted; if that fails too the session stops with protection rolled back. The session
    /// keeps its owner.
    fn switch_profile(
        &self,
        owner: Owner,
        profile_id: &str,
    ) -> impl Future<Output = Result<(), SwitchError>> + Send;

    /// Protected restart in another adaptive mode and/or on a sibling profile; returns the new
    /// runtime once its fresh egress was proven.
    fn adaptive_restart(
        &self,
        owner: Owner,
        mode: AdaptiveMode,
        sibling: Option<&str>,
    ) -> impl Future<Output = Result<RuntimeId, OpError>> + Send;

    /// Lifecycle events from now on.
    fn events(&self) -> broadcast::Receiver<LifecycleEvent>;

    /// Delivers a notice: always to the in-app list, as an OS toast when `category` is enabled.
    fn notify(&self, category: NoticeCategory, notice: Notice);
}

/// Test doubles shared by the scheduler, rotation and AutoPilot tests.
#[cfg(test)]
pub(crate) mod testing;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_errors_carry_user_messages() {
        assert_eq!(
            OpError::NoLocalProxy.reason().key,
            "automation.coordinator.noLocalProxy"
        );
        assert_eq!(OpError::Timeout.reason().key, "errors.timeout");
        let app: AppError = OpError::ProfileUnavailable.into();
        assert_eq!(app.kind, ErrorKind::Conflict);
        assert_eq!(
            app.user_msg().key,
            "automation.coordinator.profileUnavailable"
        );
        let inner = AppError::validation(Msg::new("x.y"));
        let app: AppError = OpError::Failed(inner).into();
        assert_eq!(
            (app.kind, app.user_msg().key.as_ref()),
            (ErrorKind::Validation, "x.y")
        );
    }

    #[test]
    fn requests_know_their_session_kind() {
        let direct = ConnectRequest::Direct {
            profile_id: "p".into(),
        };
        assert_eq!(direct.kind(), SessionKind::Direct);
        assert_eq!(
            ConnectRequest::Soft { endpoint: None }.kind(),
            SessionKind::Soft
        );
    }
}
