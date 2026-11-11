//! Collaborators of the lifecycle, each behind a small trait the app implements over its crate.
//! Every method is cheap or async; none may call back into the lifecycle (it would deadlock the
//! actor that is waiting for it).
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use vpnte_base::AppResult;
use vpnte_base::types::{Notice, ProxyKind};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;

use crate::api::{Runtime, VpnProfile};
use crate::history::{History, SessionMode};

/// A server ready to run plus the facts history wants about it.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerChoice {
    pub server: VpnProfile,
    /// Country of the server (egress evidence of the session), when known.
    pub country: Option<String>,
}

/// The server list (single source of truth for Direct VPN).
pub trait ProfileSource: Send + Sync {
    /// The server `id`, or the active selection for `None`; `None` when there is no such server
    /// (missing, disabled, or nothing selected).
    fn resolve(&self, id: Option<&str>) -> Option<ServerChoice>;
}

/// Soft mode: the user-level tweaks (system proxy, opted-in variables and dev targets) that point
/// programs at the engine's loopback mixed inbound (NOADMIN.md §2).
#[async_trait]
pub trait SoftProxy: Send + Sync {
    /// Our Soft proxy is applied, as read back from the system; `None` when it cannot be read
    /// (the state machine then fails closed).
    fn applied(&self) -> Option<bool>;
    /// Applies the proxy `addr` (`host:port`) of `kind` (over whatever is applied).
    async fn apply(&self, addr: &str, kind: ProxyKind) -> AppResult<()>;
    /// Restores the user's previous settings; `Ok` also when nothing was applied.
    async fn rollback(&self) -> AppResult<()>;
    /// The system points at `addr` / `kind` (the read-back that proves Soft: our mixed port).
    async fn is_configured(&self, addr: &str, kind: ProxyKind) -> AppResult<bool>;
}

/// Public-IP monitoring and leak self-tests.
pub trait Monitor: Send + Sync {
    /// No leak alarms while a tunnel comes up.
    fn suppress_leak_tests(&self, span: Duration);
    /// A tunnel is up (`generation` of the engine run, Hard or Soft): start IP monitoring, the
    /// post-connect egress probe and the periodic leak tests.
    fn start(&self, generation: Option<u64>);
    /// The tunnel is down: stop them and forget the VPN IP.
    fn stop(&self);
    /// Last public IP seen (egress evidence of a history row).
    fn egress_ip(&self) -> Option<String>;
}

/// Traffic forensics of a session (counters, domains, optional capture).
#[async_trait]
pub trait Forensics: Send + Sync {
    /// A session began (`target`: proxy address or server name).
    fn start_session(&self, mode: SessionMode, target: &str);
    /// Ends the session; `false` when a capture could not be confirmed stopped.
    async fn stop_session(&self, reason: &str) -> bool;
    /// `(down, up)` bytes of the current session. Read before anything stops.
    fn session_bytes(&self) -> (u64, u64);
}

/// External loopback proxy slots: they live only as long as the tunnel runtime.
#[async_trait]
pub trait ExternalProxies: Send + Sync {
    /// Stops every slot (`reason` is log text).
    async fn stop_all(&self, reason: &str);
}

/// User-toggleable notification category (settings `notifications.*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoticeKind {
    VpnConnect,
    VpnDisconnect,
    ConnectionError,
    ProfileRotation,
}

/// Toasts and the in-app notification list.
pub trait Notifier: Send + Sync {
    /// Shows `notice` unless the user switched its category `kind` off.
    fn notify(&self, notice: Notice, kind: NoticeKind);
}

/// Everything the lifecycle actor talks to.
#[derive(Clone)]
pub struct LifecycleDeps {
    pub runtime: Arc<dyn Runtime>,
    pub profiles: Arc<dyn ProfileSource>,
    pub soft: Arc<dyn SoftProxy>,
    pub monitor: Arc<dyn Monitor>,
    pub forensics: Arc<dyn Forensics>,
    pub proxies: Arc<dyn ExternalProxies>,
    pub notifier: Arc<dyn Notifier>,
    pub history: History,
    pub settings: Arc<Store<Settings>>,
}
