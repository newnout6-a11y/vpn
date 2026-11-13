//! The pipe protocol between the app and the service (the app uses this module too).
//!
//! Framing: a 4-byte little-endian length, then that many bytes of JSON ([`frame`]). The client
//! sends [`ClientFrame`]s (a request with an id), the service answers each with a
//! [`ServerFrame::Reply`] or [`ServerFrame::Failed`] carrying the same id and pushes
//! [`ServerFrame::Event`]s to the controlling client at any time.
//!
//! Versions: the first request is [`Request::Hello`]; both sides then speak
//! `min(client, service)`, accepted while the two differ by at most one ([`negotiate`]).
//! Evolution rule: a version may only add requests, replies, events and optional fields
//! (`#[serde(default)]`); the newer side never sends what the negotiated version lacks. Structs
//! refuse unknown fields, so a field the service does not know is an error, never ignored.
//!
//! The client is untrusted: requests carry typed inputs only — no file path, command line or
//! engine JSON (the service builds every engine config itself, see `crate::validate`).
use serde::{Deserialize, Serialize};
use vpnte_base::Msg;
use vpnte_base::error::ErrorKind;
use vpnte_base::types::{AdaptiveMode, ClientDevice, EnginePref, ProxyKind};
use vpnte_engine::routing::dns::DnsAddr;
use vpnte_engine::routing::domain::DomainRule;
use vpnte_profiles::model::Profile;
use vpnte_tunnel::api::Origin;
use vpnte_winnet::wfp::ProtectionSettings;

mod back;
pub mod frame;
mod wire;

#[cfg(test)]
mod tests;

pub use wire::{
    EngineRunWire, ExitWire, KillSwitchStateWire, ProtectionWire, SessionWire, StartReceiptWire,
    StatusKindWire, StatusWire, StopReceiptWire, SwitchFailureWire, SwitchReceiptWire,
    TunnelEventWire,
};

/// The protocol version this build speaks. 2 (p-svc-recheck): `StatusWire::self_test`, the
/// service's leak self-test (`StatusWire::speak` strips it for a version-1 client).
pub const PROTOCOL: u32 = 2;

/// The version both sides speak, or `None` when they are more than one version apart.
pub fn negotiate(client: u32, service: u32) -> Option<u32> {
    (client.abs_diff(service) <= 1 && client.min(service) >= 1).then(|| client.min(service))
}

/// One request of the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientFrame {
    /// Chosen by the client; echoed in the answer.
    pub id: u64,
    pub request: Request,
}

/// What the client asks for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "camelCase")]
pub enum Request {
    /// First request on a connection: versions; makes the caller the controlling client.
    Hello(Hello),
    /// Starts a TUN session (`Conflict` while one runs).
    Start(Box<TunnelStart>),
    /// Ends the session.
    Stop(StopTunnel),
    /// Protected restart into `next` (old session kept until the new one runs).
    Restart(Box<TunnelStart>),
    /// Restart of the last start with the current inputs; `None` reply = nothing to restart.
    RestartWithLast { reason: String },
    /// Restart in another adaptive mode, optionally on another server.
    RestartAdaptive(Box<AdaptiveRestart>),
    /// Upstream switch in place; `None` reply = not possible in place (use `Restart`).
    Switch(Box<TunnelStart>),
    /// Replaces the routing inputs a crash restart or `RestartWithLast` reads.
    Inputs(Box<RoutingInputs>),
    /// Current tunnel and protection state.
    Status,
    /// Applies the kill-switch settings (level, toggles, app / IP exceptions).
    KillSwitch(Box<ProtectionSettings>),
    /// Removes protection leftovers (refused while a session runs).
    Cleanup,
    /// The caller's Windows user no longer uses the service (per-user uninstall); the last one
    /// leaving removes the service.
    ForgetMe,
}

/// Versions of the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Hello {
    /// Highest protocol version the client speaks.
    pub protocol: u32,
    /// The app's version, for the service log.
    pub app_version: String,
}

/// Where the session's traffic goes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum Upstream {
    /// A proxy another program runs on this machine (loopback address only).
    LocalProxy {
        addr: std::net::SocketAddr,
        kind: ProxyKind,
    },
    /// A server of the user's list, as the typed profile model.
    Server(Box<ServerUpstream>),
}

/// A server profile and how to run it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerUpstream {
    /// The app's id of the server (history, failover); opaque to the service.
    pub id: String,
    pub profile: Profile,
    #[serde(default)]
    pub device: Option<ClientDevice>,
    /// The server's own engine choice.
    #[serde(default)]
    pub engine: EnginePref,
}

/// Everything one start needs, typed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelStart {
    pub upstream: Upstream,
    pub routing: RoutingInputs,
    /// Kill-switch settings applied before the start (the level guards the session).
    pub protection: ProtectionSettings,
    #[serde(default)]
    pub adaptive: AdaptiveMode,
    /// The user's engine preference (`Auto`: the server's own choice).
    #[serde(default)]
    pub engine: EnginePref,
    pub origin: Origin,
}

/// The routing inputs of the user's stores (no file paths: Smart RU uses the service's own rule
/// sets; split-tunnel entries are already-resolved `process_path_regex` values).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct RoutingInputs {
    pub smart_ru: bool,
    pub smart_ru_maps_direct: bool,
    pub domain_rules: Vec<DomainRule>,
    pub split_direct: Vec<String>,
    pub split_vpn: Vec<String>,
    pub dns: Option<DnsAddr>,
    pub public_wifi: bool,
    pub stealth: bool,
    pub auto_restart_on_crash: bool,
}

/// How a stop ends the session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct StopTunnel {
    /// Keep the kill switch blocking after the engines stopped.
    pub preserve_protection: bool,
    /// Keep the start for a later `RestartWithLast`.
    pub preserve_last: bool,
}

/// A restart in another adaptive mode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdaptiveRestart {
    pub mode: AdaptiveMode,
    pub reason: String,
    /// Another server; `None` = the running one.
    #[serde(default)]
    pub server: Option<ServerUpstream>,
}

/// What the service sends.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ServerFrame {
    /// The answer to request `id`.
    Reply { id: u64, reply: Box<Reply> },
    /// Request `id` failed.
    Failed { id: u64, error: WireError },
    /// A pushed event (controlling client only).
    Event { event: Box<Event> },
}

/// Successful answers, one shape per request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "camelCase")]
pub enum Reply {
    /// To `Hello`: the negotiated version and the service's own version.
    Welcome {
        protocol: u32,
        service_version: String,
    },
    /// To `Start`, `Restart`, `RestartWithLast` (`None`: idle), `RestartAdaptive`.
    Started(Option<StartReceiptWire>),
    /// To `Stop`.
    Stopped(StopReceiptWire),
    /// To `Switch` (`None`: not possible in place).
    Switched(Option<SwitchReceiptWire>),
    /// To `Status`.
    Status(Box<StatusReply>),
    /// To `Inputs`, `KillSwitch`, `ForgetMe` (`removing`: this was the last user).
    Done { removing: bool },
    /// To `Cleanup`: protection objects removed.
    Cleaned {
        filters: usize,
        sublayer: bool,
        provider: bool,
    },
}

/// The tunnel and the kill switch right now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusReply {
    pub tunnel: StatusWire,
    #[serde(default)]
    pub last_exit: Option<ExitWire>,
    #[serde(default)]
    pub recent_fault: Option<vpnte_base::types::OutboundFault>,
    pub protection: ProtectionWire,
    /// The session the service kept running for this user after his app's connection dropped
    /// without a stop (owner question 23); `None` for anyone else and while nothing runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept: Option<KeptSession>,
}

/// A running session as its own user's app takes it over at its next start.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeptSession {
    /// The run as a start receipt: the current native generation, pid, start time, engine.
    pub receipt: StartReceiptWire,
    /// The server list id of the upstream (`None`: a local proxy).
    #[serde(default)]
    pub server_id: Option<String>,
    /// The local proxy upstream (`None`: a server).
    #[serde(default)]
    pub local_proxy: Option<std::net::SocketAddr>,
}

/// Pushed to the controlling client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "camelCase")]
pub enum Event {
    /// The runtime's status changed (sent before the matching `Tunnel(Status(..))`).
    Status(Box<StatusWire>),
    /// A runtime event, in order.
    Tunnel(TunnelEventWire),
    /// A kill-switch notice (traffic blocked, exception skipped, protection unverified).
    Notice(vpnte_base::types::Notice),
}

/// Why a request failed: the user-facing message plus a machine code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireError {
    pub code: ErrorCode,
    pub kind: ErrorKind,
    pub msg: Msg,
    #[serde(default)]
    pub warnings: Vec<Msg>,
}

/// Failures the client handles differently from a plain error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    /// Another client controls the service.
    Busy,
    /// The versions are more than one apart.
    Version,
    /// The first request was not `Hello`.
    HelloFirst,
    /// A request this version does not know, or one that does not decode.
    BadRequest,
    /// A typed input the service refuses (path, raw JSON, size, value).
    Refused,
    /// The operation itself failed (`kind` / `msg` say why).
    Failed,
}

impl WireError {
    /// An error with `code`, `kind` and the message key `key`.
    pub fn new(code: ErrorCode, kind: ErrorKind, key: &'static str) -> Self {
        Self {
            code,
            kind,
            msg: Msg::new(key),
            warnings: Vec::new(),
        }
    }

    /// The operation failed with `err`.
    pub fn failed(err: &vpnte_base::AppError) -> Self {
        Self {
            code: ErrorCode::Failed,
            kind: err.kind,
            msg: err.user_msg(),
            warnings: Vec::new(),
        }
    }
}
