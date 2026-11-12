//! What the runtime publishes about a session: the status watch, its endpoints (secrets
//! hidden from `Debug`, never serialized), the announced status changes and warnings.
use std::fmt;

use serde::Serialize;
use vpnte_base::Msg;
use vpnte_base::types::{ProxyKind, UnixMs};

use super::{CaptureKind, EngineRun, ModeKind};

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
    /// `false` while the watchdog sees the upstream down (the capture keeps holding the traffic).
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
    /// Engine down, the kill switch still blocking (WFP under the TUN, the system proxy on the
    /// dead port under the proxy capture).
    KillSwitchActive,
    Restarting {
        attempt: u8,
        max: u8,
    },
    /// The upstream stopped answering; the capture stays up and holds the traffic.
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
