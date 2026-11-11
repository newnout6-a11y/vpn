//! View models of the panel row: what the backend pushes for the servers panel and the external
//! proxies column. Display data only (no credentials, no full configs); traffic uses
//! [`vpnte_view::traffic::TrafficSample`] as it is.
use vpnte_base::Msg;
use vpnte_base::types::UnixMs;
use vpnte_view::identity::ServerHealth;

/// The servers panel's state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServersView {
    /// Servers in list order; servers removed from their subscription are already left out.
    pub rows: Vec<ServerRowView>,
    /// The selected server (the ink row).
    pub active_id: Option<String>,
    /// Our tunnel runs. Endpoint round trips depend on the route, so every change of this flag
    /// clears the pings measured from the panel and discards the ones still in flight.
    pub tun_running: bool,
    /// A connection operation or a server switch is in flight: clicks on a server are ignored.
    pub locked: bool,
}

/// One server of the list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerRowView {
    pub id: String,
    pub name: String,
    /// ISO 3166-1 alpha-2 code, upper case; `None` renders no flag.
    pub country: Option<String>,
    /// Protocol as stored (`vless`, `hysteria2`, …), for the slab's node line.
    pub protocol: Option<String>,
    /// Last stored ping, ms.
    pub ping: Option<u32>,
    /// Latency of the last health check, ms.
    pub health_latency: Option<u32>,
    pub health: ServerHealth,
    /// Time of the last health check.
    pub checked_at: Option<UnixMs>,
}

/// The external proxies column's state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxiesView {
    /// Configured slots by slot number: running, starting, failed and auto-disabled ones (a
    /// failed slot stays listed with its error so the user can stop or restart it).
    pub rows: Vec<ProxyRowView>,
    /// Servers the picker offers, in list order.
    pub choices: Vec<ProxyChoice>,
}

/// Route health of an external proxy slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProxyHealth {
    #[default]
    Stopped,
    Starting,
    Healthy,
    Degraded,
    Rotating,
    Quarantined,
    Failed,
}

impl ProxyHealth {
    /// Key of the word used as the health dot's tooltip.
    pub fn i18n_key(self) -> &'static str {
        match self {
            ProxyHealth::Stopped => "ui.panels.proxy.health.stopped",
            ProxyHealth::Starting => "ui.panels.proxy.health.starting",
            ProxyHealth::Healthy => "ui.panels.proxy.health.healthy",
            ProxyHealth::Degraded => "ui.panels.proxy.health.degraded",
            ProxyHealth::Rotating => "ui.panels.proxy.health.rotating",
            ProxyHealth::Quarantined => "ui.panels.proxy.health.quarantined",
            ProxyHealth::Failed => "ui.panels.proxy.health.failed",
        }
    }
}

/// One external proxy slot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyRowView {
    /// Slot number, from 1.
    pub slot: u16,
    /// The slot's engine process runs.
    pub process_running: bool,
    /// Listener up and the first probe passed.
    pub ready: bool,
    pub health: ProxyHealth,
    pub profile_name: Option<String>,
    /// ISO 3166-1 alpha-2 code of the server.
    pub country: Option<String>,
    /// Loopback port of the listener.
    pub port: Option<u16>,
    /// `socks5://127.0.0.1:18001`; never with credentials.
    pub proxy_url: Option<String>,
    /// Round trip of the last probe, ms.
    pub latency_ms: Option<u32>,
    /// Why the last start or probe failed.
    pub last_error: Option<Msg>,
}

impl ProxyRowView {
    /// A start or a profile rotation is in progress (blinking hollow dot, «запуск…»).
    pub fn starting(&self) -> bool {
        matches!(self.health, ProxyHealth::Starting | ProxyHealth::Rotating)
    }
}

/// A server the picker offers for a new external proxy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyChoice {
    pub id: String,
    pub name: String,
    /// ISO 3166-1 alpha-2 code.
    pub country: Option<String>,
    /// Protocol as stored; shown upper-cased.
    pub protocol: Option<String>,
    pub health: ServerHealth,
    /// Already running as an external proxy.
    pub in_proxy: bool,
    /// The server the VPN connection uses.
    pub vpn_server: bool,
}

impl ProxyChoice {
    /// Neither a running proxy nor the VPN's server: can be started.
    pub fn usable(&self) -> bool {
        !self.in_proxy && !self.vpn_server
    }
}

/// Result of [`super::PanelsApi::select_server`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selected {
    /// The server is now the active one.
    Done,
    /// A higher-priority operation or the user cancelled the switch.
    Cancelled,
}
