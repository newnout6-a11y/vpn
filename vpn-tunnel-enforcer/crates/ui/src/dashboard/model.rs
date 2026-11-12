//! Pure rules of the start page that are not already in `vpnte_view`: the power-button click
//! rule, which banners show, the node line of the identity column and its engine caption. No
//! Dioxus, no clock reads.
use vpnte_base::Msg;
use vpnte_base::types::UnixMs;
use vpnte_view::identity::{ping_of, visible_leak};
use vpnte_view::labels::{
    KillSwitchBanner, foreign_vpn_friendly_name, kill_switch_banner, node_meta,
};
use vpnte_view::swiss::ConnView;

use super::{DashboardView, EngineLine, PauseLine};
use crate::panels::{LocalPings, ServersView};

/// What a press of the power button (click or Ctrl+Enter) does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerAction {
    Connect,
    Disconnect,
    /// A transition, a switch or one of our own commands is in flight.
    Ignore,
}

/// The click rule: with our protection installed a press disconnects at once (owner, 12.11.2026:
/// no confirmation for an action the next press undoes); otherwise the press connects.
pub fn power_click(conn: &ConnView, command_running: bool) -> PowerAction {
    if conn.circle_busy() || command_running {
        PowerAction::Ignore
    } else if conn.cleanup_required {
        PowerAction::Disconnect
    } else {
        PowerAction::Connect
    }
}

/// How long «скопировано» replaces «копировать» after copying the exit IP.
pub const COPIED_MS: u64 = 1_300;

/// The notices above the facts strip, in page order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Banners {
    /// «Интернет на паузе» with «Подключить» / «Продолжить без VPN» (ks-a): it replaces the
    /// restart and kill-switch banners while it lasts.
    pub pause: Option<PauseLine>,
    /// Automatic restart after an engine crash: «1/3».
    pub restart: Option<String>,
    /// Adapter description of a second TUN while ours runs.
    pub competing_tun: Option<String>,
    pub kill_switch: Option<KillSwitchBanner>,
    /// «Виден ваш реальный IP».
    pub leak: bool,
    /// Another VPN while ours is down: its product name (`Happ`), shown in the notice strip.
    pub foreign_vpn: Option<String>,
    /// Another VPN carries all traffic while ours runs: no pause on a drop (one calm line).
    pub no_pause_vpn: Option<String>,
}

/// Which notices the snapshot calls for.
pub fn banners(view: &DashboardView) -> Banners {
    let conn = &view.conn;
    let foreign = view.foreign_vpn.as_deref().filter(|_| !conn.tun_running());
    let paused = view.pause.is_some();
    Banners {
        pause: view.pause.clone(),
        restart: conn
            .restarting
            .filter(|_| !paused)
            .map(|(attempt, max)| format!("{attempt}/{max}")),
        competing_tun: conn.competing_tun_banner().map(str::to_owned),
        kill_switch: kill_switch_banner(conn, &view.firewall).filter(|_| !paused),
        leak: visible_leak(conn, &view.exit),
        foreign_vpn: foreign_vpn_friendly_name(foreign),
        no_pause_vpn: view.no_pause_vpn.clone().filter(|_| !paused),
    }
}

/// «следующая попытка через 0:40»: the wait left until `at`, as m:ss (never negative).
pub fn countdown(at: UnixMs, now: UnixMs) -> String {
    let secs = ((at - now).max(0) + 999) / 1_000;
    format!("{}:{:02}", secs / 60, secs % 60)
}

/// The «Узел» block: the active server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLine {
    pub name: String,
    /// ISO 3166-1 alpha-2 for the flag coin.
    pub country: Option<String>,
    /// «VLESS · 38 мс».
    pub meta: Msg,
}

/// The active server's line; the ping is the one the servers panel measured in this route
/// generation, else the stored ping, else the health checker's latency (shared with the panel).
pub fn node_line(servers: &ServersView, local: &LocalPings) -> Option<NodeLine> {
    let id = servers.active_id.as_deref()?;
    let row = servers.rows.iter().find(|row| row.id == id)?;
    let ping = ping_of(local.get(&row.id), row.ping, row.health_latency);
    Some(NodeLine {
        name: row.name.clone(),
        country: row.country.clone(),
        meta: node_meta(row.protocol.as_deref(), ping, row.health),
    })
}

/// The engine caption under the node: the product name, then the reason when one was given
/// («Xray · REALITY»; `reason` is the already translated text).
pub fn engine_caption(line: &EngineLine, reason: Option<String>) -> String {
    let name = crate::servers::engine_name(line.engine);
    match reason.filter(|r| !r.is_empty()) {
        Some(reason) => format!("{name} · {reason}"),
        None => name.to_owned(),
    }
}
