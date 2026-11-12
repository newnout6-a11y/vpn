//! Pure rules of the start page that are not already in `vpnte_view`: the power-button click
//! rule, the disconnect confirmation's timer generations (D-01), which banners show, the node
//! line of the identity column and its engine caption. No Dioxus, no clock reads.
use vpnte_base::Msg;
use vpnte_view::identity::{ping_of, visible_leak};
use vpnte_view::labels::{
    KillSwitchBanner, foreign_vpn_friendly_name, kill_switch_banner, node_meta,
};
use vpnte_view::swiss::ConnView;

use super::{DashboardView, EngineLine};
use crate::panels::{LocalPings, ServersView};

/// What a press of the power button (click or Ctrl+Enter) does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerAction {
    /// Something of ours is installed: ask «Отключить VPN…?» first.
    AskConfirm,
    Connect,
    Disconnect,
    /// A transition, a switch or one of our own commands is in flight.
    Ignore,
}

/// The click rule of the old dashboard (`Dashboard.tsx:864-873`): with our protection installed
/// the first press opens the confirmation and a second press while it is open disconnects (the
/// confirmation's «Да» does the same); otherwise the press connects.
pub fn power_click(conn: &ConnView, confirm_open: bool, command_running: bool) -> PowerAction {
    if conn.circle_busy() || command_running {
        PowerAction::Ignore
    } else if !conn.cleanup_required {
        PowerAction::Connect
    } else if confirm_open {
        PowerAction::Disconnect
    } else {
        PowerAction::AskConfirm
    }
}

/// How long the disconnect confirmation stays open without an answer.
pub const CONFIRM_TTL_MS: u64 = 3_000;

/// How long «скопировано» replaces «копировать» after copying the exit IP.
pub const COPIED_MS: u64 = 1_300;

/// What keeps the confirmation open past its timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hold {
    /// The pointer is over the row.
    Pointer,
    /// The keyboard focus is inside the row.
    Focus,
}

/// The disconnect confirmation (D-01): every opening gets its own generation, so the timer of an
/// earlier opening never closes a later one; while the pointer or the focus is inside the row the
/// timer is held and re-armed when both have left.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Confirm {
    open: bool,
    pointer: bool,
    focus: bool,
    generation: u64,
}

impl Confirm {
    /// The confirmation is shown.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Opens it; returns the generation to arm the timer with.
    pub fn open(&mut self) -> u64 {
        *self = Confirm {
            open: true,
            generation: self.generation + 1,
            ..Confirm::default()
        };
        self.generation
    }

    /// Closes it (answered, or a connection command started); pending timers become stale.
    pub fn close(&mut self) {
        *self = Confirm {
            generation: self.generation + 1,
            ..Confirm::default()
        };
    }

    /// The timer armed with `generation` fired: closes the confirmation unless the timer is stale
    /// or the row is held. Returns whether it closed.
    pub fn expire(&mut self, generation: u64) -> bool {
        if !self.open || self.pointer || self.focus || generation != self.generation {
            return false;
        }
        self.close();
        true
    }

    /// The pointer / focus entered (`true`) or left (`false`) the row. When the last hold is
    /// released the timer starts again: returns the generation to arm it with.
    pub fn hold(&mut self, by: Hold, on: bool) -> Option<u64> {
        if !self.open {
            return None;
        }
        let was_held = self.pointer || self.focus;
        match by {
            Hold::Pointer => self.pointer = on,
            Hold::Focus => self.focus = on,
        }
        if was_held && !(self.pointer || self.focus) {
            self.generation += 1;
            Some(self.generation)
        } else {
            None
        }
    }
}

/// The notices above the facts strip, in page order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Banners {
    /// Automatic restart after an engine crash: «1/3».
    pub restart: Option<String>,
    /// Adapter description of a second TUN while ours runs.
    pub competing_tun: Option<String>,
    pub kill_switch: Option<KillSwitchBanner>,
    /// «Виден ваш реальный IP».
    pub leak: bool,
    /// Another VPN while ours is down: its product name (`Happ`), shown in the notice strip.
    pub foreign_vpn: Option<String>,
}

/// Which notices the snapshot calls for.
pub fn banners(view: &DashboardView) -> Banners {
    let conn = &view.conn;
    let foreign = view.foreign_vpn.as_deref().filter(|_| !conn.tun_running());
    Banners {
        restart: conn
            .restarting
            .map(|(attempt, max)| format!("{attempt}/{max}")),
        competing_tun: conn.competing_tun_banner().map(str::to_owned),
        kill_switch: kill_switch_banner(conn, &view.firewall),
        leak: visible_leak(conn, &view.exit),
        foreign_vpn: foreign_vpn_friendly_name(foreign),
    }
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
