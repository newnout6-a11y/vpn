//! Pure tray logic: the status shown for a tunnel snapshot (lifecycle §3.14), the menu items and
//! their enable rules, the tooltip lines, the speed format and what a window close request does
//! (§3.7). No Dioxus or Win32 here, so every rule is a unit test.
use vpnte_base::Msg;

/// Stable protection state (mirror of the lifecycle snapshot's `state`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TunnelState {
    #[default]
    Disconnected,
    Connected,
    Error,
    Blocked,
    Unknown,
}

/// Operation in flight (mirror of the snapshot's `transition`; not a state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    Connecting,
    Disconnecting,
    Reconnecting,
}

/// Upstream reachability (mirror of the snapshot's `proxyStatus`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProxyStatus {
    Running,
    ProxyDown,
    #[default]
    Stopped,
}

/// Everything the tray shows, pushed by the app through [`super::TrayApi::state`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrayState {
    pub tunnel: TunnelState,
    pub transition: Option<Transition>,
    /// Snapshot `health == degraded` (competing-interface evidence).
    pub degraded: bool,
    pub proxy: ProxyStatus,
    /// An engine process of ours runs (snapshot `processState == running`).
    pub engine_running: bool,
    /// Monitoring's leak flag: set on a leak, cleared by the next clean check or a disconnect.
    pub leak: bool,
    /// The WFP kill switch is engaged.
    pub kill_switch: bool,
    /// Watchdog restart attempt `(n, max)` while reconnecting.
    pub restart: Option<(u32, u32)>,
    /// Verified exit IP.
    pub public_ip: Option<String>,
    /// Upstream proxy address `host:port` (never with credentials).
    pub proxy_addr: Option<String>,
    /// Download rate, bytes per second.
    pub down_bps: u64,
    /// Upload rate, bytes per second.
    pub up_bps: u64,
    /// Setting «Сворачивать в трей»: the close button hides the window to the tray.
    pub minimize_to_tray: bool,
    /// «Интернет на паузе»: the VPN dropped by itself and the kill switch holds (ks-a); the menu
    /// then offers «Подключить» and «Продолжить без VPN».
    pub paused: bool,
}

/// What the tray says about protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrayStatus {
    Protected,
    Leak,
    Off,
    Starting,
    ProxyDown,
    KillSwitch,
    Restarting,
    Stopping,
    Error,
    Unknown,
    Paused,
}

/// Colour family of the tray icon: a badge on the app icon, or the greyed icon when off.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Badge {
    Green,
    Amber,
    Red,
    Off,
}

impl TrayStatus {
    /// Every status, in declaration order.
    pub const ALL: [TrayStatus; 11] = [
        TrayStatus::Protected,
        TrayStatus::Leak,
        TrayStatus::Off,
        TrayStatus::Starting,
        TrayStatus::ProxyDown,
        TrayStatus::KillSwitch,
        TrayStatus::Restarting,
        TrayStatus::Stopping,
        TrayStatus::Error,
        TrayStatus::Unknown,
        TrayStatus::Paused,
    ];

    /// The canonical mapping (`trayStatusForTunnel`). A pure function of the snapshot and the two
    /// flags: the old app also accepted explicit statuses and silently dropped them (L-01). A
    /// pause wins: it is reconnecting under a held kill switch, with its own two actions.
    pub fn of(state: &TrayState) -> TrayStatus {
        if state.paused && state.transition != Some(Transition::Disconnecting) {
            return TrayStatus::Paused;
        }
        if let Some(transition) = state.transition {
            return match transition {
                Transition::Connecting => TrayStatus::Starting,
                Transition::Disconnecting => TrayStatus::Stopping,
                Transition::Reconnecting => TrayStatus::Restarting,
            };
        }
        if state.leak {
            return TrayStatus::Leak;
        }
        match state.tunnel {
            TunnelState::Blocked => TrayStatus::KillSwitch,
            _ if state.kill_switch && state.tunnel != TunnelState::Connected => {
                TrayStatus::KillSwitch
            }
            TunnelState::Error => TrayStatus::Error,
            TunnelState::Unknown => TrayStatus::Unknown,
            TunnelState::Connected if state.proxy == ProxyStatus::ProxyDown => {
                TrayStatus::ProxyDown
            }
            TunnelState::Connected if state.degraded => TrayStatus::Unknown,
            TunnelState::Connected => TrayStatus::Protected,
            TunnelState::Disconnected => TrayStatus::Off,
        }
    }

    /// Key segment of the status texts (`ui.tray.menu.status.<key>`, `ui.tray.tip.<key>`).
    pub fn key(self) -> &'static str {
        match self {
            TrayStatus::Protected => "protected",
            TrayStatus::Leak => "leak",
            TrayStatus::Off => "off",
            TrayStatus::Starting => "starting",
            TrayStatus::ProxyDown => "proxyDown",
            TrayStatus::KillSwitch => "killSwitch",
            TrayStatus::Restarting => "restarting",
            TrayStatus::Stopping => "stopping",
            TrayStatus::Error => "error",
            TrayStatus::Unknown => "unknown",
            TrayStatus::Paused => "paused",
        }
    }

    /// Icon colour: the old fallback shield's palette (`tray.ts:52-57`), now always applied (L-02).
    pub fn badge(self) -> Badge {
        match self {
            TrayStatus::Protected => Badge::Green,
            TrayStatus::Leak | TrayStatus::KillSwitch => Badge::Red,
            TrayStatus::Off => Badge::Off,
            _ => Badge::Amber,
        }
    }

    /// Protection (or its failure) is in place, so «Выключить защиту» is the way out.
    fn holds_protection(self) -> bool {
        matches!(
            self,
            TrayStatus::ProxyDown
                | TrayStatus::Protected
                | TrayStatus::Leak
                | TrayStatus::KillSwitch
                | TrayStatus::Error
                | TrayStatus::Unknown
                | TrayStatus::Paused
        )
    }

    fn in_flight(self) -> bool {
        matches!(
            self,
            TrayStatus::Starting | TrayStatus::Restarting | TrayStatus::Stopping
        )
    }
}

/// A tray menu entry, top to bottom (`tray.ts:153-198`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrayItemId {
    Status,
    Ip,
    Proxy,
    Speed,
    Show,
    Start,
    Stop,
    CheckRoute,
    OpenLogs,
    Quit,
}

impl TrayItemId {
    /// Menu order.
    pub const ALL: [TrayItemId; 10] = [
        TrayItemId::Status,
        TrayItemId::Ip,
        TrayItemId::Proxy,
        TrayItemId::Speed,
        TrayItemId::Show,
        TrayItemId::Start,
        TrayItemId::Stop,
        TrayItemId::CheckRoute,
        TrayItemId::OpenLogs,
        TrayItemId::Quit,
    ];

    /// muda menu id (muda's numeric ids come from a global counter; only these strings are stable).
    pub fn menu_id(self) -> &'static str {
        match self {
            TrayItemId::Status => "tray.status",
            TrayItemId::Ip => "tray.ip",
            TrayItemId::Proxy => "tray.proxy",
            TrayItemId::Speed => "tray.speed",
            TrayItemId::Show => "tray.show",
            TrayItemId::Start => "tray.start",
            TrayItemId::Stop => "tray.stop",
            TrayItemId::CheckRoute => "tray.checkRoute",
            TrayItemId::OpenLogs => "tray.openLogs",
            TrayItemId::Quit => "tray.quit",
        }
    }

    /// The item behind a muda menu id.
    pub fn from_menu_id(id: &str) -> Option<TrayItemId> {
        TrayItemId::ALL
            .into_iter()
            .find(|item| item.menu_id() == id)
    }

    /// A separator follows this item.
    pub fn separator_after(self) -> bool {
        matches!(self, TrayItemId::Speed | TrayItemId::OpenLogs)
    }
}

/// One menu entry as the model wants it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrayItem {
    pub id: TrayItemId,
    pub label: Msg,
    pub enabled: bool,
}

/// What the tray shows: icon status, tooltip and menu. Language independent; rendered with
/// [`Msg::render`], so a language switch re-renders it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrayModel {
    pub status: TrayStatus,
    /// Tooltip lines that change rarely: status, IP, proxy.
    pub tooltip: Vec<Msg>,
    /// Tooltip speed line while an engine runs; it changes every traffic tick.
    pub tooltip_speed: Option<Msg>,
    /// Menu entries in [`TrayItemId::ALL`] order.
    pub items: Vec<TrayItem>,
}

impl TrayModel {
    /// Builds the model. `quitting`: the shutdown cleanup runs, only «Показать окно» stays usable.
    pub fn build(state: &TrayState, quitting: bool) -> TrayModel {
        let status = TrayStatus::of(state);
        // An engaged kill switch is active protection too (traySource.test.ts).
        let active = state.engine_running || state.kill_switch || status.holds_protection();
        let can_start = !active && !status.in_flight();
        let can_stop = status != TrayStatus::Stopping && (active || status.in_flight());
        let ip = match &state.public_ip {
            Some(ip) => Msg::new("ui.tray.ip").arg("ip", ip),
            None => Msg::new("ui.tray.ipUnknown"),
        };
        let proxy = match &state.proxy_addr {
            Some(addr) => Msg::new("ui.tray.proxy").arg("addr", addr),
            None => Msg::new("ui.tray.proxyNone"),
        };
        let (down, up) = (format_speed(state.down_bps), format_speed(state.up_bps));
        let paused = status == TrayStatus::Paused;
        // The paused state's two buttons (research 5.2): «Подключить» retries now,
        // «Продолжить без VPN» is the disconnect.
        let (start, stop) = match paused {
            true => (
                "ui.tray.menu.reconnectNow",
                "ui.tray.menu.continueWithoutVpn",
            ),
            false => ("ui.tray.menu.start", "ui.tray.menu.stop"),
        };
        let can_start = can_start || paused;
        let mut tooltip = vec![status_msg("tip", status, state.restart)];
        tooltip.extend(state.public_ip.is_some().then(|| ip.clone()));
        tooltip.extend(state.proxy_addr.is_some().then(|| proxy.clone()));
        let tooltip_speed = state.engine_running.then(|| {
            Msg::new("ui.tray.tip.speed")
                .arg("down", &down)
                .arg("up", &up)
        });
        let items = TrayItemId::ALL
            .into_iter()
            .map(|id| {
                let (label, enabled) = match id {
                    TrayItemId::Status => (status_msg("menu.status", status, state.restart), false),
                    TrayItemId::Ip => (ip.clone(), false),
                    TrayItemId::Proxy => (proxy.clone(), false),
                    TrayItemId::Speed => (
                        Msg::new("ui.tray.menu.speed")
                            .arg("down", &down)
                            .arg("up", &up),
                        false,
                    ),
                    TrayItemId::Show => (Msg::new("ui.tray.menu.show"), true),
                    TrayItemId::Start => (Msg::new(start), can_start && !quitting),
                    TrayItemId::Stop => (Msg::new(stop), can_stop && !quitting),
                    TrayItemId::CheckRoute => (Msg::new("ui.tray.menu.checkRoute"), !quitting),
                    TrayItemId::OpenLogs => (Msg::new("ui.tray.menu.openLogs"), !quitting),
                    TrayItemId::Quit => (Msg::new("ui.tray.menu.quit"), !quitting),
                };
                TrayItem { id, label, enabled }
            })
            .collect();
        TrayModel {
            status,
            tooltip,
            tooltip_speed,
            items,
        }
    }

    /// The entry with this id.
    pub fn item(&self, id: TrayItemId) -> &TrayItem {
        // `items` always holds ALL in order (built only by `build`).
        &self.items[id as usize]
    }
}

/// Status text in one of the two places it appears (`tip` = first tooltip line, `menu.status` =
/// first menu line); a restart shows its attempt counter when known.
fn status_msg(place: &str, status: TrayStatus, restart: Option<(u32, u32)>) -> Msg {
    match (status, restart) {
        (TrayStatus::Restarting, Some((n, max))) => {
            Msg::new(format!("ui.tray.{place}.restartingProgress"))
                .arg("n", n)
                .arg("max", max)
        }
        _ => Msg::new(format!("ui.tray.{place}.{}", status.key())),
    }
}

/// Speed as the old tray printed it (`tray.ts:104-108`): bits per second, `Kbps` below 1 Mbit/s,
/// one decimal below 10 Mbit/s. Integer half-up rounding (JS `Math.round` / `toFixed`) instead of
/// float formatting, which rounds exact ties to even.
pub fn format_speed(bytes_per_second: u64) -> String {
    let bits = bytes_per_second.saturating_mul(8);
    if bits < 1_000_000 {
        format!("{} Kbps", (bits + 500) / 1_000)
    } else if bits < 10_000_000 {
        let tenths = (bits + 50_000) / 100_000;
        format!("{}.{} Mbps", tenths / 10, tenths % 10)
    } else {
        format!("{} Mbps", bits.saturating_add(500_000) / 1_000_000)
    }
}

/// Windows keeps 127 UTF-16 units of a tray tooltip (`NOTIFYICONDATAW::szTip` holds 128 with the
/// terminator); tray-icon copies blindly, so a longer text would lose its terminator.
pub const TOOLTIP_MAX: usize = 127;

/// Joins tooltip lines and cuts them to [`TOOLTIP_MAX`] with an ellipsis.
pub fn fit_tooltip(lines: &[String]) -> String {
    let text = lines.join("\n");
    if text.encode_utf16().count() <= TOOLTIP_MAX {
        return text;
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in text.chars() {
        used += ch.len_utf16();
        if used > TOOLTIP_MAX - 1 {
            break;
        }
        out.push(ch);
    }
    out.truncate(out.trim_end().len());
    out.push('…');
    out
}

/// What a close request (title-bar ×, Alt+F4, taskbar) does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseAction {
    /// Hide the window; protection keeps running in the background.
    Hide,
    /// Run the shutdown cleanup and exit.
    Quit,
    /// Protection is on: ask, offering «Свернуть в трей» when the setting allows it.
    Ask { offer_tray: bool },
}

impl TrayState {
    /// Protection counts as on for the close prompt: an engine of ours runs, the tunnel is
    /// connected (also while its engine is between restarts) or an operation is in flight.
    pub fn protection_on(&self) -> bool {
        self.engine_running || self.tunnel == TunnelState::Connected || self.transition.is_some()
    }

    /// The close decision of `index.ts:850-916`.
    pub fn close_action(&self) -> CloseAction {
        match (self.protection_on(), self.minimize_to_tray) {
            (true, offer_tray) => CloseAction::Ask { offer_tray },
            (false, true) => CloseAction::Hide,
            (false, false) => CloseAction::Quit,
        }
    }
}

#[cfg(test)]
mod tests;
