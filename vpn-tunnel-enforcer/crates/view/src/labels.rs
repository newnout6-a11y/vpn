//! User-facing labels of the start page as [`Msg`]: the status caption, the power and cancel
//! buttons, the facts strip, the identity column, server health, the kill-switch banner and the
//! foreign-VPN name. Language and DOM stay in the UI.
use std::net::IpAddr;

use vpnte_base::Msg;
use vpnte_base::types::Verdict;

use crate::identity::{ExitIp, ServerHealth, visible_leak};
use crate::swiss::{Busy, ConnView, TunnelState};

/// The status caption (`role=status`, and the power button's text while busy), first match:
/// cancelling, switching, connecting, disconnecting, a faulted tunnel, proxy down, degraded,
/// connected, disconnected.
///
/// Degraded is a branch of its own (D-03): the big word says DEGRADED, so the caption must not
/// claim a plain «Подключено»; a competing TUN is named as the reason. The old literal
/// «Перезапуск N/M» branch is not ported: an auto-restart always keeps the connect busy, so the
/// connecting branch answered first (the restart banner carries the progress).
pub fn status_label(conn: &ConnView) -> Msg {
    if conn.cancelling {
        return Msg::new("dashboard.cancelling");
    }
    if let Some(name) = &conn.switching {
        return Msg::new("dashboard.switchingServer").arg("name", name);
    }
    match conn.busy() {
        Some(Busy::Connecting) => return Msg::new("dashboard.connecting"),
        Some(Busy::Disconnecting) => return Msg::new("dashboard.disconnecting"),
        None => {}
    }
    match conn.state {
        TunnelState::Blocked => return Msg::new("dashboard.tunnelBlocked"),
        TunnelState::Unknown => return Msg::new("dashboard.tunnelUnknown"),
        TunnelState::Error => return Msg::new("dashboard.tunnelError"),
        TunnelState::Disconnected | TunnelState::Connected => {}
    }
    if !conn.connected() {
        return Msg::new("dashboard.disconnected");
    }
    if conn.proxy_down {
        return Msg::new("view.status.proxyDown");
    }
    if let Some(name) = &conn.competing_tun {
        return Msg::new("view.status.degradedTun").arg("name", name);
    }
    if conn.degraded {
        return Msg::new("view.status.degraded");
    }
    Msg::new("dashboard.connected")
}

/// Look of the power button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PowerLook {
    Plain,
    /// `.is-on`: connected.
    On,
    /// `.is-busy`: a server switch is in flight.
    Switching,
    /// `.is-cancel`: a cancellation is in flight.
    Cancelling,
}

/// The power button.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerButton {
    /// Visible text and the accessible name (D-02: no `aria-label`; the caption describes it).
    pub label: Msg,
    /// Tooltip: the action the button performs.
    pub title: Msg,
    pub look: PowerLook,
    /// Disabled with a spinner (`.is-wait`) while a transition or a switch runs.
    pub waiting: bool,
}

/// The power button: shows the status while anything is in flight, else the action. The action is
/// "turn off" whenever something of ours is installed, even if the tunnel is not up.
pub fn power_button(conn: &ConnView) -> PowerButton {
    let action = Msg::new(if conn.cleanup_required {
        "dashboard.swissDisable"
    } else {
        "dashboard.swissEnable"
    });
    let look = if conn.cancelling {
        PowerLook::Cancelling
    } else if conn.switching.is_some() {
        PowerLook::Switching
    } else if conn.connected() {
        PowerLook::On
    } else {
        PowerLook::Plain
    };
    PowerButton {
        label: if conn.swiss_busy() {
            status_label(conn)
        } else {
            action.clone()
        },
        title: action,
        look,
        waiting: conn.circle_busy(),
    }
}

/// Text of the transient cancel button; `None` when it is not shown (only while connecting,
/// switching or cancelling).
pub fn cancel_label(conn: &ConnView) -> Option<Msg> {
    let key = if conn.cancelling {
        "dashboard.cancelling"
    } else if conn.switching.is_some() {
        "dashboard.cancelServerSwitch"
    } else if conn.connecting() {
        "dashboard.cancelConnection"
    } else {
        return None;
    };
    Some(Msg::new(key))
}

/// A value in the facts strip with its emphasis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactValue {
    pub text: Msg,
    /// `.is-alert`
    pub alert: bool,
    /// `.is-dim`
    pub dim: bool,
    /// The calm sentence behind a short value (the cell's tooltip).
    pub hint: Option<Msg>,
}

impl FactValue {
    fn plain(key: &'static str) -> Self {
        Self {
            text: Msg::new(key),
            alert: false,
            dim: false,
            hint: None,
        }
    }
}

/// Routing mode fact: «Прокси» (Soft) or «Туннель» (Hard), the setting applied on the next
/// connect. Named by what takes the traffic: the old «Soft Mode» was English inside Russian text.
pub fn mode_fact(soft: bool) -> FactValue {
    FactValue::plain(if soft {
        "view.fact.modeProxy"
    } else {
        "view.fact.modeTunnel"
    })
}

/// Smart RU fact with its inline toggle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartFact {
    pub value: FactValue,
    /// Toggle text (`swiss.turnOn` / `swiss.turnOff`).
    pub action: Msg,
    /// Toggle accessible name.
    pub action_aria: Msg,
}

/// Smart RU fact (the persisted setting; the tooltip `swiss.smartPending` says it applies on the
/// next connect).
pub fn smart_fact(on: bool) -> SmartFact {
    let (value, action, aria) = if on {
        ("swiss.on", "swiss.turnOff", "swiss.smartTurnOff")
    } else {
        ("swiss.off", "swiss.turnOn", "swiss.smartTurnOn")
    };
    SmartFact {
        value: FactValue {
            dim: !on,
            ..FactValue::plain(value)
        },
        action: Msg::new(action),
        action_aria: Msg::new(aria),
    }
}

/// What the kill-switch read-back established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FwState {
    /// Our protection is installed and was read back as intended.
    Verified,
    /// Nothing of ours is installed.
    Inactive,
    /// Not confirmed either way: never presented as protected.
    Unknown,
    /// No WFP in this process, level standard: only Soft's system-proxy hold can act (programs
    /// that honour the proxy stay blocked while the engine is down).
    ProxyHold,
    /// The saved level needs WFP, which this process cannot host (not elevated).
    NeedsAdmin,
}

/// Kill-switch status as the firewall backend publishes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FirewallStatus {
    pub state: FwState,
    /// A read-back is in flight.
    pub checking: bool,
}

impl Default for FirewallStatus {
    /// Before the first read-back: unknown, checking.
    fn default() -> Self {
        Self {
            state: FwState::Unknown,
            checking: true,
        }
    }
}

impl FirewallStatus {
    /// The status as the routing mode presents it: the proxy hold exists only in Soft, so in
    /// Hard (TUN, needs WFP) a level without WFP holds nothing and needs administrator rights.
    pub fn in_mode(self, soft: bool) -> Self {
        match self.state {
            FwState::ProxyHold if !soft => Self {
                state: FwState::NeedsAdmin,
                ..self
            },
            _ => self,
        }
    }
}

/// Kill-switch fact: Проверяем / Держит / Снят / Неизвестно / Через прокси / Нужны права
/// администратора; an unconfirmed state and a level that cannot hold are alerts.
pub fn kill_switch_fact(fw: &FirewallStatus) -> FactValue {
    let key = if fw.checking {
        "swiss.ksChecking"
    } else {
        match fw.state {
            FwState::Verified => "swiss.ksHolding",
            FwState::Inactive => "swiss.ksOff",
            FwState::Unknown => "swiss.ksUnknown",
            FwState::ProxyHold => "view.fact.ksProxy",
            FwState::NeedsAdmin => "view.fact.ksNeedsAdmin",
        }
    };
    FactValue {
        alert: matches!(fw.state, FwState::Unknown | FwState::NeedsAdmin) && !fw.checking,
        dim: fw.state == FwState::Inactive,
        ..FactValue::plain(key)
    }
}

/// Leak fact from the last leak check's summary (`NotChecked` = no verdict, shown as «—»). While
/// `checking`, the UI adds the blinking cursor and hides (but keeps the space of) the button.
pub fn leak_fact(summary: Verdict, checking: bool) -> FactValue {
    let key = if checking {
        "swiss.leakChecking"
    } else {
        match summary {
            Verdict::Ok => "swiss.leakNone",
            Verdict::Fail => "swiss.leakFound",
            Verdict::Warn => "swiss.leakWarn",
            Verdict::NotChecked => "view.dash",
        }
    };
    FactValue {
        alert: summary == Verdict::Fail,
        dim: summary == Verdict::NotChecked && !checking,
        ..FactValue::plain(key)
    }
}

/// The leak fact of a Proxy-mode session (lab F10, p-follow3). The check reads what ordinary
/// programs see over the OS route, which Proxy mode does not take (programs that ignore the
/// system proxy, and UDP, go direct: NOADMIN §2), so a failure there is what the mode is and is
/// said calmly. «Найдены» stays for a leak of what the mode takes: the exit through the proxy is
/// the real address (`exit_leak`).
pub fn proxy_leak_fact(summary: Verdict, checking: bool, exit_leak: bool) -> FactValue {
    match (checking, exit_leak, summary) {
        (true, ..) => leak_fact(summary, true),
        (false, true, _) => leak_fact(Verdict::Fail, false),
        (false, false, Verdict::Fail) => FactValue {
            hint: Some(Msg::new("view.leak.outsideProxyHint")),
            ..FactValue::plain("view.leak.outsideProxy")
        },
        (false, false, _) => leak_fact(summary, false),
    }
}

/// A sub-line under an identity value (`div.swiss-sub`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubLine {
    pub text: Msg,
    /// Prefixed with «— » (leak, unverified IP).
    pub dash: bool,
    /// `.is-alert`
    pub alert: bool,
    /// Country for the flag coin before the text (geo line only).
    pub flag: Option<String>,
}

impl SubLine {
    fn plain(text: Msg) -> Self {
        Self {
            text,
            dash: false,
            alert: false,
            flag: None,
        }
    }

    fn dashed(key: &'static str) -> Self {
        Self {
            dash: true,
            ..Self::plain(Msg::new(key))
        }
    }
}

/// The «Выходной IP» block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitLine {
    /// The address to show (copy button); `None` renders a dim «—».
    pub ip: Option<IpAddr>,
    /// Render dim: no address, or a transition is in flight.
    pub dim: bool,
    /// Settled off and nothing measured yet (before the first session): the slot says
    /// «ещё не определён» instead of a dash that reads as a broken value.
    pub unmeasured: bool,
    pub sub: SubLine,
}

/// The exit-IP block. Mid-transition or with a faulted tunnel nothing about the exit is proven
/// (D-29: exposure wording only when settled off): the address is dim and the sub-line is the
/// status text. The snapshot keeps the previous exit IP during a protected transition, so
/// «ваш провайдер» under it would be false.
pub fn exit_line(conn: &ConnView, exit: &ExitIp) -> ExitLine {
    let connected = conn.connected();
    let leak = exit.ip.is_some() && visible_leak(conn, exit);
    let neutral = conn.swiss_busy() || (!leak && conn.state.faulted());
    let sub = match exit.ip {
        _ if neutral => SubLine::plain(status_label(conn)),
        _ if leak => SubLine {
            alert: true,
            ..SubLine::dashed("dashboard.swissIpLeak")
        },
        Some(_) if connected && exit.verdict == Verdict::Warn => {
            SubLine::dashed("dashboard.ipChangedUnverified")
        }
        Some(_) if connected && exit.verdict == Verdict::NotChecked => {
            SubLine::dashed("dashboard.ipNotChecked")
        }
        Some(_) if connected && exit.verdict == Verdict::Ok => {
            geo_line(exit).unwrap_or_else(|| SubLine::plain(Msg::new("dashboard.swissViaVpn")))
        }
        _ if connected => SubLine::plain(Msg::new("dashboard.swissIpDetecting")),
        _ => SubLine::plain(Msg::new("dashboard.swissIpYourIsp")),
    };
    let settled_off = !neutral && !connected && !leak;
    ExitLine {
        ip: exit.ip,
        dim: neutral || exit.ip.is_none(),
        unmeasured: settled_off && exit.ip.is_none(),
        sub,
    }
}

// «Netherlands, Amsterdam» with the flag, for a geo looked up for this very address.
fn geo_line(exit: &ExitIp) -> Option<SubLine> {
    let geo = exit.current_geo()?;
    let country = geo.country.as_deref().filter(|c| !c.is_empty())?;
    let text = match geo.city.as_deref().filter(|c| !c.is_empty()) {
        Some(city) => Msg::new("view.identity.countryCity")
            .arg("country", country)
            .arg("city", city),
        None => Msg::new("view.identity.country").arg("country", country),
    };
    Some(SubLine {
        flag: Some(country.to_owned()),
        ..SubLine::plain(text)
    })
}

/// How the real address is presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RealLook {
    /// Behind a settled tunnel without a visible leak: struck through.
    Hidden,
    /// Settled off, or leaking: alert sub-line «открыт всем».
    Exposed,
    /// In flight or faulted: dim, neither struck nor "exposed" (nothing is proven either way).
    Neutral,
}

/// The «Настоящий адрес» block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealLine {
    /// The captured home address (`None` renders «—»).
    pub ip: Option<IpAddr>,
    pub look: RealLook,
}

impl RealLine {
    /// Strike-through only applies to an address that is shown (`.is-hidden`).
    pub fn struck(&self) -> bool {
        self.look == RealLook::Hidden && self.ip.is_some()
    }

    /// The alert sub-line, only when exposed.
    pub fn sub(&self) -> Option<SubLine> {
        (self.look == RealLook::Exposed).then(|| SubLine {
            alert: true,
            ..SubLine::plain(Msg::new("dashboard.swissExposedToAll"))
        })
    }

    /// Exposed with no address captured yet: the slot says «ещё не определён», not «—».
    pub fn unmeasured(&self) -> bool {
        self.look == RealLook::Exposed && self.ip.is_none()
    }
}

/// The real-address block: exposure wording only for a settled off state or a visible leak
/// (D-29); a faulted tunnel (error / blocked / unknown) or a transition shows it neutral.
pub fn real_line(conn: &ConnView, exit: &ExitIp, home: Option<IpAddr>) -> RealLine {
    let look = if conn.swiss_busy() {
        RealLook::Neutral
    } else if visible_leak(conn, exit) || conn.state == TunnelState::Disconnected {
        RealLook::Exposed
    } else if conn.connected() {
        RealLook::Hidden
    } else {
        RealLook::Neutral
    };
    RealLine { ip: home, look }
}

/// The node sub-line «VLESS · 38 мс» (`ping` = stored ping, else the health checker's latency).
pub fn node_meta(protocol: Option<&str>, ping: Option<u32>, health: ServerHealth) -> Msg {
    let protocol = protocol.filter(|p| !p.is_empty()).map(str::to_uppercase);
    let (with_protocol, bare) = match (ping, health) {
        (Some(_), _) => ("view.identity.metaPing", "view.identity.ping"),
        (None, ServerHealth::Offline) => ("view.identity.metaOffline", "dashboard.swissOffline"),
        (None, _) => ("view.identity.metaUnchecked", "dashboard.swissUnchecked"),
    };
    let mut msg = Msg::new(if protocol.is_some() {
        with_protocol
    } else {
        bare
    });
    if let Some(p) = protocol {
        msg = msg.arg("protocol", p);
    }
    if let Some(ms) = ping {
        msg = msg.arg("ms", ms);
    }
    msg
}

/// Health cell of a server row: offline, not checked, or online with the age of the last check
/// (`minutes_ago` from [`crate::fmt::minutes_ago`]).
pub fn health_label(health: ServerHealth, minutes_ago: Option<u64>) -> Msg {
    match (health, minutes_ago) {
        (ServerHealth::Offline, _) => Msg::new("swiss.offline"),
        (ServerHealth::Unknown, _) => Msg::new("swiss.unchecked"),
        (ServerHealth::Online, None) => Msg::new("swiss.online"),
        (ServerHealth::Online, Some(0)) => Msg::new("swiss.justNow"),
        (ServerHealth::Online, Some(n)) => Msg::new("swiss.minAgo").arg("n", n),
    }
}

/// The kill-switch banner's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillSwitchBanner {
    pub title: Msg,
    pub body: Msg,
}

/// The kill-switch banner: shown when our WFP protection holds (or cannot be confirmed) while no
/// TUN runs and nothing is in flight. A read-back in flight hides it; the backend publishes the
/// status after a settled transition, so no suppression timer is needed (D-28). The proxy hold
/// and a level that needs administrator rights install no filters: no banner.
pub fn kill_switch_banner(conn: &ConnView, fw: &FirewallStatus) -> Option<KillSwitchBanner> {
    let show = matches!(fw.state, FwState::Verified | FwState::Unknown)
        && !fw.checking
        && !conn.tun_running()
        && conn.switching.is_none()
        && conn.busy().is_none()
        && conn.restarting.is_none();
    show.then(|| {
        let (title, body) = if fw.state == FwState::Verified {
            (
                "dashboard.firewallVerifiedTitle",
                "dashboard.firewallVerifiedBody",
            )
        } else {
            (
                "dashboard.firewallUnknownTitle",
                "dashboard.firewallUnknownBody",
            )
        };
        KillSwitchBanner {
            title: Msg::new(title),
            body: Msg::new(body),
        }
    })
}

/// Short product name for a foreign VPN adapter descriptor (`happ-tun (172.18.0.1)` → `Happ`);
/// an unknown vendor shows the adapter name without the address suffix. Product names are not
/// translated.
pub fn foreign_vpn_friendly_name(raw: Option<&str>) -> Option<String> {
    let raw = raw.filter(|r| !r.is_empty())?;
    let lower = raw.to_lowercase();
    let has = |needle: &str| lower.contains(needle);
    let vendor = if has("happ") {
        Some("Happ")
    } else if has("hiddify") {
        Some("Hiddify")
    } else if has("wireguard") || has_wg_token(&lower) {
        Some("WireGuard")
    } else if has("openvpn") || has("tap-windows") {
        Some("OpenVPN")
    } else if has("xray") || has("v2ray") || has("singbox") {
        Some("Xray/V2Ray")
    } else {
        None
    };
    if let Some(vendor) = vendor {
        return Some(vendor.to_owned());
    }
    let name = strip_paren_suffix(raw).trim();
    Some(if name.is_empty() { raw } else { name }.to_owned())
}

// JS `/\bwg\d*\b/` (ASCII word characters): `wg`, `wg0`, `my-wg2`, but not `wgx` or `swg`.
fn has_wg_token(lower: &str) -> bool {
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = lower.as_bytes();
    lower.match_indices("wg").any(|(i, _)| {
        let mut end = i + 2;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        (i == 0 || !word(bytes[i - 1])) && (end == bytes.len() || !word(bytes[end]))
    })
}

// JS `raw.replace(/\s*\(.*\)\s*$/, '')`: from the first `(` whose line runs to a `)` that ends the
// text (only whitespace after it), together with the whitespace before that `(`.
fn strip_paren_suffix(raw: &str) -> &str {
    let body = raw.trim_end();
    if !body.ends_with(')') {
        return raw;
    }
    // `.` does not cross line breaks, so the `(` must be on the closing parenthesis' line
    // (U+2028 / U+2029 are line breaks of three bytes each).
    let line = body
        .rsplit(['\n', '\r', '\u{2028}', '\u{2029}'])
        .next()
        .unwrap_or(body);
    let line_start = body.len() - line.len();
    match line.find('(') {
        Some(open) => raw[..line_start + open].trim_end(),
        None => raw,
    }
}

#[cfg(test)]
mod tests;
