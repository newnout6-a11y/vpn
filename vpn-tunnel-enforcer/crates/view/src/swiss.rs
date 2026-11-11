//! The «Пломба» status slab: the connection projection the start page renders, the big-word
//! state machine (`swissState.ts`, ported verbatim), the mascot phase, FitWord sizing and the
//! ten-cell progress ruler.
use std::time::Instant;

use vpnte_base::Msg;
use vpnte_base::types::{UnixMs, Verdict};

use crate::MascotPhase;
use crate::identity::{ExitIp, visible_leak};

/// Stable lifecycle state of our tunnel (transitions are separate, see [`Transition`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TunnelState {
    #[default]
    Disconnected,
    Connected,
    Error,
    Blocked,
    Unknown,
}

/// A lifecycle transition in flight; never shown as connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transition {
    Connecting,
    Disconnecting,
    Reconnecting,
}

/// How the live session routes traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// sing-box TUN (Hard mode).
    Tun,
    /// Environment proxy autoconfig, no TUN (Soft mode).
    Soft,
}

/// The connection is busy with a user-visible transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Busy {
    Connecting,
    Disconnecting,
}

/// Start and deadline of the operation in flight (drives the progress ruler).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpWindow {
    pub started: Instant,
    pub deadline: Option<Instant>,
}

/// Projection of the tunnel lifecycle snapshot that the start page renders; the app fills it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnView {
    pub state: TunnelState,
    pub transition: Option<Transition>,
    /// Routing of the session; `None` when there is no session.
    pub mode: Option<Mode>,
    /// The user asked to cancel a connect or a server switch; released by the lifecycle owner.
    pub cancelling: bool,
    /// Name of the server a switch is moving to.
    pub switching: Option<String>,
    /// Automatic restart after an engine crash: (attempt, max attempts).
    pub restarting: Option<(u8, u8)>,
    /// Snapshot health is degraded (possible DNS leak, packet loss, unverifiable full tunnel).
    pub degraded: bool,
    /// Another TUN adapter competes with ours (adapter description).
    pub competing_tun: Option<String>,
    /// Published by the lifecycle backend: connected, but the proxy answers nothing (D-23).
    pub proxy_down: bool,
    /// Something of ours is installed (engine, routes, filters) that a disconnect must remove.
    pub cleanup_required: bool,
    /// Wall-clock start of the confirmed session.
    pub started_at: Option<UnixMs>,
    pub operation: Option<OpWindow>,
}

impl ConnView {
    /// Busy flag as the old store projected it: cancelling reads as disconnecting, an auto-restart
    /// keeps the connect busy.
    pub fn busy(&self) -> Option<Busy> {
        if self.cancelling {
            return Some(Busy::Disconnecting);
        }
        match self.transition {
            Some(Transition::Disconnecting) => Some(Busy::Disconnecting),
            Some(Transition::Connecting | Transition::Reconnecting) => Some(Busy::Connecting),
            None => self.restarting.map(|_| Busy::Connecting),
        }
    }

    /// Busy connecting (also while an auto-restart runs).
    pub fn connecting(&self) -> bool {
        self.busy() == Some(Busy::Connecting)
    }

    /// Busy disconnecting (also while a cancellation runs).
    pub fn disconnecting(&self) -> bool {
        self.busy() == Some(Busy::Disconnecting)
    }

    /// Connected and settled: a transition never counts as connected.
    pub fn connected(&self) -> bool {
        self.state == TunnelState::Connected && self.transition.is_none()
    }

    /// A connect/disconnect or a server switch is in flight (power button waits).
    pub fn circle_busy(&self) -> bool {
        self.busy().is_some() || self.switching.is_some()
    }

    /// Anything transient on the slab: stripes, busy dot, neutral identity column.
    pub fn swiss_busy(&self) -> bool {
        self.circle_busy() || self.cancelling || self.restarting.is_some()
    }

    /// Our TUN is up (the old `tunRunning`).
    pub fn tun_running(&self) -> bool {
        self.connected() && self.mode == Some(Mode::Tun)
    }

    /// Start of the TUN session (the old `tunStartedAt`; Soft mode has none).
    pub fn tun_started_at(&self) -> Option<UnixMs> {
        self.started_at.filter(|_| self.tun_running())
    }

    /// Start time for the uptime label, shown only on a settled TUN session.
    pub fn uptime_since(&self) -> Option<UnixMs> {
        self.tun_started_at().filter(|_| !self.swiss_busy())
    }

    /// Degraded for the big word: snapshot health, or a competing TUN.
    pub fn degraded_any(&self) -> bool {
        self.degraded || self.competing_tun.is_some()
    }

    /// Adapter name for the competing-TUN banner (only while our TUN runs).
    pub fn competing_tun_banner(&self) -> Option<&str> {
        self.competing_tun.as_deref().filter(|_| self.tun_running())
    }
}

/// Input of [`derive_swiss_state`], one flag per fact the dashboard knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SwissInput {
    pub cancelling: bool,
    pub switching: bool,
    pub connecting: bool,
    pub disconnecting: bool,
    pub restarting: bool,
    pub connected: bool,
    /// A visible leak verdict (already suppressed during server switches).
    pub leak: bool,
    pub tunnel_state: TunnelState,
    /// Connected but the proxy answers nothing: traffic is blocked.
    pub proxy_down: bool,
    /// Snapshot health is degraded, or another TUN competes with ours.
    pub degraded: bool,
    /// Exit-IP verdict (`Ok` = passed, see [`ExitIp`]).
    pub verdict: Verdict,
}

impl SwissInput {
    /// The input exactly as the dashboard assembled it from the snapshot and the exit-IP facts.
    pub fn new(conn: &ConnView, exit: &ExitIp) -> Self {
        Self {
            cancelling: conn.cancelling,
            switching: conn.switching.is_some(),
            connecting: conn.connecting(),
            disconnecting: conn.disconnecting(),
            restarting: conn.restarting.is_some(),
            connected: conn.connected(),
            leak: visible_leak(conn, exit),
            tunnel_state: conn.state,
            proxy_down: conn.proxy_down,
            degraded: conn.degraded_any(),
            verdict: exit.verdict,
        }
    }
}

/// Which big word the slab shows. Deliberately Latin in every locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwissState {
    Cancel,
    Switch,
    Linking,
    Closing,
    Restart,
    Leak,
    Alert,
    Blocked,
    Degraded,
    Verify,
    Secure,
    Exposed,
}

/// Precedence: user-started transitions first (cancel > switch > linking > closing > restart),
/// then hazards (leak > alert > blocked > degraded), then verification. SECURE needs a connected,
/// healthy tunnel with a passed IP check.
pub fn derive_swiss_state(i: &SwissInput) -> SwissState {
    use SwissState::*;
    if i.cancelling {
        return Cancel;
    }
    if i.switching {
        return Switch;
    }
    if i.connecting {
        return Linking;
    }
    if i.disconnecting {
        return Closing;
    }
    if i.restarting {
        return Restart;
    }
    // A leak only counts while connected.
    if i.connected && i.leak {
        return Leak;
    }
    // Not gated by `connected`: an unknown tunnel alerts even when off.
    if matches!(
        i.tunnel_state,
        TunnelState::Error | TunnelState::Blocked | TunnelState::Unknown
    ) {
        return Alert;
    }
    if i.connected && i.proxy_down {
        return Blocked;
    }
    if i.connected && i.degraded {
        return Degraded;
    }
    if i.connected && i.verdict != Verdict::Ok {
        return Verify;
    }
    if i.connected { Secure } else { Exposed }
}

impl SwissState {
    /// The big word (`dashboard.swissWord*`, Latin in both locales).
    pub fn word(self) -> Msg {
        Msg::new(match self {
            SwissState::Cancel => "dashboard.swissWordCancel",
            SwissState::Switch => "dashboard.swissWordSwitch",
            SwissState::Linking => "dashboard.swissWordLinking",
            SwissState::Closing => "dashboard.swissWordClosing",
            SwissState::Restart => "dashboard.swissWordRestart",
            SwissState::Leak => "dashboard.swissWordLeak",
            SwissState::Alert => "dashboard.swissWordAlert",
            SwissState::Blocked => "dashboard.swissWordBlocked",
            SwissState::Degraded => "dashboard.swissWordDegraded",
            SwissState::Verify => "dashboard.swissWordVerify",
            SwissState::Secure => "dashboard.swissWordSecure",
            SwissState::Exposed => "dashboard.swissWordExposed",
        })
    }

    /// Hazard states: the slab gets `.is-alert`.
    pub fn is_alert(self) -> bool {
        matches!(
            self,
            SwissState::Leak | SwissState::Alert | SwissState::Blocked | SwissState::Degraded
        )
    }

    /// Only SECURE lights the slab (`.is-on`).
    pub fn is_on(self) -> bool {
        self == SwissState::Secure
    }
}

/// Mascot phase from the slab state; `busy` is [`ConnView::swiss_busy`]. VERIFY is a live tunnel
/// waiting for its IP check, not a transition: the mascot must not treat a recheck as reconnecting.
pub fn swiss_phase(state: SwissState, busy: bool) -> MascotPhase {
    if state.is_on() || state == SwissState::Verify {
        MascotPhase::On
    } else if state.is_alert() {
        MascotPhase::Alert
    } else if busy {
        MascotPhase::Connecting
    } else {
        MascotPhase::Off
    }
}

/// Largest size of the big word, px (fullscreen reaches it).
pub const WORD_MAX_PX: f64 = 150.0;
/// Smallest size of the big word, px.
pub const WORD_MIN_PX: f64 = 40.0;
/// The word never outgrows ~15% of the window height, so a windowed app keeps the identity
/// column and the panels on screen.
pub const WORD_HEIGHT_SHARE: f64 = 0.15;
/// Size used before the first measurement, px.
pub const WORD_INITIAL_PX: f64 = 96.0;

/// FitWord: the font size (px) at which every word (SECURE, LINKING, EXPOSED…) is equally wide.
/// `probe_px` is the word's width rendered at 100 px (letter-spacing is in em, so width scales
/// linearly), `box_px` the width of its box, `window_h` the window's inner height and `current`
/// the size in use. A word that is not laid out (probe width 0, hidden page) keeps `current`.
pub fn fit_word(probe_px: f64, box_px: f64, window_h: f64, current: Option<f64>) -> Option<f64> {
    if probe_px <= 0.0 {
        return current;
    }
    let cap = WORD_MAX_PX.min(window_h * WORD_HEIGHT_SHARE);
    let next = WORD_MIN_PX.max(cap.min(box_px / probe_px * 100.0 * 0.98));
    match current {
        // Hysteresis: a sub-pixel change would feed the resize observer forever.
        Some(size) if (size - next).abs() < 0.5 => Some(size),
        _ => Some(next),
    }
}

/// Number of cells of the progress ruler under the slab.
pub const RULER_CELLS: u8 = 10;

/// The ruler: the backend reports an operation's start and deadline but not its steps, so cells
/// fill by elapsed time against the deadline; without a deadline the ruler shows stripes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ruler {
    /// Cells marked done (`.is-done` on the first `lit` cells).
    pub lit: u8,
    /// Busy without a usable deadline (`.is-indeterminate`).
    pub indeterminate: bool,
}

/// Ruler state at `now`; `busy` is [`ConnView::swiss_busy`].
pub fn ruler(op: Option<&OpWindow>, busy: bool, now: Instant) -> Ruler {
    if !busy {
        return Ruler::default();
    }
    // A deadline at or before the start is unusable: stripes instead of a frozen empty ruler.
    let window = op.and_then(|op| {
        let span = op.deadline?.checked_duration_since(op.started)?;
        (!span.is_zero()).then_some((op.started, span))
    });
    match window {
        None => Ruler {
            lit: 0,
            indeterminate: true,
        },
        Some((started, span)) => {
            let fill = (now.saturating_duration_since(started).as_secs_f64() / span.as_secs_f64())
                .clamp(0.0, 1.0);
            Ruler {
                lit: (fill * f64::from(RULER_CELLS)).round() as u8,
                indeterminate: false,
            }
        }
    }
}

#[cfg(test)]
mod tests;
