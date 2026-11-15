//! «Пломбик», the start page's mascot: the behaviour machine that maps the tunnel phase and UI
//! events to moods, effects, short lines and hops between perches.
//!
//! Lines never claim a safeguard state (kill switch, DNS, leaks) the mascot does not actually
//! know: they react to the dashboard's derived phase and to explicit UI events only.
//!
//! The brain is pure and deterministic: no timers, no clock reads, no DOM. The host feeds events
//! with explicit [`Instant`](std::time::Instant)s, sleeps until [`MascotBrain::next_deadline`],
//! calls [`MascotBrain::tick`] and renders [`MascotBrain::view`] at [`MascotBrain::perch`].
//! Randomness (line picks, the wink chance, wander spot and delay) comes from the caller's
//! `fastrand::Rng`, so a seeded generator makes every run reproducible.
use std::time::Duration;

use vpnte_base::Msg;

mod brain;
#[cfg(test)]
mod tests;

pub use crate::MascotPhase;
use crate::swiss::Mode;
pub use brain::MascotBrain;

/// i18n key of the mascot's accessible name (aria-label and title of the mascot button).
pub const LABEL_KEY: &str = "mascot.name";

/// Facial expression (one face per mood in the markup).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mood {
    Calm,
    Worried,
    Scan,
    Happy,
    Love,
    Squint,
    Think,
    Dizzy,
    Wink,
    Excited,
    Sleep,
    Scared,
    Petted,
}

impl Mood {
    /// Name used by the markup (`calm`, `worried`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            Mood::Calm => "calm",
            Mood::Worried => "worried",
            Mood::Scan => "scan",
            Mood::Happy => "happy",
            Mood::Love => "love",
            Mood::Squint => "squint",
            Mood::Think => "think",
            Mood::Dizzy => "dizzy",
            Mood::Wink => "wink",
            Mood::Excited => "excited",
            Mood::Sleep => "sleep",
            Mood::Scared => "scared",
            Mood::Petted => "petted",
        }
    }
}

/// Effect drawn around him; it replays whenever [`MascotView::fx_id`] changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fx {
    Confetti,
    Zzz,
    Dots,
    Sweat,
    Speed,
    Hearts,
}

impl Fx {
    /// Name used by the markup (`confetti`, `zzz`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            Fx::Confetti => "confetti",
            Fx::Zzz => "zzz",
            Fx::Dots => "dots",
            Fx::Sweat => "sweat",
            Fx::Speed => "speed",
            Fx::Hearts => "hearts",
        }
    }
}

/// One-shot body animation; it replays whenever [`MascotView::body_id`] changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum BodyAnim {
    #[default]
    None,
    Jump,
    Shake,
    Spin,
    Lean,
    Startle,
}

impl BodyAnim {
    /// CSS animation class (`""` for none).
    pub fn class(self) -> &'static str {
        match self {
            BodyAnim::None => "",
            BodyAnim::Jump => "m-jump",
            BodyAnim::Shake => "m-shake",
            BodyAnim::Spin => "m-spin",
            BodyAnim::Lean => "m-lean",
            BodyAnim::Startle => "m-startle",
        }
    }
}

/// A spot the brain sends him to. The page marks it with `data-perch="<as_str>"`; where exactly he
/// lands (gap search, scale, surface colours) is the stage's geometry, not the brain's business.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Perch {
    /// The word row of the slab; he returns here after every outing.
    #[default]
    Home,
    /// The power button (exposed nag, wander).
    Toggle,
    /// The sidebar clock (wander).
    Clock,
    /// The servers panel head (wander).
    Servers,
    /// The external-proxies panel head (wander, proxy actions).
    Proxies,
    /// The leak fact cell (leak check).
    Leak,
    /// The Smart RU fact cell (Smart RU toggle).
    Smart,
}

impl Perch {
    /// Value of the `data-perch` attribute.
    pub fn as_str(self) -> &'static str {
        match self {
            Perch::Home => "home",
            Perch::Toggle => "toggle",
            Perch::Clock => "clock",
            Perch::Servers => "servers",
            Perch::Proxies => "proxies",
            Perch::Leak => "leak",
            Perch::Smart => "smart",
        }
    }
}

/// A short line in the speech bubble.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Speech {
    /// Grows with every new line: key the bubble on it so it replays its entrance.
    pub id: u32,
    pub msg: Msg,
    /// Read out to screen readers (`aria-live`): only replies the user asked for (pokes, petting).
    pub announce: bool,
}

/// What to draw right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MascotView {
    pub mood: Mood,
    pub fx: Option<Fx>,
    pub fx_id: u32,
    pub body: BodyAnim,
    pub body_id: u32,
    pub speech: Option<Speech>,
}

/// Input of the brain: tunnel facts, window and page state, and UI events.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MascotEvent {
    /// The dashboard's derived phase (only a change does something).
    Phase(MascotPhase),
    /// The routing of the session (`ConnView::mode`, `None` without one). Send it before the
    /// phase: his lines about the session follow it, «Туннель…» only in Tunnel mode.
    Mode(Option<Mode>),
    /// Download speed band in Mbit/s as bucketed by `traffic` (0 = idle or ordinary: nothing to
    /// say). Send it when the band changes; repeating the same value is ignored.
    SpeedBand(f32),
    /// Age of the running tunnel session at `now`, `None` without a session. Send it when the
    /// session's start time changes (drives the 10-minute milestones).
    SessionAge(Option<Duration>),
    /// Pointer move/press, key press or wheel anywhere in the window. `on_mascot` = the target is
    /// the mascot itself (a stroke wakes him gently; the petting reaction takes over).
    Activity {
        on_mascot: bool,
    },
    /// The window became visible / hidden (minimised, covered, sent to the tray).
    Visible(bool),
    /// The dashboard became / stopped being the active page. While the window is hidden or another
    /// page is active the brain is paused: its timers freeze and ambient reactions are skipped.
    PageActive(bool),
    /// The resolved theme switched to dark (`true`) or light. The first value is only recorded.
    ThemeDark(bool),
    /// Pointer entered / left the power button.
    HoverIn,
    HoverOut,
    /// The user started a leak check; its verdict follows as `LeakOk` / `LeakWarn` / `LeakFail`.
    LeakStart,
    LeakOk,
    LeakWarn,
    LeakFail,
    /// The Smart RU setting was saved as on / off.
    SmartOn,
    SmartOff,
    /// External proxy column actions.
    ProxyStart,
    ProxyRotate,
    ProxyStop,
    ProxyStopAll,
    /// A new error / warning / success notification appeared (info ones are too frequent).
    NoticeError,
    NoticeWarn,
    NoticeOk,
    /// Click, Enter or Space on the mascot button.
    Poke,
    /// A stroke over him (detected by the markup).
    Pet,
    /// The stage cannot place him on the current perch (it vanished or has no free gap):
    /// hop home instead of snapping.
    GoHome,
}
