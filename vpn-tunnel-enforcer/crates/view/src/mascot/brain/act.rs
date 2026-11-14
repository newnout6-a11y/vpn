//! The brain's repertoire: one reaction ([`Act`]), the numbered line families and the fixed
//! lines for greetings and wander spots.
use std::time::Duration;

use vpnte_base::Msg;

use crate::mascot::{BodyAnim, Fx, Mood, Perch};
use crate::swiss::Mode;

/// Where he wanders when protected and idle, with the mood and the line for the spot.
pub(super) const WANDER: [(Perch, Mood, &str); 4] = [
    (Perch::Toggle, Mood::Happy, "mascot.wanderToggle"),
    (Perch::Clock, Mood::Calm, "mascot.wanderClock"),
    (Perch::Servers, Mood::Think, "mascot.wanderServers"),
    (Perch::Proxies, Mood::Squint, "mascot.wanderProxies"),
];

/// Families of lines; one is picked at random.
#[derive(Clone, Copy)]
pub(super) enum Family {
    Connected,
    PokeOn,
    PokeOff,
    Wink,
    Startle,
    Pet,
}

impl Family {
    /// A line of the family for a session routed by `mode`.
    pub(super) fn pick(self, mode: Option<Mode>, rng: &mut fastrand::Rng) -> Msg {
        let lines = self.lines(mode);
        Msg::new(lines[rng.usize(..lines.len())])
    }

    /// The family's lines. «Туннель…» only in Tunnel mode (p-follow3): Proxy mode has its own
    /// words, an unknown mode the plain one.
    pub(super) fn lines(self, mode: Option<Mode>) -> &'static [&'static str] {
        match (self, mode) {
            (Family::Connected, Some(Mode::Tun)) => &[
                "mascot.connected0",
                "mascot.connected1",
                "mascot.connected2",
            ],
            (Family::Connected, Some(Mode::Soft)) => &[
                "view.mascot.connectedProxy0",
                "view.mascot.connectedProxy1",
                "mascot.connected2",
            ],
            (Family::Connected, None) => &["mascot.connected2"],
            (Family::PokeOn, Some(Mode::Tun)) => &[
                "mascot.pokeOn0",
                "mascot.pokeOn1",
                "mascot.pokeOn2",
                "mascot.pokeOn3",
                "mascot.pokeOn4",
            ],
            (Family::PokeOn, _) => &[
                "mascot.pokeOn0",
                "mascot.pokeOn2",
                "mascot.pokeOn3",
                "mascot.pokeOn4",
            ],
            (Family::PokeOff, _) => &["mascot.pokeOff0", "mascot.pokeOff1", "mascot.pokeOff2"],
            (Family::Wink, _) => &["mascot.wink0", "mascot.wink1"],
            (Family::Startle, _) => &["mascot.startle0", "mascot.startle1", "mascot.startle2"],
            (Family::Pet, _) => &["mascot.pet0", "mascot.pet1", "mascot.pet2", "mascot.pet3"],
        }
    }
}

/// One reaction: a mood held for `ms` with an optional effect, body move and line.
pub(super) struct Act {
    pub(super) mood: Mood,
    pub(super) hold: Duration,
    pub(super) fx: Option<Fx>,
    pub(super) body: BodyAnim,
    pub(super) text: Option<Msg>,
    pub(super) text_hold: Duration,
    pub(super) announce: bool,
}

impl Act {
    pub(super) fn new(mood: Mood) -> Self {
        Self {
            mood,
            hold: Duration::from_millis(1800),
            fx: None,
            body: BodyAnim::None,
            text: None,
            text_hold: Duration::from_millis(3200),
            announce: false,
        }
    }
    pub(super) fn ms(mut self, ms: u64) -> Self {
        self.hold = Duration::from_millis(ms);
        self
    }
    pub(super) fn fx(mut self, fx: Fx) -> Self {
        self.fx = Some(fx);
        self
    }
    pub(super) fn body(mut self, body: BodyAnim) -> Self {
        self.body = body;
        self
    }
    pub(super) fn text(mut self, msg: impl Into<Msg>) -> Self {
        self.text = Some(msg.into());
        self
    }
    pub(super) fn text_ms(mut self, ms: u64) -> Self {
        self.text_hold = Duration::from_millis(ms);
        self
    }
    pub(super) fn announce(mut self) -> Self {
        self.announce = true;
        self
    }
}

/// Greeting by local time of day: night owls get a sleepy one without the jump.
pub(super) fn greeting_for(time_of_day: Duration) -> (Mood, &'static str) {
    match time_of_day.as_secs() / 3600 % 24 {
        0..=4 => (Mood::Sleep, "mascot.greetNight"),
        5..=11 => (Mood::Happy, "mascot.greetMorning"),
        12..=17 => (Mood::Happy, "mascot.greetDay"),
        _ => (Mood::Calm, "mascot.greetEvening"),
    }
}
