//! The brain's repertoire: one reaction ([`Act`]), the numbered line families and the fixed
//! lines for greetings and wander spots.
use std::time::Duration;

use vpnte_base::Msg;

use crate::mascot::{BodyAnim, Fx, Mood, Perch};

/// Where he wanders when protected and idle, with the mood and the line for the spot.
pub(super) const WANDER: [(Perch, Mood, &str); 4] = [
    (Perch::Toggle, Mood::Happy, "mascot.wanderToggle"),
    (Perch::Clock, Mood::Calm, "mascot.wanderClock"),
    (Perch::Servers, Mood::Think, "mascot.wanderServers"),
    (Perch::Proxies, Mood::Squint, "mascot.wanderProxies"),
];

/// Families of numbered lines (`mascot.<family><n>`) with their variant count in the locales.
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
    pub(super) fn pick(self, rng: &mut fastrand::Rng) -> Msg {
        let (stem, variants) = match self {
            Family::Connected => ("mascot.connected", 3),
            Family::PokeOn => ("mascot.pokeOn", 5),
            Family::PokeOff => ("mascot.pokeOff", 3),
            Family::Wink => ("mascot.wink", 2),
            Family::Startle => ("mascot.startle", 3),
            Family::Pet => ("mascot.pet", 4),
        };
        Msg::new(format!("{stem}{}", rng.usize(..variants)))
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
