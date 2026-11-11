//! The behaviour machine behind [`super::MascotView`]: old `useMascot.ts` timers become named
//! deadlines in one fixed array, so one host task sleeping until `next_deadline` drives it all.
//! This file holds the state, the public driver API, the deadline slots and the pause logic; the
//! repertoire is in `act`, the reactions in `reactions`.
use std::time::{Duration, Instant};

use vpnte_base::Msg;

use super::{BodyAnim, Fx, MascotEvent, MascotPhase, MascotView, Mood, Perch, Speech};
use act::{Act, greeting_for};

mod act;
mod reactions;

/// No input for this long and he falls asleep.
const IDLE: Duration = Duration::from_secs(30);
/// Genuinely exposed for this long: he hops onto the power button.
const EXPOSED_NAG: Duration = Duration::from_secs(20);
const GREET_DELAY: Duration = Duration::from_millis(700);
const WELCOME_AFTER: Duration = Duration::from_secs(5);
const WANDER_MIN_MS: u64 = 25_000;
const WANDER_SPREAD_MS: u64 = 20_000;

/// The ten one-shot timers of the old hook, one pending deadline each (re-arming replaces it).
#[derive(Clone, Copy, Debug)]
enum Slot {
    Greet,
    Speech,
    Emote,
    Home,
    Pet,
    Idle,
    Nag,
    Slow,
    Wander,
    Milestone,
}

const SLOTS: [Slot; 10] = [
    Slot::Greet,
    Slot::Speech,
    Slot::Emote,
    Slot::Home,
    Slot::Pet,
    Slot::Idle,
    Slot::Nag,
    Slot::Slow,
    Slot::Wander,
    Slot::Milestone,
];

/// Next wander in 25–45 s.
fn wander_delay(rng: &mut fastrand::Rng) -> Duration {
    Duration::from_millis(WANDER_MIN_MS + rng.u64(..WANDER_SPREAD_MS))
}

/// «Пломбик»'s brain (see the module docs for the host loop).
#[derive(Debug, Clone)]
pub struct MascotBrain {
    phase: MascotPhase,
    /// Latest speed band, Mbit/s.
    down: f32,
    /// The band is in the slow range (the slow comment's timer runs while it stays there).
    slow: bool,
    /// Session age `.1` as observed at `.0`.
    session: Option<(Instant, Duration)>,
    /// Last 10-minute mark of the session already passed.
    milestone_mark: u128,
    perch: Perch,
    sleeping: bool,
    petting: bool,
    hover_mood: Option<Mood>,
    emote: Option<(Mood, Option<Fx>)>,
    speech: Option<Speech>,
    speech_seq: u32,
    fx_id: u32,
    body: BodyAnim,
    body_id: u32,
    /// The greeting still to come (once per app session): local time of day `.1` as of `.0`.
    greeting: Option<(Instant, Duration)>,
    window_visible: bool,
    page_active: bool,
    /// Paused since: the window is hidden or another page is active.
    paused_since: Option<Instant>,
    hidden_since: Option<Instant>,
    theme_dark: Option<bool>,
    pokes: Vec<Instant>,
    last_notice: Option<Instant>,
    last_spike: Option<Instant>,
    last_slow: Option<Instant>,
    pet_start: Option<Instant>,
    last_pet_line: Option<Instant>,
    pet_cooldown_until: Option<Instant>,
    deadlines: [Option<Instant>; SLOTS.len()],
}

impl MascotBrain {
    /// A brain for a freshly shown dashboard. `time_of_day` is the local time since midnight when
    /// this app session has not greeted yet, `None` afterwards. The greeting comes 700 ms after he
    /// is first shown (after a start in the tray that can be hours later) and fits the hour then.
    pub fn new(
        now: Instant,
        phase: MascotPhase,
        time_of_day: Option<Duration>,
        rng: &mut fastrand::Rng,
    ) -> Self {
        let mut brain = Self {
            phase,
            down: 0.0,
            slow: false,
            session: None,
            milestone_mark: 0,
            perch: Perch::Home,
            sleeping: false,
            petting: false,
            hover_mood: None,
            emote: None,
            speech: None,
            speech_seq: 0,
            fx_id: 0,
            body: BodyAnim::None,
            body_id: 0,
            greeting: time_of_day.map(|t| (now, t)),
            window_visible: true,
            page_active: true,
            paused_since: None,
            hidden_since: None,
            theme_dark: None,
            pokes: Vec::new(),
            last_notice: None,
            last_spike: None,
            last_slow: None,
            pet_start: None,
            last_pet_line: None,
            pet_cooldown_until: None,
            deadlines: [None; SLOTS.len()],
        };
        if brain.greeting.is_some() {
            brain.arm(Slot::Greet, now, GREET_DELAY);
        }
        brain.arm(Slot::Idle, now, IDLE);
        brain.arm(Slot::Wander, now, wander_delay(rng));
        if phase == MascotPhase::Off {
            brain.arm(Slot::Nag, now, EXPOSED_NAG);
        }
        brain
    }

    /// Feeds one event that happened at `now`.
    pub fn handle(&mut self, ev: MascotEvent, now: Instant, rng: &mut fastrand::Rng) {
        use MascotEvent as E;
        match ev {
            E::Phase(phase) => self.set_phase(phase, now, rng),
            E::SpeedBand(band) => self.set_band(band, now),
            E::SessionAge(age) => {
                self.session = age.map(|age| (now, age));
                self.rearm_milestone(now);
            }
            E::Visible(visible) => self.set_visible(visible, now),
            E::PageActive(active) => {
                self.page_active = active;
                self.update_pause(now);
            }
            E::ThemeDark(dark) => self.set_theme(dark, now),
            E::HoverOut => self.hover_mood = None,
            E::GoHome => self.go_home(),
            // Nobody sees him: reactions would only replay stale news later (D-13).
            _ if self.paused() => {}
            E::Activity { on_mascot } => self.activity(on_mascot, now, rng),
            E::HoverIn => self.hover_in(now),
            E::LeakStart => {
                self.hop(now, Perch::Leak, 2600);
                let act = Act::new(Mood::Think).fx(Fx::Dots).body(BodyAnim::Lean);
                self.act(now, act.ms(1500).text("mascot.leakStart").text_ms(1500));
            }
            E::LeakOk => self.act(
                now,
                Act::new(Mood::Happy)
                    .body(BodyAnim::Jump)
                    .text("mascot.leakOk"),
            ),
            E::LeakWarn => self.act(now, Act::new(Mood::Think).text("mascot.leakWarn")),
            E::LeakFail => {
                let act = Act::new(Mood::Scared).fx(Fx::Sweat).body(BodyAnim::Shake);
                self.act(now, act.text("mascot.leakFail").ms(2600));
            }
            E::SmartOn => {
                self.hop(now, Perch::Smart, 2600);
                self.act(now, Act::new(Mood::Wink).text("mascot.smartOn"));
            }
            E::SmartOff => {
                self.hop(now, Perch::Smart, 2600);
                self.act(now, Act::new(Mood::Think).text("mascot.smartOff"));
            }
            E::ProxyStart | E::ProxyRotate | E::ProxyStop | E::ProxyStopAll => self.proxy(ev, now),
            E::NoticeError | E::NoticeWarn | E::NoticeOk => self.notice(ev, now),
            E::Poke => self.poke(now, rng),
            E::Pet => self.pet(now, rng),
        }
    }

    /// Fires every deadline up to `now`, in time order and each at its own due instant, so a late
    /// wake-up plays out exactly as an on-time one would have.
    pub fn tick(&mut self, now: Instant, rng: &mut fastrand::Rng) {
        if self.paused() {
            return;
        }
        while let Some((slot, due)) = self.earliest_due(now) {
            self.deadlines[slot as usize] = None;
            self.fire(slot, due, rng);
        }
    }

    /// When the host should call [`tick`](Self::tick) next; `None` while paused (nothing runs).
    pub fn next_deadline(&self) -> Option<Instant> {
        if self.paused() {
            return None;
        }
        self.deadlines.iter().flatten().min().copied()
    }

    /// What to draw now. The stage itself shows `Excited` while he is airborne.
    pub fn view(&self) -> MascotView {
        let base = if self.sleeping {
            Mood::Sleep
        } else {
            match self.phase {
                MascotPhase::On => Mood::Calm,
                MascotPhase::Connecting => Mood::Scan,
                MascotPhase::Off | MascotPhase::Alert => Mood::Worried,
            }
        };
        let ambient_fx = if self.petting {
            Some(Fx::Hearts)
        } else if self.sleeping {
            Some(Fx::Zzz)
        } else {
            None
        };
        let (mood, fx) = match self.emote {
            Some((mood, fx)) => (mood, fx.or(ambient_fx)),
            None if self.petting => (Mood::Petted, ambient_fx),
            None => (self.hover_mood.unwrap_or(base), ambient_fx),
        };
        MascotView {
            mood,
            fx,
            fx_id: self.fx_id,
            body: self.body,
            body_id: self.body_id,
            speech: self.speech.clone(),
        }
    }

    /// The perch he should be on (or flying to).
    pub fn perch(&self) -> Perch {
        self.perch
    }
}

impl MascotBrain {
    /// Arms `slot` to fire `delay` after `now`. While he is away his clock stands at the moment
    /// he left, so a timer armed then still gets its full delay after the return (`resume`).
    fn arm(&mut self, slot: Slot, now: Instant, delay: Duration) {
        self.deadlines[slot as usize] = Some(self.paused_since.unwrap_or(now) + delay);
    }

    fn clear(&mut self, slot: Slot) {
        self.deadlines[slot as usize] = None;
    }

    fn paused(&self) -> bool {
        self.paused_since.is_some()
    }

    /// The earliest deadline at or before `now`; ties go to the slot declared first.
    fn earliest_due(&self, now: Instant) -> Option<(Slot, Instant)> {
        SLOTS
            .iter()
            .filter_map(|&slot| {
                self.deadlines[slot as usize]
                    .filter(|&due| due <= now)
                    .map(|due| (slot, due))
            })
            .min_by_key(|&(_, due)| due)
    }

    fn fire(&mut self, slot: Slot, at: Instant, rng: &mut fastrand::Rng) {
        match slot {
            Slot::Greet => {
                if let Some((seen, time_of_day)) = self.greeting.take() {
                    let elapsed = at.saturating_duration_since(seen);
                    let (mood, key) = greeting_for(time_of_day.saturating_add(elapsed));
                    let body = if mood == Mood::Sleep {
                        BodyAnim::None
                    } else {
                        BodyAnim::Jump
                    };
                    self.act(at, Act::new(mood).ms(2000).body(body).text(key));
                }
            }
            Slot::Speech => self.speech = None,
            Slot::Emote => self.emote = None,
            Slot::Home => self.perch = Perch::Home,
            Slot::Pet => {
                self.petting = false;
                self.pet_start = None;
            }
            Slot::Idle => self.sleeping = true,
            // Genuinely exposed (not merely degraded): show the way to the power button, once.
            Slot::Nag => {
                self.hop(at, Perch::Toggle, 4500);
                let act = Act::new(Mood::Scared).fx(Fx::Sweat);
                self.act(at, act.text("mascot.exposedNag").ms(3000));
            }
            Slot::Slow => self.comment_slow(at),
            Slot::Wander => self.wander(at, rng),
            Slot::Milestone => self.milestone(at),
        }
    }

    fn act(&mut self, now: Instant, act: Act) {
        self.emote = Some((act.mood, act.fx));
        if act.fx.is_some() {
            self.fx_id = self.fx_id.wrapping_add(1);
        }
        self.arm(Slot::Emote, now, act.hold);
        if act.body != BodyAnim::None {
            self.body = act.body;
            self.body_id = self.body_id.wrapping_add(1);
        }
        if let Some(text) = act.text {
            self.say(now, text, act.text_hold, act.announce);
        }
    }

    fn say(&mut self, now: Instant, msg: Msg, hold: Duration, announce: bool) {
        self.speech_seq = self.speech_seq.wrapping_add(1);
        self.speech = Some(Speech {
            id: self.speech_seq,
            msg,
            announce,
        });
        self.arm(Slot::Speech, now, hold);
    }

    /// Sends him to `perch` for `stay_ms`, then home.
    fn hop(&mut self, now: Instant, perch: Perch, stay_ms: u64) {
        self.perch = perch;
        self.arm(Slot::Home, now, Duration::from_millis(stay_ms));
    }

    fn go_home(&mut self) {
        self.perch = Perch::Home;
        self.clear(Slot::Home);
    }

    fn set_visible(&mut self, visible: bool, now: Instant) {
        if visible == self.window_visible {
            return;
        }
        self.window_visible = visible;
        if !visible {
            self.hidden_since = Some(now);
            self.update_pause(now);
            return;
        }
        let away = self
            .hidden_since
            .take()
            .map(|t| now.saturating_duration_since(t));
        self.update_pause(now);
        // A pending greeting is the better first line after a start in the tray.
        if !self.paused() && self.greeting.is_none() && away.is_some_and(|d| d > WELCOME_AFTER) {
            let act = Act::new(Mood::Love).body(BodyAnim::Jump);
            self.act(now, act.text("mascot.welcomeBack"));
        }
    }

    fn update_pause(&mut self, now: Instant) {
        let shown = self.window_visible && self.page_active;
        match (shown, self.paused_since) {
            (false, None) => self.paused_since = Some(now),
            (true, Some(since)) => {
                self.paused_since = None;
                self.resume(now, now.saturating_duration_since(since));
            }
            _ => {}
        }
    }

    /// Frozen timers continue where they stopped instead of all firing at once on return; so does
    /// an interrupted stroke session (its release timer is frozen with the rest).
    fn resume(&mut self, now: Instant, gap: Duration) {
        let frozen = self.deadlines.iter_mut().chain([&mut self.pet_start]);
        for due in frozen.flatten() {
            *due += gap;
        }
        // Coming back counts as activity, but quietly: no startle.
        self.sleeping = false;
        self.arm(Slot::Idle, now, IDLE);
        // Wall-clock marks passed while nobody was looking are skipped, not replayed.
        self.rearm_milestone(now);
    }
}
