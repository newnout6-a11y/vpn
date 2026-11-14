//! How the brain reacts: phase changes, speed bands and milestones, wandering, waking up, theme
//! switches and the UI events (hover, proxy actions, notices, pokes, petting).
use std::time::{Duration, Instant};

use vpnte_base::Msg;

use super::act::{Act, Family, WANDER};
use super::{EXPOSED_NAG, IDLE, MascotBrain, Slot, wander_delay};
use crate::mascot::{BodyAnim, Fx, MascotEvent, MascotPhase, Mood, Perch};

/// Strokes for longer than this and he asks to stop.
const PET_ENOUGH: Duration = Duration::from_secs(6);
const PET_COOLDOWN: Duration = Duration::from_millis(3000);
const PET_LINE_GAP: Duration = Duration::from_millis(3500);
/// Petting ends this long after the last stroke.
const PET_RELEASE: Duration = Duration::from_millis(800);
const MILESTONE_MS: u128 = 600_000;
const SPIKE_MBPS: f32 = 75.0;
const SPIKE_COOLDOWN: Duration = Duration::from_secs(30);
const SLOW_MBPS: f32 = 3.0;
const SLOW_AFTER: Duration = Duration::from_secs(30);
const SLOW_GAP: Duration = Duration::from_secs(120);
const NOTICE_GAP: Duration = Duration::from_millis(2500);
const POKE_WINDOW: Duration = Duration::from_millis(2500);
const POKES_DIZZY: usize = 5;
const WINK_CHANCE: f64 = 0.25;

/// Time from a session age to its next 10-minute mark (never zero).
fn until_next_mark(age_ms: u128) -> Duration {
    Duration::from_millis((MILESTONE_MS - age_ms % MILESTONE_MS) as u64)
}

impl MascotBrain {
    pub(super) fn set_phase(&mut self, phase: MascotPhase, now: Instant, rng: &mut fastrand::Rng) {
        let prev = self.phase;
        if prev == phase {
            return;
        }
        self.phase = phase;
        self.hover_mood = None;
        if phase != MascotPhase::Connecting {
            self.go_home();
        }
        if phase == MascotPhase::Off {
            self.arm(Slot::Nag, now, EXPOSED_NAG);
        } else {
            self.clear(Slot::Nag);
        }
        if !self.paused() {
            match phase {
                MascotPhase::On => {
                    let act = Act::new(Mood::Happy).fx(Fx::Confetti).body(BodyAnim::Jump);
                    self.act(
                        now,
                        act.text(Family::Connected.pick(self.mode, rng)).ms(2200),
                    );
                }
                MascotPhase::Alert => {
                    let act = Act::new(Mood::Scared).fx(Fx::Sweat).body(BodyAnim::Shake);
                    self.act(now, act.text("mascot.alert").ms(2600));
                }
                // Backing out of a connect is not "exposed": just stand down.
                MascotPhase::Off if prev == MascotPhase::Connecting => {
                    self.act(
                        now,
                        Act::new(Mood::Worried).text("mascot.cancelled").ms(1200),
                    );
                }
                MascotPhase::Off => {
                    let act = Act::new(Mood::Scared).fx(Fx::Sweat).body(BodyAnim::Shake);
                    self.act(now, act.text("mascot.exposed").ms(2600));
                }
                MascotPhase::Connecting => {
                    let key = if prev == MascotPhase::On {
                        "mascot.switching"
                    } else {
                        "mascot.building"
                    };
                    self.say(now, Msg::new(key), Duration::from_millis(2600), false);
                }
            }
        }
        self.rearm_milestone(now);
        self.check_spike(now);
        self.update_slow(now);
    }

    pub(super) fn set_band(&mut self, band: f32, now: Instant) {
        let band = if band.is_finite() { band } else { 0.0 };
        if band == self.down {
            return;
        }
        self.down = band;
        self.check_spike(now);
        self.update_slow(now);
    }

    /// Fast link: cheer, at most every 30 s (each new band >= 75 may fire after the cooldown).
    fn check_spike(&mut self, now: Instant) {
        if self.paused() || self.phase != MascotPhase::On || self.down < SPIKE_MBPS {
            return;
        }
        if self
            .last_spike
            .is_some_and(|t| now.saturating_duration_since(t) < SPIKE_COOLDOWN)
        {
            return;
        }
        self.last_spike = Some(now);
        let text = Msg::new("mascot.speed").arg("mbps", format!("{:.0}", self.down));
        let act = Act::new(Mood::Excited).fx(Fx::Speed);
        self.act(now, act.text(text).ms(2200));
    }

    /// Something downloads (band > 0) but under 3 Mbit/s: comment once it lasts 30 s. A zero band
    /// means idle, not slow.
    fn update_slow(&mut self, now: Instant) {
        let slow = self.phase == MascotPhase::On && self.down > 0.0 && self.down < SLOW_MBPS;
        if slow && !self.slow {
            self.arm(Slot::Slow, now, SLOW_AFTER);
        } else if !slow {
            self.clear(Slot::Slow);
        }
        self.slow = slow;
    }

    pub(super) fn comment_slow(&mut self, at: Instant) {
        if self
            .last_slow
            .is_some_and(|t| at.saturating_duration_since(t) < SLOW_GAP)
        {
            return;
        }
        self.last_slow = Some(at);
        let text = Msg::new("mascot.slow").arg("mbps", format!("{:.1}", self.down));
        let act = Act::new(Mood::Think).fx(Fx::Dots).body(BodyAnim::Lean);
        self.act(at, act.text(text).ms(2600).text_ms(4500));
    }

    fn session_age(&self, now: Instant) -> Option<Duration> {
        self.session
            .map(|(seen, age)| age.saturating_add(now.saturating_duration_since(seen)))
    }

    /// Milestones run only while protected; restarting them skips marks already passed.
    pub(super) fn rearm_milestone(&mut self, now: Instant) {
        match self.session_age(now) {
            Some(age) if self.phase == MascotPhase::On => {
                let ms = age.as_millis();
                self.milestone_mark = ms / MILESTONE_MS;
                self.arm(Slot::Milestone, now, until_next_mark(ms));
            }
            _ => self.clear(Slot::Milestone),
        }
    }

    /// Every 10 minutes of a session; whole hours get confetti.
    pub(super) fn milestone(&mut self, at: Instant) {
        let Some(age) = self.session_age(at) else {
            return;
        };
        if self.phase != MascotPhase::On {
            return;
        }
        let ms = age.as_millis();
        self.arm(Slot::Milestone, at, until_next_mark(ms));
        let mark = ms / MILESTONE_MS;
        if mark <= self.milestone_mark {
            return;
        }
        self.milestone_mark = mark;
        let minutes = mark * 10;
        if minutes.is_multiple_of(60) {
            let text = Msg::new("mascot.milestoneHour").arg("hours", minutes / 60);
            let act = Act::new(Mood::Love).fx(Fx::Confetti).body(BodyAnim::Jump);
            self.act(at, act.text(text));
        } else {
            let text = Msg::new("mascot.milestoneMin").arg("minutes", minutes);
            self.act(at, Act::new(Mood::Happy).body(BodyAnim::Jump).text(text));
        }
    }

    /// Strolls to a random spot while protected, awake and at home; always reschedules.
    pub(super) fn wander(&mut self, at: Instant, rng: &mut fastrand::Rng) {
        if self.phase == MascotPhase::On && !self.sleeping && self.perch == Perch::Home {
            let (spot, mood, key) = WANDER[rng.usize(..WANDER.len())];
            self.hop(at, spot, 4500);
            self.act(at, Act::new(mood).text(key).ms(2500));
        }
        self.arm(Slot::Wander, at, wander_delay(rng));
    }

    pub(super) fn activity(&mut self, on_mascot: bool, now: Instant, rng: &mut fastrand::Rng) {
        self.arm(Slot::Idle, now, IDLE);
        if !self.sleeping {
            return;
        }
        self.sleeping = false;
        // Woken by a stroke: wake gently, the petting reaction takes over.
        if !on_mascot {
            let act = Act::new(Mood::Scared).body(BodyAnim::Startle);
            self.act(now, act.text(Family::Startle.pick(self.mode, rng)).ms(1200));
        }
    }

    pub(super) fn set_theme(&mut self, dark: bool, now: Instant) {
        let prev = self.theme_dark.replace(dark);
        if prev.is_none() || prev == Some(dark) || self.paused() {
            return;
        }
        if dark {
            self.act(now, Act::new(Mood::Calm).text("mascot.themeDark"));
        } else {
            self.act(now, Act::new(Mood::Squint).text("mascot.themeLight"));
        }
    }

    /// Pointer over the power button: eager when off, "sure?" when on.
    pub(super) fn hover_in(&mut self, now: Instant) {
        match self.phase {
            MascotPhase::Off => self.hover_mood = Some(Mood::Excited),
            MascotPhase::On => {
                self.hover_mood = Some(Mood::Squint);
                let hold = Duration::from_millis(1400);
                self.say(now, Msg::new("mascot.hoverSure"), hold, false);
            }
            MascotPhase::Connecting | MascotPhase::Alert => {}
        }
    }

    /// External proxies column: hop over and comment on what the user just did.
    pub(super) fn proxy(&mut self, ev: MascotEvent, now: Instant) {
        let act = match ev {
            MascotEvent::ProxyStart => Act::new(Mood::Scan)
                .fx(Fx::Dots)
                .ms(1200)
                .text("mascot.proxyStart")
                .text_ms(1200),
            MascotEvent::ProxyRotate => Act::new(Mood::Think)
                .body(BodyAnim::Lean)
                .text("mascot.proxyRotate"),
            MascotEvent::ProxyStop => Act::new(Mood::Calm).text("mascot.proxyStop"),
            _ => Act::new(Mood::Squint)
                .body(BodyAnim::Shake)
                .text("mascot.proxyStopAll"),
        };
        self.hop(now, Perch::Proxies, 3000);
        self.act(now, act);
    }

    /// React to every new notification, but not to a burst.
    pub(super) fn notice(&mut self, ev: MascotEvent, now: Instant) {
        if self
            .last_notice
            .is_some_and(|t| now.saturating_duration_since(t) < NOTICE_GAP)
        {
            return;
        }
        self.last_notice = Some(now);
        let act = match ev {
            MascotEvent::NoticeError => Act::new(Mood::Scared)
                .fx(Fx::Sweat)
                .body(BodyAnim::Startle)
                .text("mascot.noticeError")
                .ms(2400),
            MascotEvent::NoticeWarn => Act::new(Mood::Worried)
                .body(BodyAnim::Lean)
                .text("mascot.noticeWarn"),
            _ => Act::new(Mood::Happy)
                .body(BodyAnim::Jump)
                .text("mascot.noticeOk"),
        };
        self.act(now, act);
    }

    /// Five pokes within 2.5 s make him dizzy; otherwise a wink now and then, or a line that
    /// fits the phase. Replies the user asked for are announced.
    pub(super) fn poke(&mut self, now: Instant, rng: &mut fastrand::Rng) {
        self.pokes
            .retain(|&p| now.saturating_duration_since(p) < POKE_WINDOW);
        self.pokes.push(now);
        if self.pokes.len() >= POKES_DIZZY {
            self.pokes.clear();
            let act = Act::new(Mood::Dizzy)
                .body(BodyAnim::Spin)
                .text("mascot.dizzy");
            self.act(now, act.ms(2600).announce());
            return;
        }
        if rng.f64() < WINK_CHANCE {
            let act = Act::new(Mood::Wink).body(BodyAnim::Jump);
            self.act(now, act.text(Family::Wink.pick(self.mode, rng)).announce());
            return;
        }
        let uneasy = matches!(self.phase, MascotPhase::Off | MascotPhase::Alert);
        let (mood, family) = if uneasy {
            (Mood::Worried, Family::PokeOff)
        } else {
            (Mood::Happy, Family::PokeOn)
        };
        let act = Act::new(mood)
            .body(BodyAnim::Jump)
            .text(family.pick(self.mode, rng));
        self.act(now, act.ms(1200).announce());
    }

    /// A stroke: purr while it goes on, ask to stop after 6 s, then ignore strokes for 3 s.
    pub(super) fn pet(&mut self, now: Instant, rng: &mut fastrand::Rng) {
        if self.pet_cooldown_until.is_some_and(|until| now < until) {
            return;
        }
        let start = *self.pet_start.get_or_insert(now);
        if now.saturating_duration_since(start) > PET_ENOUGH {
            self.pet_start = None;
            self.pet_cooldown_until = Some(now + PET_COOLDOWN);
            self.petting = false;
            let act = Act::new(Mood::Squint).text("mascot.petEnough");
            self.act(now, act.ms(1600).announce());
            return;
        }
        self.emote = None;
        self.clear(Slot::Emote);
        self.petting = true;
        if self
            .last_pet_line
            .is_none_or(|t| now.saturating_duration_since(t) > PET_LINE_GAP)
        {
            self.last_pet_line = Some(now);
            let hold = Duration::from_millis(1800);
            self.say(now, Family::Pet.pick(self.mode, rng), hold, true);
        }
        // Stops being petted shortly after the strokes stop.
        self.arm(Slot::Pet, now, PET_RELEASE);
    }
}
