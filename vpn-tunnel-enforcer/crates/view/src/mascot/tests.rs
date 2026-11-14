//! Behaviour vectors: ui-dashboard spec §7.3 (ported from `useMascot.test.ts`, no AT tag exists for
//! the mascot) plus vectors derived from `useMascot.ts` and from the D-13 pause decision.
use std::time::{Duration, Instant};

use vpnte_base::Msg;

use super::*;

/// A brain on a fake clock. Built as already greeted: the old suite silently relied on the
/// module-level `greeted` flag being set (spec §7.3 porting caveat).
struct Rig {
    brain: MascotBrain,
    t0: Instant,
    now: Instant,
    rng: fastrand::Rng,
}

impl Rig {
    fn mount(phase: MascotPhase) -> Self {
        Self::mount_greeting(phase, None)
    }

    /// `hour`: local hour of a not yet greeted app session.
    fn mount_greeting(phase: MascotPhase, hour: Option<u64>) -> Self {
        let now = Instant::now();
        let mut rng = fastrand::Rng::with_seed(7);
        let time_of_day = hour.map(|h| Duration::from_secs(h * 3600));
        let brain = MascotBrain::new(now, phase, time_of_day, &mut rng);
        Self {
            brain,
            t0: now,
            now,
            rng,
        }
    }

    fn send(&mut self, ev: MascotEvent) {
        self.brain.handle(ev, self.now, &mut self.rng);
    }

    /// Like fake timers: every deadline on the way fires at its own time.
    fn advance(&mut self, ms: u64) {
        self.now += Duration::from_millis(ms);
        self.brain.tick(self.now, &mut self.rng);
    }

    fn view(&self) -> MascotView {
        self.brain.view()
    }

    fn mood(&self) -> Mood {
        self.view().mood
    }

    fn speech(&self) -> Option<Speech> {
        self.view().speech
    }

    fn key(&self) -> String {
        self.speech()
            .map(|s| s.msg.key.into_owned())
            .unwrap_or_default()
    }
}

/// `key` is `<stem><n>` with `n < variants` (the old `^mascot\.<family>[0-n]$` matches).
fn in_family(key: &str, stem: &str, variants: usize) -> bool {
    key.strip_prefix(stem)
        .and_then(|n| n.parse::<usize>().ok())
        .is_some_and(|n| n < variants)
}

/// A generator whose next `f64()` satisfies `pred` (deterministic seed scan).
fn rng_where(pred: impl Fn(f64) -> bool) -> fastrand::Rng {
    (0u64..)
        .map(fastrand::Rng::with_seed)
        .find(|r| pred(r.clone().f64()))
        .unwrap()
}

/// useMascot.test.ts: "announces the build, then celebrates when the tunnel comes up".
#[test]
fn announces_the_build_then_celebrates() {
    let mut rig = Rig::mount(MascotPhase::Off);
    rig.send(MascotEvent::Phase(MascotPhase::Connecting));
    assert_eq!(rig.key(), "mascot.building");
    assert_eq!(rig.mood(), Mood::Scan);
    rig.send(MascotEvent::Phase(MascotPhase::On));
    assert!(
        in_family(&rig.key(), "mascot.connected", 3),
        "{}",
        rig.key()
    );
    assert_eq!(rig.mood(), Mood::Happy);
    assert_eq!(rig.view().fx, Some(Fx::Confetti));
}

/// useMascot.test.ts: "warns in the alert phase but never sends the user to the power button".
#[test]
fn alert_warns_but_never_nags() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::Phase(MascotPhase::Alert));
    assert_eq!(rig.key(), "mascot.alert");
    rig.advance(25_000);
    assert_eq!(rig.brain.perch(), Perch::Home);
    assert_ne!(rig.key(), "mascot.exposedNag");
}

/// useMascot.test.ts: "when genuinely exposed, hops onto the power button after 20 s".
#[test]
fn exposed_hops_onto_the_power_button_after_20s() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::Phase(MascotPhase::Off));
    assert_eq!(rig.key(), "mascot.exposed");
    rig.advance(20_000);
    assert_eq!(rig.brain.perch(), Perch::Toggle);
    assert_eq!(rig.key(), "mascot.exposedNag");
    // ... and returns home after 4.5 s on the button.
    rig.advance(4_500);
    assert_eq!(rig.brain.perch(), Perch::Home);
}

/// useMascot.test.ts: "falls asleep after 30 s without input and startles awake".
#[test]
fn falls_asleep_and_startles_awake() {
    let mut rig = Rig::mount(MascotPhase::Connecting);
    rig.advance(30_000);
    assert_eq!(rig.mood(), Mood::Sleep);
    assert_eq!(rig.view().fx, Some(Fx::Zzz));
    rig.send(MascotEvent::Activity { on_mascot: false });
    assert_eq!(rig.mood(), Mood::Scared);
    assert!(in_family(&rig.key(), "mascot.startle", 3), "{}", rig.key());
    assert_eq!(rig.view().body, BodyAnim::Startle);
}

/// useMascot.test.ts: "comments on a link that stays in the slow band for 30 s".
#[test]
fn comments_on_a_link_slow_for_30s() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::SpeedBand(1.5));
    rig.advance(29_000);
    assert_ne!(rig.key(), "mascot.slow");
    rig.advance(1_000);
    let speech = rig.speech().unwrap();
    assert_eq!(speech.msg, Msg::new("mascot.slow").arg("mbps", "1.5"));
}

/// useMascot.test.ts: "stays quiet about speed while idle (0 = nothing to say)".
#[test]
fn quiet_about_speed_while_idle() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::SpeedBand(0.0));
    rig.advance(31_000);
    assert_ne!(rig.key(), "mascot.slow");
}

/// useMascot.test.ts: "purrs while petted and asks to stop after 6 s of strokes".
#[test]
fn purrs_while_petted_then_asks_to_stop() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::Pet);
    assert_eq!(rig.mood(), Mood::Petted);
    assert_eq!(rig.view().fx, Some(Fx::Hearts));
    assert!(in_family(&rig.key(), "mascot.pet", 4), "{}", rig.key());
    assert!(rig.speech().unwrap().announce);
    for _ in 0..13 {
        rig.advance(500);
        rig.send(MascotEvent::Pet);
    }
    assert_eq!(rig.key(), "mascot.petEnough");
    assert_eq!(rig.mood(), Mood::Squint);
}

/// useMascot.test.ts: "stops looking petted shortly after the strokes stop".
#[test]
fn stops_looking_petted_after_the_strokes_stop() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::Pet);
    rig.advance(900);
    assert_eq!(rig.mood(), Mood::Calm);
}

/// Spec §7.3 extra: five pokes within 2.5 s make him dizzy, and the reply is announced.
#[test]
fn five_quick_pokes_make_him_dizzy() {
    let mut rig = Rig::mount(MascotPhase::On);
    for _ in 0..4 {
        rig.send(MascotEvent::Poke);
        rig.advance(500);
    }
    rig.send(MascotEvent::Poke);
    let view = rig.view();
    assert_eq!(view.mood, Mood::Dizzy);
    assert_eq!(view.body, BodyAnim::Spin);
    assert_eq!(rig.key(), "mascot.dizzy");
    assert!(rig.speech().unwrap().announce);
    // The count starts over: the next poke is an ordinary one.
    rig.send(MascotEvent::Poke);
    assert_ne!(rig.mood(), Mood::Dizzy);
}

/// Pokes spread wider than 2.5 s never add up to dizzy.
#[test]
fn slow_pokes_never_make_him_dizzy() {
    let mut rig = Rig::mount(MascotPhase::On);
    for _ in 0..8 {
        rig.send(MascotEvent::Poke);
        assert_ne!(rig.mood(), Mood::Dizzy);
        rig.advance(700);
    }
}

/// A poke winks 25 % of the time; otherwise the line fits the phase (useMascot.ts:371-376).
#[test]
fn poke_winks_or_answers_by_phase() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.rng = rng_where(|x| x < 0.25);
    rig.send(MascotEvent::Poke);
    assert_eq!(rig.mood(), Mood::Wink);
    assert!(in_family(&rig.key(), "mascot.wink", 2), "{}", rig.key());

    rig.advance(3_000);
    rig.rng = rng_where(|x| x >= 0.25);
    rig.send(MascotEvent::Poke);
    assert_eq!(rig.mood(), Mood::Happy);
    assert_eq!(rig.view().body, BodyAnim::Jump);
    assert!(in_family(&rig.key(), "mascot.pokeOn", 5), "{}", rig.key());
    assert!(rig.speech().unwrap().announce);
    rig.advance(1_200);
    assert_eq!(
        rig.mood(),
        Mood::Calm,
        "a poke reply holds the mood for 1.2 s"
    );

    for phase in [MascotPhase::Off, MascotPhase::Alert] {
        rig.send(MascotEvent::Phase(phase));
        rig.advance(3_000);
        rig.rng = rng_where(|x| x >= 0.25);
        rig.send(MascotEvent::Poke);
        assert_eq!(rig.mood(), Mood::Worried);
        assert!(in_family(&rig.key(), "mascot.pokeOff", 3), "{}", rig.key());
    }
}

/// Spec §7.3 extra: a burst of notifications gets one reaction (2.5 s throttle).
#[test]
fn notice_burst_gets_one_reaction() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::NoticeError);
    let first = rig.view();
    assert_eq!(first.mood, Mood::Scared);
    assert_eq!(first.fx, Some(Fx::Sweat));
    assert_eq!(first.body, BodyAnim::Startle);
    assert_eq!(rig.key(), "mascot.noticeError");
    rig.advance(1_000);
    rig.send(MascotEvent::NoticeError);
    rig.send(MascotEvent::NoticeOk);
    assert_eq!(rig.view().speech, first.speech, "no new line within 2.5 s");
    assert_eq!(rig.view().body_id, first.body_id);
    rig.advance(1_500);
    rig.send(MascotEvent::NoticeWarn);
    assert_eq!(rig.key(), "mascot.noticeWarn");
    assert_eq!(rig.mood(), Mood::Worried);
    rig.advance(2_500);
    rig.send(MascotEvent::NoticeOk);
    assert_eq!(rig.key(), "mascot.noticeOk");
    assert_eq!(rig.mood(), Mood::Happy);
}

/// Spec §7.3 extra: a fast band cheers, again 10 s later nothing (30 s cooldown); the same band
/// sent again is not a change.
#[test]
fn speed_spike_has_a_30s_cooldown() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::SpeedBand(80.0));
    assert_eq!(rig.mood(), Mood::Excited);
    assert_eq!(rig.view().fx, Some(Fx::Speed));
    assert_eq!(
        rig.speech().unwrap().msg,
        Msg::new("mascot.speed").arg("mbps", "80")
    );
    rig.advance(10_000);
    rig.send(MascotEvent::SpeedBand(90.0));
    assert_eq!(rig.speech(), None);
    assert_eq!(rig.mood(), Mood::Calm);
    rig.advance(25_000);
    rig.send(MascotEvent::SpeedBand(90.0));
    assert_eq!(rig.speech(), None, "an unchanged band is not news");
    rig.send(MascotEvent::SpeedBand(100.0));
    assert_eq!(rig.speech().unwrap().msg.args[0].1, "100");
}

/// Speed talk is for protected links only; a link that turns protected while fast cheers right
/// after the connect line (old effect order: transition, then spike).
#[test]
fn speed_reactions_need_phase_on() {
    let mut rig = Rig::mount(MascotPhase::Connecting);
    rig.send(MascotEvent::SpeedBand(80.0));
    assert_eq!(rig.speech(), None);
    rig.send(MascotEvent::Phase(MascotPhase::On));
    assert_eq!(rig.key(), "mascot.speed");
    assert_eq!(rig.view().fx_id, 2, "confetti, then speed");

    let mut rig = Rig::mount(MascotPhase::Alert);
    rig.send(MascotEvent::SpeedBand(1.0));
    rig.advance(31_000);
    assert_ne!(rig.key(), "mascot.slow");
}

/// The slow comment needs 30 s in the slow band without a break, and comes at most every 2 min.
#[test]
fn slow_comment_needs_an_unbroken_30s_and_a_2min_gap() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::SpeedBand(1.0));
    rig.advance(20_000);
    rig.send(MascotEvent::SpeedBand(0.0));
    rig.send(MascotEvent::SpeedBand(2.5));
    rig.advance(20_000);
    assert_ne!(rig.key(), "mascot.slow", "the 30 s restart after the break");
    rig.send(MascotEvent::SpeedBand(2.0));
    rig.advance(10_000);
    assert_eq!(
        rig.speech().unwrap().msg,
        Msg::new("mascot.slow").arg("mbps", "2.0")
    );
    // Another slow episode a minute later stays quiet (2 min gap).
    rig.send(MascotEvent::SpeedBand(0.0));
    rig.advance(30_000);
    rig.send(MascotEvent::SpeedBand(1.0));
    rig.advance(30_000);
    assert_ne!(rig.key(), "mascot.slow");
}

/// Greeting 700 ms after the first mount, by local hour; at night without the jump.
#[test]
fn greets_once_by_the_hour() {
    let cases = [
        (3, Mood::Sleep, "mascot.greetNight", BodyAnim::None),
        (9, Mood::Happy, "mascot.greetMorning", BodyAnim::Jump),
        (14, Mood::Happy, "mascot.greetDay", BodyAnim::Jump),
        (20, Mood::Calm, "mascot.greetEvening", BodyAnim::Jump),
    ];
    for (hour, mood, key, body) in cases {
        let mut rig = Rig::mount_greeting(MascotPhase::Off, Some(hour));
        rig.advance(699);
        assert_eq!(rig.speech(), None, "hour {hour}");
        rig.advance(1);
        assert_eq!(
            (rig.mood(), rig.key(), rig.view().body),
            (mood, key.to_owned(), body)
        );
        rig.advance(2_000);
        assert_eq!(rig.mood(), Mood::Worried, "the greeting mood lasts 2 s");
    }
}

/// Hovering the power button: eager when off, "sure?" when on, nothing in between.
#[test]
fn hover_reacts_by_phase() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::HoverIn);
    assert_eq!(rig.mood(), Mood::Squint);
    assert_eq!(rig.key(), "mascot.hoverSure");
    rig.advance(1_400);
    assert_eq!(rig.speech(), None);
    rig.send(MascotEvent::HoverOut);
    assert_eq!(rig.mood(), Mood::Calm);

    let mut rig = Rig::mount(MascotPhase::Off);
    rig.send(MascotEvent::HoverIn);
    assert_eq!((rig.mood(), rig.speech()), (Mood::Excited, None));
    // A phase change resets the hover mood.
    rig.send(MascotEvent::Phase(MascotPhase::Connecting));
    rig.advance(3_000);
    assert_eq!(rig.mood(), Mood::Scan);
    rig.send(MascotEvent::HoverIn);
    assert_eq!(rig.mood(), Mood::Scan);
}

/// Leak check, Smart RU and proxy actions hop onto their cell and come back home.
#[test]
fn ui_events_hop_to_their_perch_and_back() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::LeakStart);
    assert_eq!(rig.brain.perch(), Perch::Leak);
    assert_eq!((rig.mood(), rig.view().fx), (Mood::Think, Some(Fx::Dots)));
    assert_eq!(rig.key(), "mascot.leakStart");
    rig.send(MascotEvent::LeakFail);
    assert_eq!(rig.view().body, BodyAnim::Shake);
    assert_eq!(rig.key(), "mascot.leakFail");
    rig.advance(2_600);
    assert_eq!(rig.brain.perch(), Perch::Home);

    rig.send(MascotEvent::SmartOn);
    assert_eq!((rig.brain.perch(), rig.mood()), (Perch::Smart, Mood::Wink));
    rig.send(MascotEvent::SmartOff);
    assert_eq!(
        (rig.mood(), rig.key()),
        (Mood::Think, "mascot.smartOff".to_owned())
    );
    rig.advance(2_600);
    assert_eq!(rig.brain.perch(), Perch::Home);

    rig.send(MascotEvent::ProxyStopAll);
    assert_eq!(
        (rig.brain.perch(), rig.mood()),
        (Perch::Proxies, Mood::Squint)
    );
    assert_eq!(rig.key(), "mascot.proxyStopAll");
    rig.advance(2_999);
    assert_eq!(rig.brain.perch(), Perch::Proxies);
    rig.advance(1);
    assert_eq!(rig.brain.perch(), Perch::Home);

    // The stage lost the spot: home at once, and the pending return is void.
    rig.send(MascotEvent::ProxyStart);
    rig.send(MascotEvent::GoHome);
    assert_eq!(rig.brain.perch(), Perch::Home);
}

/// Every 25–45 s, protected, awake and at home: a stroll to one of the wander spots.
#[test]
fn wanders_only_when_protected_awake_and_home() {
    let mut rig = Rig::mount(MascotPhase::On);
    let mut spot = None;
    for _ in 0..45 {
        rig.advance(1_000);
        rig.send(MascotEvent::Activity { on_mascot: false });
        if rig.brain.perch() != Perch::Home {
            spot = Some(rig.brain.perch());
            break;
        }
    }
    let spot = spot.expect("a stroll within 45 s");
    let wander_keys = [
        (Perch::Toggle, "mascot.wanderToggle"),
        (Perch::Clock, "mascot.wanderClock"),
        (Perch::Servers, "mascot.wanderServers"),
        (Perch::Proxies, "mascot.wanderProxies"),
    ];
    assert!(
        wander_keys.contains(&(spot, rig.key().as_str())),
        "{spot:?} {}",
        rig.key()
    );
    rig.advance(4_500);
    assert_eq!(rig.brain.perch(), Perch::Home);

    for phase in [MascotPhase::Alert, MascotPhase::Connecting] {
        let mut rig = Rig::mount(phase);
        for _ in 0..100 {
            rig.advance(1_000);
            rig.send(MascotEvent::Activity { on_mascot: false });
            assert_eq!(rig.brain.perch(), Perch::Home);
        }
    }
    // Asleep he stays put (35 s: a stroll begun just before falling asleep is over by then).
    let mut rig = Rig::mount(MascotPhase::On);
    rig.advance(35_000);
    for _ in 0..100 {
        rig.advance(1_000);
        assert_eq!(rig.brain.perch(), Perch::Home);
    }
}

/// A stroke wakes him gently: no startle, the petting takes over.
#[test]
fn a_stroke_wakes_him_gently() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.advance(40_000);
    assert_eq!(rig.mood(), Mood::Sleep);
    rig.send(MascotEvent::Activity { on_mascot: true });
    assert_eq!((rig.mood(), rig.speech()), (Mood::Calm, None));
    rig.send(MascotEvent::Pet);
    assert_eq!(rig.mood(), Mood::Petted);
}

/// Theme switches get a remark; the first value and repeats do not.
#[test]
fn remarks_on_theme_switches_only() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::ThemeDark(false));
    assert_eq!(rig.speech(), None);
    rig.send(MascotEvent::ThemeDark(true));
    assert_eq!(
        (rig.mood(), rig.key()),
        (Mood::Calm, "mascot.themeDark".to_owned())
    );
    let id = rig.speech().unwrap().id;
    rig.send(MascotEvent::ThemeDark(true));
    assert_eq!(rig.speech().unwrap().id, id);
    rig.send(MascotEvent::ThemeDark(false));
    assert_eq!(
        (rig.mood(), rig.key()),
        (Mood::Squint, "mascot.themeLight".to_owned())
    );
}

/// Session milestones land exactly on the 10-minute marks; whole hours get confetti.
#[test]
fn milestones_every_ten_minutes() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::SessionAge(Some(Duration::from_secs(
        9 * 60 + 59,
    ))));
    rig.advance(999);
    assert_eq!(rig.speech(), None);
    rig.advance(1);
    assert_eq!(
        rig.speech().unwrap().msg,
        Msg::new("mascot.milestoneMin").arg("minutes", 10)
    );
    assert_eq!((rig.mood(), rig.view().body), (Mood::Happy, BodyAnim::Jump));

    rig.advance(49 * 60_000 + 59_000);
    assert_ne!(rig.key(), "mascot.milestoneHour");
    rig.advance(1_000);
    assert_eq!(
        rig.speech().unwrap().msg,
        Msg::new("mascot.milestoneHour").arg("hours", 1)
    );
    assert_eq!(
        (rig.mood(), rig.view().fx),
        (Mood::Love, Some(Fx::Confetti))
    );

    // Off protection the count pauses; back on, marks already passed are skipped.
    rig.send(MascotEvent::Phase(MascotPhase::Alert));
    rig.advance(25 * 60_000);
    rig.send(MascotEvent::Phase(MascotPhase::On));
    rig.advance(4 * 60_000);
    assert_ne!(rig.key(), "mascot.milestoneMin");
    rig.advance(60_000);
    assert_eq!(
        rig.speech().unwrap().msg,
        Msg::new("mascot.milestoneMin").arg("minutes", 90)
    );
    // No session, no milestones.
    rig.send(MascotEvent::SessionAge(None));
    rig.advance(3_600_000);
    assert_eq!(rig.speech(), None);
}

/// D-13: on another page his timers freeze (no wake-ups, no burst on return) and a page switch
/// is not "welcome back".
#[test]
fn page_switch_freezes_timers_silently() {
    let mut rig = Rig::mount(MascotPhase::Off);
    rig.advance(5_000);
    rig.send(MascotEvent::PageActive(false));
    assert_eq!(rig.brain.next_deadline(), None);
    rig.advance(60_000);
    assert_eq!(rig.brain.perch(), Perch::Home);
    rig.send(MascotEvent::PageActive(true));
    assert_eq!((rig.mood(), rig.speech()), (Mood::Worried, None));
    assert!(rig.brain.next_deadline().is_some());
    // 15 s of the 20 s nag were left when he was put away.
    rig.advance(14_999);
    assert_eq!(rig.brain.perch(), Perch::Home);
    rig.advance(1);
    assert_eq!(rig.brain.perch(), Perch::Toggle);
    assert_eq!(rig.key(), "mascot.exposedNag");
}

/// Back to the window after more than 5 s: "welcome back".
#[test]
fn welcome_back_after_more_than_5s_hidden() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::Visible(false));
    rig.advance(5_000);
    rig.send(MascotEvent::Visible(true));
    assert_eq!(rig.speech(), None, "5 s is not away");
    rig.send(MascotEvent::Visible(false));
    rig.advance(5_001);
    rig.send(MascotEvent::Visible(true));
    assert_eq!(
        (rig.mood(), rig.key()),
        (Mood::Love, "mascot.welcomeBack".to_owned())
    );
    assert_eq!(rig.view().body, BodyAnim::Jump);
}

/// While away: reactions are dropped (toasts do not use up the throttle), state still follows the
/// tunnel, and he wakes quietly on return.
#[test]
fn away_drops_reactions_but_keeps_state() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.advance(40_000);
    assert_eq!(rig.mood(), Mood::Sleep);
    rig.send(MascotEvent::PageActive(false));
    rig.send(MascotEvent::NoticeError);
    rig.send(MascotEvent::Phase(MascotPhase::Off));
    rig.send(MascotEvent::Activity { on_mascot: false });
    rig.advance(2_000);
    rig.send(MascotEvent::PageActive(true));
    assert_eq!((rig.mood(), rig.speech()), (Mood::Worried, None));
    rig.send(MascotEvent::NoticeError);
    assert_eq!(rig.key(), "mascot.noticeError");
    rig.advance(20_000);
    assert_eq!(
        rig.brain.perch(),
        Perch::Toggle,
        "the nag armed while away still comes"
    );
}

/// D-13: a timer armed while he is away (exposed nag, slow comment) runs its full delay from the
/// return; the time away before the event is not added on top.
#[test]
fn timers_armed_while_away_count_from_the_return() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::PageActive(false));
    rig.advance(10_000);
    rig.send(MascotEvent::Phase(MascotPhase::Off));
    rig.advance(5_000);
    rig.send(MascotEvent::PageActive(true));
    rig.advance(19_999);
    assert_eq!(rig.brain.perch(), Perch::Home);
    rig.advance(1);
    assert_eq!(rig.brain.perch(), Perch::Toggle);

    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::PageActive(false));
    rig.advance(10_000);
    rig.send(MascotEvent::SpeedBand(1.0));
    rig.advance(5_000);
    rig.send(MascotEvent::PageActive(true));
    rig.advance(29_999);
    assert_ne!(rig.key(), "mascot.slow");
    rig.advance(1);
    assert_eq!(rig.key(), "mascot.slow");
}

/// Petting cut short by a page switch goes on after the return: the time away does not count
/// towards the 6 s after which he asks to stop.
#[test]
fn petting_resumes_after_a_page_switch() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::Pet);
    rig.advance(500);
    rig.send(MascotEvent::PageActive(false));
    rig.advance(10_000);
    rig.send(MascotEvent::PageActive(true));
    rig.advance(100);
    rig.send(MascotEvent::Pet);
    assert_eq!(rig.mood(), Mood::Petted);
}

/// Started in the tray: the greeting waits for the window, beats "welcome back" and fits the hour
/// he is first shown at (autostart at 10:00, window opened at 12:00).
#[test]
fn greeting_waits_for_the_window() {
    let mut rig = Rig::mount_greeting(MascotPhase::On, Some(10));
    rig.send(MascotEvent::Visible(false));
    rig.advance(2 * 3_600_000);
    assert_eq!(rig.speech(), None);
    rig.send(MascotEvent::Visible(true));
    assert_eq!(rig.speech(), None);
    rig.advance(700);
    assert_eq!(rig.key(), "mascot.greetDay");
}

/// The host loop (sleep until `next_deadline`, tick) over a two-hour session: deadlines always
/// move forward and the session gets twelve milestones, two of them hours.
#[test]
fn host_loop_runs_a_two_hour_session() {
    let mut rig = Rig::mount(MascotPhase::On);
    rig.send(MascotEvent::SessionAge(Some(Duration::ZERO)));
    let end = rig.t0 + Duration::from_secs(2 * 3600);
    let (mut minutes, mut hours, mut last_id) = (0, 0, 0);
    while let Some(due) = rig.brain.next_deadline() {
        assert!(due > rig.now, "a tick leaves no deadline behind");
        if due > end {
            break;
        }
        rig.now = due;
        rig.brain.tick(due, &mut rig.rng);
        if let Some(speech) = rig.speech()
            && speech.id != last_id
        {
            last_id = speech.id;
            match speech.msg.key.as_ref() {
                "mascot.milestoneMin" => minutes += 1,
                "mascot.milestoneHour" => hours += 1,
                _ => {}
            }
        }
    }
    assert_eq!((minutes, hours), (10, 2));
}

/// Names shared with the markup and the CSS.
#[test]
fn markup_names() {
    assert_eq!(BodyAnim::None.class(), "");
    assert_eq!(BodyAnim::Startle.class(), "m-startle");
    assert_eq!(Mood::Petted.as_str(), "petted");
    assert_eq!(Fx::Zzz.as_str(), "zzz");
    assert_eq!(Perch::Proxies.as_str(), "proxies");
    assert_eq!(Perch::default(), Perch::Home);
}

/// Every line the brain can say exists, non-empty and with its placeholders, in both languages of
/// the UI's base locale layer (the old app's `mascot.*` strings, reused as they are); the numbered
/// families have exactly the variant counts the brain draws from. The crate's fragments are
/// checked by `test_locales`.
#[test]
fn every_line_exists_in_ru_and_en() {
    let families = [
        ("connected", 3),
        ("pokeOn", 5),
        ("pokeOff", 3),
        ("wink", 2),
        ("startle", 3),
        ("pet", 4),
    ];
    let lines = [
        "name",
        "greetNight",
        "greetMorning",
        "greetDay",
        "greetEvening",
        "dizzy",
        "cancelled",
        "exposed",
        "exposedNag",
        "alert",
        "building",
        "switching",
        "milestoneMin",
        "milestoneHour",
        "speed",
        "slow",
        "petEnough",
        "wanderToggle",
        "wanderClock",
        "wanderServers",
        "wanderProxies",
        "proxyStart",
        "proxyRotate",
        "proxyStop",
        "proxyStopAll",
        "noticeError",
        "noticeWarn",
        "noticeOk",
        "leakStart",
        "leakOk",
        "leakWarn",
        "leakFail",
        "smartOn",
        "smartOff",
        "welcomeBack",
        "themeDark",
        "themeLight",
        "hoverSure",
    ];
    // The arguments the brain passes; each template must use its own.
    let args = [
        ("milestoneMin", "minutes"),
        ("milestoneHour", "hours"),
        ("speed", "mbps"),
        ("slow", "mbps"),
    ];
    assert_eq!(format!("mascot.{}", lines[0]), LABEL_KEY);
    let catalogs = crate::test_locales::catalogs();
    let numbered = families
        .iter()
        .flat_map(|&(stem, n)| (0..n).map(move |i| format!("{stem}{i}")));
    for key in lines.iter().map(|k| k.to_string()).chain(numbered) {
        let mut msg = Msg::new(format!("mascot.{key}"));
        for &(_, name) in args.iter().filter(|(k, _)| *k == key) {
            msg = msg.arg(name, 1);
        }
        crate::test_locales::assert_resolves(&msg, &catalogs);
        for cat in &catalogs {
            let text = &cat[msg.key.as_ref()];
            assert!(!text.is_empty(), "{} is empty", msg.key);
            for (name, _) in &msg.args {
                let placeholder = format!("{{{{{name}}}}}");
                assert!(
                    text.contains(&placeholder),
                    "{} lacks {placeholder}",
                    msg.key
                );
            }
        }
    }
    for cat in &catalogs {
        for (stem, variants) in families {
            let unused = format!("mascot.{stem}{variants}");
            assert!(!cat.contains_key(&unused), "unused {unused}");
        }
    }
}

/// p-follow3: in Proxy mode, and while the mode is unknown, neither the connected line nor a
/// poke says «Туннель» (nothing is a tunnel there); Tunnel mode keeps its tunnel lines.
#[test]
fn session_lines_follow_the_mode() {
    use crate::swiss::Mode;
    let catalogs = crate::test_locales::catalogs();
    let tunnel = |key: &str| {
        catalogs.iter().any(|c| {
            let text = c.get(key).map(|t| t.to_lowercase()).unwrap_or_default();
            text.contains("туннел") || text.contains("tunnel")
        })
    };
    let lines = |mode: Option<Mode>, seed: u64| {
        let mut rig = Rig::mount(MascotPhase::Off);
        rig.rng = fastrand::Rng::with_seed(seed);
        rig.send(MascotEvent::Mode(mode));
        rig.send(MascotEvent::Phase(MascotPhase::On));
        let connected = rig.key();
        rig.send(MascotEvent::Poke);
        (connected, rig.key())
    };
    let mut tun_said = std::collections::BTreeSet::new();
    for seed in 0..60 {
        for mode in [Some(Mode::Soft), None] {
            let (connected, poke) = lines(mode, seed);
            assert!(
                !connected.is_empty() && !tunnel(&connected),
                "{mode:?}: {connected}"
            );
            assert!(!poke.is_empty() && !tunnel(&poke), "{mode:?}: {poke}");
        }
        tun_said.insert(lines(Some(Mode::Tun), seed).0);
    }
    assert!(tun_said.contains("mascot.connected0"), "{tun_said:?}");
    let proxy: Vec<String> = (0..60)
        .map(|seed| lines(Some(Mode::Soft), seed).0)
        .collect();
    assert!(
        proxy.iter().any(|k| k == "view.mascot.connectedProxy0"),
        "{proxy:?}"
    );
}
