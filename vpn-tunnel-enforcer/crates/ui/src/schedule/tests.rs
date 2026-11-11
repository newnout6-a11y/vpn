//! Tests of the Schedule page (ui-pages §3.11, §7.12-§7.14, automation S3 / S6 / S7) and the
//! catalog checks of the whole `ui-lists` package (the helpers are shared with the other pages).
use jiff::civil::date;
use jiff::tz::TimeZone;
use vpnte_base::Msg;
use vpnte_base::i18n::Lang;

use super::demo::next_event;
use super::*;

pub(crate) use crate::test_locales::text as lookup;

/// A message in `lang` through the catalog as the app registers it; the key must exist in `lang`
/// itself (the checks allow no English fallback).
pub(crate) fn render(lang: Lang, msg: &Msg) -> String {
    assert!(
        lookup(lang, &msg.key).is_some(),
        "missing key {} ({lang:?})",
        msg.key
    );
    crate::test_locales::init_locales();
    msg.render(lang)
}

pub(crate) fn ru(msg: &Msg) -> String {
    render(Lang::Ru, msg)
}

pub(crate) fn en(msg: &Msg) -> String {
    render(Lang::En, msg)
}

/// AT-09-011: every literal key the package's sources pass to `t!` or `Msg::new` exists in
/// both languages (dynamic keys are checked by iterating their enums in the page tests).
#[test]
fn every_literal_key_exists() {
    let sources = [
        include_str!("page.rs"),
        include_str!("editor.rs"),
        include_str!("form.rs"),
        include_str!("../split_tunnel/page.rs"),
        include_str!("../split_tunnel/model.rs"),
        include_str!("../traffic_history/page.rs"),
        include_str!("../traffic_history/model.rs"),
    ];
    let mut checked = 0;
    for source in sources {
        for opener in ["t!(\"", "Msg::new(\""] {
            for (at, _) in source.match_indices(opener) {
                // `format!("…")` contains `t!("` too: the macro name must start a word.
                let before = source[..at].chars().next_back().unwrap_or(' ');
                if before.is_alphanumeric() || before == '_' {
                    continue;
                }
                let rest = &source[at + opener.len()..];
                let key = rest.split('"').next().unwrap_or_default();
                for lang in [Lang::Ru, Lang::En] {
                    let plural = format!("{key}_other");
                    assert!(
                        lookup(lang, key).is_some() || lookup(lang, &plural).is_some(),
                        "missing {key} ({lang:?})"
                    );
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 40, "only {checked} keys found");
}

fn hm(text: &str) -> HhMm {
    HhMm::parse(text).expect("valid time")
}

/// automation S7: only the strict `H:MM` / `HH:MM` forms parse; stored back as `HH:MM`.
#[test]
fn times_parse_strictly() {
    assert_eq!(hm("9:05").to_string(), "09:05");
    assert_eq!(hm("23:59").minutes(), 23 * 60 + 59);
    assert_eq!(hm("00:00").minutes(), 0);
    for bad in [
        "9:5", " 9:05", "09:30abc", "1e1:00", "-0:00", "24:00", "12:60", "", ":", "123:00",
    ] {
        assert_eq!(HhMm::parse(bad), None, "{bad:?}");
    }
}

/// ui-pages §7.14 (U-25): days are listed Monday first — `[0, 1, 6]` → «Пн, Сб, Вс» (the old
/// card said «Вс, Пн, Сб»).
#[test]
fn days_are_listed_monday_first() {
    let names: Vec<String> = days_keys(&[0, 1, 6])
        .into_iter()
        .map(|k| ru(&Msg::new(k)))
        .collect();
    assert_eq!(names.join(", "), "Пн, Сб, Вс");
    assert_eq!(days_keys(&[6, 6, 9]), ["schedule.saturday"]);
    for day in DISPLAY_ORDER {
        assert!(
            lookup(Lang::Ru, day_key(day)).is_some() && lookup(Lang::En, day_key(day)).is_some()
        );
    }
}

/// ui-pages §7.13 `formatTimeUntil`, with unit words from the catalog.
#[test]
fn countdown_text() {
    const H: i64 = 3_600_000;
    let now = 1_000_000;
    assert_eq!(en(&time_until(now + 25 * H, now)), "1d 1h");
    assert_eq!(en(&time_until(now + 24 * H, now)), "24h 0m");
    assert_eq!(en(&time_until(now + 90 * 60_000, now)), "1h 30m");
    assert_eq!(en(&time_until(now + 30_000, now)), "0m");
    assert_eq!(en(&time_until(now - H, now)), "0m");
    assert_eq!(ru(&time_until(now + 25 * H, now)), "1 д 1 ч");
    assert_eq!(ru(&time_until(now + 65 * 60_000, now)), "1 ч 5 мин");
}

/// The countdown re-renders when its minute changes, and stops once the moment passed.
#[test]
fn countdown_retimes_on_the_minute() {
    use std::time::Duration;
    let now = 5_000_000;
    assert_eq!(
        until_next_change(now + 90_000, now),
        Some(Duration::from_millis(30_020))
    );
    assert_eq!(
        until_next_change(now + 120_000, now),
        Some(Duration::from_millis(60_020))
    );
    assert_eq!(until_next_change(now, now), None);
}

/// ui-pages §7.12: the next-event line interpolates action, time and countdown.
#[test]
fn next_event_line() {
    let line = |action: &str| {
        Msg::new("dashboardWidgets.scheduleAt")
            .arg("action", action)
            .arg("time", "09:00")
            .arg("until", "1h 5m")
    };
    assert_eq!(ru(&line("Подключить")), "Подключить в 09:00 (через 1h 5m)");
    assert_eq!(en(&line("Connect")), "Connect at 09:00 (1h 5m)");
}

/// U-25 / automation S3: start == end is a whole day, an earlier end is the next day.
#[test]
fn window_hints() {
    assert_eq!(
        ru(&window_hint(hm("09:00"), hm("09:00")).expect("hint")),
        "Весь день"
    );
    assert_eq!(
        ru(&window_hint(hm("23:00"), hm("04:00")).expect("hint")),
        "до 04:00 следующего дня"
    );
    assert_eq!(window_hint(hm("09:00"), hm("18:00")), None);
}

fn servers() -> Vec<ServerChoice> {
    vec![ServerChoice {
        id: "srv-1".into(),
        name: "Germany".into(),
        protocol: "VLESS".into(),
    }]
}

/// The form: name, at least one day and two valid times are required; the server matters only
/// for Direct (empty = current server, a deleted one is refused); Hard / Soft drop it (S6).
#[test]
fn form_validation() {
    let mut form = ScheduleForm::default();
    assert_eq!(form.input(&servers()), Err(FormProblem::Name));
    form.name = "  Работа ".into();
    assert_eq!(form.input(&servers()), Err(FormProblem::Days));
    form.toggle_day(5);
    form.toggle_day(1);
    form.toggle_day(3);
    form.toggle_day(3);
    let input = form.input(&servers()).expect("valid");
    assert_eq!(input.name, "Работа");
    assert_eq!(input.days, [1, 5]);
    assert_eq!(
        (input.start.to_string(), input.end.to_string()),
        ("09:00".into(), "18:00".into())
    );
    assert!(input.enabled);

    form.start = "9:5".into();
    assert_eq!(form.input(&servers()), Err(FormProblem::Start));
    form.start = "22:30".into();
    form.end = "".into();
    assert_eq!(form.input(&servers()), Err(FormProblem::End));
    form.end = "06:00".into();
    assert_eq!(
        form.hint().map(|m| ru(&m)),
        Some("до 06:00 следующего дня".into())
    );

    form.profile_id = "srv-gone".into();
    assert_eq!(
        form.input(&servers()).expect("hard ignores it").profile_id,
        ""
    );
    form.mode = ScheduleMode::Direct;
    assert_eq!(form.input(&servers()), Err(FormProblem::Server));
    form.profile_id = "srv-1".into();
    assert_eq!(
        form.input(&servers()).expect("known server").profile_id,
        "srv-1"
    );
    form.profile_id.clear();
    assert_eq!(
        form.input(&servers()).expect("current server").profile_id,
        ""
    );
    for problem in [
        FormProblem::Name,
        FormProblem::Days,
        FormProblem::Start,
        FormProblem::End,
        FormProblem::Server,
    ] {
        assert!(lookup(Lang::Ru, problem.msg_key()).is_some(), "{problem:?}");
        assert!(lookup(Lang::En, problem.msg_key()).is_some(), "{problem:?}");
    }
    for mode in ScheduleMode::ALL {
        assert!(lookup(Lang::En, mode.label_key()).is_some());
    }
}

/// Editing fills the form from the stored schedule and keeps its id.
#[test]
fn edit_round_trip() {
    let entry = ScheduleEntry {
        id: "s-1".into(),
        name: "Ночь".into(),
        enabled: false,
        days: vec![0, 6],
        start: hm("23:00"),
        end: hm("04:00"),
        profile_id: "srv-1".into(),
        mode: ScheduleMode::Direct,
    };
    let form = ScheduleForm::edit(&entry);
    assert_eq!(form.editing.as_deref(), Some("s-1"));
    let input = form.input(&servers()).expect("valid");
    assert_eq!(input.days, entry.days);
    assert_eq!(
        (input.start, input.end, input.enabled),
        (entry.start, entry.end, false)
    );
    assert_eq!(server_label(&entry, &servers()), Some(Ok("Germany".into())));
    let gone = ScheduleEntry {
        profile_id: "srv-x".into(),
        ..entry.clone()
    };
    assert_eq!(
        server_label(&gone, &servers()).map(|r| r.map_err(|m| ru(&m))),
        Some(Err("сервер не найден".into()))
    );
    let hard = ScheduleEntry {
        mode: ScheduleMode::Hard,
        ..entry
    };
    assert_eq!(server_label(&hard, &servers()), None);
}

/// The demo's next event (fixed zone and clock): inside a weekday window the next event is
/// its stop; after it, the next start; an overnight window stops the next morning.
#[test]
fn demo_next_event() {
    let tz = TimeZone::UTC;
    let ms = |d: jiff::civil::DateTime| {
        d.to_zoned(tz.clone())
            .expect("valid")
            .timestamp()
            .as_millisecond()
    };
    let work = ScheduleEntry {
        id: "w".into(),
        name: "Работа".into(),
        enabled: true,
        days: vec![1, 2, 3, 4, 5],
        start: hm("09:00"),
        end: hm("19:00"),
        profile_id: String::new(),
        mode: ScheduleMode::Hard,
    };
    // 2026-11-11 is a Wednesday.
    let noon = ms(date(2026, 11, 11).at(12, 0, 0, 0));
    let next = next_event(std::slice::from_ref(&work), &tz, noon).expect("event");
    assert_eq!(
        (next.action, next.at),
        (NextAction::Stop, ms(date(2026, 11, 11).at(19, 0, 0, 0)))
    );
    let evening = ms(date(2026, 11, 11).at(20, 0, 0, 0));
    let next = next_event(std::slice::from_ref(&work), &tz, evening).expect("event");
    assert_eq!(
        (next.action, next.at),
        (NextAction::Start, ms(date(2026, 11, 12).at(9, 0, 0, 0)))
    );
    let night = ScheduleEntry {
        days: vec![3],
        start: hm("23:00"),
        end: hm("04:00"),
        ..work.clone()
    };
    let late = ms(date(2026, 11, 11).at(23, 30, 0, 0));
    let next = next_event(&[night], &tz, late).expect("event");
    assert_eq!(
        (next.action, next.at),
        (NextAction::Stop, ms(date(2026, 11, 12).at(4, 0, 0, 0)))
    );
    let off = ScheduleEntry {
        enabled: false,
        ..work
    };
    assert_eq!(next_event(&[off], &tz, noon), None);
}

/// VirtualDom runs: the three pages of the package mount over every demo scene and render
/// without a panic (no WebView: mutations are dropped).
mod dom {
    use std::rc::Rc;
    use std::time::Duration;

    use dioxus::core::NoOpMutations;
    use dioxus::prelude::*;

    use crate::schedule::demo::DemoSchedule;
    use crate::schedule::{ScheduleApi, SchedulePage};
    use crate::split_tunnel::demo::DemoSplitTunnel;
    use crate::split_tunnel::{SplitTunnelApi, SplitTunnelPage};
    use crate::traffic_history::demo::DemoTrafficHistory;
    use crate::traffic_history::{TrafficHistoryApi, TrafficHistoryPage};
    use crate::widgets::Toasts;

    #[derive(Clone)]
    struct Scene(&'static str);

    fn root() -> Element {
        let scene = use_context::<Scene>().0;
        use_context_provider(|| Rc::new(DemoSchedule::new(scene).instant()) as Rc<dyn ScheduleApi>);
        use_context_provider(|| {
            Rc::new(DemoSplitTunnel::new(scene).instant()) as Rc<dyn SplitTunnelApi>
        });
        use_context_provider(|| {
            Rc::new(DemoTrafficHistory::new(scene, vpnte_base::types::now_ms()).instant())
                as Rc<dyn TrafficHistoryApi>
        });
        Toasts::use_provider();
        rsx! {
            SchedulePage {}
            SplitTunnelPage {}
            TrafficHistoryPage {}
        }
    }

    #[tokio::test]
    async fn every_scene_renders() {
        for scene in ["full", "empty", "loading", "failed", "errors", "many"] {
            let mut dom = VirtualDom::new(root).with_root_context(Scene(scene));
            dom.rebuild_in_place();
            for _ in 0..6 {
                tokio::select! {
                    () = dom.wait_for_work() => {}
                    () = tokio::time::sleep(Duration::from_millis(60)) => {}
                }
                dom.render_immediate(&mut NoOpMutations);
            }
        }
    }
}
