use super::*;
use jiff::civil::date;

fn zone(name: &str) -> TimeZone {
    TimeZone::get(name).unwrap()
}

/// No DST since 2014: the old "local" fixtures (2024-01-10 is a Wednesday) without surprises.
fn msk() -> TimeZone {
    zone("Europe/Moscow")
}

fn at(tz: &TimeZone, day: i8, h: i8, m: i8) -> Timestamp {
    tz.to_timestamp(date(2024, 1, day).at(h, m, 0, 0)).unwrap()
}

fn ts(text: &str) -> Timestamp {
    text.parse().unwrap()
}

fn entry(id: &str, days: &[u8], start: &str, end: &str) -> ScheduleEntry {
    ScheduleEntry {
        id: id.into(),
        name: id.into(),
        enabled: true,
        days: days.to_vec(),
        start_time: start.parse().unwrap(),
        end_time: end.parse().unwrap(),
        profile_id: String::new(),
        capture: Capture::Tun,
        upstream: Upstream::LocalProxy,
    }
}

const WED: u8 = 3;
const THU: u8 = 4;
const SUN: u8 = 0;
const MON_FRI: [u8; 5] = [1, 2, 3, 4, 5];

fn ms(n: i64) -> jiff::Span {
    n.milliseconds()
}

/// `parseTimeToMinutes` vectors plus the strict-form additions of fix S7.
#[test]
fn strict_time_parser() {
    let ok = |s: &str| s.parse::<HhMm>().map(HhMm::minutes);
    assert_eq!(ok("00:00"), Ok(0));
    assert_eq!(ok("09:30"), Ok(570));
    assert_eq!(ok("23:59"), Ok(1439));
    assert_eq!(ok("9:05"), Ok(545));
    for bad in [
        "", "abc", "25:00", "24:00", "12:60", "9:5", "09:30abc", "1e1:00", " 9:05", "-0:00",
        "1:2:3", "009:00",
    ] {
        assert_eq!(ok(bad), Err(InvalidTime), "{bad:?}");
    }
    assert_eq!(HhMm::new(9, 5).unwrap().to_string(), "09:05");
}

/// Old lenient rules survive for stored / imported values only: `"9:5"` is stored as `"09:05"`.
#[test]
fn lenient_parser_matches_the_old_parse_int_rules() {
    let lenient = |s: &str| HhMm::parse_lenient(s).map(|t| t.to_string());
    assert_eq!(lenient("9:5").as_deref(), Some("09:05"));
    assert_eq!(lenient("09:30abc").as_deref(), Some("09:30"));
    assert_eq!(lenient("1e1:00").as_deref(), Some("01:00"));
    assert_eq!(lenient(" 9:05").as_deref(), Some("09:05"));
    assert_eq!(lenient("-0:00").as_deref(), Some("00:00"));
    for bad in [
        "",
        "abc",
        "25:00",
        "12:60",
        "-1:00",
        "1:2:3",
        ":30",
        "99999999999999999999:00",
    ] {
        assert_eq!(lenient(bad), None, "{bad:?}");
    }
    let t: HhMm = serde_json::from_str("\"9:5\"").unwrap();
    assert_eq!(serde_json::to_string(&t).unwrap(), "\"09:05\"");
}

/// `isScheduleActive` (scheduler.test.ts): `[start, stop)`, weekday of the start day.
#[test]
fn is_active_basics() {
    let tz = msk();
    let wed = entry("a", &[WED], "09:00", "17:00");
    assert!(is_active(&wed, &tz, at(&tz, 10, 12, 0)));
    assert!(!is_active(&wed, &tz, at(&tz, 10, 8, 59)));
    assert!(is_active(&wed, &tz, at(&tz, 10, 9, 0)));
    assert!(!is_active(&wed, &tz, at(&tz, 10, 17, 0)));
    let workdays = entry("b", &MON_FRI, "09:00", "17:00");
    assert!(!is_active(&workdays, &tz, at(&tz, 7, 12, 0)), "Sunday");
    let disabled = ScheduleEntry {
        enabled: false,
        ..wed.clone()
    };
    assert!(!is_active(&disabled, &tz, at(&tz, 10, 12, 0)));
    let no_days = ScheduleEntry {
        days: vec![],
        ..wed
    };
    assert!(!is_active(&no_days, &tz, at(&tz, 10, 12, 0)));
}

/// `computeNextEvent` basics: none, disabled, start ahead, stop ahead; always after `now`.
#[test]
fn next_event_basics() {
    let tz = msk();
    assert_eq!(next_event(&[], &tz, at(&tz, 10, 7, 0)), None);
    let mut off = entry("a", &[WED], "09:00", "17:00");
    off.enabled = false;
    assert_eq!(next_event(&[off], &tz, at(&tz, 10, 7, 0)), None);
    let wed = [entry("a", &[WED], "09:00", "17:00")];
    let start = next_event(&wed, &tz, at(&tz, 10, 7, 0));
    assert_eq!(
        start,
        Some(NextEvent::Start {
            at: at(&tz, 10, 9, 0),
            entry: 0
        })
    );
    let stop = next_event(&wed, &tz, at(&tz, 10, 12, 0));
    assert_eq!(
        stop,
        Some(NextEvent::Stop {
            at: at(&tz, 10, 17, 0),
            entry: 0
        })
    );
    let at_start = next_event(&wed, &tz, at(&tz, 10, 9, 0)).unwrap();
    assert!(at_start.at() > at(&tz, 10, 9, 0));
}

/// AT-10-002: a stop of one schedule never ends protection another one still covers.
#[test]
fn combined_window_across_overlapping_schedules() {
    let tz = msk();
    let both = [
        entry("s1", &[WED], "09:00", "17:00"),
        entry("s2", &[WED], "15:30", "20:00"),
    ];
    let next = next_event(&both, &tz, at(&tz, 10, 15, 0));
    assert_eq!(
        next,
        Some(NextEvent::Stop {
            at: at(&tz, 10, 20, 0),
            entry: 1
        })
    );
}

/// Overnight window plus the next morning's window, in both orders (scheduler.test.ts:300-308).
#[test]
fn overnight_window_merges_with_the_next_morning() {
    let tz = msk();
    let night = entry("night", &[WED], "22:00", "06:00");
    let morning = entry("morning", &[THU], "05:00", "08:00");
    let now = at(&tz, 11, 2, 0);
    let a = next_event(&[night.clone(), morning.clone()], &tz, now);
    assert_eq!(
        a,
        Some(NextEvent::Stop {
            at: at(&tz, 11, 8, 0),
            entry: 1
        })
    );
    let b = next_event(&[morning, night], &tz, now);
    assert_eq!(
        b,
        Some(NextEvent::Stop {
            at: at(&tz, 11, 8, 0),
            entry: 0
        })
    );
}

/// A disabled window and a real one-minute gap do not merge (scheduler.test.ts:310-321).
#[test]
fn disabled_window_and_gap_do_not_merge() {
    let tz = msk();
    let mut disabled = entry("disabled", &[WED], "09:30", "12:00");
    disabled.enabled = false;
    let list = [
        entry("first", &[WED], "09:00", "10:00"),
        disabled,
        entry("later", &[WED], "10:01", "11:00"),
    ];
    let stop = next_event(&list, &tz, at(&tz, 10, 9, 30));
    assert_eq!(
        stop,
        Some(NextEvent::Stop {
            at: at(&tz, 10, 10, 0),
            entry: 0
        })
    );
    let start = next_event(&list, &tz, at(&tz, 10, 10, 0));
    assert_eq!(
        start,
        Some(NextEvent::Start {
            at: at(&tz, 10, 10, 1),
            entry: 2
        })
    );
}

/// AT-10-001 / AT-10-002: local DST boundaries (Sunday schedule ending 04:00). A start inside
/// the gap moves forward by the gap; a start inside the repeated hour takes the earlier instant.
#[test]
fn local_dst_boundaries() {
    let rows = [
        (
            "America/New_York",
            "2024-03-10T01:00:00-05:00",
            "02:30",
            "2024-03-10T03:30:00-04:00",
            "2024-03-10T04:00:00-04:00",
        ),
        (
            "Australia/Lord_Howe",
            "2024-10-06T01:00:00+10:30",
            "02:15",
            "2024-10-06T02:45:00+11:00",
            "2024-10-06T04:00:00+11:00",
        ),
        (
            "America/New_York",
            "2024-11-03T00:00:00-04:00",
            "01:30",
            "2024-11-03T01:30:00-04:00",
            "2024-11-03T04:00:00-05:00",
        ),
    ];
    for (name, now, start_time, start, stop) in rows {
        let tz = zone(name);
        let e = entry("dst", &[SUN], start_time, "04:00");
        let list = [e.clone()];
        let (start, stop) = (ts(start), ts(stop));
        assert_eq!(
            next_event(&list, &tz, ts(now)),
            Some(NextEvent::Start {
                at: start,
                entry: 0
            }),
            "{name}"
        );
        assert!(!is_active(&e, &tz, start - ms(1)), "{name}");
        assert!(is_active(&e, &tz, start), "{name}");
        assert_eq!(
            next_event(&list, &tz, start),
            Some(NextEvent::Stop { at: stop, entry: 0 }),
            "{name}"
        );
        assert!(is_active(&e, &tz, stop - ms(1)), "{name}");
        assert!(!is_active(&e, &tz, stop), "{name}");
    }
}

/// The second repetition of 01:30 does not re-activate a 01:15–01:45 window.
#[test]
fn repeated_hour_is_active_once() {
    let tz = zone("America/New_York");
    let e = entry("fold", &[SUN], "01:15", "01:45");
    assert!(is_active(&e, &tz, ts("2024-11-03T01:30:00-04:00")));
    assert!(!is_active(&e, &tz, ts("2024-11-03T01:30:00-05:00")));
}

/// Overnight end after a gap, gap-normalised start merging, and a window reversed by the gap.
#[test]
fn dst_gap_cases() {
    let tz = zone("America/New_York");
    let overnight = [entry("night", &[SUN], "22:00", "02:30")];
    let stop = next_event(&overnight, &tz, ts("2024-03-10T23:00:00-04:00"));
    assert_eq!(
        stop,
        Some(NextEvent::Stop {
            at: ts("2024-03-11T02:30:00-04:00"),
            entry: 0
        })
    );

    let merged = [
        entry("a", &[SUN], "01:00", "03:45"),
        entry("b", &[SUN], "02:30", "04:00"),
    ];
    let stop = next_event(&merged, &tz, ts("2024-03-10T01:30:00-05:00"));
    assert_eq!(
        stop,
        Some(NextEvent::Stop {
            at: ts("2024-03-10T04:00:00-04:00"),
            entry: 1
        })
    );

    let reversed = entry("rev", &[SUN], "02:30", "03:00");
    assert!(!is_active(&reversed, &tz, ts("2024-03-10T03:15:00-04:00")));
    let next = next_event(&[reversed], &tz, ts("2024-03-10T01:00:00-05:00"));
    assert_eq!(
        next,
        Some(NextEvent::Start {
            at: ts("2024-03-17T02:30:00-04:00"),
            entry: 0
        })
    );
}

/// Overnight Wed 22:00–06:00, including the window opened yesterday (F-193).
#[test]
fn overnight_window() {
    let tz = msk();
    let night = entry("night", &[WED], "22:00", "06:00");
    assert!(is_active(&night, &tz, at(&tz, 10, 23, 0)));
    assert!(is_active(&night, &tz, at(&tz, 11, 5, 0)));
    assert!(!is_active(&night, &tz, at(&tz, 10, 12, 0)));
    assert!(!is_active(&night, &tz, at(&tz, 11, 12, 0)));
    assert!(!is_active(&night, &tz, at(&tz, 11, 23, 0)));
    let list = [night];
    let start = |at| NextEvent::Start { at, entry: 0 };
    let stop = |at| NextEvent::Stop { at, entry: 0 };
    assert_eq!(
        next_event(&list, &tz, at(&tz, 10, 20, 0)),
        Some(start(at(&tz, 10, 22, 0)))
    );
    assert_eq!(
        next_event(&list, &tz, at(&tz, 10, 23, 0)),
        Some(stop(at(&tz, 11, 6, 0)))
    );
    assert_eq!(
        next_event(&list, &tz, at(&tz, 11, 2, 0)),
        Some(stop(at(&tz, 11, 6, 0)))
    );
    assert_eq!(
        next_event(&list, &tz, at(&tz, 11, 7, 0)),
        Some(start(at(&tz, 17, 22, 0)))
    );
}

/// Changed by design (S3): equal times are a 24-hour window, not an empty one.
#[test]
fn equal_times_mean_24_hours() {
    let tz = msk();
    let day = entry("day", &[WED], "09:00", "09:00");
    assert!(is_active(&day, &tz, at(&tz, 10, 12, 0)));
    assert!(is_active(&day, &tz, at(&tz, 11, 8, 59)));
    assert!(!is_active(&day, &tz, at(&tz, 11, 9, 0)));

    let always = [entry("always", &[0, 1, 2, 3, 4, 5, 6], "00:00", "00:00")];
    let now = at(&tz, 10, 12, 0);
    assert!(is_active(&always[0], &tz, now));
    assert_eq!(next_event(&always, &tz, now), None);
    // A run of chained 24-hour windows keeps a start far behind `now` (stable run identity).
    let run = active_run(&always, &tz, now).unwrap();
    assert!(run.start <= at(&tz, 3, 0, 0), "{run:?}");
}

/// AT-10-002 / F-123: overlap, adjacency, same end and nesting merge into one run.
#[test]
fn merged_schedule_windows() {
    let tz = msk();
    let base = entry("a", &MON_FRI, "09:00", "10:00");
    for (b_start, b_end, end_h) in [
        ("09:30", "11:00", 11),
        ("10:00", "11:00", 11),
        ("09:30", "10:00", 10),
        ("09:15", "09:45", 10),
    ] {
        let list = [base.clone(), entry("b", &MON_FRI, b_start, b_end)];
        let end = at(&tz, 10, end_h, 0);
        let first = next_event(&list, &tz, at(&tz, 10, 8, 59));
        assert_eq!(
            first,
            Some(NextEvent::Start {
                at: at(&tz, 10, 9, 0),
                entry: 0
            }),
            "{b_start}"
        );
        for probe in [at(&tz, 10, 9, 0), at(&tz, 10, 9, 59), end - ms(1)] {
            assert_eq!(
                next_event(&list, &tz, probe).map(|e| e.at()),
                Some(end),
                "{b_start}"
            );
            assert_eq!(
                active_run(&list, &tz, probe).map(|r| r.stop),
                Some(end),
                "{b_start}"
            );
        }
        assert_eq!(active_run(&list, &tz, end), None, "{b_start}");
    }
}
