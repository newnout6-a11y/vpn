//! Tests of the Traffic page: the ported vectors of ui-pages §7.13 (sizes) and §7.14 (the
//! 300-row cap), plurals, day groups, the second line, dates, links and the demo.
use jiff::civil::date;
use jiff::tz::TimeZone;
use vpnte_base::Msg;
use vpnte_base::i18n::Lang;

use super::demo::{DemoTrafficHistory, generated, sample};
use super::*;
use crate::schedule::tests::{en, lookup, render, ru};

fn utc_ms(y: i16, mo: i8, d: i8, h: i8, mi: i8, s: i8) -> i64 {
    date(y, mo, d)
        .at(h, mi, s, 0)
        .to_zoned(TimeZone::UTC)
        .expect("valid")
        .timestamp()
        .as_millisecond()
}

/// ui-pages §7.14: 450 matches → 300 drawn with «Показаны последние 300 записей…»; the search
/// runs over all 450.
#[test]
fn render_cap() {
    let rows = generated(1_800_000_000_000, 450);
    assert_eq!(filter(&rows, "").len(), 450);
    assert!(filter(&rows, "").len() > MAX_RENDERED);
    let deep: Vec<&str> = filter(&rows, " HOST-44")
        .iter()
        .map(|r| r.domain.as_str())
        .collect();
    assert_eq!(deep.len(), 10, "host-440…449, all beyond the drawn 300");
    assert!(deep.contains(&"host-449.example.net"));
    let more = Msg::new("trafficHistory.showingLatest").arg("count", MAX_RENDERED);
    assert!(
        ru(&more).starts_with("Показаны последние 300 записей"),
        "{}",
        ru(&more)
    );
    assert!(
        en(&more).starts_with("Showing the latest 300 entries"),
        "{}",
        en(&more)
    );
}

/// AT-09-011 / U-14: the count uses plural forms («1 уникальных доменов» before).
#[test]
fn total_plurals() {
    let total = |lang, n: usize| render(lang, &Msg::new("trafficHistory.total").arg("count", n));
    assert_eq!(total(Lang::Ru, 1), "1 уникальный домен");
    assert_eq!(total(Lang::Ru, 3), "3 уникальных домена");
    assert_eq!(total(Lang::Ru, 5), "5 уникальных доменов");
    assert_eq!(total(Lang::Ru, 21), "21 уникальный домен");
    assert_eq!(total(Lang::En, 1), "1 unique domain");
    assert_eq!(total(Lang::En, 2), "2 unique domains");
}

/// Groups follow the local date of `last_seen`, in arrival order; totals add up every match.
#[test]
fn day_groups_and_totals() {
    let now = utc_ms(2026, 11, 11, 12, 0, 0);
    let rows = sample(now);
    let all = filter(&rows, "");
    let groups = by_day(&all, &TimeZone::UTC);
    let sizes: Vec<(Option<jiff::civil::Date>, usize)> =
        groups.iter().map(|(d, l)| (*d, l.len())).collect();
    assert_eq!(
        sizes,
        [
            (Some(date(2026, 11, 11)), 10),
            (Some(date(2026, 11, 10)), 2)
        ]
    );
    let (down, up) = totals(&all);
    assert_eq!(down, rows.iter().map(|r| r.bytes_down).sum::<u64>());
    assert_eq!(up, rows.iter().map(|r| r.bytes_up).sum::<u64>());
    assert_eq!(ru(&day_heading(date(2026, 11, 1))), "01.11.2026");
    assert_eq!(en(&day_heading(date(2026, 11, 1))), "2026-11-01");
}

/// The second line: the site title, else the first time; « · » / « – » and the last time.
#[test]
fn second_line() {
    let row = DomainRow {
        domain: "a.example".into(),
        first_seen: 1,
        last_seen: 2,
        count: 2,
        bytes_up: 0,
        bytes_down: 0,
        site: SiteInfo::None,
    };
    let when = |ms: i64| format!("t{ms}");
    assert_eq!(seen_line(&row, when), "t1 – t2");
    let titled = DomainRow {
        site: SiteInfo::Ready {
            name: Some("A".into()),
            title: Some("Главная".into()),
        },
        ..row.clone()
    };
    assert_eq!(seen_line(&titled, when), "Главная · t2");
    let blank_title = DomainRow {
        site: SiteInfo::Ready {
            name: None,
            title: Some("  ".into()),
        },
        ..row.clone()
    };
    assert_eq!(seen_line(&blank_title, when), "t1 – t2");
    let once = DomainRow {
        last_seen: 1,
        ..row
    };
    assert_eq!(seen_line(&once, when), "t1");
}

/// «11 нояб., 11:53:56» / «Nov 11, 11:53:56» (24-hour clock in both languages).
#[test]
fn local_date_time() {
    let ms = utc_ms(2026, 11, 11, 11, 53, 56);
    let m = moment(ms, &TimeZone::UTC).expect("moment");
    assert_eq!((m.day, m.month, m.time.as_str()), (11, 11, "11:53:56"));
    let month = |lang| lookup(lang, month_key(m.month)).expect("month");
    assert_eq!(ru(&m.msg(month(Lang::Ru))), "11 нояб., 11:53:56");
    assert_eq!(en(&m.msg(month(Lang::En))), "Nov 11, 11:53:56");
    for n in 1..=12 {
        assert!(
            lookup(Lang::Ru, month_key(n)).is_some() && lookup(Lang::En, month_key(n)).is_some()
        );
    }
}

/// Only plain host names become links.
#[test]
fn site_links() {
    assert_eq!(
        site_url("video.example.com").as_deref(),
        Some("https://video.example.com")
    );
    assert_eq!(site_url("пример.рф").as_deref(), Some("https://пример.рф"));
    for bad in [
        "",
        ".x",
        "-x",
        "a/b",
        "x y",
        "evil.com?x",
        "user@host",
        "host:443",
        "a\\b",
    ] {
        assert_eq!(site_url(bad), None, "{bad:?}");
    }
}

/// The demo: a clear publishes an empty list; `open_site` only records the URL.
#[tokio::test]
async fn demo_actions() {
    let demo = DemoTrafficHistory::new("full", utc_ms(2026, 11, 11, 12, 0, 0)).instant();
    let rx = demo.state();
    assert_eq!(rx.borrow().domains.ready().map(|r| r.len()), Some(12));
    demo.open_site("https://video.example.com".into())
        .await
        .expect("opened");
    assert_eq!(*demo.opened.borrow(), ["https://video.example.com"]);
    demo.clear().await.expect("cleared");
    assert_eq!(rx.borrow().domains.ready().map(|r| r.len()), Some(0));
    let failing = DemoTrafficHistory::new("errors", 0).instant();
    assert!(failing.clear().await.is_err());
}
