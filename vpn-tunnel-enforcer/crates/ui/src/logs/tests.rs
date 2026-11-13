//! Tests of the Logs page: the ported vectors of ui-pages §7.3 / §7.4 / §7.12 / §7.13 and the
//! parsers, plus VirtualDom runs of the page over [`super::demo::DemoLogs`].
use jiff::civil::date;
use jiff::tz::TimeZone;
use vpnte_base::i18n::Lang;
use vpnte_base::{ErrorKind, Msg};

use super::demo::DemoLogs;
use super::*;

/// A message in `lang` through the catalog as the app registers it (old strings, every UI
/// fragment, the canonical errors of vpnte-base).
fn render(lang: Lang, msg: &Msg) -> String {
    crate::test_locales::init_locales();
    msg.render(lang)
}

fn ru(msg: &Msg) -> String {
    render(Lang::Ru, msg)
}

fn en(msg: &Msg) -> String {
    render(Lang::En, msg)
}

fn row(id: &str) -> SessionRow {
    SessionRow {
        id: id.to_owned(),
        started_at: 1_000,
        ended_at: Some(2_000),
        duration_ms: None,
        profile_name: "retained-history".to_owned(),
        mode: Mode::Direct,
        bytes_down: 0,
        bytes_up: 0,
        reason: DisconnectReason::User,
        error_message: None,
        outcome: None,
    }
}

fn with_outcome(mut r: SessionRow, kind: OutcomeKind, headline: &str) -> SessionRow {
    r.outcome = Some(Outcome {
        kind,
        headline: Text::Plain(headline.to_owned()),
        evidence: Evidence::default(),
    });
    r
}

/// ui-pages §7.13 `formatDuration`; unit words now come from the catalog (U-14).
#[test]
fn durations() {
    assert_eq!(duration_msg(0), None);
    let show = |ms| en(&duration_msg(ms).expect("non-zero"));
    assert_eq!(show(65_000), "1m 5s");
    assert_eq!(show(59_999), "59s");
    assert_eq!(show(3_600_000), "1h 0m");
    assert_eq!(show(95 * 60_000), "1h 35m");
    assert_eq!(ru(&duration_msg(65_000).expect("non-zero")), "1 мин 5 с");
    assert_eq!(ru(&duration_msg(3_600_000).expect("non-zero")), "1 ч 0 мин");
}

/// ui-pages §7.4 `isStartFailure` (from source).
#[test]
fn start_failures() {
    let failed = with_outcome(row("a"), OutcomeKind::StartFailed, "x");
    assert!(is_start_failure(&failed));
    let short_error = SessionRow {
        duration_ms: Some(500),
        reason: DisconnectReason::Error,
        ..row("b")
    };
    assert!(is_start_failure(&short_error));
    let short_user = SessionRow {
        reason: DisconnectReason::User,
        ..short_error.clone()
    };
    assert!(!is_start_failure(&short_user));
    let running = SessionRow {
        ended_at: None,
        ..short_error.clone()
    };
    assert!(!is_start_failure(&running));
    let with_traffic = SessionRow {
        duration_ms: Some(999),
        bytes_down: 1,
        ..short_error
    };
    assert!(!is_start_failure(&with_traffic));
}

/// ui-pages §7.4 `legacyKind`, and the chip of an old row without an outcome.
#[test]
fn legacy_rows() {
    use DisconnectReason as R;
    assert_eq!(legacy_kind(R::User), OutcomeKind::UserStop);
    assert_eq!(legacy_kind(R::Rotation), OutcomeKind::Rotation);
    assert_eq!(legacy_kind(R::Schedule), OutcomeKind::Schedule);
    assert_eq!(legacy_kind(R::Crash), OutcomeKind::Killswitch);
    assert_eq!(legacy_kind(R::Error), OutcomeKind::Unknown);
    let legacy = row("legacy1");
    assert_eq!(chip_kind(&legacy), Some(OutcomeKind::UserStop));
    assert_eq!(shown_kind(&legacy).label().key, "logs.outcome.user-stop");
    // headline: the stored message, else the chip label
    assert_eq!(shown_headline(&legacy).render_with(&ru), "Вы отключили");
    let with_message = SessionRow {
        error_message: Some("sing-box exited with code 1".into()),
        reason: DisconnectReason::Error,
        ..row("legacy2")
    };
    assert_eq!(
        shown_headline(&with_message),
        Text::Plain("sing-box exited with code 1".into())
    );
    assert_eq!(
        extra_message(&with_message, "sing-box exited with code 1"),
        None
    );
    // a running session has no chip yet (the old table said «Вы отключили»), and its detail does
    // not claim an end either
    let running = SessionRow {
        ended_at: None,
        ..row("live")
    };
    assert_eq!(chip_kind(&running), None);
    assert_eq!(shown_headline(&running).render_with(&ru), "Сессия ещё идёт");
    assert_eq!(
        shown_headline(&running).render_with(&en),
        "The session is still running"
    );
    assert!(!diagnostics_text(&running, &en).contains("user"));
}

/// ui-pages §7.4 "splits real sessions from start failures" and AT-00-005 "shows elapsed
/// duration after a backward clock correction".
#[test]
fn sessions_and_failures_are_split() {
    let now = 1_800_000_000_000;
    let corrected = SessionRow {
        started_at: now,
        ended_at: Some(now - 3_600_000),
        duration_ms: Some(65_000),
        reason: DisconnectReason::Error,
        ..with_outcome(row("clock"), OutcomeKind::Unknown, "x")
    };
    assert_eq!(connection_duration_ms(&corrected), 65_000);
    assert_eq!(
        en(&duration_msg(connection_duration_ms(&corrected)).expect("elapsed")),
        "1m 5s"
    );
    assert!(!is_start_failure(&corrected));
    let rows = [
        with_outcome(row("s1"), OutcomeKind::SingboxCrash, "… после 3 попыток …"),
        with_outcome(
            row("f1"),
            OutcomeKind::StartFailed,
            "Не удалось запустить: Нет выбранного сервера",
        ),
        row("legacy1"),
        corrected,
    ];
    let (sessions, failures) = split(rows.iter());
    let ids = |v: &[&SessionRow]| v.iter().map(|r| r.id.clone()).collect::<Vec<_>>();
    assert_eq!(ids(&sessions), ["s1", "legacy1", "clock"]);
    assert_eq!(ids(&failures), ["f1"]);
    assert_eq!(
        shown_kind(&rows[0]).label().key,
        "logs.outcome.singbox-crash"
    );
    // legacy rows fall back to end − start; a negative span is 0, a running one is 0
    let backwards = SessionRow {
        ended_at: Some(500),
        ..row("b")
    };
    assert_eq!(connection_duration_ms(&backwards), 0);
    assert_eq!(connection_duration_ms(&row("ok")), 1_000);
}

/// U-11 (new vector): the date filter uses local days of the system zone, not UTC midnight.
#[test]
fn date_bounds_are_local_days() {
    let tz = TimeZone::get("Europe/Moscow").expect("bundled tzdb");
    let day = date(2026, 11, 11);
    let from = day_start(day, &tz).expect("start");
    let to = day_end(day, &tz).expect("end");
    assert_eq!(iso_utc(from), "2026-11-10T21:00:00.000Z");
    assert_eq!(iso_utc(to), "2026-11-11T20:59:59.999Z");
    let filters = Filters {
        from: Some(day),
        to: Some(day),
        ..Filters::default()
    };
    let query = Query::new(&filters, &tz, Lang::Ru);
    let at = |ms| SessionRow {
        started_at: ms,
        ..row("t")
    };
    assert!(query.matches(&at(from)));
    assert!(query.matches(&at(to)));
    assert!(!query.matches(&at(from - 1)));
    assert!(!query.matches(&at(to + 1)));
}

/// Decision 6 (search covers what is shown): the mode column shows «Туннель» / «Tunnel», so the
/// search finds a Hard session by that word in either language (it matched only `hard` before).
#[test]
fn search_finds_the_shown_mode_label() {
    crate::test_locales::init_locales();
    let tz = TimeZone::UTC;
    let hard = SessionRow {
        mode: Mode::Hard,
        ..row("h")
    };
    let search = |text: &str, lang| {
        Query::new(
            &Filters {
                text: text.into(),
                ..Filters::default()
            },
            &tz,
            lang,
        )
    };
    assert!(search("туннель", Lang::Ru).matches(&hard));
    assert!(search("tunnel", Lang::En).matches(&hard));
    assert!(search("hard", Lang::En).matches(&hard));
    assert!(!search("прокси", Lang::Ru).matches(&hard));
}

/// ui-pages §3.9 history query: AND of reasons, days and a case-insensitive text match over
/// what the row shows.
#[test]
fn filters_combine() {
    let tz = TimeZone::UTC;
    let crash = SessionRow {
        profile_name: "Netherlands · Amsterdam".into(),
        reason: DisconnectReason::Error,
        ..with_outcome(
            row("c"),
            OutcomeKind::SingboxCrash,
            "Ядро упало после 3 попыток",
        )
    };
    let user = SessionRow {
        profile_name: "Germany · Frankfurt".into(),
        ..row("u")
    };
    let query = |f: Filters| Query::new(&f, &tz, Lang::En);
    let all = query(Filters::default());
    assert!(all.matches(&crash) && all.matches(&user));
    let errors = query(Filters {
        reasons: [DisconnectReason::Error].into(),
        ..Filters::default()
    });
    assert!(errors.matches(&crash) && !errors.matches(&user));
    let text = |t: &str| {
        query(Filters {
            text: t.into(),
            ..Filters::default()
        })
    };
    assert!(text("  AMSTERDAM ").matches(&crash));
    assert!(text("singbox-crash").matches(&crash));
    assert!(text("попыток").matches(&crash));
    assert!(text("direct").matches(&user));
    assert!(!text("amsterdam").matches(&user));
    let both = query(Filters {
        reasons: [DisconnectReason::User].into(),
        text: "amsterdam".into(),
        ..Filters::default()
    });
    assert!(!both.matches(&crash) && !both.matches(&user));
    assert!(Filters::default().is_empty());
    assert!(
        !Filters {
            text: "x".into(),
            ..Filters::default()
        }
        .is_empty()
    );
    assert!(
        Filters {
            text: "  ".into(),
            ..Filters::default()
        }
        .is_empty()
    );
}

/// ui-pages §3.9 sorting: start descending by default; the same header flips; another header
/// sorts by it descending; a running session's end counts as 0; traffic = down + up.
#[test]
fn sorting() {
    let mk = |id: &str, start: i64, end: Option<i64>, down: u64, up: u64| SessionRow {
        started_at: start,
        ended_at: end,
        bytes_down: down,
        bytes_up: up,
        ..row(id)
    };
    let rows = [
        mk("a", 10, Some(50), 5, 5),
        mk("b", 30, None, 1, 1),
        mk("c", 20, Some(40), 0, 30),
    ];
    let order = |sort: SortState| {
        let mut v: Vec<&SessionRow> = rows.iter().collect();
        sort_rows(&mut v, sort, Lang::En);
        v.iter().map(|r| r.id.as_str()).collect::<String>()
    };
    let default = SortState::default();
    assert_eq!(order(default), "bca");
    let asc = default.toggle(SortField::Started);
    assert!(!asc.descending);
    assert_eq!(order(asc), "acb");
    let ended = asc.toggle(SortField::Ended);
    assert!(ended.descending);
    assert_eq!(order(ended), "acb");
    assert_eq!(order(ended.toggle(SortField::Ended)), "bca");
    assert_eq!(order(default.toggle(SortField::Traffic)), "cab");
}

/// ui-pages §3.9 stats: the period window on start time, ended durations only, bytes of every
/// counted session; start failures (by kind or the old short-error rule) are not connections.
#[test]
fn period_stats() {
    let now = 1_800_000_000_000;
    let day = 86_400_000;
    let mk = |id: &str, ago: i64, dur: Option<i64>, down: u64| SessionRow {
        started_at: now - ago,
        ended_at: dur.map(|d| now - ago + d),
        duration_ms: dur.map(|d| d as u64),
        bytes_down: down,
        bytes_up: 1,
        reason: DisconnectReason::Rotation,
        ..row(id)
    };
    let failed_kind = with_outcome(
        mk("f1", 3_600_000, Some(300), 0),
        OutcomeKind::StartFailed,
        "x",
    );
    let failed_old = SessionRow {
        reason: DisconnectReason::Error,
        bytes_up: 0,
        ..mk("f2", 7_200_000, Some(200), 0)
    };
    let rows = [
        mk("live", 60_000, None, 100),
        mk("today", 3 * 3_600_000, Some(65_000), 10),
        mk("week", 3 * day, Some(3_600_000), 20),
        mk("month", 20 * day, Some(60_000), 40),
        mk("old", 40 * day, Some(60_000), 80),
        failed_kind,
        failed_old,
    ];
    let d = stats(&rows, Period::Day, now);
    assert_eq!(
        d,
        Stats {
            total_time_ms: 65_000,
            bytes_down: 110,
            bytes_up: 2,
            sessions: 2
        }
    );
    let w = stats(&rows, Period::Week, now);
    assert_eq!((w.total_time_ms, w.sessions), (3_665_000, 3));
    let m = stats(&rows, Period::Month, now);
    assert_eq!(
        (m.total_time_ms, m.bytes_down, m.sessions),
        (3_725_000, 170, 4)
    );
}

/// ui-pages §2.7 download name, with the user's local date.
#[test]
fn export_names() {
    assert_eq!(
        export_file_name(ExportFormat::Csv, date(2026, 11, 11)),
        "connection-history-2026-11-11.csv"
    );
    assert_eq!(
        export_file_name(ExportFormat::Json, date(2026, 1, 2)),
        "connection-history-2026-01-02.json"
    );
    let tz = TimeZone::get("Europe/Moscow").expect("bundled tzdb");
    // 22:30 UTC on Nov 10 is already Nov 11 in Moscow
    let ms = jiff::Timestamp::from_second(1_762_813_800)
        .expect("valid")
        .as_millisecond();
    assert_eq!(local_date(ms, &tz), Some(date(2025, 11, 11)));
}

fn crash_evidence() -> Evidence {
    Evidence {
        singbox_exit_code: Some(0),
        singbox_stderr_tail: Some("  ".into()),
        outbound_fault: Some(vpnte_base::types::OutboundFault::RealityKeyMismatch),
        auto_restart_attempts: Some(3),
        kill_switch_engaged: Some(false),
        leak_detected_during_session: Some(true),
        egress_ip: Some(String::new()),
        proxy_engine: Some(vpnte_base::types::Engine::SingBox),
        proxy_engine_reason: Some(Text::Plain("REALITY".into())),
        ..Evidence::default()
    }
}

/// ui-pages §3.9 evidence grid: absent and blank values are left out, `false` and `0` stay;
/// faults by label, flags as «✓» / «—»; §7.4 expand shows `singboxExitCode` and
/// `autoRestartAttempts`.
#[test]
fn evidence_grid() {
    let items = evidence_items(&crash_evidence());
    let names: Vec<&str> = items.iter().map(|(k, _)| k.name()).collect();
    assert_eq!(
        names,
        [
            "singboxExitCode",
            "outboundFault",
            "autoRestartAttempts",
            "killSwitchEngaged",
            "leakDetectedDuringSession",
            "proxyEngine",
            "proxyEngineReason"
        ]
    );
    let shown: Vec<String> = items.iter().map(|(_, v)| evidence_text(v, &ru)).collect();
    assert_eq!(
        shown,
        [
            "0",
            "REALITY-ключ отклонён",
            "3",
            "—",
            "✓",
            "sing-box",
            "REALITY"
        ]
    );
    assert_eq!(
        ru(&EvidenceKey::AutoRestartAttempts.label()),
        "Авто-перезапусков"
    );
    assert_eq!(
        en(&EvidenceKey::SingboxExitCode.label()),
        "sing-box exit code"
    );
    assert_eq!(
        en(&EvidenceKey::ProxyEngineReason.label()),
        "Why this engine"
    );
    let hint = Evidence {
        hint: Some(Text::Plain(" ".into())),
        ..Evidence::default()
    };
    assert!(evidence_items(&hint).is_empty());
}

/// ui-pages §3.9 «Скопировать диагностику»: profile, UTC ISO times, byte counts, then the
/// outcome with raw evidence values, or the old reason and message.
#[test]
fn diagnostics_text_of_rows() {
    let outcome_row = SessionRow {
        outcome: Some(Outcome {
            kind: OutcomeKind::SingboxCrash,
            headline: Text::Msg(
                Msg::new("logs.demo.headline.singboxCrash")
                    .arg("code", 0)
                    .arg("n", 3),
            ),
            evidence: crash_evidence(),
        }),
        error_message: Some("exit status 0".into()),
        bytes_down: 2048,
        bytes_up: 512,
        ..row("x")
    };
    let text = diagnostics_text(&outcome_row, &ru);
    assert_eq!(
        text,
        "Профиль: retained-history (direct)\nНачало: 1970-01-01T00:00:01.000Z\nКонец: 1970-01-01T00:00:02.000Z\n\
         Трафик: ↓2048 / ↑512 байт\n\
         Итог: singbox-crash — Ядро VPN (sing-box) неожиданно завершилось (код 0) после 3 попыток авто-перезапуска. Последняя ошибка: сервер оборвал TLS-рукопожатие\n\
         Детали:\n  singboxExitCode: 0\n  outboundFault: reality-key-mismatch\n  autoRestartAttempts: 3\n  killSwitchEngaged: false\n  \
         leakDetectedDuringSession: true\n  proxyEngine: sing-box\n  proxyEngineReason: REALITY\nСообщение: exit status 0"
    );
    let legacy = row("y");
    assert_eq!(
        diagnostics_text(&legacy, &en),
        "Profile: retained-history (direct)\nStarted: 1970-01-01T00:00:01.000Z\nEnded: 1970-01-01T00:00:02.000Z\n\
         Traffic: ↓0 / ↑0 bytes\nReason: user"
    );
    // a session still running has no disconnect reason to copy
    let running = SessionRow {
        ended_at: None,
        ..row("z")
    };
    assert_eq!(
        diagnostics_text(&running, &en),
        "Profile: retained-history (direct)\nStarted: 1970-01-01T00:00:01.000Z\nTraffic: ↓0 / ↑0 bytes"
    );
}

/// AT-00-004/008 (ui-pages §7.3, now the technical tab's clear): a partial clear never shows
/// full success; canonical reasons in ru / en, equal reasons named once.
#[test]
fn cleanup_summary() {
    let partial = ArtifactReport {
        cleared: vec![
            "app-log".into(),
            "xray-log".into(),
            "xray-previous-log".into(),
        ],
        absent: vec![],
        failed: vec![("sing-box-log".into(), ErrorKind::Permission)],
    };
    let summary = ClearSummary::of(&partial);
    assert!(!summary.is_success());
    let (title, body) = summary.toast(&ru);
    assert_eq!(title, "Очистка выполнена частично");
    assert_eq!(
        body,
        "Удалено: 3, отсутствует: 0, ошибок: 1. Недостаточно прав для операции"
    );
    let (title, body) = summary.toast(&en);
    assert_eq!(title, "Cleanup incomplete");
    assert_eq!(body, "Cleared: 3, absent: 0, failed: 1. Permission denied");

    let complete = ArtifactReport {
        cleared: vec!["app-log".into()],
        absent: vec!["xray-log".into()],
        failed: vec![],
    };
    let summary = ClearSummary::of(&complete);
    assert!(summary.is_success());
    assert_eq!(
        summary.toast(&ru),
        (
            "Технические журналы очищены".into(),
            "Журналы приложения и движков в вашей папке пусты.".into()
        )
    );

    let failed = ArtifactReport {
        cleared: vec![],
        absent: vec![],
        failed: vec![
            ("app-log".into(), ErrorKind::Permission),
            ("sing-box-log".into(), ErrorKind::Permission),
            ("xray-log".into(), ErrorKind::Conflict),
        ],
    };
    let summary = ClearSummary::of(&failed);
    assert_eq!((summary.cleared, summary.absent, summary.failed), (0, 0, 3));
    assert_eq!(
        summary.toast(&ru).1,
        "Удалено: 0, отсутствует: 0, ошибок: 3. Недостаточно прав для операции; Операция недоступна в текущем состоянии"
    );
}

fn moscow() -> TimeZone {
    TimeZone::get("Europe/Moscow").expect("bundled tzdb")
}

fn line(time: Option<&str>, level: LineLevel, scope: Option<&str>, text: &str) -> JournalLine {
    JournalLine {
        key: 0,
        time: time.map(str::to_owned),
        level,
        scope: scope.map(str::to_owned),
        text: text.to_owned(),
        fields: Vec::new(),
    }
}

/// p-logs: app.log and service lines formatted for reading: local time, level, a short scope
/// (crate and first module), the message; the full module path, the fields and the operation
/// id apart (shown on expand); never raw JSON. Anything else is an info line as written.
#[test]
fn app_log_lines() {
    let tz = moscow();
    let json = r#"{"ts":"2026-11-11T08:00:05.120Z","level":"WARN","target":"vpnte_tunnel::lifecycle::actor","msg":"engine restarted","fields":{"attempt":2,"profile":"NL"},"corr":"op_1"}"#;
    let mut expected = line(
        Some("11:00:05"),
        LineLevel::Warn,
        Some("tunnel/lifecycle"),
        "engine restarted",
    );
    expected.fields = vec![
        ("target".into(), "vpnte_tunnel::lifecycle::actor".into()),
        ("attempt".into(), "2".into()),
        ("profile".into(), "NL".into()),
        ("corr".into(), "op_1".into()),
    ];
    assert_eq!(
        parse_line(LogSource::App, json, &tz),
        Some(expected.clone())
    );
    assert_eq!(
        parse_line(LogSource::Service, json, &tz),
        Some(expected.clone())
    );
    assert_eq!(
        expected.copy_text(),
        "11:00:05 warn [tunnel/lifecycle] engine restarted target=vpnte_tunnel::lifecycle::actor attempt=2 profile=NL corr=op_1"
    );
    let old =
        r#"{"ts":"2026-11-11T08:00:05Z","level":"error","scope":"tun","message":"spawn failed"}"#;
    let mut expected = line(
        Some("11:00:05"),
        LineLevel::Error,
        Some("tun"),
        "spawn failed",
    );
    expected.fields = vec![("target".into(), "tun".into())];
    assert_eq!(parse_line(LogSource::App, old, &tz), Some(expected));
    assert_eq!(
        parse_line(LogSource::App, "thread 'main' panicked\r\n", &tz),
        Some(line(None, LineLevel::Info, None, "thread 'main' panicked"))
    );
    assert_eq!(
        parse_line(LogSource::App, r#"["not","an","object"]"#, &tz).map(|l| l.level),
        Some(LineLevel::Info)
    );
    assert_eq!(parse_line(LogSource::App, "   ", &tz), None);
    let long = "x".repeat(MAX_LINE_CHARS + 500);
    let cut = parse_line(LogSource::App, &long, &tz).expect("line");
    assert_eq!(cut.text.chars().count(), MAX_LINE_CHARS + 1);
    assert!(cut.text.ends_with('…'));
}

/// sing-box output (`log/format.go`): full timestamp, relative seconds, or the level alone.
#[test]
fn singbox_lines() {
    let tz = moscow();
    let parse = |l: &str| parse_line(LogSource::SingBox, l, &tz);
    assert_eq!(
        parse(
            "+0300 2026-11-11 12:34:56 INFO [3912 0ms] inbound/tun[tun-in]: inbound connection to 1.1.1.1:53"
        ),
        Some(line(
            Some("12:34:56"),
            LineLevel::Info,
            Some("inbound/tun[tun-in]"),
            "[3912 0ms] inbound connection to 1.1.1.1:53"
        ))
    );
    assert_eq!(
        parse("WARN[0012] dns: exchange failed"),
        Some(line(None, LineLevel::Warn, Some("dns"), "exchange failed"))
    );
    assert_eq!(
        parse("FATAL start service: bad config"),
        Some(line(
            None,
            LineLevel::Error,
            None,
            "start service: bad config"
        ))
    );
    assert_eq!(
        parse("DEBUG router: match[0] => direct").map(|l| l.level),
        Some(LineLevel::Debug)
    );
    assert_eq!(
        parse("no level here"),
        Some(line(None, LineLevel::Info, None, "no level here"))
    );
}

/// Xray output: `date time[.µs] [Level] …`; access lines carry no level.
#[test]
fn xray_lines() {
    let tz = moscow();
    let parse = |l: &str| parse_line(LogSource::Xray, l, &tz);
    assert_eq!(
        parse(
            "2026/11/11 12:34:56.123456 [Warning] [1234567] proxy/vless/outbound: failed to dial"
        ),
        Some(line(
            Some("12:34:56"),
            LineLevel::Warn,
            Some("proxy/vless/outbound"),
            "[1234567] failed to dial"
        ))
    );
    assert_eq!(
        parse(
            "2026/11/11 12:34:57 from 127.0.0.1:50000 accepted tcp:example.org:443 [socks >> proxy]"
        ),
        Some(line(
            Some("12:34:57"),
            LineLevel::Info,
            None,
            "from 127.0.0.1:50000 accepted tcp:example.org:443 [socks >> proxy]"
        ))
    );
    assert_eq!(
        parse("2026/11/11 12:34:58.1 [Error] core: failed").map(|l| l.level),
        Some(LineLevel::Error)
    );
}

/// The pane: newest first, the level filter, at most [`TAIL_LINES`] lines.
/// p-logs: at most the last 2 000 lines, newest first, each keyed by its file offset; the
/// level filter and the search narrow them.
#[test]
fn journal_tail_levels_and_search() {
    let tz = TimeZone::UTC;
    let lines = (0..2400u64)
        .map(|i| {
            let level = if i % 10 == 0 { "ERROR" } else if i % 10 == 5 { "WARN" } else { "INFO" };
            TailLine {
                offset: i * 100,
                text: format!(
                    r#"{{"ts":"2026-11-11T08:00:00Z","level":"{level}","target":"vpnte_x","msg":"{i}"}}"#
                ),
            }
        })
        .collect();
    let tail = LogTail {
        lines,
        exists: true,
        truncated: true,
        note: TailNote::None,
    };
    let all = journal(LogSource::App, &tail, LevelFilter::All, "", &tz);
    assert_eq!(all.len(), TAIL_LINES);
    assert_eq!(
        (all[0].text.as_str(), all[TAIL_LINES - 1].text.as_str()),
        ("2399", "400")
    );
    assert_eq!((all[0].key, all[TAIL_LINES - 1].key), (239_900, 40_000));
    let warnings = journal(LogSource::App, &tail, LevelFilter::Warnings, "", &tz);
    assert_eq!(warnings.len(), 480);
    assert_eq!(warnings[0].text, "2395");
    let errors = journal(LogSource::App, &tail, LevelFilter::Errors, "", &tz);
    assert_eq!(errors.len(), 240);
    assert!(errors.iter().all(|l| l.level == LineLevel::Error));
    let found = journal(LogSource::App, &tail, LevelFilter::All, " 123 ", &tz);
    let texts: Vec<&str> = found.iter().map(|l| l.text.as_str()).collect();
    assert_eq!(
        texts,
        [
            "2123", "1239", "1238", "1237", "1236", "1235", "1234", "1233", "1232", "1231", "1230",
            "1123", "123"
        ]
    );
    let scoped = journal(LogSource::App, &tail, LevelFilter::Errors, "VPNTE_X", &tz);
    assert_eq!(scoped.len(), 240, "the search sees the module path too");
    assert!(LevelFilter::All.keeps(LineLevel::Debug));
    assert!(!LevelFilter::Warnings.keeps(LineLevel::Info));
}

fn event(id: u64, at: i64, topic: Topic, level: EventLevel, key: &'static str) -> EventRow {
    EventRow {
        id,
        at,
        topic,
        level,
        title: Text::Msg(Msg::new(key)),
        body: None,
        session: None,
    }
}

/// p-logs: the chips keep their topic (Ошибки: every error), the search finds the shown
/// text and the profile, newest first, at most `EVENTS_SHOWN` with a note.
#[test]
fn event_filters_and_search() {
    let mut up = event(
        3,
        3_000,
        Topic::Connection,
        EventLevel::Ok,
        "logs.events.sessionUp",
    );
    up.title = Text::Msg(Msg::new("logs.events.sessionUp").arg("profile", "Амстердам"));
    up.session = Some(SessionFacts {
        profile: "Амстердам".into(),
        mode: Mode::Hard,
        duration_ms: None,
        bytes_down: 0,
        bytes_up: 0,
        engine: None,
        outcome: None,
    });
    let rows = vec![
        event(
            1,
            1_000,
            Topic::Update,
            EventLevel::Ok,
            "logs.demo.event.updated",
        ),
        event(
            2,
            2_000,
            Topic::Protection,
            EventLevel::Error,
            "logs.demo.event.leak",
        ),
        up,
        event(
            4,
            4_000,
            Topic::Other,
            EventLevel::Error,
            "logs.demo.event.listFailed",
        ),
    ];
    let ids = |query: EventQuery| {
        shown_events(&rows, &query, &ru)
            .0
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>()
    };
    let q = |filter, text: &str| EventQuery {
        filter,
        text: text.into(),
    };
    assert_eq!(ids(q(EventFilter::All, "")), [4, 3, 2, 1]);
    assert_eq!(ids(q(EventFilter::Errors, "")), [4, 2]);
    assert_eq!(ids(q(EventFilter::Connections, "")), [3]);
    assert_eq!(ids(q(EventFilter::Protection, "")), [2]);
    assert_eq!(ids(q(EventFilter::Automation, "")), Vec::<u64>::new());
    assert_eq!(ids(q(EventFilter::Updates, "")), [1]);
    assert_eq!(ids(q(EventFilter::All, "амстердам")), [3], "the profile");
    assert_eq!(
        ids(q(EventFilter::All, " SMART ru ")),
        [4],
        "the shown text, any case"
    );
    let many: Vec<EventRow> = (0..EVENTS_SHOWN as u64 + 3)
        .map(|i| {
            event(
                i,
                i as i64,
                Topic::Other,
                EventLevel::Info,
                "logs.demo.event.updated",
            )
        })
        .collect();
    let (shown, more) = shown_events(&many, &EventQuery::default(), &ru);
    assert_eq!((shown.len(), more), (EVENTS_SHOWN, true));
    assert_eq!(shown[0].id, EVENTS_SHOWN as u64 + 2);
}

/// p-logs: the timeline is grouped by local day (Сегодня, Вчера, a date).
#[test]
fn events_are_grouped_by_day() {
    let tz = moscow();
    // 2026-11-13 12:00 in Moscow.
    let now = 1_794_560_400_000;
    let rows = [
        event(3, now - 3_600_000, Topic::Other, EventLevel::Info, "x"),
        event(2, now - 86_400_000, Topic::Other, EventLevel::Info, "x"),
        event(1, now - 3 * 86_400_000, Topic::Other, EventLevel::Info, "x"),
    ];
    let groups = by_day(rows.iter().collect(), now, &tz);
    let days: Vec<Day> = groups.iter().map(|(d, _)| *d).collect();
    assert_eq!(
        days,
        [Day::Today, Day::Yesterday, Day::On(date(2026, 11, 10))]
    );
    let labels: Vec<String> = days.iter().map(|d| d.label(&ru)).collect();
    assert_eq!(labels, ["Сегодня", "Вчера", "10 нояб."]);
    assert_eq!(Day::On(date(2026, 11, 10)).label(&en), "Nov 10");
}

/// p-logs: a session end says how it ended on its one line; the copied text adds the date,
/// the details and the facts.
#[test]
fn event_lines_and_copied_text() {
    let tz = moscow();
    let mut end = event(
        9,
        1_794_560_400_000,
        Topic::Connection,
        EventLevel::Error,
        "x",
    );
    end.title = Text::Msg(Msg::new("logs.events.sessionEnd").arg("profile", "NL"));
    end.body = Some(Text::Plain("Узел недоступен".into()));
    end.session = Some(SessionFacts {
        profile: "NL".into(),
        mode: Mode::Soft,
        duration_ms: Some(65_000),
        bytes_down: 1024,
        bytes_up: 0,
        engine: Some(vpnte_base::types::Engine::Xray),
        outcome: Some(OutcomeKind::ServerDown),
    });
    let line = line_text(&end, &en);
    assert_eq!(
        line,
        format!(
            "Disconnected · NL — {}",
            en(&OutcomeKind::ServerDown.label())
        )
    );
    let copied = event_text(&end, &tz, &en, &|b| format!("{b} B"));
    let lines: Vec<&str> = copied.lines().collect();
    assert_eq!(lines[0], format!("2026-11-13 12:00:00 · {line}"));
    assert_eq!(lines[1], "Узел недоступен");
    assert!(lines.contains(&"Duration: 1m 5s"), "{copied}");
    assert!(lines.contains(&"Engine: Xray"), "{copied}");
    let mut failed = end.clone();
    failed.session.as_mut().expect("facts").outcome = Some(OutcomeKind::StartFailed);
    failed.title = Text::Msg(Msg::new("logs.events.sessionFailed").arg("profile", "NL"));
    assert_eq!(line_text(&failed, &en), "Could not connect · NL");
}

/// The owner named the page «Журнал»: the nav label and the title.
#[test]
fn the_page_is_called_journal() {
    assert_eq!(
        ru(&Msg::new(crate::pages::Page::Logs.label_key())),
        "Журнал"
    );
    assert_eq!(ru(&Msg::new("logs.title")), "Журнал");
    assert_eq!(
        en(&Msg::new(crate::pages::Page::Logs.label_key())),
        "Journal"
    );
}

/// U-14: counted strings use plural keys (the old «1 подключения»).
#[test]
fn counted_strings_are_plural() {
    let count = |lang, n: u32| render(lang, &Msg::new("logs.connectionsCount").arg("count", n));
    assert_eq!(count(Lang::Ru, 1), "1 подключение");
    assert_eq!(count(Lang::Ru, 2), "2 подключения");
    assert_eq!(count(Lang::Ru, 5), "5 подключений");
    assert_eq!(count(Lang::Ru, 11), "11 подключений");
    assert_eq!(count(Lang::Ru, 21), "21 подключение");
    assert_eq!(count(Lang::En, 1), "1 connection");
    assert_eq!(count(Lang::En, 6), "6 connections");
    let lines = |lang, n: u32| render(lang, &Msg::new("logs.live.lines").arg("count", n));
    assert_eq!(lines(Lang::Ru, 3), "3 строки");
    assert_eq!(lines(Lang::Ru, 300), "300 строк");
    assert_eq!(lines(Lang::En, 1), "1 line");
}

/// Literal catalog keys in a source file: every `"logs.…"`, `"common.…"`, `"modes.…"`,
/// `"errors.…"` string (keys built with `format!` are checked by iterating their enums).
fn literal_keys(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for prefix in ["\"logs.", "\"common.", "\"modes.", "\"errors."] {
        let mut rest = src;
        while let Some(at) = rest.find(prefix) {
            let tail = &rest[at + 1..];
            let end = tail.find('"').unwrap_or(tail.len());
            let key = &tail[..end];
            if !key.ends_with('.') && !key.contains(['{', ' ', '<']) {
                out.push(key.to_owned());
            }
            rest = &tail[end..];
        }
    }
    out
}

/// i18n gate (ui-pages §7.12) for this package: every dynamic and literal key exists in both
/// languages (the fragment rules are checked crate-wide in `test_locales`).
#[test]
fn locale_gate() {
    let mut dynamic: Vec<String> = OutcomeKind::ALL
        .iter()
        .map(|k| k.label().key.to_string())
        .collect();
    dynamic.extend(EvidenceKey::ALL.iter().map(|k| k.label().key.to_string()));
    use vpnte_base::types::OutboundFault as F;
    for fault in [
        F::RealityKeyMismatch,
        F::TlsHandshakeFailed,
        F::UpstreamUnreachable,
    ] {
        dynamic.push(fault_label(fault).key.to_string());
    }
    dynamic.extend((1..=12).map(|m| format!("logs.month.{m}")));
    for target in ["events", "history", "technical"] {
        dynamic.push(format!("logs.erase.{target}.title"));
        dynamic.push(format!("logs.erase.{target}.confirm"));
    }
    dynamic.extend(["events", "history"].map(|t| format!("logs.erase.{t}.done")));
    dynamic.extend(ErrorKindAll::ALL.iter().map(|k| k.i18n_key().to_owned()));
    let sources = [
        include_str!("model.rs"),
        include_str!("history.rs"),
        include_str!("format.rs"),
        include_str!("report.rs"),
        include_str!("journal.rs"),
        include_str!("page.rs"),
        include_str!("table.rs"),
        include_str!("viewer.rs"),
        include_str!("events.rs"),
        include_str!("events_view.rs"),
        include_str!("connections.rs"),
        include_str!("clear.rs"),
        include_str!("state.rs"),
        include_str!("demo.rs"),
        include_str!("../bin/demo_logs.rs"),
    ];
    let literal: Vec<String> = sources.iter().flat_map(|s| literal_keys(s)).collect();
    assert!(literal.len() > 60, "the scan found the page's keys");
    crate::test_locales::assert_resolve(
        &crate::test_locales::catalogs(&[]),
        dynamic.iter().chain(&literal).map(String::as_str),
    );
    // the demo's headlines render in both languages
    for row in demo::sessions(1_800_000_000_000) {
        if let Some(outcome) = &row.outcome {
            for lang in [Lang::Ru, Lang::En] {
                let text = outcome.headline.render_with(&|m: &Msg| render(lang, m));
                assert!(!text.starts_with("logs."), "{text}");
            }
        }
    }
}

/// Every error category, for the canonical-message check.
struct ErrorKindAll;
impl ErrorKindAll {
    const ALL: [ErrorKind; 7] = [
        ErrorKind::Validation,
        ErrorKind::Permission,
        ErrorKind::Network,
        ErrorKind::Conflict,
        ErrorKind::Internal,
        ErrorKind::Cancelled,
        ErrorKind::Timeout,
    ];
}

/// VirtualDom runs: every tab over every demo scene, the remembered state, and a clear's
/// request lifetime.
mod dom {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use dioxus::prelude::*;
    use tokio::sync::{oneshot, watch};
    use vpnte_base::{AppError, AppResult};

    use super::super::clear::{ClearTarget, start};
    use super::super::state::STATE;
    use super::*;
    use crate::test_support::settle;
    use crate::widgets::{ToastKind, Toasts, use_job};

    /// The scene, the tab and the remembered source to mount with; the mounted demo comes back.
    #[derive(Clone)]
    struct Mount {
        scene: &'static str,
        tab: Tab,
        source: LogSource,
        show: Rc<Cell<bool>>,
        seen: Rc<RefCell<Option<Rc<DemoLogs>>>>,
    }

    fn page_root() -> Element {
        let mount = use_context::<Mount>();
        let api = use_hook(|| Rc::new(DemoLogs::new(mount.scene, vpnte_base::types::now_ms())));
        mount.seen.replace(Some(api.clone()));
        use_context_provider(|| api.clone() as Rc<dyn LogsApi>);
        // «Сохранить для поддержки» shows with a maintenance backend in context.
        use_context_provider(|| {
            use crate::maintenance::demo::{DemoMaintenanceApi, Scene as Maintenance};
            DemoMaintenanceApi::new(Maintenance::Default)
                as Rc<dyn crate::maintenance::MaintenanceApi>
        });
        Toasts::use_provider();
        use_hook(|| {
            let mut state = STATE.write();
            state.tab = mount.tab;
            state.tech.source = mount.source;
        });
        rsx! {
            if mount.show.get() {
                LogsPage {}
            }
        }
    }

    fn mount(scene: &'static str, tab: Tab, source: LogSource) -> (VirtualDom, Mount) {
        let mount = Mount {
            scene,
            tab,
            source,
            show: Rc::new(Cell::new(true)),
            seen: Rc::new(RefCell::new(None)),
        };
        let mut dom = VirtualDom::new(page_root).with_root_context(mount.clone());
        dom.rebuild_in_place();
        (dom, mount)
    }

    fn calls(mount: &Mount) -> Vec<String> {
        let api = mount.seen.borrow().clone().expect("mounted");
        api.calls.borrow().clone()
    }

    /// Every tab mounts over every demo scene and renders without a panic; only the technical
    /// tab reads a log, once, the remembered source.
    #[tokio::test]
    async fn every_tab_renders_in_every_scene() {
        for scene in ["full", "empty", "loading", "failed", "service", "partial"] {
            for tab in Tab::ALL {
                let (mut dom, mount) = mount(scene, tab, LogSource::App);
                settle(&mut dom, 8, 40).await;
                let expected: &[&str] = match tab {
                    Tab::Technical => &["read_log:App"],
                    _ => &[],
                };
                assert_eq!(calls(&mount), expected, "{scene} {tab:?}");
            }
        }
    }

    /// A Tunnel session through the service: the service source reads its lines.
    #[tokio::test]
    async fn the_service_source_reads_the_service_lines() {
        let (mut dom, mount) = mount("service", Tab::Technical, LogSource::Service);
        settle(&mut dom, 8, 40).await;
        assert_eq!(calls(&mount), ["read_log:Service"]);
    }

    /// The owner's rule: the tab and the source survive leaving the page (unmount, mount).
    #[tokio::test]
    async fn the_tab_and_source_survive_leaving_the_page() {
        let (mut dom, mount) = mount("full", Tab::Technical, LogSource::Xray);
        settle(&mut dom, 6, 40).await;
        mount.show.set(false);
        dom.mark_dirty(ScopeId::APP);
        settle(&mut dom, 3, 20).await;
        mount.show.set(true);
        dom.mark_dirty(ScopeId::APP);
        settle(&mut dom, 6, 40).await;
        assert_eq!(calls(&mount), ["read_log:Xray", "read_log:Xray"]);
        let remembered = dom.in_runtime(|| STATE.peek().clone());
        assert_eq!(remembered.tab, Tab::Technical);
        assert_eq!(remembered.tech.source, LogSource::Xray);
    }

    /// A clear whose reply the test sends.
    struct GateApi {
        snapshot: watch::Sender<LogsSnapshot>,
        calls: Cell<u32>,
        reply: RefCell<Option<oneshot::Receiver<ArtifactReport>>>,
    }

    #[async_trait::async_trait(?Send)]
    impl LogsApi for GateApi {
        fn snapshot(&self) -> watch::Receiver<LogsSnapshot> {
            self.snapshot.subscribe()
        }
        async fn reload_history(&self) -> AppResult<()> {
            Ok(())
        }
        async fn export_history(&self, _: ExportFormat, name: String) -> AppResult<String> {
            Ok(name)
        }
        async fn clear_events(&self) -> AppResult<()> {
            Ok(())
        }
        async fn clear_history(&self) -> AppResult<()> {
            Ok(())
        }
        async fn clear_technical(&self) -> AppResult<ArtifactReport> {
            self.calls.set(self.calls.get() + 1);
            let reply = self
                .reply
                .borrow_mut()
                .take()
                .ok_or_else(AppError::cancelled)?;
            reply.await.map_err(|_| AppError::cancelled())
        }
        async fn read_log(&self, _: LogSource) -> AppResult<LogTail> {
            Ok(LogTail::default())
        }
        async fn open_log_folder(&self, _: LogSource) -> AppResult<()> {
            Ok(())
        }
        async fn copy_text(&self, _: String) -> AppResult<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct Probe {
        api: Rc<GateApi>,
        show: Rc<Cell<bool>>,
        toasts: Rc<RefCell<Option<Toasts>>>,
    }

    fn clear_root() -> Element {
        let probe = use_context::<Probe>();
        let toasts = Toasts::use_provider();
        probe.toasts.replace(Some(toasts));
        rsx! {
            if probe.show.get() {
                ClearChild {}
            }
        }
    }

    /// Confirms «Очистить» twice while the first clear runs.
    #[component]
    fn ClearChild() -> Element {
        let probe = use_context::<Probe>();
        let toasts = Toasts::use_context();
        let job = use_job::<()>();
        let open = use_signal(|| true);
        use_hook(|| {
            let api: Rc<dyn LogsApi> = probe.api.clone();
            let done = EventHandler::new(|()| {});
            start(api.clone(), ClearTarget::Technical, job, toasts, open, done);
            start(api, ClearTarget::Technical, job, toasts, open, done);
        });
        rsx! {}
    }

    fn mount_clear() -> (VirtualDom, Probe, oneshot::Sender<ArtifactReport>) {
        let (tx, rx) = oneshot::channel();
        let probe = Probe {
            api: Rc::new(GateApi {
                snapshot: watch::Sender::new(LogsSnapshot::default()),
                calls: Cell::new(0),
                reply: RefCell::new(Some(rx)),
            }),
            show: Rc::new(Cell::new(true)),
            toasts: Rc::new(RefCell::new(None)),
        };
        let mut dom = VirtualDom::new(clear_root).with_root_context(probe.clone());
        dom.rebuild_in_place();
        (dom, probe, tx)
    }

    fn toast_kinds(dom: &VirtualDom, probe: &Probe) -> Vec<ToastKind> {
        let toasts = probe.toasts.borrow().expect("provider");
        dom.in_runtime(|| toasts.list().iter().map(|t| t.kind).collect())
    }

    fn partial() -> ArtifactReport {
        ArtifactReport {
            cleared: vec!["app-log".into()],
            absent: vec![],
            failed: vec![("sing-box-log".into(), ErrorKind::Permission)],
        }
    }

    /// AT-00-008 (§7.3 "blocks duplicate clicks", "partial cleanup never displays full
    /// success"): one call for two confirms, no toast before the reply, then an error toast.
    #[tokio::test]
    async fn one_clear_for_two_confirms_and_no_success_on_partial() {
        let (mut dom, probe, tx) = mount_clear();
        settle(&mut dom, 3, 40).await;
        assert_eq!(probe.api.calls.get(), 1);
        assert!(toast_kinds(&dom, &probe).is_empty());
        tx.send(partial()).expect("clear running");
        settle(&mut dom, 3, 40).await;
        assert_eq!(toast_kinds(&dom, &probe), [ToastKind::Error]);
    }

    /// AT-00-008 (§7.3 "suppresses a late toast after unmount"): the page left while the clear
    /// runs shows nothing when the reply comes.
    #[tokio::test]
    async fn no_toast_after_the_page_is_left() {
        let (mut dom, probe, tx) = mount_clear();
        settle(&mut dom, 3, 40).await;
        probe.show.set(false);
        dom.mark_dirty(ScopeId::APP);
        settle(&mut dom, 3, 40).await;
        let _ = tx.send(partial());
        settle(&mut dom, 3, 40).await;
        assert!(toast_kinds(&dom, &probe).is_empty());
    }
}
