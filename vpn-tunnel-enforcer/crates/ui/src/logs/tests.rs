//! Tests of the Logs page: the ported vectors of ui-pages §7.3 / §7.4 / §7.12 / §7.13 and the
//! parsers, plus VirtualDom runs of the page over [`super::demo::DemoLogs`].
use jiff::civil::date;
use jiff::tz::TimeZone;
use vpnte_base::i18n::Lang;
use vpnte_base::{ErrorKind, Msg};

use super::demo::DemoLogs;
use super::*;
use crate::widgets::UiError;

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
            "proxyEngine"
        ]
    );
    let shown: Vec<String> = items.iter().map(|(_, v)| evidence_text(v, &ru)).collect();
    assert_eq!(
        shown,
        ["0", "REALITY-ключ отклонён", "3", "—", "✓", "sing-box"]
    );
    assert_eq!(
        ru(&EvidenceKey::AutoRestartAttempts.label()),
        "Авто-перезапусков"
    );
    assert_eq!(
        en(&EvidenceKey::SingboxExitCode.label()),
        "sing-box exit code"
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
         leakDetectedDuringSession: true\n  proxyEngine: sing-box\nСообщение: exit status 0"
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

fn report(
    history: Result<(), ErrorKind>,
    traffic: Result<(), ErrorKind>,
    artifacts: Result<ArtifactReport, ErrorKind>,
) -> ClearReport {
    let err = |kind: ErrorKind| UiError {
        kind,
        msg: Msg::new(kind.i18n_key()),
    };
    ClearReport {
        history: history.map_err(err),
        traffic: traffic.map_err(err),
        artifacts: artifacts.map_err(err),
    }
}

/// AT-00-004/008 (ui-pages §7.3): partial cleanup and failed histories never display full
/// success; canonical reasons in ru / en; history 1 + traffic 1 + artifacts 1 = «Удалено: 3».
#[test]
fn cleanup_summary() {
    let partial = report(
        Ok(()),
        Ok(()),
        Ok(ArtifactReport {
            cleared: vec!["app-log".into()],
            absent: vec![],
            failed: vec![("snapshots".into(), ErrorKind::Permission)],
        }),
    );
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

    let complete = report(
        Ok(()),
        Ok(()),
        Ok(ArtifactReport {
            cleared: vec!["app-log".into(), "snapshots".into()],
            absent: vec![],
            failed: vec![],
        }),
    );
    let summary = ClearSummary::of(&complete);
    assert!(summary.is_success());
    assert_eq!(
        summary.toast(&ru),
        (
            "Логи очищены".into(),
            "История, runtime-логи и диагностические артефакты удалены".into()
        )
    );

    // a failed history clear keeps the rows and is an error; equal reasons are named once
    let failed = report(
        Err(ErrorKind::Permission),
        Err(ErrorKind::Permission),
        Err(ErrorKind::Conflict),
    );
    let summary = ClearSummary::of(&failed);
    assert!(!summary.is_success());
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
        time: time.map(str::to_owned),
        level,
        scope: scope.map(str::to_owned),
        text: text.to_owned(),
    }
}

/// app.log lines (core format): local time, level, the crate prefix dropped from the target,
/// fields after the message; anything else is an info line as written.
#[test]
fn app_log_lines() {
    let tz = moscow();
    let json = r#"{"ts":"2026-11-11T08:00:05.120Z","level":"WARN","target":"vpnte_tunnel::lifecycle","msg":"engine restarted","fields":{"attempt":2,"profile":"NL"},"corr":"op_1"}"#;
    assert_eq!(
        parse_line(LogSource::App, json, &tz),
        Some(line(
            Some("11:00:05"),
            LineLevel::Warn,
            Some("tunnel::lifecycle"),
            "engine restarted attempt=2 profile=NL"
        ))
    );
    let old =
        r#"{"ts":"2026-11-11T08:00:05Z","level":"error","scope":"tun","message":"spawn failed"}"#;
    assert_eq!(
        parse_line(LogSource::App, old, &tz),
        Some(line(
            Some("11:00:05"),
            LineLevel::Error,
            Some("tun"),
            "spawn failed"
        ))
    );
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
#[test]
fn journal_tail_and_levels() {
    let tz = TimeZone::UTC;
    let lines = (0..400)
        .map(|i| {
            let level = if i % 10 == 0 { "ERROR" } else if i % 10 == 5 { "WARN" } else { "INFO" };
            format!(r#"{{"ts":"2026-11-11T08:00:00Z","level":"{level}","target":"vpnte_x","msg":"{i}"}}"#)
        })
        .collect();
    let tail = LogTail {
        lines,
        exists: true,
        truncated: true,
    };
    let all = journal(LogSource::App, &tail, LevelFilter::All, &tz);
    assert_eq!(all.len(), TAIL_LINES);
    assert_eq!(
        (all[0].text.as_str(), all[TAIL_LINES - 1].text.as_str()),
        ("399", "100")
    );
    let warnings = journal(LogSource::App, &tail, LevelFilter::Warnings, &tz);
    assert_eq!(warnings.len(), 80);
    assert_eq!(warnings[0].text, "395");
    let errors = journal(LogSource::App, &tail, LevelFilter::Errors, &tz);
    assert_eq!(errors.len(), 40);
    assert!(errors.iter().all(|l| l.level == LineLevel::Error));
    assert!(LevelFilter::All.keeps(LineLevel::Debug));
    assert!(!LevelFilter::Warnings.keeps(LineLevel::Info));
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

/// VirtualDom runs: the page over every demo scene, and the cleanup's request lifetime.
mod dom {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use dioxus::core::NoOpMutations;
    use dioxus::prelude::*;
    use tokio::sync::{oneshot, watch};
    use vpnte_base::{AppError, AppResult};

    use super::super::page::clear;
    use super::*;
    use crate::widgets::{ToastKind, Toasts, use_job};

    use crate::test_support::settle;

    #[derive(Clone)]
    struct Scene(&'static str, Rc<RefCell<Option<Rc<DemoLogs>>>>);

    fn page_root() -> Element {
        let scene = use_context::<Scene>();
        let api = use_hook(|| Rc::new(DemoLogs::new(scene.0, vpnte_base::types::now_ms())));
        scene.1.replace(Some(api.clone()));
        use_context_provider(|| api.clone() as Rc<dyn LogsApi>);
        Toasts::use_provider();
        rsx! { LogsPage {} }
    }

    /// Every demo scene mounts, reads the app journal once and renders without a panic.
    #[tokio::test]
    async fn every_scene_renders() {
        for name in ["full", "empty", "loading", "failed", "partial"] {
            let seen = Rc::new(RefCell::new(None));
            let mut dom = VirtualDom::new(page_root).with_root_context(Scene(name, seen.clone()));
            dom.rebuild_in_place();
            settle(&mut dom, 8, 40).await;
            let api = seen.borrow().clone().expect("mounted");
            let calls = api.calls.borrow().clone();
            assert_eq!(calls, ["read_log:App"], "scene {name}");
        }
    }

    /// A cleanup whose reply the test sends.
    struct GateApi {
        history: watch::Sender<LogsSnapshot>,
        calls: Cell<u32>,
        reply: RefCell<Option<oneshot::Receiver<ClearReport>>>,
    }

    #[async_trait::async_trait(?Send)]
    impl LogsApi for GateApi {
        fn history(&self) -> watch::Receiver<LogsSnapshot> {
            self.history.subscribe()
        }
        async fn reload_history(&self) -> AppResult<()> {
            Ok(())
        }
        async fn export_history(&self, _: ExportFormat, name: String) -> AppResult<String> {
            Ok(name)
        }
        async fn clear_all(&self) -> AppResult<ClearReport> {
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
        async fn open_log_folder(&self) -> AppResult<()> {
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

    /// Clicks «Очистить» twice while the first cleanup runs.
    #[component]
    fn ClearChild() -> Element {
        let probe = use_context::<Probe>();
        let toasts = Toasts::use_context();
        let job = use_job::<()>();
        let confirm = use_signal(|| true);
        let reload = use_signal(|| 0u64);
        use_hook(|| {
            let api: Rc<dyn LogsApi> = probe.api.clone();
            clear(api.clone(), job, toasts, confirm, reload);
            clear(api, job, toasts, confirm, reload);
        });
        rsx! {}
    }

    fn mount() -> (VirtualDom, Probe, oneshot::Sender<ClearReport>) {
        let (tx, rx) = oneshot::channel();
        let probe = Probe {
            api: Rc::new(GateApi {
                history: watch::Sender::new(LogsSnapshot::default()),
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

    fn partial() -> ClearReport {
        ClearReport {
            history: Ok(()),
            traffic: Ok(()),
            artifacts: Ok(ArtifactReport {
                cleared: vec!["app-log".into()],
                absent: vec![],
                failed: vec![("snapshots".into(), ErrorKind::Permission)],
            }),
        }
    }

    /// AT-00-008 (§7.3 "blocks duplicate clicks", "waits for every clear", "partial cleanup
    /// never displays full success"): one call for two clicks, no toast before the reply, then
    /// an error toast.
    #[tokio::test]
    async fn one_cleanup_for_two_clicks_and_no_success_on_partial() {
        let (mut dom, probe, tx) = mount();
        settle(&mut dom, 3, 40).await;
        assert_eq!(probe.api.calls.get(), 1);
        assert!(toast_kinds(&dom, &probe).is_empty());
        tx.send(partial()).expect("cleanup running");
        settle(&mut dom, 3, 40).await;
        assert_eq!(toast_kinds(&dom, &probe), [ToastKind::Error]);
    }

    /// AT-00-008 (§7.3 "suppresses a late toast after unmount"): the page left while the
    /// cleanup runs shows nothing when the reply comes.
    #[tokio::test]
    async fn no_toast_after_the_page_is_left() {
        let (mut dom, probe, tx) = mount();
        settle(&mut dom, 3, 40).await;
        probe.show.set(false);
        dom.mark_dirty(ScopeId::APP);
        dom.render_immediate(&mut NoOpMutations);
        let _ = tx.send(partial());
        settle(&mut dom, 3, 40).await;
        assert!(toast_kinds(&dom, &probe).is_empty());
        assert_eq!(probe.api.calls.get(), 1);
    }
}
