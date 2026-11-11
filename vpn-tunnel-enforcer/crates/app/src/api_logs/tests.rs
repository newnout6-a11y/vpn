//! Tests of the Logs API: history rows (outcomes and evidence), the pushed history, the full
//! cleanup with its per-part report and the log tails.
use std::time::Duration;

use vpnte_base::ErrorKind;
use vpnte_base::i18n::Lang;
use vpnte_base::types::Owner;
use vpnte_core::ops::Source;
use vpnte_tunnel::history::{Entry, NewEntry, Route, SessionMode};
use vpnte_tunnel::outcome::{
    AdaptiveContext, Evidence, NetworkTransition, OutcomeKind, SessionOutcome, verbatim,
};
use vpnte_ui::logs::{self as ui, LogSource, LogsApi, Text};
use vpnte_ui::widgets::Load;

use super::{LogsService, rows};
use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};

const T0: i64 = 1_700_000_000_000;

fn new_entry(name: &str, outcome: SessionOutcome) -> NewEntry {
    NewEntry {
        correlation_id: None,
        source: Source::Ui,
        owner: Some(Owner::Manual),
        route: Route::Tun,
        started_at: T0,
        ended_at: T0 + 60_000,
        duration_ms: 60_000,
        profile_name: name.into(),
        profile_id: "p1".into(),
        mode: SessionMode::Hard,
        bytes_down: 2048,
        bytes_up: 512,
        outcome,
    }
}

/// AT-00-005 (backend side): the stored monotonic duration, the outcome kind, the verbatim
/// headline, every evidence field and the coarse bucket reach the row unchanged.
#[test]
fn rows_carry_outcomes_and_evidence() {
    let evidence = Evidence {
        singbox_exit_code: Some(1),
        singbox_stderr_tail: Some("FATAL start".into()),
        adaptive_mode: Some(AdaptiveContext::TlsCompatibility),
        auto_restart_attempts: Some(2),
        network_transition: Some(NetworkTransition::AdapterRemoved),
        hint: Some(verbatim("Restart the app")),
        ..Evidence::default()
    };
    let outcome =
        SessionOutcome::with_headline(OutcomeKind::SingboxCrash, evidence, verbatim("Crashed"));
    let entry = Entry::from_new(new_entry("Lab", outcome)).expect("valid row");
    let row = rows::row(&entry, Lang::En);
    assert_eq!(row.profile_name, "Lab");
    assert_eq!(row.mode, ui::Mode::Hard);
    assert_eq!(row.duration_ms, Some(60_000));
    assert_eq!((row.bytes_down, row.bytes_up), (2048, 512));
    // The stored coarse bucket of a crash (the lifecycle's `OutcomeKind::bucket`).
    assert_eq!(row.reason, ui::DisconnectReason::Error);
    let outcome = row.outcome.expect("outcome");
    assert_eq!(outcome.kind, ui::OutcomeKind::SingboxCrash);
    assert_eq!(outcome.headline, Text::Plain("Crashed".into()));
    let e = outcome.evidence;
    assert_eq!(e.singbox_exit_code, Some(1));
    assert_eq!(e.singbox_stderr_tail.as_deref(), Some("FATAL start"));
    assert_eq!(e.adaptive_mode.as_deref(), Some("tls-compatibility"));
    assert_eq!(e.auto_restart_attempts, Some(2));
    assert_eq!(e.network_transition.as_deref(), Some("adapter-removed"));
    assert_eq!(e.hint, Some(Text::Plain("Restart the app".into())));
    assert_eq!(e.kill_switch_engaged, None, "absent facts stay absent");
}

/// A translated headline stays a message (re-rendered on a language switch).
#[test]
fn translated_headlines_stay_messages() {
    let outcome = SessionOutcome::new(OutcomeKind::UserStop, Evidence::default());
    let entry = Entry::from_new(new_entry("Lab", outcome)).expect("valid row");
    let row = rows::row(&entry, Lang::Ru);
    let headline = row.outcome.expect("outcome").headline;
    assert!(matches!(headline, Text::Msg(_)));
    assert_eq!(row.reason, ui::DisconnectReason::User);
}

/// AT-00-004 / AT-00-008: the history is pushed on every change; «clear all» reports each part
/// on its own (never a full success for a partial cleanup): the
/// traffic history is honestly "not available" with a tunnel that does not host it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_is_pushed_and_cleared_part_by_part() {
    let dir = TempDir::new("logs");
    let backend = backend(&dir, FakeTunnel::new(false));
    let api = LogsService::start(backend.clone());
    let outcome = SessionOutcome::new(OutcomeKind::UserStop, Evidence::default());
    backend.history.add(new_entry("Lab", outcome)).expect("row");
    let mut rx = api.history();
    let rows_now = |s: &ui::LogsSnapshot| match &s.history {
        Load::Ready(rows) => rows.len(),
        _ => usize::MAX,
    };
    let wait = rx.wait_for(|s| rows_now(s) == 1);
    tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .expect("pushed")
        .expect("open");
    std::fs::write(backend.dirs.logs.join("sing-box.1.log"), "old\n").expect("old log");
    let report = api.clear_all().await.expect("report");
    assert!(report.history.is_ok());
    let traffic = report.traffic.expect_err("not hosted by this tunnel");
    assert_eq!(traffic.kind, ErrorKind::Conflict);
    assert_eq!(traffic.msg.key, "app.logs.trafficUnavailable");
    let artifacts = report.artifacts.expect("logs cleared");
    assert!(artifacts.failed.is_empty());
    assert!(!artifacts.cleared.is_empty() || !artifacts.absent.is_empty());
    assert!(!backend.dirs.logs.join("sing-box.1.log").exists());
    let wait = rx.wait_for(|s| rows_now(s) == 0);
    tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .expect("cleared")
        .expect("open");
}

/// Log tails: whole lines, oldest first; an engine that never ran has no log yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn log_tails_read_whole_lines() {
    let dir = TempDir::new("logs-tail");
    let backend = backend(&dir, FakeTunnel::new(false));
    std::fs::write(backend.dirs.logs.join("sing-box.log"), "one\ntwo\nthree\n").expect("log");
    let api = LogsService::start(backend);
    let tail = api.read_log(LogSource::SingBox).await.expect("tail");
    assert!(tail.exists);
    assert_eq!(tail.lines, ["one", "two", "three"]);
    let xray = api.read_log(LogSource::Xray).await.expect("tail");
    assert!(!xray.exists && xray.lines.is_empty());
}
