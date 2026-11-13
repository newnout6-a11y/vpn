//! Tests of the «Журнал» API: history rows (outcomes and evidence), the history and the events
//! pushed together, one clear per tab, the engine logs of Proxy and service sessions, the
//! service's lines (a fake pipe; temp folders only).
use std::time::Duration;

use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_base::types::Owner;
use vpnte_core::ops::Source;
use vpnte_tunnel::api::CaptureKind;
use vpnte_tunnel::history::{Entry, NewEntry, Route, SessionMode};
use vpnte_tunnel::outcome::{
    AdaptiveContext, Evidence, NetworkTransition, OutcomeKind, SessionOutcome, verbatim,
};
use vpnte_ui::logs::{self as ui, LogSource, LogsApi, TailNote, Text};
use vpnte_ui::widgets::Load;

use super::{Folders, LogsService, ServiceAnswer, ServiceLogs, engine_place, rows, sources};
use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};
use crate::services::Backend;
use std::sync::Arc;

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
        proxy_engine: Some(vpnte_base::types::Engine::Xray),
        proxy_engine_reason: Some(Msg::new("engine.xray.reason.reality")),
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
    assert_eq!(e.proxy_engine, Some(vpnte_base::types::Engine::Xray));
    // The engine's reason stays a message: the page renders it in the user's language.
    assert_eq!(
        e.proxy_engine_reason,
        Some(Text::Msg(Msg::new("engine.xray.reason.reality")))
    );
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

/// Folders of a test: the user's logs folder and a temp stand-in for the service's.
fn folders(backend: &Backend, dir: &TempDir) -> Folders {
    let service = dir.0.join("service-logs");
    std::fs::create_dir_all(&service).expect("service folder");
    Folders {
        user: backend.dirs.logs.clone(),
        service: Some(service),
    }
}

/// The helper service's lines as a fake pipe gives them.
struct FakeService(std::sync::Mutex<Option<ServiceAnswer>>);

#[async_trait::async_trait(?Send)]
impl ServiceLogs for FakeService {
    async fn read(&self) -> vpnte_base::AppResult<ServiceAnswer> {
        Ok(self
            .0
            .lock()
            .expect("fake")
            .take()
            .unwrap_or(ServiceAnswer::NotInstalled))
    }
}

fn start(backend: &Arc<Backend>, dir: &TempDir, answer: ServiceAnswer) -> LogsService {
    let fake = Arc::new(FakeService(std::sync::Mutex::new(Some(answer))));
    LogsService::start_with(backend.clone(), folders(backend, dir), fake)
}

async fn wait(
    rx: &mut tokio::sync::watch::Receiver<ui::LogsSnapshot>,
    f: impl Fn(&ui::LogsSnapshot) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(10), rx.wait_for(f))
        .await
        .expect("pushed")
        .expect("open");
}

fn count<T>(load: &Load<std::sync::Arc<[T]>>) -> usize {
    match load {
        Load::Ready(rows) => rows.len(),
        _ => usize::MAX,
    }
}

/// p-logs: the history and the journal are pushed together; each tab's clear empties its own
/// part only (the events, the sessions history, the technical logs of the user's folder).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_clear_empties_its_own_part() {
    let dir = TempDir::new("logs");
    let backend = backend(&dir, FakeTunnel::new(false));
    let api = start(&backend, &dir, ServiceAnswer::NotInstalled);
    let outcome = SessionOutcome::new(OutcomeKind::UserStop, Evidence::default());
    backend.history.add(new_entry("Lab", outcome)).expect("row");
    let mut rx = api.snapshot();
    wait(&mut rx, |s| count(&s.history) == 1 && count(&s.events) == 1).await;
    std::fs::write(backend.dirs.logs.join("sing-box.1.log"), "old\n").expect("old log");
    api.clear_events().await.expect("events");
    wait(&mut rx, |s| count(&s.events) == 0 && count(&s.history) == 1).await;
    let report = api.clear_technical().await.expect("technical");
    assert!(report.failed.is_empty());
    assert!(!backend.dirs.logs.join("sing-box.1.log").exists());
    assert_eq!(backend.history.list().len(), 1, "the history stays");
    api.clear_history().await.expect("history");
    wait(&mut rx, |s| count(&s.history) == 0).await;
    let events = backend.dirs.root.join(crate::svc_journal::FILE);
    assert!(
        events.exists(),
        "the journal file stays (it is not seeded again)"
    );
    backend.shutdown.cancel();
}

/// p-logs: an engine log is the current session's wherever it runs: Proxy mode reads the
/// user's folder, a Tunnel session through the service the service's folder; each says which.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_logs_follow_the_session() {
    let dir = TempDir::new("logs-tail");
    let tunnel = FakeTunnel::new(false);
    let backend = backend(&dir, tunnel.clone());
    let api = start(&backend, &dir, ServiceAnswer::NotInstalled);
    let service = folders(&backend, &dir).service.expect("folder");
    std::fs::write(backend.dirs.logs.join("sing-box.log"), "own one\nown two\n").expect("log");
    std::fs::write(service.join("sing-box.log"), "service one\n").expect("log");
    let idle = api.read_log(LogSource::SingBox).await.expect("tail");
    let texts = |t: &ui::LogTail| t.lines.iter().map(|l| l.text.clone()).collect::<Vec<_>>();
    assert_eq!(texts(&idle), ["own one", "own two"]);
    assert_eq!(idle.note, TailNote::None);
    assert_eq!(idle.lines[1].offset, 8);
    tunnel
        .status
        .send_modify(|s| s.capture = Some(CaptureKind::Proxy));
    let proxy = api.read_log(LogSource::SingBox).await.expect("tail");
    assert_eq!(
        (texts(&proxy).len(), proxy.note),
        (2, TailNote::ProxySession)
    );
    assert_eq!(
        engine_place(Some(CaptureKind::Tun), true),
        (true, TailNote::ServiceSession)
    );
    assert_eq!(
        engine_place(Some(CaptureKind::Tun), false),
        (false, TailNote::TunnelSession)
    );
    let xray = api.read_log(LogSource::Xray).await.expect("tail");
    assert!(!xray.exists && xray.lines.is_empty());
    // A Tunnel session through the service: its folder (a temp stand-in here) and its line.
    let folders = folders(&backend, &dir);
    let (at, note) = folders.engine(Some(CaptureKind::Tun), true);
    assert_eq!(
        (at.as_path(), note),
        (service.as_path(), TailNote::ServiceSession)
    );
    let tail = sources::read_tail(&at, "sing-box", note).expect("tail");
    assert_eq!(texts(&tail), ["service one"]);
    let (here, note) = folders.engine(Some(CaptureKind::Tun), false);
    assert_eq!(
        (here, note),
        (backend.dirs.logs.clone(), TailNote::TunnelSession)
    );
    backend.shutdown.cancel();
}

/// p-logs: the service source shows what the pipe gave for this user (its lines, or why there
/// are none); nothing is read from the service's private folder.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_service_source_shows_the_users_lines() {
    use vpnte_service::proto::{ServiceLogLine, ServiceLogWire};
    let dir = TempDir::new("logs-service");
    let backend = backend(&dir, FakeTunnel::new(false));
    let log = ServiceLogWire {
        lines: vec![ServiceLogLine {
            offset: 40,
            text: r#"{"ts":"2026-11-13T08:00:00.000Z","level":"INFO","target":"vpnte_service::service","msg":"service starting"}"#.into(),
        }],
        truncated: true,
    };
    let api = start(&backend, &dir, ServiceAnswer::Lines(log));
    let tail = api.read_log(LogSource::Service).await.expect("tail");
    assert!(tail.exists && tail.truncated);
    assert_eq!(
        (tail.lines[0].offset, tail.note),
        (40, TailNote::ServiceLines)
    );
    let none = api.read_log(LogSource::Service).await.expect("tail");
    assert!(!none.exists);
    assert_eq!(none.note, TailNote::NoService);
    let old = sources::service_tail(ServiceAnswer::Old);
    assert_eq!((old.exists, old.note), (false, TailNote::OldService));
    backend.shutdown.cancel();
}
