//! Tests of the «Журнал» API: history rows (outcomes and evidence), the history and the events
//! pushed together, one clear per tab, the engine logs of Proxy and service sessions, the
//! service's lines (a fake pipe; temp folders only).
use std::time::Duration;

use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_base::types::Owner;
use vpnte_core::ops::Source;
use vpnte_service::proto::EngineLog;
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

/// Folders of a test: the user's logs folder.
fn folders(backend: &Backend) -> Folders {
    Folders {
        user: backend.dirs.logs.clone(),
    }
}

/// The helper service's lines as a fake pipe gives them (its engine logs: `engine one` for
/// whichever log is asked).
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

    async fn engine(&self, log: EngineLog) -> vpnte_base::AppResult<ServiceAnswer> {
        use vpnte_service::proto::{ServiceLogLine, ServiceLogWire};
        Ok(ServiceAnswer::Lines(ServiceLogWire {
            lines: vec![ServiceLogLine {
                offset: 0,
                text: format!("{} one", log.stem()),
            }],
            truncated: false,
        }))
    }
}

fn start(backend: &Arc<Backend>, answer: ServiceAnswer) -> LogsService {
    let fake = Arc::new(FakeService(std::sync::Mutex::new(Some(answer))));
    LogsService::start_with(backend.clone(), folders(backend), fake)
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
    let api = start(&backend, ServiceAnswer::NotInstalled);
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
/// user's folder, a Tunnel session through the service its pipe (p-owner-logs O-4: the service's
/// folder is SYSTEM and Administrators only); each says which.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_logs_follow_the_session() {
    let dir = TempDir::new("logs-tail");
    let tunnel = FakeTunnel::new(false);
    let backend = backend(&dir, tunnel.clone());
    let api = start(&backend, ServiceAnswer::NotInstalled);
    std::fs::write(backend.dirs.logs.join("sing-box.log"), "own one\nown two\n").expect("log");
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
    // Xray's session log is slot A's (`xray.log` was never written).
    std::fs::write(backend.dirs.logs.join("xray-a.log"), "slot a\n").expect("log");
    let xray = api.read_log(LogSource::Xray).await.expect("tail");
    assert_eq!(texts(&xray), ["slot a"]);
    // A Tunnel session through the service: its lines come through the (fake) pipe, under the
    // session's line (`read_log` takes this branch when `engine_place` says so, as above).
    let fake = FakeService(std::sync::Mutex::new(None));
    for (log, line) in [
        (EngineLog::SingBox, "sing-box one"),
        (EngineLog::XrayA, "xray-a one"),
    ] {
        let answer = fake.engine(log).await.expect("answer");
        let tail = sources::engine_tail(answer, TailNote::ServiceSession);
        assert_eq!(
            (texts(&tail), tail.note),
            (vec![line.to_owned()], TailNote::ServiceSession)
        );
    }
    let old = sources::engine_tail(ServiceAnswer::Old, TailNote::ServiceSession);
    assert_eq!(old.note, TailNote::OldService, "an older service says so");
    backend.shutdown.cancel();
}

/// p-owner-logs follow-up: after a server switch the running server's Xray lines are in slot
/// B's log; the Xray source shows both slots by their lines' time, each tagged (a continuation
/// line keeps the time before it). With lines of slot A only nothing is tagged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_xray_source_shows_both_slots() {
    use ui::XraySlot::{A, B};
    let dir = TempDir::new("logs-slots");
    let backend = backend(&dir, FakeTunnel::new(false));
    let api = start(&backend, ServiceAnswer::NotInstalled);
    let logs = &backend.dirs.logs;
    let a = concat!(
        "2026/11/15 04:44:45.100000 [Warning] a started\n",
        "2026/11/15 04:46:00.000000 [Warning] a stopped\n",
    );
    std::fs::write(logs.join("xray-a.log"), a).expect("log");
    let alone = api.read_log(LogSource::Xray).await.expect("tail");
    assert_eq!(alone.lines.len(), 2);
    assert!(
        alone.lines.iter().all(|l| l.slot.is_none()),
        "one slot: untagged"
    );
    let b = "2026/11/15 04:45:10.200000 [Warning] b started\n  continued\n";
    std::fs::write(logs.join("xray-b.log"), b).expect("log");
    let both = api.read_log(LogSource::Xray).await.expect("tail");
    let seen: Vec<_> = (both.lines.iter())
        .map(|l| {
            (
                l.slot,
                l.text.rsplit(' ').next().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let want = [
        (A, "started"),
        (B, "started"),
        (B, "continued"),
        (A, "stopped"),
    ];
    let want: Vec<_> = want
        .iter()
        .map(|(s, t)| (Some(*s), (*t).to_owned()))
        .collect();
    assert_eq!(seen, want);
    // Through the service's pipe the same merge (its lines here carry no time).
    let fake = FakeService(std::sync::Mutex::new(None));
    let a = fake.engine(EngineLog::XrayA).await.expect("answer");
    let b = fake.engine(EngineLog::XrayB).await.expect("answer");
    let note = TailNote::ServiceSession;
    let merged = sources::slots_tail(sources::engine_tail(a, note), sources::engine_tail(b, note));
    let slots: Vec<_> = merged.lines.iter().map(|l| l.slot).collect();
    assert_eq!(slots, [Some(A), Some(B)]);
    assert_eq!(merged.note, note);
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
    let api = start(&backend, ServiceAnswer::Lines(log));
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

/// p-follow3: an installed service that Windows is starting or has stopped is said as such on
/// the service source (the helper's own line), not as a failure or «не установлена».
#[test]
fn a_paused_service_is_said_as_such() {
    use crate::boot::service::Presence;
    let note = |p: Presence| sources::not_answering(p).map(|a| sources::service_tail(a).note);
    assert_eq!(note(Presence::Starting), Some(TailNote::ServiceStarting));
    assert_eq!(note(Presence::Stopped), Some(TailNote::ServiceStopped));
    assert_eq!(note(Presence::Stopping), Some(TailNote::ServiceStopped));
    // running (its pipe failed for another reason) or gone: the pipe's own error stays
    assert_eq!(note(Presence::Running), None);
    assert_eq!(note(Presence::Missing), None);
    let stopped = sources::service_tail(ServiceAnswer::Stopped);
    assert!(!stopped.exists && stopped.lines.is_empty());
}
