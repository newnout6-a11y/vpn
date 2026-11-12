use std::time::Duration;

use jiff::civil::date;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;
use vpnte_base::types::Owner;

use super::reconcile::Reconciler;
use super::*;
use crate::coordinator::testing::{Call, FakeCoordinator};
use crate::coordinator::{
    ConnectOutcome, ConnectRequest as Req, LifecycleEvent, OpError, RuntimeId, SessionKind,
    StopCause,
};
use crate::schedule::{Capture, ScheduleMode, Upstream};
use crate::test_support::TempDir;

struct Fixture {
    _dir: TempDir,
    store: Arc<Store<Schedules>>,
    coord: Arc<FakeCoordinator>,
    sched: Scheduler<FakeCoordinator>,
    tz: TimeZone,
}

fn fixture(entries: Vec<ScheduleEntry>) -> Fixture {
    let dir = TempDir::new("sched");
    let store = Arc::new(Store::<Schedules>::open(dir.path()));
    store.update(|d| d.schedules = entries).unwrap();
    let coord = FakeCoordinator::new();
    let sched = Scheduler::new(store.clone(), coord.clone());
    let tz = TimeZone::get("Europe/Moscow").unwrap();
    Fixture {
        _dir: dir,
        store,
        coord,
        sched,
        tz,
    }
}

/// January 2024 in Moscow: the 10th is a Wednesday.
fn at(tz: &TimeZone, day: i8, h: i8, m: i8) -> Timestamp {
    tz.to_timestamp(date(2024, 1, day).at(h, m, 0, 0)).unwrap()
}

fn entry(
    id: &str,
    days: &[u8],
    start: &str,
    end: &str,
    mode: ScheduleMode,
    profile: &str,
) -> ScheduleEntry {
    ScheduleEntry {
        id: id.into(),
        name: id.into(),
        enabled: true,
        days: days.to_vec(),
        start_time: start.parse().unwrap(),
        end_time: end.parse().unwrap(),
        profile_id: profile.into(),
        capture: mode.split().0,
        upstream: mode.split().1,
    }
}

fn hard(id: &str, days: &[u8], start: &str, end: &str) -> ScheduleEntry {
    entry(id, days, start, end, ScheduleMode::Hard, "")
}

fn direct(id: &str, days: &[u8], start: &str, end: &str, profile: &str) -> ScheduleEntry {
    entry(id, days, start, end, ScheduleMode::Direct, profile)
}

const WED: u8 = 3;
const MON_FRI: [u8; 5] = [1, 2, 3, 4, 5];

fn draft(name: &str, days: &[u8], mode: ScheduleMode, profile: &str) -> ScheduleDraft {
    ScheduleDraft {
        name: name.into(),
        enabled: true,
        days: days.to_vec(),
        start_time: "09:00".parse().unwrap(),
        end_time: "17:00".parse().unwrap(),
        profile_id: profile.into(),
        capture: mode.split().0,
        upstream: mode.split().1,
    }
}

fn manual_stop() -> LifecycleEvent {
    LifecycleEvent::Stopped {
        owner: Owner::Schedule,
        runtime_id: RuntimeId(1),
        cause: StopCause::Requested(Owner::Manual),
    }
}

#[test]
fn create_update_delete_validate_and_normalise() {
    let fx = fixture(vec![]);
    let created = fx
        .sched
        .create(draft("  Work  ", &[5, 1, 5, 3], ScheduleMode::Hard, ""))
        .unwrap();
    assert_eq!(
        (created.name.as_str(), created.days.as_slice()),
        ("Work", &[1, 3, 5][..])
    );
    assert!(!created.id.is_empty());

    for bad in [
        draft(" ", &[1], ScheduleMode::Hard, ""),
        draft("x", &[7], ScheduleMode::Hard, ""),
    ] {
        assert_eq!(
            fx.sched.create(bad).unwrap_err().kind,
            ErrorKind::Validation
        );
    }
    let err = fx
        .sched
        .create(draft("x", &[1], ScheduleMode::Direct, " "))
        .unwrap_err();
    assert_eq!(err.user_msg().key, "automation.scheduler.profileRequired");

    let updated = fx
        .sched
        .update(&created.id, draft("Home", &[], ScheduleMode::Direct, "p1"))
        .unwrap();
    assert_eq!(
        (updated.id.as_str(), updated.name.as_str()),
        (created.id.as_str(), "Home")
    );
    let missing = fx
        .sched
        .update("nope", draft("x", &[1], ScheduleMode::Hard, ""))
        .unwrap_err();
    assert_eq!(missing.user_msg().key, "automation.scheduler.notFound");

    fx.sched.delete("nope").unwrap();
    assert_eq!(fx.sched.list(), vec![updated]);
    fx.sched.delete(&created.id).unwrap();
    assert!(fx.sched.list().is_empty());
}

/// One-time import: ids kept, old lenient times stored normalised (`"9:5"` → `"09:05"`).
#[test]
fn legacy_import_keeps_ids_and_normalises_times() {
    let legacy = json!({ "schedules": [
        { "id": "s1", "name": "Work", "enabled": true, "days": [5, 1, 1], "startTime": "9:5",
          "endTime": "18:00", "profileId": "p1", "mode": "direct" },
        { "id": "s2", "name": "Bad", "enabled": true, "days": [1], "startTime": "25:00",
          "endTime": "18:00", "profileId": "", "mode": "hard" },
        { "name": "No id", "enabled": false, "days": [0], "startTime": "22:00",
          "endTime": "06:00", "mode": "soft" },
    ]});
    let (doc, warnings) = Schedules::from_legacy(&legacy);
    assert_eq!(doc.schedules.len(), 2);
    let first = &doc.schedules[0];
    assert_eq!(
        (first.id.as_str(), first.days.as_slice()),
        ("s1", &[1, 5][..])
    );
    assert_eq!(first.start_time.to_string(), "09:05");
    let json = serde_json::to_value(first).unwrap();
    assert_eq!(json["startTime"], "09:05");
    assert!(!doc.schedules[1].id.is_empty());
    assert_eq!(
        warnings,
        vec![Msg::new("automation.scheduler.importSkipped").arg("name", "Bad")]
    );
}

/// A repeated old id gets a fresh one: edits address schedules by id.
#[test]
fn legacy_import_gives_a_repeated_id_a_fresh_one() {
    let entry = |name: &str| {
        json!({ "id": "dup", "name": name, "enabled": false, "days": [1],
                "startTime": "09:00", "endTime": "10:00", "mode": "hard" })
    };
    let (doc, warnings) = Schedules::from_legacy(&json!({ "schedules": [entry("A"), entry("B")] }));
    assert!(warnings.is_empty());
    let ids: Vec<&str> = doc.schedules.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids[0], "dup");
    assert!(!ids[1].is_empty() && ids[1] != "dup");
}

/// A hand-broken entry is skipped instead of making the whole file unreadable.
#[test]
fn stored_file_with_a_bad_entry_still_loads() {
    let dir = TempDir::new("sched-file");
    let text = r#"{ "schemaVersion": 1, "schedules": [
        { "id": "a", "name": "A", "enabled": true, "days": [3, 3], "startTime": "9:00",
          "endTime": "17:00", "profileId": "", "mode": "hard" },
        { "id": "b", "name": "B", "enabled": true, "days": [3], "startTime": "nope",
          "endTime": "17:00", "profileId": "", "mode": "hard" } ] }"#;
    std::fs::write(dir.path().join("schedules.json"), text).unwrap();
    let store = Store::<Schedules>::open(dir.path());
    let doc = store.snapshot();
    assert_eq!(doc.schedules.len(), 1);
    assert_eq!(doc.schedules[0].days, vec![3]);
}

/// AT-10-002 / F-123: overlapping, adjacent, same-end and nested windows → one connect, no
/// disconnect until the end of the last window, one disconnect at that end.
#[tokio::test]
async fn merged_windows_connect_once_and_disconnect_once() {
    for (b_start, b_end, end_h) in [
        ("09:30", "11:00", 11),
        ("10:00", "11:00", 11),
        ("09:30", "10:00", 10),
        ("09:15", "09:45", 10),
    ] {
        let fx = fixture(vec![
            hard("a", &MON_FRI, "09:00", "10:00"),
            hard("b", &MON_FRI, b_start, b_end),
        ]);
        let mut task = Reconciler::new(&fx.sched);
        let end = at(&fx.tz, 10, end_h, 0);
        let one_ms = jiff::SignedDuration::from_millis(1);
        for t in [
            at(&fx.tz, 10, 8, 59),
            at(&fx.tz, 10, 9, 0),
            at(&fx.tz, 10, 9, 30),
            at(&fx.tz, 10, 9, 59),
            end - one_ms,
        ] {
            task.pass(t, &fx.tz).await;
        }
        assert_eq!(
            (fx.coord.connects(), fx.coord.disconnects()),
            (1, 0),
            "{b_start}"
        );
        task.pass(end, &fx.tz).await;
        assert_eq!(fx.coord.disconnects(), 1, "{b_start}");
        let keys = fx.coord.notice_keys();
        assert!(
            keys.contains(&"automation.scheduler.started".into()),
            "{keys:?}"
        );
        assert!(
            keys.contains(&"automation.scheduler.stopped".into()),
            "{keys:?}"
        );
    }
}

/// AT-00-007 / AT-10-006: only an unavailable profile falls through to the next active
/// schedule; exactly one start.
#[tokio::test]
async fn unavailable_profile_falls_through_to_the_next_schedule() {
    let fx = fixture(vec![
        direct("missing", &[WED], "09:00", "17:00", "gone"),
        direct("available", &[WED], "09:00", "17:00", "p2"),
    ]);
    fx.coord
        .connect_results
        .lock()
        .push_back(Err(OpError::ProfileUnavailable));
    let mut task = Reconciler::new(&fx.sched);
    task.pass(at(&fx.tz, 10, 9, 0), &fx.tz).await;
    let expected = vec![
        Call::Connect(
            Owner::Schedule,
            Req::Direct {
                profile_id: "gone".into(),
            },
        ),
        Call::Connect(
            Owner::Schedule,
            Req::Direct {
                profile_id: "p2".into(),
            },
        ),
    ];
    assert_eq!(fx.coord.calls(), expected);
    assert_eq!(
        fx.coord.session().and_then(|s| s.profile_id).as_deref(),
        Some("p2")
    );
}

/// All candidates unavailable: each tried once, one notice, then a backoff retry (S2).
#[tokio::test]
async fn all_unavailable_notifies_once_and_retries() {
    let fx = fixture(vec![
        direct("a", &[WED], "09:00", "17:00", "x"),
        direct("b", &[WED], "09:00", "17:00", "y"),
    ]);
    for _ in 0..4 {
        fx.coord
            .connect_results
            .lock()
            .push_back(Err(OpError::ProfileUnavailable));
    }
    let mut task = Reconciler::new(&fx.sched);
    task.pass(at(&fx.tz, 10, 9, 0), &fx.tz).await;
    assert_eq!(fx.coord.connects(), 2);
    let retry_at = fx.sched.status().borrow().retry_at.unwrap();
    // One minute after the attempt (the attempt's own duration, well under a second, included).
    assert!((0..1000).contains(&(retry_at - at(&fx.tz, 10, 9, 1).as_millisecond())));
    task.pass(
        at(&fx.tz, 10, 9, 0) + jiff::SignedDuration::from_secs(30),
        &fx.tz,
    )
    .await;
    assert_eq!(fx.coord.connects(), 2, "not due yet");
    task.pass(Timestamp::from_millisecond(retry_at).unwrap(), &fx.tz)
        .await;
    assert_eq!(fx.coord.connects(), 4);
    let keys = fx.coord.notice_keys();
    let unavailable = keys
        .iter()
        .filter(|k| *k == "automation.scheduler.profileUnavailable")
        .count();
    assert_eq!(unavailable, 1, "{keys:?}");
}

/// Cancellation, conflict, a network failure or success never fall through (1 call each).
#[tokio::test]
async fn other_outcomes_do_not_fall_through() {
    let outcomes: [fn() -> Result<ConnectOutcome, OpError>; 4] = [
        || Err(OpError::Cancelled),
        || Err(OpError::Conflict),
        || Err(OpError::Failed(AppError::new(ErrorKind::Network))),
        || Ok(ConnectOutcome::Connected),
    ];
    for outcome in outcomes {
        let fx = fixture(vec![
            direct("a", &[WED], "09:00", "17:00", "x"),
            direct("b", &[WED], "09:00", "17:00", "y"),
        ]);
        fx.coord.connect_results.lock().push_back(outcome());
        Reconciler::new(&fx.sched)
            .pass(at(&fx.tz, 10, 9, 0), &fx.tz)
            .await;
        assert_eq!(fx.coord.connects(), 1);
    }
}

/// Refused while a higher-priority operation runs: retried with backoff, without a notice.
#[tokio::test]
async fn busy_coordinator_is_retried_quietly() {
    let fx = fixture(vec![hard("a", &[WED], "09:00", "17:00")]);
    fx.coord
        .connect_results
        .lock()
        .push_back(Err(OpError::Conflict));
    let mut task = Reconciler::new(&fx.sched);
    task.pass(at(&fx.tz, 10, 9, 0), &fx.tz).await;
    assert!(fx.coord.notice_keys().is_empty());
    let retry_at = fx.sched.status().borrow().retry_at.unwrap();
    task.pass(Timestamp::from_millisecond(retry_at).unwrap(), &fx.tz)
        .await;
    assert_eq!(fx.coord.connects(), 2);
    assert_eq!(
        fx.coord.notice_keys(),
        vec!["automation.scheduler.title", "automation.scheduler.started"]
    );
}

/// A manual stop racing the fan-out fences the remaining candidates and suppresses the run.
#[tokio::test]
async fn manual_action_fences_a_pending_fallback() {
    let fx = fixture(vec![
        direct("a", &[WED], "09:00", "17:00", "x"),
        direct("b", &[WED], "09:00", "17:00", "y"),
    ]);
    fx.coord
        .connect_results
        .lock()
        .push_back(Err(OpError::ProfileUnavailable));
    *fx.coord.during_connect.lock() = Some(manual_stop());
    let mut task = Reconciler::new(&fx.sched);
    task.pass(at(&fx.tz, 10, 9, 0), &fx.tz).await;
    assert_eq!(fx.coord.connects(), 1);
    assert!(fx.store.read(|d| d.suppressed_at.is_some()));
    assert!(fx.coord.notice_keys().is_empty());
    assert!(fx.sched.status().borrow().suppressed);
}

/// Fix S6 and NOADMIN §2: capture and upstream decide the request apart; a local-proxy schedule
/// never touches the profile id, a server schedule runs over either capture.
#[tokio::test]
async fn capture_and_upstream_pick_the_request() {
    for (capture, upstream, expected) in [
        (
            Capture::Tun,
            Upstream::LocalProxy,
            Req::LocalProxyHard { endpoint: None },
        ),
        (
            Capture::Proxy,
            Upstream::LocalProxy,
            Req::Soft { endpoint: None },
        ),
        (
            Capture::Tun,
            Upstream::Server,
            Req::Direct {
                profile_id: "p1".into(),
            },
        ),
        (
            Capture::Proxy,
            Upstream::Server,
            Req::SoftDirect {
                profile_id: "p1".into(),
            },
        ),
    ] {
        let mut e = hard("a", &[WED], "09:00", "17:00");
        (e.capture, e.upstream, e.profile_id) = (capture, upstream, "p1".into());
        let fx = fixture(vec![e]);
        Reconciler::new(&fx.sched)
            .pass(at(&fx.tz, 10, 9, 0), &fx.tz)
            .await;
        assert_eq!(
            fx.coord.calls(),
            vec![Call::Connect(Owner::Schedule, expected)]
        );
    }
}

/// Records written before capture / upstream were stored apart keep their meaning 1:1; new
/// records store the pair; a record with neither is skipped, not the whole file.
#[test]
fn stored_entries_read_the_old_mode_and_the_pair() {
    let doc: Schedules = serde_json::from_value(json!({"schedules": [
        {"id": "h", "name": "h", "enabled": true, "days": [1], "startTime": "09:00",
         "endTime": "10:00", "mode": "hard"},
        {"id": "s", "name": "s", "enabled": true, "days": [1], "startTime": "09:00",
         "endTime": "10:00", "mode": "soft"},
        {"id": "d", "name": "d", "enabled": true, "days": [1], "startTime": "09:00",
         "endTime": "10:00", "mode": "direct", "profileId": "p"},
        {"id": "n", "name": "n", "enabled": true, "days": [1], "startTime": "09:00",
         "endTime": "10:00", "capture": "proxy", "upstream": "server", "profileId": "p"},
        {"id": "x", "name": "x", "enabled": true, "days": [1], "startTime": "09:00",
         "endTime": "10:00"},
    ]}))
    .unwrap();
    let pairs: Vec<_> = doc
        .schedules
        .iter()
        .map(|e| (e.id.as_str(), e.capture, e.upstream))
        .collect();
    assert_eq!(
        pairs,
        [
            ("h", Capture::Tun, Upstream::LocalProxy),
            ("s", Capture::Proxy, Upstream::LocalProxy),
            ("d", Capture::Tun, Upstream::Server),
            ("n", Capture::Proxy, Upstream::Server),
        ]
    );
    let written = serde_json::to_value(&doc.schedules[3]).unwrap();
    assert_eq!(
        (
            &written["capture"],
            &written["upstream"],
            written.get("mode")
        ),
        (&json!("proxy"), &json!("server"), None)
    );
}

/// S1: asleep 09:30–11:00 across A 09–10 and B 10:30–12 → on wake the task connects for B
/// and issues no disconnect.
#[tokio::test]
async fn wake_after_sleep_connects_the_current_run_without_a_stop() {
    let fx = fixture(vec![
        hard("a", &[WED], "09:00", "10:00"),
        direct("b", &[WED], "10:30", "12:00", "pb"),
    ]);
    let mut task = Reconciler::new(&fx.sched);
    task.pass(at(&fx.tz, 10, 9, 0), &fx.tz).await;
    task.pass(at(&fx.tz, 10, 11, 0), &fx.tz).await;
    let expected = vec![
        Call::Connect(Owner::Schedule, Req::LocalProxyHard { endpoint: None }),
        Call::Connect(
            Owner::Schedule,
            Req::Direct {
                profile_id: "pb".into(),
            },
        ),
    ];
    assert_eq!(fx.coord.calls(), expected);
}

/// S5: a manual session from 08:30 satisfies the run: no connect at 09:00, no retry, no
/// notice, and it is still connected at 17:01.
#[tokio::test]
async fn manual_session_is_never_taken_over_or_stopped() {
    let fx = fixture(vec![hard("a", &[WED], "09:00", "17:00")]);
    fx.coord
        .set_session(SessionKind::Direct, Owner::Manual, Some("m"));
    let mut task = Reconciler::new(&fx.sched);
    for t in [
        at(&fx.tz, 10, 9, 0),
        at(&fx.tz, 10, 12, 0),
        at(&fx.tz, 10, 17, 1),
    ] {
        task.pass(t, &fx.tz).await;
    }
    assert!(fx.coord.calls().is_empty());
    assert!(fx.coord.notice_keys().is_empty());
    assert_eq!(fx.coord.session().map(|s| s.owner), Some(Owner::Manual));
}

/// S8: a manual stop at 12:00 survives a restart at 13:00 (no reconnect until the next run);
/// a restart without a manual stop (crash) reconnects because `acted` is not persisted.
#[tokio::test]
async fn manual_stop_suppresses_the_run_across_restarts() {
    let fx = fixture(vec![hard("a", &[WED, 4], "09:00", "17:00")]);
    let mut task = Reconciler::new(&fx.sched);
    task.pass(at(&fx.tz, 10, 9, 0), &fx.tz).await;
    *fx.coord.session.lock() = None;
    fx.coord.emit(manual_stop());
    task.pass(at(&fx.tz, 10, 12, 0), &fx.tz).await;
    drop(task);
    let restarted = Scheduler::new(fx.store.clone(), fx.coord.clone());
    let mut task = Reconciler::new(&restarted);
    task.pass(at(&fx.tz, 10, 13, 0), &fx.tz).await;
    task.pass(at(&fx.tz, 10, 17, 0), &fx.tz).await;
    assert_eq!((fx.coord.connects(), fx.coord.disconnects()), (1, 0));
    assert_eq!(
        fx.store.read(|d| d.suppressed_at),
        None,
        "cleared once the run is over"
    );
    task.pass(at(&fx.tz, 11, 9, 0), &fx.tz).await;
    assert_eq!(fx.coord.connects(), 2, "the next run connects again");

    let crash = fixture(vec![hard("a", &[WED], "09:00", "17:00")]);
    Reconciler::new(&crash.sched)
        .pass(at(&crash.tz, 10, 9, 0), &crash.tz)
        .await;
    *crash.coord.session.lock() = None;
    let restarted = Scheduler::new(crash.store.clone(), crash.coord.clone());
    Reconciler::new(&restarted)
        .pass(at(&crash.tz, 10, 13, 0), &crash.tz)
        .await;
    assert_eq!(crash.coord.connects(), 2);
}

/// S9: the run ends while nothing of the schedule runs → no stop, no notice.
#[tokio::test]
async fn run_end_without_a_schedule_session_does_nothing() {
    let fx = fixture(vec![hard("a", &[WED], "09:00", "17:00")]);
    fx.coord
        .connect_results
        .lock()
        .push_back(Err(OpError::NoLocalProxy));
    let mut task = Reconciler::new(&fx.sched);
    task.pass(at(&fx.tz, 10, 9, 0), &fx.tz).await;
    task.pass(at(&fx.tz, 10, 17, 0), &fx.tz).await;
    assert_eq!(fx.coord.disconnects(), 0);
    let keys = fx.coord.notice_keys();
    assert_eq!(
        keys,
        vec![
            "automation.scheduler.connectFailed",
            "automation.coordinator.noLocalProxy"
        ]
    );
}

/// fixauto-a4/b3: the schedule's session ended shortly before the run's end and left the kill
/// switch's block (an abandoned adaptive check): the run's end releases it with the schedule's
/// stop and notice. What another owner's session left is not the schedule's to release.
#[tokio::test]
async fn run_end_releases_what_its_session_left_behind() {
    for (left, released) in [(Owner::Schedule, true), (Owner::Manual, false)] {
        let fx = fixture(vec![hard("a", &[WED], "09:00", "17:00")]);
        let mut task = Reconciler::new(&fx.sched);
        task.pass(at(&fx.tz, 10, 9, 0), &fx.tz).await;
        fx.coord.stop(StopCause::Fault);
        *fx.coord.left_by.lock() = Some(left);
        task.pass(at(&fx.tz, 10, 17, 0), &fx.tz).await;
        assert_eq!(fx.coord.disconnects(), usize::from(released), "{left:?}");
        assert_eq!(fx.coord.left_by(), (!released).then_some(left));
        let stopped = (fx.coord.notice_keys().iter()).any(|k| k == "automation.scheduler.stopped");
        assert_eq!(stopped, released, "{left:?}");
    }
}

/// An AutoPilot-owned session at the run start is switched to the scheduled request.
#[tokio::test]
async fn autopilot_session_is_switched_to_the_schedule() {
    let fx = fixture(vec![direct("a", &[WED], "09:00", "17:00", "p1")]);
    fx.coord
        .set_session(SessionKind::LocalProxyHard, Owner::Autopilot, None);
    Reconciler::new(&fx.sched)
        .pass(at(&fx.tz, 10, 9, 0), &fx.tz)
        .await;
    let session = fx.coord.session().unwrap();
    assert_eq!(
        (session.owner, session.kind),
        (Owner::Schedule, SessionKind::Direct)
    );
}

/// A crash of the schedule's own session inside the run arms the backoff retry.
#[tokio::test]
async fn crashed_schedule_session_is_retried_with_backoff() {
    let fx = fixture(vec![hard("a", &[WED], "09:00", "17:00")]);
    let mut task = Reconciler::new(&fx.sched);
    task.pass(at(&fx.tz, 10, 9, 0), &fx.tz).await;
    *fx.coord.session.lock() = None;
    fx.coord.emit(LifecycleEvent::Stopped {
        owner: Owner::Schedule,
        runtime_id: RuntimeId(1),
        cause: StopCause::Fault,
    });
    task.pass(at(&fx.tz, 10, 12, 0), &fx.tz).await;
    assert_eq!(fx.coord.connects(), 1, "retry is not immediate");
    task.pass(at(&fx.tz, 10, 12, 1), &fx.tz).await;
    assert_eq!(fx.coord.connects(), 2);
}

/// S2 backoff 60, 120, 300, 600, 600 s; the failure is notified once per run.
#[tokio::test]
async fn failed_connects_back_off_and_notify_once() {
    let fx = fixture(vec![hard("a", &[WED], "09:00", "17:00")]);
    let mut task = Reconciler::new(&fx.sched);
    let mut t = at(&fx.tz, 10, 9, 0);
    let mut delays = Vec::new();
    for _ in 0..5 {
        fx.coord
            .connect_results
            .lock()
            .push_back(Err(OpError::Timeout));
        task.pass(t, &fx.tz).await;
        let next =
            Timestamp::from_millisecond(fx.sched.status().borrow().retry_at.unwrap()).unwrap();
        delays.push((next - t).get_seconds());
        t = next;
    }
    assert_eq!(delays, vec![60, 120, 300, 600, 600]);
    assert_eq!(
        fx.coord
            .notice_keys()
            .iter()
            .filter(|k| *k == "automation.scheduler.connectFailed")
            .count(),
        1
    );
}

/// AT-10-001 timer row: New York, Sunday 02:30–04:00 on the spring-forward day → one connect
/// at 03:30 EDT (the gap moves the start), one disconnect 30 minutes later.
#[tokio::test]
async fn dst_gap_run_connects_once_and_stops_half_an_hour_later() {
    let mut fx = fixture(vec![hard("dst", &[0], "02:30", "04:00")]);
    fx.tz = TimeZone::get("America/New_York").unwrap();
    let ts = |s: &str| s.parse::<Timestamp>().unwrap();
    let mut task = Reconciler::new(&fx.sched);
    task.pass(ts("2024-03-10T01:00:00-05:00"), &fx.tz).await;
    let next = fx.sched.status().borrow().next.clone().unwrap();
    assert_eq!(next.at, ts("2024-03-10T03:30:00-04:00").as_millisecond());
    task.pass(ts("2024-03-10T03:29:59.999-04:00"), &fx.tz).await;
    assert_eq!(fx.coord.connects(), 0);
    task.pass(ts("2024-03-10T03:30:00-04:00"), &fx.tz).await;
    task.pass(ts("2024-03-10T03:59:59.999-04:00"), &fx.tz).await;
    assert_eq!((fx.coord.connects(), fx.coord.disconnects()), (1, 0));
    task.pass(ts("2024-03-10T04:00:00-04:00"), &fx.tz).await;
    assert_eq!(fx.coord.disconnects(), 1);
}

/// A zone change is picked up by the next pass: the boundary is recomputed in the new zone.
#[tokio::test]
async fn zone_change_recomputes_the_next_boundary() {
    let fx = fixture(vec![hard("a", &[WED], "09:00", "17:00")]);
    let mut task = Reconciler::new(&fx.sched);
    let now = at(&fx.tz, 10, 6, 0);
    task.pass(now, &fx.tz).await;
    let moscow = fx.sched.status().borrow().next.clone().unwrap();
    let berlin = TimeZone::get("Europe/Berlin").unwrap();
    task.pass(now, &berlin).await;
    let next = fx.sched.status().borrow().next.clone().unwrap();
    assert_eq!(next.at - moscow.at, 2 * 3_600_000);
    assert_eq!(
        (next.kind, next.schedule_id.as_str()),
        (BoundaryKind::Start, "a")
    );
}

/// The real loop: first pass connects inside an active window, `ready` is published, cancel ends it.
#[tokio::test]
async fn run_loop_first_pass_and_cancel() {
    let fx = fixture(vec![hard(
        "always",
        &[0, 1, 2, 3, 4, 5, 6],
        "00:00",
        "00:00",
    )]);
    let sched = Arc::new(Scheduler::new(fx.store.clone(), fx.coord.clone()));
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let (sched, cancel) = (sched.clone(), cancel.clone());
        async move { sched.run(cancel).await }
    });
    let mut status = sched.status();
    tokio::time::timeout(Duration::from_secs(10), status.wait_for(|s| s.ready))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fx.coord.connects(), 1);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
}
