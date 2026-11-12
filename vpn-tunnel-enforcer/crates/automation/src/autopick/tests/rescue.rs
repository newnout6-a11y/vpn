//! When the failed server cannot be kept (RU item 8): one episode per server and network, its
//! subscription fetched again once, its fresh keys first, then the other groups when the user
//! allows switching, in rounds with a growing pause; a success only after traffic passed; the
//! user's own actions and opt-outs always win.
use vpnte_base::types::{AdaptiveMode, Level, Owner};
use vpnte_base::{AppError, ErrorKind};

use super::*;
use crate::coordinator::testing::Call;
use crate::coordinator::{
    ConnectOutcome, LifecycleEvent, OpError, RuntimeId, SessionKind, StopCause, SwitchError,
};

pub(super) fn failed() -> Result<ConnectOutcome, OpError> {
    Err(OpError::Failed(AppError::new(ErrorKind::Internal)))
}

/// Every server the episodes connected (as `Autopilot`) or switched to (as `AdaptiveRetry`).
pub(super) fn dials(rig: &Rig) -> Vec<String> {
    (rig.coord.calls().into_iter())
        .filter_map(|c| match c {
            Call::Connect(Owner::Autopilot, ConnectRequest::Direct { profile_id }) => {
                Some(profile_id)
            }
            Call::Switch(Owner::AdaptiveRetry, id) => Some(id),
            _ => None,
        })
        .collect()
}

/// Every notice as (level, title key, body key).
pub(super) fn notices(rig: &Rig) -> Vec<(Level, String, Option<String>)> {
    let notices = rig.coord.notices.lock();
    (notices.iter())
        .map(|(_, n)| {
            let body = n.body.as_ref().map(|b| b.key.to_string());
            (n.level, n.title.key.to_string(), body)
        })
        .collect()
}

pub(super) fn notice(
    level: Level,
    key: &str,
    body: Option<&str>,
) -> (Level, String, Option<String>) {
    (
        level,
        format!("automation.autopick.{key}"),
        body.map(str::to_owned),
    )
}

/// The watch task runs.
pub(super) async fn watching(rig: &Rig) -> CancellationToken {
    let cancel = CancellationToken::new();
    let (pick, c) = (rig.pick.clone(), cancel.clone());
    tokio::spawn(async move { pick.run(c).await });
    tokio::task::yield_now().await;
    cancel
}

/// The watch task runs, then the user's session on `id` starts and ends with a fault.
async fn fault_on(rig: &Rig, id: &str) -> CancellationToken {
    let cancel = watching(rig).await;
    rig.coord
        .start(SessionKind::SoftDirect, Some(id), AdaptiveMode::Baseline);
    tokio::task::yield_now().await;
    rig.coord.stop(StopCause::Fault);
    cancel
}

/// Review fix b6, a7/b8, b11: the subscription is fetched once, the fresh key goes first, and
/// "restored" is said only after a transfer passed through the new session, as the one notice
/// (nothing announced before it was tried, no body that contradicts it).
#[tokio::test(start_paused = true)]
async fn a_fault_is_restored_only_after_traffic_passed() {
    let rig = rig(vec![server("a", "g"), server("b", "h"), server("a2", "g")]);
    *rig.host.fresh.lock() = Some(vec!["a2".into()]);
    let cancel = fault_on(&rig, "a").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(*rig.host.refreshes.lock(), ["a"]);
    assert_eq!(dials(&rig), ["a2"]);
    assert_eq!(*rig.host.slots.lock(), ["a2"], "every dial behind a slot");
    assert_eq!(
        *rig.host.confirms.lock(),
        ["a2"],
        "the proof of the new session"
    );
    assert_eq!(
        notices(&rig),
        [notice(Level::Info, "rescue.recovered", None)]
    );
    assert_eq!(rig.pick.status().borrow().phase, Phase::Idle);
    cancel.cancel();
}

/// Review fix b6: a session that starts but carries nothing is no recovery; the next candidate
/// moves the episode's own session.
#[tokio::test(start_paused = true)]
async fn a_dial_that_carries_nothing_is_no_recovery() {
    let rig = rig(vec![server("a", "g"), server("a2", "g"), server("b", "h")]);
    *rig.host.fresh.lock() = Some(vec!["a2".into()]);
    rig.host
        .confirm_results
        .lock()
        .push_back(Confirmation::NoTraffic);
    let cancel = fault_on(&rig, "a").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        rig.coord.calls(),
        [
            Call::Connect(
                Owner::Autopilot,
                ConnectRequest::Direct {
                    profile_id: "a2".into()
                }
            ),
            Call::Switch(Owner::AdaptiveRetry, "b".into()),
        ]
    );
    assert_eq!(
        notices(&rig),
        [notice(Level::Info, "rescue.recovered", None)]
    );
    cancel.cancel();
}

/// No fresh key helps: the other groups, then rounds over everything not dialled within the
/// freeze window, pauses 30 s, 60 s, ...; bounded in rounds and dials; one notice when it gives
/// up, with what traffic does then.
#[tokio::test(start_paused = true)]
async fn then_the_other_groups_then_bounded_rounds_then_it_gives_up() {
    let rig = rig(vec![server("a", "g"), server("a3", "g"), server("b", "h")]);
    *rig.host.fresh.lock() = Some(Vec::new());
    *rig.host.exposure.lock() = Exposure::Direct;
    let fails = (0..40).map(|_| failed());
    rig.coord.connect_results.lock().extend(fails);
    let cancel = fault_on(&rig, "a").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(dials(&rig), ["b"], "round 1: the other group");
    let status = rig.pick.status().borrow().clone();
    assert_eq!((status.phase, status.round), (Phase::Waiting, 1));
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(
        dials(&rig),
        ["b", "a3"],
        "round 2: what is out of its quiet window"
    );
    tokio::time::sleep(Duration::from_secs(3600)).await;
    let tries = dials(&rig).len();
    use super::super::rescue::{PER_ROUND, ROUNDS};
    let bound = 2 * PER_ROUND + usize::from(ROUNDS - 1) * PER_ROUND;
    assert!((3..=bound).contains(&tries), "{tries} dials");
    assert_eq!(rig.pick.status().borrow().phase, Phase::GaveUp);
    assert_eq!(
        notices(&rig),
        [notice(
            Level::Warn,
            "rescue.gaveUp",
            Some("automation.autopick.exposure.direct")
        )]
    );
    assert_eq!(*rig.host.refreshes.lock(), ["a"], "fetched once");
    cancel.cancel();
}

/// Review fix a1/b5/b6: one episode per failed server and network; a network change gives every
/// server a new chance.
#[tokio::test(start_paused = true)]
async fn one_episode_per_server_and_network() {
    let rig = rig(vec![server("a", "g"), server("b", "h")]);
    let fails = (0..80).map(|_| failed());
    rig.coord.connect_results.lock().extend(fails);
    let cancel = fault_on(&rig, "a").await;
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(rig.pick.status().borrow().phase, Phase::GaveUp);
    let spent = dials(&rig).len();
    rig.coord
        .start(SessionKind::SoftDirect, Some("a"), AdaptiveMode::Baseline);
    tokio::task::yield_now().await;
    assert_eq!(
        rig.pick.status().borrow().phase,
        Phase::Idle,
        "a session ends it"
    );
    rig.coord.stop(StopCause::Fault);
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(*rig.host.refreshes.lock(), ["a"]);
    assert_eq!(
        dials(&rig).len(),
        spent,
        "the same server on the same network: no episode"
    );
    rig.coord.emit(LifecycleEvent::NetworkChanged);
    tokio::task::yield_now().await;
    rig.coord
        .start(SessionKind::SoftDirect, Some("a"), AdaptiveMode::Baseline);
    tokio::task::yield_now().await;
    rig.coord.stop(StopCause::Fault);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(*rig.host.refreshes.lock(), ["a", "a"], "a new network");
    cancel.cancel();
}

/// Review fix a2: the user's Cancel of the episode's own switch ends the episode; nothing more
/// is dialled, nothing is announced.
#[tokio::test(start_paused = true)]
async fn the_users_cancel_of_its_switch_ends_the_episode() {
    let rig = rig(vec![
        server("a", "g"),
        server("b", "h"),
        server("c", "h"),
        server("d", "h"),
    ]);
    rig.host
        .confirm_results
        .lock()
        .push_back(Confirmation::NoTraffic);
    rig.coord
        .switch_results
        .lock()
        .push_back(Err(SwitchError::Failed {
            reason: OpError::Cancelled,
            restored_previous: true,
        }));
    let cancel = fault_on(&rig, "a").await;
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(
        dials(&rig),
        ["b", "c"],
        "never the next one after the Cancel"
    );
    assert!(notices(&rig).is_empty());
    assert_eq!(rig.pick.status().borrow().phase, Phase::Idle);
    cancel.cancel();
}

/// Review fix b1: the user cancels their own switch; the lane ends the session with a stop
/// nobody asked for, which the app reads as a fault. That is the user's doing: nothing starts.
#[tokio::test(start_paused = true)]
async fn the_users_cancel_of_their_own_switch_starts_nothing() {
    let rig = rig(vec![server("a", "g"), server("b", "h")]);
    let cancel = watching(&rig).await;
    rig.coord
        .start(SessionKind::SoftDirect, Some("a"), AdaptiveMode::Baseline);
    tokio::task::yield_now().await;
    rig.host.user_acts_now();
    rig.host.user_stops();
    rig.coord.stop(StopCause::Fault);
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert!(rig.host.refreshes.lock().is_empty());
    assert!(dials(&rig).is_empty());
    assert!(notices(&rig).is_empty());
    cancel.cancel();
}

/// Review fix a5: a Disconnect while the episode waits for its handshake slot is final.
#[tokio::test(start_paused = true)]
async fn a_disconnect_during_the_slot_wait_is_final() {
    let rig = rig(vec![server("a", "g"), server("b", "h"), server("c", "h")]);
    *rig.host.act_at.lock() = Some(("b".into(), true));
    let cancel = fault_on(&rig, "a").await;
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(*rig.host.slots.lock(), ["b"]);
    assert!(dials(&rig).is_empty(), "{:?}", rig.coord.calls());
    cancel.cancel();
}

/// Review fix a3/b4: «Restart the engine after a crash» off = no automatic reconnect at all.
#[tokio::test(start_paused = true)]
async fn with_restarts_after_a_crash_off_a_fault_reconnects_nothing() {
    let rig = rig(vec![server("a", "g"), server("b", "h")]);
    rig.host.allowed.lock().reconnect = false;
    let cancel = fault_on(&rig, "a").await;
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert!(rig.host.refreshes.lock().is_empty());
    assert!(dials(&rig).is_empty());
    assert!(notices(&rig).is_empty());
    cancel.cancel();
}

/// Review fix a3/b4: the neighbouring-server switch off = no other server; only the failed one
/// is dialled again, after its freeze window.
#[tokio::test(start_paused = true)]
async fn without_switching_only_the_failed_server_is_dialled_again() {
    let rig = rig(vec![server("a", "g"), server("b", "h"), server("a2", "g")]);
    *rig.host.fresh.lock() = Some(vec!["a2".into()]);
    rig.host.allowed.lock().switch = false;
    let fails = (0..40).map(|_| failed());
    rig.coord.connect_results.lock().extend(fails);
    let cancel = fault_on(&rig, "a").await;
    tokio::time::sleep(Duration::from_secs(3600)).await;
    let tries = dials(&rig);
    assert!(
        !tries.is_empty() && tries.iter().all(|id| id == "a"),
        "{tries:?}"
    );
    cancel.cancel();
}

/// Rule 2: a block the kill switch keeps is never replaced by an automatic connect; review fix
/// a4: neither is a session the coordinator restored (or anyone started) after the fault.
#[tokio::test(start_paused = true)]
async fn what_the_lane_holds_after_a_fault_is_left_alone() {
    let blocked = rig(vec![server("a", "g"), server("b", "h")]);
    let cancel = watching(&blocked).await;
    blocked
        .coord
        .start(SessionKind::SoftDirect, Some("a"), AdaptiveMode::Baseline);
    tokio::task::yield_now().await;
    *blocked.coord.left_by.lock() = Some(Owner::Manual);
    blocked.coord.stop(StopCause::Fault);
    tokio::time::sleep(Duration::from_secs(600)).await;
    cancel.cancel();

    let restored = rig(vec![server("a", "g"), server("b", "h")]);
    let cancel = watching(&restored).await;
    restored
        .coord
        .start(SessionKind::SoftDirect, Some("a"), AdaptiveMode::Baseline);
    tokio::task::yield_now().await;
    restored.coord.stop(StopCause::Fault);
    restored
        .coord
        .set_session(SessionKind::SoftDirect, Owner::Manual, Some("a"));
    tokio::time::sleep(Duration::from_secs(600)).await;
    cancel.cancel();
    for rig in [&blocked, &restored] {
        assert!(rig.host.refreshes.lock().is_empty());
        assert!(dials(rig).is_empty(), "{:?}", rig.coord.calls());
    }
}

/// Rule 3: only the end of the run the watch tracks counts; a stale stop leaves it tracked.
#[tokio::test(start_paused = true)]
async fn a_stop_of_another_run_is_ignored() {
    let rig = rig(vec![server("a", "g"), server("b", "h")]);
    let cancel = watching(&rig).await;
    rig.coord
        .start(SessionKind::SoftDirect, Some("a"), AdaptiveMode::Baseline);
    tokio::task::yield_now().await;
    rig.coord.emit(LifecycleEvent::Stopped {
        owner: Owner::Manual,
        runtime_id: RuntimeId(7),
        cause: StopCause::Fault,
    });
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert!(rig.host.refreshes.lock().is_empty());
    rig.coord.stop(StopCause::Fault);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        *rig.host.refreshes.lock(),
        ["a"],
        "the tracked run's own fault"
    );
    cancel.cancel();
}

/// The automatic paths never act against the user: an action ends the retries, and a strip that
/// gave up is cleared by the next one.
#[tokio::test(start_paused = true)]
async fn the_users_own_action_ends_the_retries() {
    let rig = rig(vec![server("a", "g"), server("b", "h"), server("c", "h")]);
    let fails = (0..40).map(|_| failed());
    rig.coord.connect_results.lock().extend(fails);
    let cancel = fault_on(&rig, "a").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let before = dials(&rig).len();
    rig.host.user_acts_now();
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(dials(&rig).len(), before);
    assert_eq!(rig.pick.status().borrow().phase, Phase::Idle);
    cancel.cancel();

    let rig = super::rig(vec![server("a", "g"), server("b", "h")]);
    let fails = (0..40).map(|_| failed());
    rig.coord.connect_results.lock().extend(fails);
    let cancel = fault_on(&rig, "a").await;
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(rig.pick.status().borrow().phase, Phase::GaveUp);
    rig.host.user_acts_now();
    tokio::task::yield_now().await;
    assert_eq!(
        rig.pick.status().borrow().phase,
        Phase::Idle,
        "review fix b2"
    );
    cancel.cancel();
}

#[tokio::test(start_paused = true)]
async fn the_users_stop_and_a_schedules_fault_are_no_trigger() {
    let rig = rig(vec![server("a", "g"), server("b", "h")]);
    let cancel = watching(&rig).await;
    rig.coord
        .start(SessionKind::SoftDirect, Some("a"), AdaptiveMode::Baseline);
    tokio::task::yield_now().await;
    rig.coord.stop(StopCause::Requested(Owner::Manual));
    rig.coord
        .set_session(SessionKind::SoftDirect, Owner::Schedule, Some("a"));
    tokio::time::sleep(Duration::from_secs(6)).await;
    rig.coord.stop(StopCause::Fault);
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert!(rig.host.refreshes.lock().is_empty());
    assert!(dials(&rig).is_empty());
    cancel.cancel();
}

/// Review fix b11: a failed launch goes to one episode, and only how it ended is announced.
#[tokio::test(start_paused = true)]
async fn a_failed_launch_goes_to_the_retries_and_tells_once() {
    let rig = rig(vec![server("a", "g"), server("b", "h")]);
    *rig.host.last_used.lock() = Some("a".into());
    rig.pick.set_choice(LaunchChoice::LastUsed).unwrap();
    rig.coord.connect_results.lock().push_back(failed());
    let done = rig.pick.launch(CancellationToken::new()).await;
    assert_eq!(
        done,
        Launched::Failed {
            profile_id: "a".into()
        }
    );
    assert_eq!(*rig.host.refreshes.lock(), ["a"]);
    assert_eq!(rig.coord.connects(), 2, "{:?}", rig.coord.calls());
    assert_eq!(dials(&rig), ["a", "b"]);
    assert_eq!(
        notices(&rig),
        [notice(Level::Info, "launch.connected", None)]
    );
}
