//! The session watch (RU item 7): a stall seen in the engine's counters or the watchdog is
//! confirmed once by a transfer, handed to the reactions, and escalated only once.
use vpnte_base::types::{AdaptiveMode, Owner};
use vpnte_base::{AppError, ErrorKind};

use super::*;
use crate::adaptive::reaction::{CheckReaction, CheckVerdict};
use crate::coordinator::testing::Call;
use crate::coordinator::{OpError, SessionKind, SwitchError};

/// Five-second samples of a session whose upload grows (2 KiB a sample) and whose download
/// stays at 100 bytes, for `secs` seconds from upload `up`.
async fn stalled(host: &FakeHost, up: &mut u64, secs: u64) {
    for _ in 0..secs / 5 {
        *up += 2048;
        *host.counters.lock() = Some(Counters {
            up: *up,
            down: 100,
            proxy_down: false,
        });
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn running(rig: &Rig, id: &str) -> CancellationToken {
    rig.coord
        .start(SessionKind::SoftDirect, Some(id), AdaptiveMode::Baseline);
    let cancel = CancellationToken::new();
    let (pick, c) = (rig.pick.clone(), cancel.clone());
    tokio::spawn(async move { pick.run(c).await });
    cancel
}

#[tokio::test(start_paused = true)]
async fn a_stall_is_confirmed_once_and_handed_to_the_reactions() {
    let rig = rig(vec![server("a", "g"), server("b", "g")]);
    rig.host
        .confirm_results
        .lock()
        .push_back(Confirmation::Frozen);
    let cancel = running(&rig, "a");
    let mut up = 0;
    stalled(&rig.host, &mut up, 45).await;
    assert_eq!(*rig.host.confirms.lock(), ["a"]);
    let want = Report {
        profile_id: "a".into(),
        verdict: CheckVerdict::Frozen,
        reaction: CheckReaction::SwitchServer,
    };
    assert_eq!(*rig.host.reports.lock(), [want]);
    // The reactions get their grace: no second transfer inside it.
    stalled(&rig.host, &mut up, 60).await;
    assert_eq!(rig.host.confirms.lock().len(), 1);
    assert!(rig.host.refreshes.lock().is_empty());
    cancel.cancel();
}

/// Nothing came back at all: the server is offline for the reactions.
#[tokio::test(start_paused = true)]
async fn a_session_that_carries_nothing_is_offline() {
    let rig = rig(vec![server("a", "g")]);
    rig.host
        .confirm_results
        .lock()
        .push_back(Confirmation::NoTraffic);
    let cancel = running(&rig, "a");
    stalled(&rig.host, &mut 0, 45).await;
    let reports = rig.host.reports.lock().clone();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].verdict, CheckVerdict::Offline);
    cancel.cancel();
}

/// A false alarm backs off: the next transfer waits 60 s, the one after 120 s.
#[tokio::test(start_paused = true)]
async fn a_false_alarm_backs_the_confirmations_off() {
    let rig = rig(vec![server("a", "g")]);
    let cancel = running(&rig, "a");
    let mut up = 0;
    stalled(&rig.host, &mut up, 40).await;
    assert_eq!(rig.host.confirms.lock().len(), 1);
    stalled(&rig.host, &mut up, 50).await;
    assert_eq!(
        rig.host.confirms.lock().len(),
        1,
        "inside the first backoff"
    );
    stalled(&rig.host, &mut up, 30).await;
    assert_eq!(rig.host.confirms.lock().len(), 2);
    stalled(&rig.host, &mut up, 80).await;
    assert_eq!(
        rig.host.confirms.lock().len(),
        2,
        "inside the doubled backoff"
    );
    stalled(&rig.host, &mut up, 40).await;
    assert_eq!(rig.host.confirms.lock().len(), 3);
    assert!(rig.host.reports.lock().is_empty());
    cancel.cancel();
}

#[tokio::test(start_paused = true)]
async fn the_watchdog_needs_no_window_and_idle_or_proxy_sessions_cost_nothing() {
    let rig = rig(vec![server("a", "g")]);
    let cancel = running(&rig, "a");
    *rig.host.counters.lock() = Some(Counters {
        up: 10,
        down: 10,
        proxy_down: true,
    });
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(*rig.host.confirms.lock(), ["a"]);
    cancel.cancel();

    // A local proxy's server is not ours: never confirmed. No session: never sampled.
    let rig = super::rig(vec![server("a", "g")]);
    rig.coord
        .start(SessionKind::LocalProxyHard, None, AdaptiveMode::Baseline);
    let cancel = CancellationToken::new();
    let (pick, c) = (rig.pick.clone(), cancel.clone());
    tokio::spawn(async move { pick.run(c).await });
    stalled(&rig.host, &mut 0, 60).await;
    assert!(rig.host.confirms.lock().is_empty());
    cancel.cancel();
}

/// The reactions could not move it and it is still stalled after their grace: the retries
/// take the session (subscription refreshed once, a switch to another server, its proof), once.
#[tokio::test(start_paused = true)]
async fn a_stall_that_stays_goes_to_the_retries_once() {
    let rig = rig(vec![server("a", "g"), server("b", "h")]);
    rig.host
        .confirm_results
        .lock()
        .extend([Confirmation::Frozen, Confirmation::Frozen]);
    let cancel = running(&rig, "a");
    let mut up = 0;
    stalled(&rig.host, &mut up, 140).await;
    assert_eq!(
        *rig.host.confirms.lock(),
        ["a", "a", "b"],
        "two looks, then the proof"
    );
    assert_eq!(*rig.host.refreshes.lock(), ["a"]);
    assert_eq!(
        rig.coord.calls(),
        [Call::Switch(Owner::AdaptiveRetry, "b".into())]
    );
    // Traffic flows on "b": nothing more is confirmed.
    for i in 1..=60u64 {
        *rig.host.counters.lock() = Some(Counters {
            up: up + i * 2048,
            down: i * 50_000,
            proxy_down: false,
        });
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    assert_eq!(rig.host.confirms.lock().len(), 3);
    cancel.cancel();
}

/// Review fix a1/b5 (high): the episode's own switch that lost the tunnel leaves a stop nobody
/// asked for and the coordinator's restore; neither starts a second episode afterwards.
#[tokio::test(start_paused = true)]
async fn its_own_lost_switch_starts_no_second_episode() {
    let rig = rig(vec![server("a", "g"), server("b", "h"), server("c", "h")]);
    rig.host
        .confirm_results
        .lock()
        .extend([Confirmation::Frozen, Confirmation::Frozen]);
    rig.coord
        .switch_results
        .lock()
        .push_back(Err(SwitchError::Failed {
            reason: OpError::Failed(AppError::new(ErrorKind::Timeout)),
            restored_previous: true,
        }));
    let cancel = running(&rig, "a");
    let mut up = 0;
    stalled(&rig.host, &mut up, 140).await;
    assert_eq!(
        rig.coord.calls(),
        [
            Call::Switch(Owner::AdaptiveRetry, "b".into()),
            Call::Switch(Owner::AdaptiveRetry, "c".into()),
        ],
        "b lost the tunnel and a was restored; c took"
    );
    for i in 1..=120u64 {
        *rig.host.counters.lock() = Some(Counters {
            up: up + i * 2048,
            down: i * 50_000,
            proxy_down: false,
        });
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    assert_eq!(*rig.host.refreshes.lock(), ["a"], "one episode");
    assert_eq!(rig.coord.calls().len(), 2);
    let keys = rig.coord.notice_keys();
    assert_eq!(keys, ["automation.autopick.rescue.recovered"], "{keys:?}");
    cancel.cancel();
}

/// Review fix a3/b4: with the neighbouring-server switch off the stall is reported (the
/// reactions tell the user), never moved by the retries.
#[tokio::test(start_paused = true)]
async fn without_switching_a_stall_is_reported_but_never_moved() {
    let rig = rig(vec![server("a", "g"), server("b", "h")]);
    rig.host.allowed.lock().switch = false;
    let looks = (0..10).map(|_| Confirmation::Frozen);
    rig.host.confirm_results.lock().extend(looks);
    let cancel = running(&rig, "a");
    stalled(&rig.host, &mut 0, 600).await;
    assert_eq!(rig.host.reports.lock().len(), 1);
    assert_eq!(
        rig.host.confirms.lock().len(),
        2,
        "after the grace the watch leaves it"
    );
    assert!(rig.host.refreshes.lock().is_empty());
    assert!(rig.coord.calls().is_empty());
    cancel.cancel();
}

/// Review fix a6: a transfer that moved data is never "offline": no report, and the next look
/// waits out a connection-count freeze.
#[tokio::test(start_paused = true)]
async fn data_that_moved_is_never_offline() {
    let rig = rig(vec![server("a", "g")]);
    rig.host
        .confirm_results
        .lock()
        .push_back(Confirmation::Inconclusive);
    let cancel = running(&rig, "a");
    let mut up = 0;
    stalled(&rig.host, &mut up, 40).await;
    assert_eq!(rig.host.confirms.lock().len(), 1);
    stalled(&rig.host, &mut up, 110).await;
    assert_eq!(
        rig.host.confirms.lock().len(),
        1,
        "inside the freeze window"
    );
    stalled(&rig.host, &mut up, 40).await;
    assert_eq!(rig.host.confirms.lock().len(), 2);
    assert!(rig.host.reports.lock().is_empty());
    cancel.cancel();
}

/// Review fix a9: the stalled server's own key changed on the refresh: it restarts on the new
/// key first (a protected restart reads the list again).
#[tokio::test(start_paused = true)]
async fn a_new_key_of_the_stalled_server_restarts_it_in_place() {
    let rig = rig(vec![server("a", "g"), server("b", "h")]);
    *rig.host.fresh.lock() = Some(vec!["a".into()]);
    rig.host
        .confirm_results
        .lock()
        .extend([Confirmation::Frozen, Confirmation::Frozen]);
    let cancel = running(&rig, "a");
    stalled(&rig.host, &mut 0, 140).await;
    assert_eq!(
        rig.coord.restarts(),
        [(AdaptiveMode::Baseline, Some("a".into()))]
    );
    assert!(
        rig.coord.calls().is_empty(),
        "no switch: the new key carried traffic"
    );
    assert_eq!(
        rig.coord.notice_keys(),
        ["automation.autopick.rescue.recovered"]
    );
    cancel.cancel();
}

/// Rule 1: after the user's Disconnect (or Cancel) nothing automatic runs until they connect
/// again, not even on a session a schedule starts.
#[tokio::test(start_paused = true)]
async fn nothing_automatic_after_the_users_stop_until_they_connect() {
    let rig = rig(vec![server("a", "g"), server("b", "g")]);
    rig.host.user_stops();
    let cancel = running(&rig, "a");
    stalled(&rig.host, &mut 0, 120).await;
    assert!(rig.host.confirms.lock().is_empty());
    rig.host.user_connects();
    stalled(&rig.host, &mut 0, 45).await;
    assert_eq!(*rig.host.confirms.lock(), ["a"]);
    cancel.cancel();
}
