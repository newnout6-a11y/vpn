//! The reaction task over the fakes: what reaches the coordinator, the budget, the override
//! knob and the user.
use vpnte_base::types::{AdaptiveMode, Level, Owner};

use super::*;
use crate::adaptive::reaction::decide::MAX_RESTARTS;
use crate::adaptive::reaction::task::Flow;
use crate::coordinator::testing::Call;
use crate::coordinator::{LifecycleEvent, NoticeCategory, OpError, SessionKind, SwitchError};

const KEY: &str = "automation.adaptive.reaction.";

fn keys(rig: &Rig) -> Vec<String> {
    let all = rig.coord.notice_keys();
    all.into_iter()
        .map(|k| k.strip_prefix(KEY).map_or(k.clone(), str::to_owned))
        .collect()
}

fn switches(rig: &Rig) -> Vec<String> {
    let calls = rig.coord.calls();
    let to = calls.into_iter().map(|c| match c {
        Call::Switch(owner, id) => {
            assert_eq!(
                owner,
                Owner::AdaptiveRetry,
                "reactions never pre-empt anybody"
            );
            id
        }
        other => panic!("unexpected call {other:?}"),
    });
    to.collect()
}

fn pool() -> Vec<ServerFacts> {
    vec![
        srv("a", "198.51.100.7", Transport::Tcp),
        srv("a-ws", "198.51.100.7", Transport::Ws),
        srv("x", "198.51.100.8", Transport::Xhttp),
        srv("c", "203.0.113.5", Transport::Tcp),
        srv("h", "192.0.2.1", Transport::Udp),
        reality(srv("r", "203.0.113.20", Transport::Tcp), Some("chrome")),
    ]
}

const BANNED: (CheckVerdict, CheckReaction) = (CheckVerdict::IpBanned, CheckReaction::SwitchServer);
const REALITY: (CheckVerdict, CheckReaction) = (
    CheckVerdict::HandshakeFailed,
    CheckReaction::TryAnotherFingerprint,
);

/// AT-RU-REACT-001: a banned IP moves the session to a server on another address, after a
/// budget slot for it, with a notice that says why and that another port would not help.
#[tokio::test]
async fn ip_banned_moves_the_session_with_a_clear_notice() {
    let rig = Rig::new(pool());
    rig.running("a");
    rig.feed("a", BANNED.0, BANNED.1).await;
    assert_eq!(switches(&rig), ["x"]);
    assert_eq!(
        *rig.host.slots.lock(),
        [("x".to_owned(), Duration::from_secs(10))]
    );
    assert_eq!(keys(&rig), ["cause.ipBanned", "action.switched"]);
    let (category, notice) = rig.coord.notices.lock()[0].clone();
    assert_eq!(
        (category, notice.level),
        (NoticeCategory::ConnectionError, Level::Warn)
    );
    let title = vpnte_base::Msg::new(format!("{KEY}cause.ipBanned")).arg("name", "A");
    assert_eq!(notice.title, title);
    // The old server's late report no longer concerns the session.
    rig.feed("a", BANNED.0, BANNED.1).await;
    assert_eq!(switches(&rig).len(), 1);
}

/// A candidate the handshake budget defers is skipped, never dialled in a burst.
#[tokio::test]
async fn budget_deferral_tries_the_next_candidate() {
    let rig = Rig::new(pool());
    rig.host.refuse.lock().insert("x".into());
    rig.running("a");
    rig.feed("a", BANNED.0, BANNED.1).await;
    assert_eq!(rig.host.slot_ids(), ["x", "c"]);
    assert_eq!(switches(&rig), ["c"]);
}

/// AT-RU-REACT-002: a failed reaction is not retried on the same network; a new network starts
/// over.
#[tokio::test]
async fn failed_switches_are_not_retried_on_this_network() {
    let rig = Rig::new(pool());
    rig.running("a");
    for _ in 0..2 {
        rig.coord
            .switch_results
            .lock()
            .push_back(Err(SwitchError::Failed {
                reason: OpError::Timeout,
                restored_previous: true,
            }));
    }
    rig.feed("a", BANNED.0, BANNED.1).await;
    assert_eq!(switches(&rig), ["x", "c"]);
    assert_eq!(keys(&rig), ["cause.ipBanned", "errors.timeout"]);
    rig.feed("a", BANNED.0, BANNED.1).await;
    assert_eq!(switches(&rig).len(), 2, "no loop");
    assert_eq!(keys(&rig).len(), 2, "told once");
    assert!(matches!(
        rig.reactions.on_event(Ok(LifecycleEvent::NetworkChanged)),
        Flow::Reset
    ));
    rig.feed("a", BANNED.0, BANNED.1).await;
    assert_eq!(switches(&rig), ["x", "c", "x"]);
}

/// Refused by a higher-priority operation: quiet, not counted as a failed reaction, and not a
/// restart of this network's budget (the tunnel was never touched).
#[tokio::test]
async fn preempted_switch_stays_quiet() {
    let rig = Rig::new(pool());
    rig.running("a");
    let refused = Err(SwitchError::NotStarted(OpError::Conflict));
    rig.coord.switch_results.lock().push_back(refused);
    rig.feed("a", BANNED.0, BANNED.1).await;
    assert_eq!((switches(&rig).len(), keys(&rig).len()), (1, 0));
    assert_eq!(rig.reactions.verdicts().with(|m| m.restarts), 0);
    rig.feed("a", BANNED.0, BANNED.1).await;
    assert_eq!(switches(&rig), ["x", "x"]);
    assert_eq!(rig.reactions.verdicts().with(|m| m.restarts), 1);
}

/// AT-RU-REACT-003: a REALITY server that rejects the handshake gets one restart with the next
/// allowed fingerprint (session-only override, budget slot first); it holds, so it is kept.
#[tokio::test]
async fn reality_retry_uses_another_fingerprint_once() {
    let rig = Rig::new(pool());
    rig.running("r");
    rig.feed("r", REALITY.0, REALITY.1).await;
    assert_eq!(rig.coord.restarts(), [(AdaptiveMode::Baseline, None)]);
    assert_eq!(
        *rig.host.overrides.lock(),
        [("r".to_owned(), Some("firefox"))]
    );
    assert_eq!(
        *rig.host.slots.lock(),
        [("r".to_owned(), Duration::from_secs(65))]
    );
    assert_eq!(keys(&rig), ["cause.handshakeFailed", "action.fingerprint"]);
    assert!(!rig.reactions.verdicts().avoided("r"), "it works again");
    // Rejected again: no second guess, the server is given up.
    rig.feed("r", REALITY.0, REALITY.1).await;
    assert_eq!(rig.coord.restarts().len(), 1);
    assert_eq!(switches(&rig).len(), 1);
}

/// A failed retry removes the override and moves the session to another server.
#[tokio::test]
async fn failed_reality_retry_gives_up_on_the_server() {
    let rig = Rig::new(pool());
    rig.running("r");
    rig.coord
        .restart_results
        .lock()
        .push_back(Err(OpError::Timeout));
    rig.feed("r", REALITY.0, REALITY.1).await;
    let expected = [("r".to_owned(), Some("firefox")), ("r".to_owned(), None)];
    assert_eq!(*rig.host.overrides.lock(), expected);
    assert_eq!(switches(&rig), ["a"], "any other server: store order");
    assert_eq!(keys(&rig), ["cause.handshakeFailed", "action.switched"]);
}

/// AT-RU-REACT-004: a UDP cut moves a UDP session to a TCP-based server and is remembered
/// until the network changes.
#[tokio::test]
async fn udp_block_moves_to_tcp_until_the_network_changes() {
    let rig = Rig::new(pool());
    rig.running("h");
    let verdicts = rig.reactions.verdicts();
    rig.feed(
        "h",
        CheckVerdict::UdpBlocked,
        CheckReaction::PreferTcpTransport,
    )
    .await;
    assert_eq!(switches(&rig), ["a"]);
    assert_eq!(keys(&rig), ["cause.udpBlocked", "action.switchedTcp"]);
    assert!(verdicts.udp_blocked());
    rig.reactions.on_event(Ok(LifecycleEvent::NetworkChanged));
    assert!(!verdicts.udp_blocked());
}

/// Switching turned off in the settings: one notice, nothing restarted.
#[tokio::test]
async fn switching_off_only_tells() {
    let rig = Rig::new(pool());
    rig.settings
        .update(|s| s.adaptive_bypass_server_fallback = false)
        .unwrap();
    rig.running("a");
    rig.feed("a", BANNED.0, BANNED.1).await;
    rig.feed("a", BANNED.0, BANNED.1).await;
    assert!(rig.coord.calls().is_empty());
    assert_eq!(keys(&rig), ["cause.ipBanned", "action.autoOff"]);
}

/// Past the restart cap of a network session reactions only learn; the user hears it once.
#[tokio::test]
async fn restart_cap_pauses_with_one_notice() {
    let rig = Rig::new(pool());
    rig.reactions.verdicts().with(|m| m.restarts = MAX_RESTARTS);
    rig.running("a");
    rig.feed("a", BANNED.0, BANNED.1).await;
    rig.running("c");
    rig.feed("c", CheckVerdict::KeyRejected, CheckReaction::SwitchServer)
        .await;
    assert!(rig.coord.calls().is_empty());
    assert_eq!(keys(&rig), ["paused.title", "paused.body"]);
}

/// Local-proxy sessions and other servers are never restarted; the verdict is still learned.
#[tokio::test]
async fn proxy_sessions_are_left_alone() {
    let rig = Rig::new(pool());
    rig.coord
        .set_session(SessionKind::LocalProxyHard, Owner::Manual, None);
    rig.feed("a", BANNED.0, BANNED.1).await;
    rig.feed("zz", BANNED.0, BANNED.1).await;
    assert!(rig.coord.calls().is_empty() && keys(&rig).is_empty());
    assert!(rig.reactions.verdicts().avoided("a-ws"));
}

/// NOADMIN §2: the system proxy over a list server is a session over a server like the TUN one,
/// so a banned server moves it the same way.
#[tokio::test]
async fn system_proxy_sessions_over_a_server_react() {
    let rig = Rig::new(pool());
    rig.coord
        .set_session(SessionKind::SoftDirect, Owner::Manual, Some("a"));
    rig.feed("a", BANNED.0, BANNED.1).await;
    assert_eq!(switches(&rig), ["x"]);
}

/// The task end to end: reports through the inbox, a network change through the events, and
/// a prompt return on cancel.
#[tokio::test]
async fn task_reacts_and_resets_on_network_change() {
    let rig = Rig::new(pool());
    rig.running("a");
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let (reactions, cancel) = (rig.reactions.clone(), cancel.clone());
        async move { reactions.run(cancel).await }
    });
    tokio::task::yield_now().await;
    rig.reactions.report(report("a", BANNED.0, BANNED.1));
    let verdicts = rig.reactions.verdicts();
    wait_for(|| switches(&rig) == ["x"]).await;
    assert!(verdicts.avoided("a"));
    rig.coord.emit(LifecycleEvent::NetworkChanged);
    wait_for(|| !verdicts.avoided("a")).await;
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

/// a5: a burst bigger than the inbox (a group check records dozens of verdicts in one write)
/// arrives in full when the feed waits for room: the report after the burst still counts.
#[tokio::test]
async fn a_burst_bigger_than_the_inbox_is_delivered() {
    let rig = Rig::new(pool());
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let (reactions, cancel) = (rig.reactions.clone(), cancel.clone());
        async move { reactions.run(cancel).await }
    });
    tokio::task::yield_now().await;
    let healthy = || report("x", CheckVerdict::Healthy, CheckReaction::None);
    for _ in 0..40 {
        assert!(rig.reactions.deliver(healthy()).await);
    }
    assert!(rig.reactions.deliver(report("c", BANNED.0, BANNED.1)).await);
    let verdicts = rig.reactions.verdicts();
    wait_for(|| verdicts.avoided("c")).await;
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

async fn wait_for(done: impl Fn() -> bool) {
    for _ in 0..500 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("condition not reached");
}

/// Every candidate busy in the budget: quiet, not a failure; the next check reacts again. No
/// candidate at all: the user is told to choose manually.
#[tokio::test]
async fn deferred_and_missing_candidates() {
    let rig = Rig::new(pool());
    rig.host
        .refuse
        .lock()
        .extend(["x".to_owned(), "c".to_owned()]);
    rig.running("a");
    rig.feed("a", BANNED.0, BANNED.1).await;
    assert!(rig.coord.calls().is_empty() && keys(&rig).is_empty());
    rig.host.refuse.lock().clear();
    rig.feed("a", BANNED.0, BANNED.1).await;
    assert_eq!(switches(&rig), ["x"]);

    let lonely = Rig::new(vec![srv("a", "198.51.100.7", Transport::Tcp)]);
    lonely.running("a");
    lonely.feed("a", BANNED.0, BANNED.1).await;
    assert!(lonely.coord.calls().is_empty());
    assert_eq!(keys(&lonely), ["cause.ipBanned", "action.noAlternative"]);
}
