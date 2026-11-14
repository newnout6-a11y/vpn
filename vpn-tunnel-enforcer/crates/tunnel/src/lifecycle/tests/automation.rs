//! What the app's automation relies on: the lane after a switch that lost the tunnel, the
//! session after a runtime failover, a stop that keeps the kill switch's block.
use std::time::Duration;

use vpnte_base::types::{KillSwitchLevel, Owner, ProxyKind};
use vpnte_core::ops::Source;

use super::fakes::{Gate, Harness};
use super::{direct, local, soft, user_stop};
use crate::api::FailoverCause;
use crate::fsm::TunnelState;
use crate::lifecycle::{DisconnectReq, SessionEvent, StopCause, SwitchReq};
use crate::outcome::OutcomeKind;

fn notices(h: &Harness, name: &str) -> Vec<vpnte_base::types::Notice> {
    let title = format!("tunnel.lifecycle.notice.{name}.title");
    let notices = h.notifier.notices.lock();
    (notices.iter())
        .filter(|(n, _)| n.title.key == title)
        .map(|(n, _)| n.clone())
        .collect()
}

/// The next session event, bounded: a missing one fails the test instead of hanging it.
async fn next(events: &mut tokio::sync::broadcast::Receiver<SessionEvent>) -> SessionEvent {
    let event = tokio::time::timeout(Duration::from_secs(2), events.recv()).await;
    event.expect("a session event").expect("events open")
}

/// a1/a2: a switch that lost the tunnel answers while its recovery stop still holds the lane,
/// so a start right then is refused (`stopInProgress`: the race the coordinator's restore
/// lost); `idle()` resolves only once that stop ended, and a start is admitted after it. The
/// switch's row ends the session with nothing following it (`continues: false`).
#[tokio::test]
async fn a_lost_switch_holds_the_lane_until_its_recovery_stop_ends() {
    let h = Harness::new();
    h.profiles.add("srv-a", "a-1", true);
    h.profiles.add("srv-b", "b-1", false);
    h.lc.connect(direct(None, Owner::Manual)).await.unwrap();
    let mut events = h.lc.events();
    let gate = Gate::new();
    {
        let mut s = h.rt.script.lock();
        s.restart_error = true;
        s.stop_gate = Some(gate.clone());
    }
    let req = SwitchReq::new("srv-b", Owner::Rotation, Source::Lifecycle);
    h.lc.rotate(req).await.unwrap_err();
    let refused = h.lc.connect(direct(None, Owner::Manual)).await.unwrap_err();
    assert_eq!(
        refused.user_msg().key,
        "tunnel.lifecycle.lane.stopInProgress"
    );
    let idle = h.lc.idle();
    tokio::pin!(idle);
    let early = tokio::time::timeout(Duration::from_millis(50), &mut idle).await;
    assert!(early.is_err(), "the recovery stop still holds the lane");
    gate.open();
    tokio::time::timeout(Duration::from_secs(2), idle)
        .await
        .expect("idle once the recovery stop ended");
    h.lc.connect(direct(None, Owner::Manual))
        .await
        .expect("admitted once idle");
    let Ok(SessionEvent::Ended {
        outcome, continues, ..
    }) = events.recv().await
    else {
        panic!("expected the switch's end");
    };
    assert_eq!((outcome, continues), (OutcomeKind::Rotation, false));
}

/// a3/b3/b8, fixauto-a1/b1: a runtime failover moves the session to the sibling under the same
/// holder: the crashed server's row (`continues`), then an `Up` naming the sibling and its run.
/// Right after the crash (still "connected") and after restarts whose starts failed (the
/// runtime's real order, "error" by then), the state ends "connected" on the sibling's run.
/// One notice per failover names both servers and claims only what the runtime saw.
#[tokio::test]
async fn a_runtime_failover_moves_the_session_to_the_sibling() {
    let h = Harness::new();
    h.profiles.add("srv-a", "a-1", true);
    h.profiles.add("srv-b", "b-1", false);
    h.lc.connect(direct(None, Owner::Schedule)).await.unwrap();
    let mut events = h.lc.events();
    for (from, to, name, cause) in [
        ("srv-a", "srv-b", "b-1", FailoverCause::ServerFault),
        ("srv-b", "srv-a", "a-1", FailoverCause::RestartsSpent),
    ] {
        if cause == FailoverCause::RestartsSpent {
            h.rt.crash_with_restart_in(Duration::from_millis(10));
            for next_attempt in 2..=4 {
                h.rt.fail_restart(next_attempt);
            }
            h.settle().await;
            assert_eq!(h.snap().state, TunnelState::Error, "the restarts failed");
        }
        let generation = h.rt.fail_over_to(to, name, cause);
        let SessionEvent::Ended {
            session,
            outcome,
            continues,
        } = next(&mut events).await
        else {
            panic!("expected the crashed server's end");
        };
        assert_eq!(
            (session.profile_id.as_str(), outcome, continues),
            (from, OutcomeKind::ServerSwitch, true)
        );
        let SessionEvent::Up(view) = next(&mut events).await else {
            panic!("expected the sibling's Up");
        };
        assert_eq!(
            (view.profile_id.as_str(), view.owner, view.generation),
            (to, Owner::Schedule, Some(generation))
        );
        h.settle().await;
        assert_eq!(h.snap().state, TunnelState::Connected, "{to}");
    }
    let bodies: Vec<_> = (notices(&h, "failover").iter())
        .filter_map(|n| n.body.clone())
        .map(|b| {
            let args: Vec<_> = b.args.iter().map(|(k, v)| format!("{k}={v}")).collect();
            (b.key.into_owned(), args)
        })
        .collect();
    let key = |part: &str| format!("tunnel.lifecycle.notice.failover.{part}");
    assert_eq!(
        bodies,
        [
            (key("body"), vec!["from=a-1".to_owned(), "name=b-1".into()]),
            (
                key("bodyRestarts"),
                vec!["from=b-1".into(), "name=a-1".into()]
            ),
        ]
    );
    let headline = |id: &str| {
        let rows = h.rows();
        let row = rows.iter().find(|r| r.profile_id == id).expect("row");
        row.outcome
            .as_ref()
            .expect("outcome")
            .headline
            .key
            .to_string()
    };
    assert_eq!(headline("srv-a"), "tunnel.lifecycle.outcome.failover");
    assert_eq!(
        headline("srv-b"),
        "tunnel.lifecycle.outcome.failoverRestarts"
    );
    assert!(notices(&h, "restored").is_empty());
}

/// fixauto-a2: a failover that finishes while a restart of the last start owns the lane (the
/// runtime runs that restart behind the failover, on the sibling) is not lost: at the
/// operation's end the session moves to the sibling first, so the restart's `Up` names it too.
#[tokio::test]
async fn a_failover_during_a_lane_restart_moves_the_session_at_its_end() {
    let h = Harness::new();
    h.profiles.add("srv-a", "a-1", true);
    h.profiles.add("srv-b", "b-1", false);
    h.lc.connect(direct(None, Owner::Manual)).await.unwrap();
    let mut events = h.lc.events();
    let gate = Gate::new();
    h.rt.script.lock().restart_gate = Some(gate.clone());
    let lc = h.lc.clone();
    let restart = tokio::spawn(async move {
        lc.restart_with_last("settings changed: mtu", Owner::Manual, Source::Ui)
            .await
    });
    super::fakes::eventually("restart in flight", || h.snap().transition.is_some()).await;
    let failover =
        h.rt.fail_over_to("srv-b", "b-1", FailoverCause::ServerFault);
    h.settle().await;
    assert!(events.try_recv().is_err(), "the operation owns the session");
    gate.open();
    restart.await.unwrap().expect("restart");
    let mut seen = Vec::new();
    while let Ok(event) = events.try_recv() {
        seen.push(match event {
            SessionEvent::Ended {
                session, continues, ..
            } => format!("ended:{}:{continues}", session.profile_id),
            SessionEvent::Up(view) => format!("up:{}:{:?}", view.profile_id, view.generation),
        });
    }
    let up = |generation: u64| format!("up:srv-b:{:?}", Some(generation));
    assert_eq!(
        seen,
        [
            "ended:srv-a:true".to_owned(),
            up(failover),
            up(failover + 1)
        ]
    );
    assert_eq!(h.snap().state, TunnelState::Connected);
    assert_eq!(notices(&h, "failover").len(), 1);
}

/// fixauto-b1: a failover after the session had already ended (no session names the crashed
/// server) still opens the sibling's session; its notice names only the sibling.
#[tokio::test]
async fn a_failover_without_a_session_names_only_the_sibling() {
    let h = Harness::new();
    h.profiles.add("srv-b", "b-1", true);
    let mut events = h.lc.events();
    let generation =
        h.rt.fail_over_to("srv-b", "b-1", FailoverCause::RestartsSpent);
    let SessionEvent::Up(view) = next(&mut events).await else {
        panic!("expected the sibling's Up");
    };
    assert_eq!(
        (view.profile_id.as_str(), view.owner, view.generation),
        ("srv-b", Owner::Recovery, Some(generation))
    );
    let bodies: Vec<_> = (notices(&h, "failover").iter())
        .filter_map(|n| n.body.clone())
        .map(|b| {
            let args: Vec<_> = b.args.iter().map(|(k, v)| format!("{k}={v}")).collect();
            (b.key.into_owned(), args)
        })
        .collect();
    let switched = "tunnel.lifecycle.notice.failover.bodySwitched".to_owned();
    assert_eq!(bodies, [(switched, vec!["name=b-1".to_owned()])]);
}

fn kept_stop() -> DisconnectReq {
    DisconnectReq {
        keep_protection: true,
        ..DisconnectReq::new(StopCause::Failed, Owner::AdaptiveRetry, Source::Lifecycle)
    }
}

fn kill_switch(h: &Harness, level: KillSwitchLevel) {
    h.settings.update(|s| s.kill_switch = level).unwrap();
}

/// a4: with the kill switch on, a stop that keeps protection ends the session and stops the
/// engine but leaves the block: Soft keeps its tweaks on the dead port, TUN gets a preserved
/// runtime stop; the state reads `blocked` with its notice, and a full stop releases it.
#[tokio::test]
async fn a_kept_stop_leaves_the_kill_switch_blocking() {
    for tun in [false, true] {
        let h = Harness::new();
        kill_switch(&h, KillSwitchLevel::Standard);
        let start = if tun {
            local(Owner::Manual)
        } else {
            soft(10808, ProxyKind::Http, Owner::Manual)
        };
        h.lc.connect(start).await.unwrap();
        h.lc.disconnect(kept_stop()).await.expect("kept stop");
        h.settle().await;
        assert!(h.lc.session().borrow().is_none(), "tun={tun}");
        assert!(!h.rt.running());
        assert_eq!(h.snap().state, TunnelState::Blocked, "tun={tun}");
        assert_eq!(h.soft.state.lock().applied.is_some(), !tun);
        assert_eq!(h.rt.script.lock().preserved_stops, u32::from(tun));
        let name = if tun {
            "keptBlocked"
        } else {
            "keptSoftBlocked"
        };
        assert_eq!(notices(&h, name).len(), 1, "tun={tun}");
        h.lc.disconnect(user_stop()).await.expect("full stop");
        assert!(h.soft.state.lock().applied.is_none());
        assert_eq!(h.snap().state, TunnelState::Disconnected, "tun={tun}");
    }
}

/// fixauto-a4/b3: the kept block names the holder of the session it ended, so whoever ends that
/// holder's run can release it; a start that runs, or a full stop, clears it.
#[tokio::test]
async fn a_kept_block_names_its_holder_until_it_is_released() {
    let h = Harness::new();
    kill_switch(&h, KillSwitchLevel::Standard);
    let start = || soft(10808, ProxyKind::Http, Owner::Schedule);
    assert_eq!(h.lc.kept_by(), None);
    h.lc.connect(start()).await.unwrap();
    h.lc.disconnect(kept_stop()).await.unwrap();
    h.settle().await;
    assert_eq!(h.lc.kept_by(), Some(Owner::Schedule));
    h.lc.connect(start())
        .await
        .expect("a start replaces the block");
    h.settle().await;
    assert_eq!(h.lc.kept_by(), None, "the start ran");
    h.lc.disconnect(kept_stop()).await.unwrap();
    h.settle().await;
    assert_eq!(h.lc.kept_by(), Some(Owner::Schedule));
    h.lc.disconnect(user_stop()).await.unwrap();
    h.settle().await;
    assert_eq!(h.lc.kept_by(), None, "the full stop released it");
}

/// With the kill switch off there is nothing to keep: a plain full stop. A full stop asked
/// while a kept one runs is not swallowed by it: it runs right after and releases the block.
#[tokio::test]
async fn kept_stops_never_outlive_a_full_one() {
    let h = Harness::new();
    kill_switch(&h, KillSwitchLevel::Off);
    h.lc.connect(soft(10808, ProxyKind::Http, Owner::Manual))
        .await
        .unwrap();
    h.lc.disconnect(kept_stop()).await.unwrap();
    assert!(h.soft.state.lock().applied.is_none());
    assert_eq!(h.snap().state, TunnelState::Disconnected);
    assert!(notices(&h, "keptSoftBlocked").is_empty());

    kill_switch(&h, KillSwitchLevel::Standard);
    h.lc.connect(soft(10808, ProxyKind::Http, Owner::Manual))
        .await
        .unwrap();
    let gate = Gate::new();
    h.rt.script.lock().stop_gate = Some(gate.clone());
    let lc = h.lc.clone();
    let kept = tokio::spawn(async move { lc.disconnect(kept_stop()).await });
    super::fakes::eventually("kept stop running", || h.rt.script.lock().stops == 2).await;
    let lc = h.lc.clone();
    let full = tokio::spawn(async move { lc.disconnect(user_stop()).await });
    h.settle().await;
    gate.open();
    kept.await.unwrap().expect("kept stop");
    full.await.unwrap().expect("full stop after it");
    h.settle().await;
    assert_eq!(
        h.rt.script.lock().stops,
        3,
        "the kept stop, then the full one"
    );
    assert!(h.soft.state.lock().applied.is_none());
    assert_eq!(h.snap().state, TunnelState::Disconnected);
    assert!(notices(&h, "keptSoftBlocked").is_empty());
}
