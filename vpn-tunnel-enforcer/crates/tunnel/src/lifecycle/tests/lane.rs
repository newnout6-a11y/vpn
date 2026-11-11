//! Lane vectors (lifecycle-app §7.1 lane side, §7.2) against the real actor and fake engines.
use std::time::Duration;

use vpnte_base::ErrorKind;
use vpnte_base::types::{Owner, ProxyKind};
use vpnte_core::ops::{OpStatus, Source};

use super::fakes::{Gate, Harness, eventually};
use super::{local, soft, user_stop};
use crate::api::{TunStatusKind, TunnelEvent};
use crate::fsm::{FaultState, ProcessState, Transition, TunnelMode, TunnelState};
use crate::lifecycle::{ConnError, DisconnectReq, StopCause};

fn refused_key(result: Result<crate::lifecycle::Done, ConnError>) -> String {
    match result {
        Err(ConnError::Refused(msg)) => msg.key.into_owned(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// AT-00-002 / AT-00-008: a connect publishes "connected" only on evidence; a stop returns to a
/// proven "disconnected" (the runtime's late `Stopped` does not turn it into "unknown").
#[tokio::test]
async fn connect_and_stop_publish_proven_states() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.expect("connect");
    let snap = h.snap();
    assert_eq!(snap.state, TunnelState::Connected);
    assert_eq!(snap.mode, Some(TunnelMode::Tun));
    assert_eq!(snap.transition, None);
    assert_eq!(snap.pid, h.rt.pid());
    assert_eq!(snap.process_state, ProcessState::Running);
    assert!(
        h.rows().is_empty(),
        "nothing is written while the session lives"
    );
    h.lc.disconnect(user_stop()).await.expect("stop");
    h.settle().await;
    let snap = h.snap();
    assert_eq!(snap.state, TunnelState::Disconnected);
    assert_eq!((snap.pid, snap.transition), (None, None));
    assert!(!snap.cleanup_required);
    assert!(!h.lc.busy());
    assert_eq!(h.rows().len(), 1);
}

/// AT-00-002: a second connect is refused before any effect runs, the snapshot unchanged.
#[tokio::test]
async fn second_connect_is_refused_before_effects() {
    let h = Harness::new();
    let gate = Gate::new();
    h.rt.script.lock().start_gate = Some(gate.clone());
    let lc = h.lc.clone();
    let first = tokio::spawn(async move { lc.connect(local(Owner::Manual)).await });
    eventually("first start", || h.rt.script.lock().starts == 1).await;
    let before = h.snap();
    let second = h.lc.connect(local(Owner::Manual)).await;
    assert_eq!(refused_key(second), "tunnel.lifecycle.lane.startInProgress");
    assert_eq!(h.rt.script.lock().starts, 1);
    assert_eq!(h.snap(), before);
    gate.open();
    first.await.unwrap().expect("first connect");
    let again = h.lc.connect(local(Owner::Manual)).await;
    assert_eq!(
        refused_key(again),
        "tunnel.lifecycle.lane.stateRefusesStart"
    );
}

/// AT-00-002: a Soft refresh never admits a second runtime over a native connection.
#[tokio::test]
async fn soft_refresh_over_native_is_refused() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    let r =
        h.lc.connect(soft(8080, ProxyKind::Http, Owner::Manual))
            .await;
    assert_eq!(refused_key(r), "tunnel.lifecycle.lane.stateRefusesStart");
    assert_eq!(h.soft.state.lock().applies, 0);
}

/// §7.1 "compensates runtime effects when main cannot confirm start": the start that cannot be
/// proven is stopped once by its own effect; the state is `error`.
#[tokio::test]
async fn unconfirmed_start_is_compensated_once() {
    let h = Harness::new();
    h.rt.script.lock().start_without_pid = true;
    let err = h.lc.connect(local(Owner::Manual)).await.unwrap_err();
    assert_eq!(
        err.user_msg().key,
        "tunnel.lifecycle.lane.confirmationMissing"
    );
    h.settle().await;
    assert_eq!(h.rt.script.lock().stops, 1);
    assert!(!h.rt.running());
    let snap = h.snap();
    assert_eq!((snap.state, snap.transition), (TunnelState::Error, None));
    assert!(!h.lc.busy());
}

/// §7.1 "rejects unconfirmed stop" + §3.10 step 4: a stop that cannot prove the engine exit
/// fails, keeps the session open and touches nothing else.
#[tokio::test]
async fn unproven_stop_retains_protection_and_session() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    h.rt.script.lock().stop_unproven = true;
    let err = h.lc.disconnect(user_stop()).await.unwrap_err();
    assert_eq!(
        err.user_msg().key,
        "tunnel.lifecycle.lane.cleanupUnconfirmed"
    );
    h.settle().await;
    assert_eq!(h.snap().state, TunnelState::Error);
    assert!(h.lc.session().borrow().is_some(), "session kept");
    assert!(h.rows().is_empty());
    {
        let c = h.services.counters.lock();
        assert_eq!(
            (c.forensics_stops, c.proxies_stops, c.monitor_stops),
            (0, 0, 0)
        );
    }
    assert!(
        h.notifier
            .titles()
            .contains(&"tunnel.lifecycle.notice.stopFailed.title".to_owned())
    );
    h.lc.disconnect(user_stop())
        .await
        .expect("second stop succeeds");
    assert_eq!(h.rows().len(), 1);
}

/// AT-00-002: a fault is cleared only by a successful owned operation.
#[tokio::test]
async fn owned_recovery_clears_a_fault() {
    let h = Harness::new();
    h.lc.fault(FaultState::Blocked);
    h.settle().await;
    assert_eq!(h.snap().state, TunnelState::Blocked);
    let recovery = DisconnectReq::new(StopCause::User, Owner::Recovery, Source::Lifecycle);
    h.lc.disconnect(recovery).await.expect("recovery stop");
    assert_eq!(h.snap().state, TunnelState::Disconnected);
    h.lc.connect(local(Owner::Manual)).await.expect("connect");
    assert_eq!(h.snap().state, TunnelState::Connected);
}

/// §7.1 "fails closed without stranding the lane if evidence fails": unreadable evidence never
/// confirms a start or a stop, and the lane is released.
#[tokio::test]
async fn unreadable_evidence_fails_closed() {
    let h = Harness::new();
    h.soft.state.lock().unreadable = true;
    let err = h.lc.connect(local(Owner::Manual)).await.unwrap_err();
    assert_eq!(
        err.user_msg().key,
        "tunnel.lifecycle.lane.confirmationMissing"
    );
    // The failed start also gets a recovery stop (nothing is proven): wait for the lane.
    eventually("lane released", || !h.lc.busy()).await;
    h.settle().await;
    let snap = h.snap();
    assert_eq!((snap.state, snap.transition), (TunnelState::Unknown, None));
    assert!(snap.cleanup_required);
    assert!(!h.lc.busy());
    let err = h.lc.disconnect(user_stop()).await.unwrap_err();
    assert_eq!(
        err.user_msg().key,
        "tunnel.lifecycle.lane.cleanupUnconfirmed"
    );
    assert!(!h.lc.busy());
}

/// §7.1 "does not report disconnected with a live unowned process".
#[tokio::test]
async fn live_unowned_process_reads_unknown() {
    let h = Harness::new();
    h.rt.bring_up(None, true);
    h.rt.emit(TunnelEvent::Status(TunStatusKind::Running));
    h.settle().await;
    let snap = h.snap();
    assert_eq!(snap.state, TunnelState::Unknown);
    assert!(snap.cleanup_required);
}

/// §7.1 "ignores a late native receipt after manual stop".
#[tokio::test]
async fn late_native_receipt_after_stop_is_ignored() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    h.lc.disconnect(user_stop()).await.unwrap();
    h.settle().await;
    let before = h.snap();
    h.rt.emit(TunnelEvent::StartFinished {
        generation: 1,
        ok: true,
    });
    h.settle().await;
    assert_eq!(h.snap(), before);
}

/// Connects with a gated runtime start; returns the caller's task once the start is in flight.
async fn gated_connect(
    h: &Harness,
    owner: Owner,
) -> (
    Gate,
    tokio::task::JoinHandle<Result<crate::lifecycle::Done, ConnError>>,
) {
    let gate = Gate::new();
    h.rt.script.lock().start_gate = Some(gate.clone());
    let before = h.rt.script.lock().starts;
    let lc = h.lc.clone();
    let task = tokio::spawn(async move { lc.connect(local(owner)).await });
    eventually("start in flight", || h.rt.script.lock().starts > before).await;
    (gate, task)
}

fn assert_clean_after_cancel(h: &Harness) {
    let snap = h.snap();
    assert_eq!(
        (snap.state, snap.transition),
        (TunnelState::Disconnected, None)
    );
    assert!(!h.lc.busy());
    assert!(!h.rt.running());
    assert!(h.lc.session().borrow().is_none());
    let connected = "tunnel.lifecycle.notice.connected.title".to_owned();
    assert!(!h.notifier.titles().contains(&connected));
}

/// AT-02-005: a stop cancels the start at once (the caller gets `Cancelled`) but touches nothing
/// before the start drained; the lane stays reserved through the whole stop effect.
#[tokio::test]
async fn stop_waits_for_the_start_to_drain() {
    let h = Harness::new();
    let (start_gate, start) = gated_connect(&h, Owner::Manual).await;
    let stop_gate = Gate::new();
    h.rt.script.lock().stop_gate = Some(stop_gate.clone());
    let lc = h.lc.clone();
    let stop = tokio::spawn(async move { lc.disconnect(user_stop()).await });
    let err = start.await.unwrap().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Cancelled);
    assert_eq!(err.user_msg().key, "tunnel.lifecycle.lane.startCancelled");
    h.settle().await;
    assert_eq!(h.rt.script.lock().stops, 0, "no cleanup before the drain");
    assert!(h.lc.busy());
    assert_eq!(h.snap().transition, Some(Transition::Disconnecting));
    start_gate.open();
    eventually("stop effect", || h.rt.script.lock().stops == 1).await;
    h.settle().await;
    assert!(h.lc.busy(), "busy until the stop effect resolved");
    stop_gate.open();
    stop.await.unwrap().expect("stop");
    h.settle().await;
    assert_eq!(h.rt.script.lock().stops, 1);
    assert_clean_after_cancel(&h);
}

/// AT-02-005 subset, 100 seeded handoffs (old LCG, seed 0x8090): whatever the moment the stop
/// arrives, cleanup runs exactly once and only after the start drained, the start fails and
/// nothing is published after the gate.
#[tokio::test]
async fn seeded_cancellation_handoffs() {
    let mut seed: u32 = 0x8090;
    for _ in 0..100 {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let h = Harness::new();
        let (gate, start) = gated_connect(&h, Owner::Manual).await;
        for _ in 0..seed % 3 {
            tokio::task::yield_now().await;
        }
        let lc = h.lc.clone();
        let stop = tokio::spawn(async move { lc.disconnect(user_stop()).await });
        let err = start.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Cancelled);
        h.settle().await;
        assert_eq!(h.rt.script.lock().stops, 0);
        gate.open();
        stop.await.unwrap().expect("stop");
        h.settle().await;
        assert_eq!(h.rt.script.lock().stops, 1, "cleanup exactly once");
        assert_eq!(h.rt.script.lock().starts, 1);
        assert_clean_after_cancel(&h);
        assert!(h.rows().is_empty());
    }
}

/// §7.2: 200 concurrent stops share one effect; a start meanwhile is refused.
#[tokio::test]
async fn concurrent_stops_coalesce() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    let gate = Gate::new();
    h.rt.script.lock().stop_gate = Some(gate.clone());
    let stops: Vec<_> = (0..200)
        .map(|_| {
            let lc = h.lc.clone();
            tokio::spawn(async move { lc.disconnect(user_stop()).await })
        })
        .collect();
    eventually("stop effect", || h.rt.script.lock().stops == 1).await;
    let r = h.lc.connect(local(Owner::Manual)).await;
    assert_eq!(refused_key(r), "tunnel.lifecycle.lane.stopInProgress");
    gate.open();
    for stop in stops {
        stop.await.unwrap().expect("joined stop");
    }
    assert_eq!(h.rt.script.lock().stops, 1);
    assert_eq!(h.rows().len(), 1);
}

/// §7.2 "consumes a late rejected native effect and releases the startup lease".
#[tokio::test]
async fn late_failed_native_start_releases_the_lane() {
    let h = Harness::new();
    let error = crate::api::TunError::new(ErrorKind::Network, vpnte_base::Msg::new("test.late"));
    let (gate, start) = gated_connect(&h, Owner::Manual).await;
    h.rt.script.lock().start_error = Some(error);
    let lc = h.lc.clone();
    let stop = tokio::spawn(async move { lc.disconnect(user_stop()).await });
    assert_eq!(
        start.await.unwrap().unwrap_err().kind(),
        ErrorKind::Cancelled
    );
    gate.open();
    stop.await.unwrap().expect("stop");
    h.settle().await;
    assert_eq!(h.rt.script.lock().stops, 1);
    assert_clean_after_cancel(&h);
    assert!(h.rows().is_empty(), "a cancelled start writes no row");
}

/// AT-00-003 / AT-02-005: a timed-out start answers `Timeout` at once, publishes the timeout and
/// keeps the lane until the late native completion and its compensation both finished.
#[tokio::test]
async fn timed_out_start_waits_for_native_completion_and_cleanup() {
    let h = Harness::new();
    let gate = Gate::new();
    h.rt.script.lock().start_gate = Some(gate.clone());
    let mut req = local(Owner::Manual);
    req.timeout = Duration::from_millis(30);
    let err = h.lc.connect(req).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Timeout);
    assert_eq!(err.user_msg().key, "tunnel.lifecycle.lane.startTimeout");
    h.settle().await;
    assert!(h.lc.busy());
    assert_eq!(h.rt.script.lock().stops, 0);
    let snap = h.snap();
    assert_eq!(snap.transition, Some(Transition::Disconnecting));
    gate.open();
    eventually("lane released", || !h.lc.busy()).await;
    h.settle().await;
    assert_eq!(h.rt.script.lock().stops, 1);
    assert_clean_after_cancel(&h);
    let op = h.snap().operation.expect("last operation");
    assert_eq!((op.owner, op.status), (Owner::Recovery, OpStatus::Success));
}

/// Owner priority: a strictly higher owner pre-empts a running start (which is cancelled and
/// compensated first) and is admitted after that stop; the session belongs to it.
#[tokio::test]
async fn higher_owner_preempts_a_running_start() {
    let h = Harness::new();
    let (gate, autopilot) = gated_connect(&h, Owner::Autopilot).await;
    let lc = h.lc.clone();
    let manual = tokio::spawn(async move { lc.connect(local(Owner::Manual)).await });
    let err = autopilot.await.unwrap().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Cancelled);
    gate.open();
    manual
        .await
        .unwrap()
        .expect("manual connect admitted after the stop");
    let s = h.rt.script.lock();
    assert_eq!((s.starts, s.stops), (2, 1));
    drop(s);
    assert_eq!(h.snap().state, TunnelState::Connected);
    let session = h.lc.session().borrow().clone().expect("session");
    assert_eq!(session.owner, Owner::Manual);
}

/// Equal / lower owners are refused while a start runs; a stop of a lower owner is refused
/// while a higher start runs (strict `<`: an equal owner's stop wins).
#[tokio::test]
async fn lower_or_equal_owners_are_refused() {
    let h = Harness::new();
    let (gate, start) = gated_connect(&h, Owner::Recovery).await;
    for owner in [Owner::Schedule, Owner::Manual, Owner::Recovery] {
        let r = h.lc.connect(local(owner)).await;
        assert_eq!(refused_key(r), "tunnel.lifecycle.lane.startInProgress");
    }
    let r = h.lc.disconnect(user_stop()).await;
    assert_eq!(refused_key(r), "tunnel.lifecycle.lane.higherPriority");
    gate.open();
    start.await.unwrap().expect("recovery start");
    let equal = DisconnectReq::new(StopCause::User, Owner::Recovery, Source::Lifecycle);
    h.lc.disconnect(equal).await.expect("stop");
}

/// H-04: "Cancel" with nothing in flight changes nothing; during a start it stops it.
#[tokio::test]
async fn cancel_pending_only_acts_on_work_in_flight() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    h.lc.cancel_pending();
    h.settle().await;
    assert_eq!(h.snap().state, TunnelState::Connected);
    assert_eq!(h.rt.script.lock().stops, 0);
    h.lc.disconnect(user_stop()).await.unwrap();
    h.notifier.notices.lock().clear();
    let (gate, start) = gated_connect(&h, Owner::Manual).await;
    h.lc.cancel_pending();
    assert_eq!(
        start.await.unwrap().unwrap_err().kind(),
        ErrorKind::Cancelled
    );
    gate.open();
    eventually("lane released", || !h.lc.busy()).await;
    assert_eq!(h.rt.script.lock().stops, 2);
    assert_clean_after_cancel(&h);
}

/// Dropping the connect future (caller gone) cancels it; the lane compensates by itself.
#[tokio::test]
async fn dropping_the_connect_future_cancels() {
    let h = Harness::new();
    let (gate, start) = gated_connect(&h, Owner::Manual).await;
    start.abort();
    let _ = start.await;
    eventually("stop published", || {
        h.snap().transition == Some(Transition::Disconnecting)
    })
    .await;
    gate.open();
    eventually("lane released", || !h.lc.busy()).await;
    h.settle().await;
    assert_eq!(h.rt.script.lock().stops, 1);
    assert_clean_after_cancel(&h);
}

/// AT-03-007 + A-06: shutdown closes admission, cancels and drains a start, stops as app-quit;
/// `reopen` re-admits only once everything is proven clean.
#[tokio::test]
async fn shutdown_drains_and_reopen_readmits() {
    let h = Harness::new();
    let (gate, start) = gated_connect(&h, Owner::Manual).await;
    let lc = h.lc.clone();
    let shutdown = tokio::spawn(async move { lc.shutdown(Duration::from_secs(5)).await });
    assert_eq!(
        start.await.unwrap().unwrap_err().kind(),
        ErrorKind::Cancelled
    );
    let r = h.lc.connect(local(Owner::Recovery)).await;
    assert_eq!(refused_key(r), "tunnel.lifecycle.lane.stopInProgress");
    gate.open();
    let report = shutdown.await.unwrap();
    assert!(report.engines_stopped && report.soft_restored && report.capture_stopped);
    assert!(!report.timed_out);
    h.settle().await;
    let r = h.lc.connect(local(Owner::Manual)).await;
    assert_eq!(refused_key(r), "tunnel.lifecycle.lane.stopInProgress");
    assert!(h.lc.reopen().await);
    h.lc.connect(local(Owner::Manual))
        .await
        .expect("connect after reopen");
}

/// H-06 / A-06: a refused Soft rollback is reported, admission stays closed (nothing proven).
#[tokio::test]
async fn shutdown_reports_a_failed_soft_rollback() {
    let h = Harness::new();
    h.lc.connect(soft(8080, ProxyKind::Http, Owner::Manual))
        .await
        .unwrap();
    h.soft.state.lock().rollback_failures = 1;
    let report = h.lc.shutdown(Duration::from_secs(5)).await;
    assert!(report.engines_stopped && !report.soft_restored);
    assert!(!h.lc.reopen().await, "Soft still applied: no reopen");
    let report = h.lc.shutdown(Duration::from_secs(5)).await;
    assert!(report.soft_restored, "retry succeeds");
    assert_eq!(h.rows().len(), 1);
    assert_eq!(
        h.rows()[0].outcome.as_ref().map(|o| o.kind.as_str()),
        Some("app-quit")
    );
}

/// H-06: on quit an unproven engine exit is no reason to leave the rest behind (the kill-on-close
/// job ends the engines with the app): capture, external proxies, monitoring and the Soft check
/// still run and the report tells each step apart.
#[tokio::test]
async fn shutdown_cleans_up_even_when_the_engine_exit_is_unproven() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    h.rt.script.lock().stop_unproven = true;
    let report = h.lc.shutdown(Duration::from_secs(5)).await;
    assert!(!report.engines_stopped && !report.timed_out);
    assert!(report.soft_restored && report.capture_stopped);
    let c = h.services.counters.lock();
    assert_eq!(
        (c.forensics_stops, c.proxies_stops, c.monitor_stops),
        (1, 1, 1)
    );
}

/// A-01 / §7.2 "startup unexpectedly throws": a panicking effect never strands the lane; the
/// caller gets an internal failure, the state reads unknown (nothing is proven) and the user is
/// told; the next connect works.
#[tokio::test]
async fn panicking_effect_releases_the_lane() {
    let h = Harness::new();
    h.soft.state.lock().apply_panics = true;
    let err =
        h.lc.connect(soft(8080, ProxyKind::Http, Owner::Manual))
            .await
            .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Internal);
    h.settle().await;
    assert!(!h.lc.busy());
    assert_eq!(h.snap().state, TunnelState::Unknown);
    let title = "tunnel.lifecycle.notice.internalError.title".to_owned();
    assert!(h.notifier.titles().contains(&title));
    h.lc.connect(local(Owner::Manual))
        .await
        .expect("connect after the panic");
}

/// The lane budget covers maintenance too: past it the action is dropped, the caller gets
/// `Timeout`, the lane is free again and the state reads unknown (nothing is proven).
#[tokio::test]
async fn maintenance_has_a_deadline() {
    let h = Harness::new();
    let never = Gate::new();
    let r =
        h.lc.maintenance(move || async move { never.wait().await })
            .await;
    assert!(
        matches!(r, Err(ConnError::Timeout(ref m)) if m.key == "tunnel.lifecycle.lane.maintenanceTimeout")
    );
    eventually("lane released", || !h.lc.busy()).await;
    h.settle().await;
    assert_eq!(h.snap().state, TunnelState::Unknown);
    h.lc.connect(local(Owner::Manual))
        .await
        .expect("lane free again");
}

/// A shutdown that runs out of budget says so (the cleanup goes on).
#[tokio::test]
async fn shutdown_budget_is_bounded() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    let gate = Gate::new();
    h.rt.script.lock().stop_gate = Some(gate.clone());
    let report = h.lc.shutdown(Duration::from_millis(30)).await;
    assert!(report.timed_out && !report.engines_stopped);
    gate.open();
    eventually("cleanup finished", || !h.lc.busy()).await;
}

/// A-05: maintenance runs only on an idle lane outside "connected" (the escape hatches stay
/// allowed in error / blocked / unknown) and holds the lane while it runs.
#[tokio::test]
async fn maintenance_gate() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    let r = h.lc.maintenance(|| async { 1 }).await;
    assert!(
        matches!(r, Err(ConnError::Refused(ref m)) if m.key == "tunnel.lifecycle.lane.maintenanceRefused")
    );
    h.lc.disconnect(user_stop()).await.unwrap();
    assert_eq!(h.lc.maintenance(|| async { 7 }).await.unwrap(), 7);
    let gate = Gate::new();
    let job_gate = gate.clone();
    let lc = h.lc.clone();
    let job = tokio::spawn(async move {
        lc.maintenance(move || async move { job_gate.wait().await })
            .await
    });
    eventually("maintenance running", || h.lc.busy()).await;
    let r = h.lc.connect(local(Owner::Manual)).await;
    assert_eq!(refused_key(r), "tunnel.lifecycle.lane.maintenanceBusy");
    let r = h.lc.disconnect(user_stop()).await;
    assert_eq!(refused_key(r), "tunnel.lifecycle.lane.maintenanceBusy");
    gate.open();
    job.await.unwrap().unwrap();
    for state in [FaultState::Error, FaultState::Blocked, FaultState::Unknown] {
        h.lc.fault(state);
        assert_eq!(h.lc.maintenance(|| async { 2 }).await.unwrap(), 2);
    }
}

/// Partial AT-00-002 tour walk (depth 4 over {connect, stop, crash, connect}): after every step
/// the state is the expected one, no transition is left, `pid` and the process state agree and
/// the lane is free. (The depth-6 walk runs on the pure state machine in `fsm::tests`.)
#[tokio::test]
async fn tour_walk() {
    #[derive(Clone, Copy, Debug)]
    enum Step {
        Connect,
        Stop,
        Crash,
    }
    const ALPHABET: [Step; 4] = [Step::Connect, Step::Stop, Step::Crash, Step::Connect];
    for tour in 0..4usize.pow(4) {
        let h = Harness::new();
        let mut expected = TunnelState::Disconnected;
        let mut code = tour;
        for _ in 0..4 {
            let step = ALPHABET[code % 4];
            code /= 4;
            match step {
                Step::Connect => {
                    let r = h.lc.connect(local(Owner::Manual)).await;
                    assert_eq!(r.is_ok(), expected != TunnelState::Connected, "{step:?}");
                    expected = TunnelState::Connected;
                }
                Step::Stop => {
                    h.lc.disconnect(user_stop()).await.expect("stop");
                    expected = TunnelState::Disconnected;
                }
                Step::Crash => {
                    h.rt.crash(1);
                    expected = TunnelState::Unknown;
                }
            }
            h.settle().await;
            let snap = h.snap();
            assert_eq!(snap.state, expected, "tour {tour} {step:?}");
            assert_eq!(snap.transition, None);
            let running = snap.process_state == ProcessState::Running;
            assert_eq!(running, snap.pid.is_some());
            assert_eq!(snap.mode == Some(TunnelMode::Tun), snap.pid.is_some());
            assert!(!h.lc.busy());
        }
    }
}

/// AT-00-007: 200 seeded commands from ten concurrent callers. After every batch the lane is
/// free, the tunnel shown connected is the one running, failures are only conflicts or
/// cancellations; a final stop leaves everything disconnected.
#[tokio::test]
async fn seeded_concurrent_commands() {
    let h = Harness::new();
    let mut seed: u32 = 0x05ee_d003;
    for _ in 0..20 {
        let mut batch = Vec::new();
        for _ in 0..10 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let lc = h.lc.clone();
            let start = seed.is_multiple_of(3);
            batch.push(tokio::spawn(async move {
                if start {
                    lc.connect(local(Owner::Manual)).await
                } else {
                    lc.disconnect(user_stop()).await
                }
            }));
        }
        for task in batch {
            if let Err(e) = task.await.unwrap() {
                assert!(
                    matches!(e.kind(), ErrorKind::Conflict | ErrorKind::Cancelled),
                    "{e:?}"
                );
            }
        }
        eventually("batch drained", || !h.lc.busy()).await;
        h.settle().await;
        let snap = h.snap();
        assert_eq!(snap.state == TunnelState::Connected, h.rt.running());
        assert_eq!(snap.mode == Some(TunnelMode::Tun), snap.pid.is_some());
    }
    h.lc.disconnect(user_stop()).await.expect("final stop");
    h.settle().await;
    let snap = h.snap();
    assert_eq!(
        (snap.state, snap.pid, snap.transition),
        (TunnelState::Disconnected, None, None)
    );
}
