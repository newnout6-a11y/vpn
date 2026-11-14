//! Overlapping requests: state changes in arrival order, a stop that overtakes a start still in
//! its prepare step, and the stop after the client left (reviews service-a1 / a2 / a10).
use super::*;

fn kill_switch(level: KillSwitchLevel) -> Request {
    Request::KillSwitch(Box::new(ProtectionSettings {
        level,
        ..ProtectionSettings::default()
    }))
}

/// Review service-a1: the second change waits for the first; the one sent last wins, for the
/// kill switch and for the routing inputs alike.
#[tokio::test]
async fn state_changes_run_one_at_a_time_in_arrival_order() {
    let h = harness();
    let mut c = Raw::open(&h).await;
    h.kill.gate.send_replace(false);
    c.send(2, local_start(KillSwitchLevel::Strict)).await;
    wait_for("the start applies its settings", || {
        h.kill.applying.load(Ordering::SeqCst) == 1
    })
    .await;
    c.send(3, kill_switch(KillSwitchLevel::Standard)).await;
    let later = RoutingInputs {
        smart_ru: true,
        ..RoutingInputs::default()
    };
    c.send(4, Request::Inputs(Box::new(later))).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        h.kill.applying.load(Ordering::SeqCst),
        1,
        "the second change waits for the first"
    );
    h.kill.gate.send_replace(true);
    for id in [2, 3, 4] {
        assert!(
            matches!(c.answer(id).await, ServerFrame::Reply { .. }),
            "{id}"
        );
    }
    assert_eq!(h.kill.level(), KillSwitchLevel::Standard);
    assert!(h.inputs.get().smart_ru, "the inputs sent last win");
}

/// Review service-a2: a stop sent while a start still applies its settings cancels that start.
#[tokio::test]
async fn a_stop_cancels_a_start_still_applying_its_settings() {
    let h = harness();
    let mut c = Raw::open(&h).await;
    h.kill.gate.send_replace(false);
    c.send(2, local_start(KillSwitchLevel::Standard)).await;
    wait_for("the start applies its settings", || {
        h.kill.applying.load(Ordering::SeqCst) == 1
    })
    .await;
    c.send(3, Request::Stop(StopTunnel::default())).await;
    assert!(matches!(c.answer(3).await, ServerFrame::Reply { .. }));
    h.kill.gate.send_replace(true);
    assert!(
        matches!(c.answer(2).await, ServerFrame::Failed { .. }),
        "the start was cancelled"
    );
    assert!(
        h.runtime.starts.lock().is_empty(),
        "no tunnel after the stop"
    );
    // The next start is not affected.
    c.send(4, local_start(KillSwitchLevel::Standard)).await;
    assert!(matches!(c.answer(4).await, ServerFrame::Reply { .. }));
}

/// Review service-a10: the client leaves while a change from "Always" to "If the VPN drops" is
/// applied; the change finishes before the slot is free again (the next controller sees it), and
/// leaving stops nothing (owner question 23).
#[tokio::test]
async fn a_change_in_flight_finishes_before_the_slot_is_free() {
    let h = harness();
    h.kill.always.store(true, Ordering::SeqCst);
    *h.kill.level.lock() = KillSwitchLevel::Strict;
    let mut c = Raw::open(&h).await;
    h.kill.gate.send_replace(false);
    c.send(2, kill_switch(KillSwitchLevel::Standard)).await;
    wait_for("the change is applied", || {
        h.kill.applying.load(Ordering::SeqCst) == 1
    })
    .await;
    drop(c);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut next = crate::pipe::client::Client::connect(
        &h.name,
        &crate::pipe::client::ServerCheck::Any,
        Duration::from_secs(5),
    )
    .await
    .expect("connect");
    assert!(next.hello("2.0.0").await.is_err(), "still settling");
    h.kill.gate.send_replace(true);
    wait_for("the change", || {
        *h.kill.level.lock() == KillSwitchLevel::Standard
    })
    .await;
    assert!(h.runtime.stops.lock().is_empty(), "leaving stops nothing");
}
