//! Protected restart (§7.19), crash recovery (§7.20) and the in-place switch (§7.17).
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;
use vpnte_base::types::{Engine, EnginePref};

use super::*;
use crate::api::{
    FailoverCause, RestartOptions, Runtime, StopOptions, SwitchOutcome, TunStatusKind, TunWarning,
    TunnelEvent,
};
use crate::runtime::TunnelHandle;

fn spawn(world: &Arc<World>) -> TunnelHandle {
    TunnelHandle::spawn(deps(world))
}

/// AT-02-005: protection is kept across the gap (no release), the new adapter is created only
/// after the old one is gone, history sees the restart while the tunnel is still up.
#[tokio::test]
async fn protected_restart_keeps_protection_across_the_gap() {
    let w = World::new();
    let h = spawn(&w);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    let receipt = h
        .restart_protected(
            "server switch".into(),
            local_req(),
            RestartOptions::default(),
        )
        .await
        .expect("restart");
    assert_eq!(receipt.generation, 2);
    assert_eq!(w.count("release"), 0);
    assert!(w.at("terminate:4100") < w.at("wait-gone"));
    assert!(w.at("wait-gone") < w.at("spawn:4101"));
    let seen = drain(&mut events);
    let restart = seen
        .iter()
        .position(|e| matches!(e, TunnelEvent::ProtectedRestart { .. }));
    let preserved = seen.iter().position(|e| {
        matches!(
            e,
            TunnelEvent::StopFinished {
                generation: 1,
                preserved: true,
                ..
            }
        )
    });
    assert!(restart.is_some() && restart < preserved, "{seen:?}");
    assert!(h.status().borrow().running);
}

/// tunnel-core §3.7 (decided): an unverified release continues on a fresh identity with a
/// warning instead of stranding the user offline.
#[tokio::test]
async fn unverified_release_continues_on_a_fresh_identity() {
    let w = World::new();
    let h = spawn(&w);
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    w.gone.store(false, Ordering::SeqCst);
    let receipt = h
        .restart_protected(
            "config change: dns".into(),
            local_req(),
            RestartOptions::default(),
        )
        .await
        .expect("restart");
    assert!(
        receipt
            .warnings
            .contains(&TunWarning::ReleaseUnverified.msg())
    );
    let avoid = w.avoid.lock().clone();
    assert_eq!(avoid.last(), Some(&vec!["Ethernet 5".to_owned()]));
}

/// A pre-cancelled restart has no effect; a failed start after the preserved stop ends in a
/// full stop that releases the protection when the kill switch is off, and counts as a drop
/// when it pauses (ks-a, research 5.3): nothing released, the crash policy restarts.
#[tokio::test]
async fn cancelled_or_failed_restart() {
    let w = World::new();
    let h = spawn(&w);
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    let before = w.log().len();
    let opts = RestartOptions::default();
    opts.cancel.cancel();
    let err = h
        .restart_protected("x".into(), local_req(), opts)
        .await
        .unwrap_err();
    assert_eq!(err.user_msg().key, "tunnel.runtime.restartCancelled");
    assert_eq!(w.log().len(), before);

    let mut events = h.subscribe();
    w.ready_fail.store(true, Ordering::SeqCst);
    let err = h
        .restart_protected("x".into(), local_req(), RestartOptions::default())
        .await
        .unwrap_err();
    assert!(err.user_msg().key.starts_with("tunnel.runtime.tunSetup"));
    assert_eq!(
        w.count("release"),
        0,
        "a planned reconnect that fails is a drop"
    );
    let restarting = TunnelEvent::Status(TunStatusKind::Restarting { attempt: 1, max: 3 });
    until(&mut events, |e| *e == restarting).await;
    assert!(!h.status().borrow().running);
    h.stop(StopOptions::default()).await;

    let w = World::new();
    *w.guard.lock() = vpnte_base::types::KillSwitchLevel::Off;
    let h = spawn(&w);
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    w.ready_fail.store(true, Ordering::SeqCst);
    let err = h
        .restart_protected("x".into(), local_req(), RestartOptions::default())
        .await
        .unwrap_err();
    assert!(err.user_msg().key.starts_with("tunnel.runtime.tunSetup"));
    assert_eq!(w.count("release"), 1);
    assert!(!h.status().borrow().running);
}

/// `restart_with_last` is a no-op when idle; `restart_adaptive` needs a running tunnel.
#[tokio::test]
async fn restarts_of_the_last_start() {
    let w = World::new();
    let h = spawn(&w);
    assert_eq!(h.restart_with_last("rules".into()).await.unwrap(), None);
    let err = h
        .restart_adaptive(
            vpnte_base::types::AdaptiveMode::MtuCompatibility,
            "x".into(),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Conflict);
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    let r = h
        .restart_adaptive(
            vpnte_base::types::AdaptiveMode::MtuCompatibility,
            "x".into(),
            None,
        )
        .await
        .expect("adaptive restart");
    assert_eq!(r.generation, 2);
    let mtu = w.configs.lock()[1]["inbounds"][0]["mtu"].clone();
    assert_eq!(mtu, 1280);
    assert!(h.restart_with_last("rules".into()).await.unwrap().is_some());
}

/// b6: an adaptive restart takes the current settings with its new mode: a stealth start
/// (MTU 1280) restarted in baseline after stealth was turned off runs with the full MTU.
#[tokio::test]
async fn adaptive_restarts_take_the_current_settings() {
    let w = World::new();
    let h = spawn(&w);
    let stealthy = StartRequest {
        stealth: true,
        ..local_req()
    };
    h.start(stealthy, CancellationToken::new()).await.unwrap();
    assert_eq!(w.configs.lock()[0]["inbounds"][0]["mtu"], 1280);
    let baseline = vpnte_base::types::AdaptiveMode::Baseline;
    h.restart_adaptive(baseline, "settings".into(), None)
        .await
        .expect("adaptive restart");
    assert_eq!(w.configs.lock()[1]["inbounds"][0]["mtu"], 1500);
}

/// AT-02-005 (§7.20): a crash restarts the last start after the backoff, protection held
/// (lost, never released), through a new native generation.
#[tokio::test]
async fn crash_restarts_after_the_backoff() {
    let w = World::new();
    let h = spawn(&w);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    w.core(0).crash();
    let seen = until(&mut events, |e| {
        matches!(e, TunnelEvent::StartFinished { generation: 2, .. })
    })
    .await;
    assert!(
        seen.contains(&TunnelEvent::Status(TunStatusKind::Restarting {
            attempt: 1,
            max: 3
        }))
    );
    assert!(seen.contains(&TunnelEvent::StartFinished {
        generation: 2,
        ok: true
    }));
    assert!(w.at("lost") < w.at("spawn:4101"));
    assert_eq!(w.count("release"), 0);
    assert_eq!(h.status().borrow().restart_attempt, 1);
    assert_eq!(h.last_exit().map(|e| e.user_initiated), Some(false));
}

/// Time from a crash of `req`'s session to the end of its recovery start (generation 2).
async fn crash_to_restart(req: StartRequest) -> Duration {
    let w = World::new();
    let mut d = deps(&w);
    d.timings.freeze = Duration::from_millis(700);
    let h = TunnelHandle::spawn(d);
    let mut events = h.subscribe();
    h.start(req, CancellationToken::new()).await.unwrap();
    drain(&mut events);
    let crashed = tokio::time::Instant::now();
    w.core(0).crash();
    let seen = until(&mut events, |e| {
        matches!(e, TunnelEvent::StartFinished { generation: 2, .. })
    })
    .await;
    let restarting = TunnelEvent::Status(TunStatusKind::Restarting { attempt: 1, max: 3 });
    assert!(seen.contains(&restarting), "{seen:?}");
    crashed.elapsed()
}

/// RU discipline: a crash with an outbound fault on record (the fake core reports one) does not
/// bring the same server back inside the freeze window, while the backoff is 20 ms; a slot
/// session is judged by Xray's log (clean here) and a local proxy's server is not ours.
#[tokio::test]
async fn a_faulted_server_waits_out_the_freeze_window() {
    let native = crash_to_restart(vpn_req(NATIVE_KEY, EnginePref::Auto)).await;
    assert!(native >= Duration::from_millis(700), "{native:?}");
    let slots = crash_to_restart(vpn_req(XRAY_KEY, EnginePref::Xray)).await;
    assert!(slots < Duration::from_millis(700), "{slots:?}");
    let local = crash_to_restart(local_req()).await;
    assert!(local < Duration::from_millis(700), "{local:?}");
}

/// A stop during the backoff cancels the pending restart.
#[tokio::test]
async fn stop_cancels_a_pending_restart() {
    let w = World::new();
    let mut d = deps(&w);
    d.timings.backoff = [Duration::from_millis(300); 3];
    let h = TunnelHandle::spawn(d);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    w.core(0).crash();
    until(&mut events, |e| {
        matches!(e, TunnelEvent::Status(TunStatusKind::Restarting { .. }))
    })
    .await;
    let receipt = h.stop(StopOptions::default()).await;
    assert!(receipt.confirms_cleanup());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(w.count("spawn:4101"), 0);
}

/// Failed recovery starts consume the budget (B-43 fixed: the chain does not silently end);
/// exhausted with the kill switch off: protection released, `Stopped`.
#[tokio::test]
async fn exhausted_budget_releases_with_the_kill_switch_off() {
    let w = World::new();
    *w.guard.lock() = vpnte_base::types::KillSwitchLevel::Off;
    let h = spawn(&w);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    w.ready_fail.store(true, Ordering::SeqCst);
    w.core(0).crash();
    let stopped = TunnelEvent::Status(TunStatusKind::Stopped);
    let seen = until(&mut events, |e| *e == stopped).await;
    assert_eq!(h.status().borrow().restart_attempt, 3);
    for attempt in 1..=3 {
        let restarting = TunnelEvent::Status(TunStatusKind::Restarting { attempt, max: 3 });
        assert!(seen.contains(&restarting), "{attempt}: {seen:?}");
    }
    assert!(w.count("release") >= 1);
    assert!(!h.status().borrow().running);
}

/// ks-a (research 5.4 "no silent release"): with "If the VPN drops" a spent budget keeps the
/// block (`KillSwitchActive`) and schedules slow retries; the first one that works runs again,
/// and nothing was released on the way.
#[tokio::test]
async fn exhausted_budget_keeps_the_pause_and_retries_slowly() {
    let w = World::new();
    let mut d = deps(&w);
    d.timings.slow_retry = [100, 200, 300].map(Duration::from_millis);
    let h = TunnelHandle::spawn(d);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    w.ready_fail.store(true, Ordering::SeqCst);
    w.core(0).crash();
    let held = TunnelEvent::Status(TunStatusKind::KillSwitchActive);
    until(&mut events, |e| *e == held).await;
    let slow = TunnelEvent::RestartScheduled {
        delay: Duration::from_millis(100),
    };
    until(&mut events, |e| *e == slow).await;
    let second = TunnelEvent::RestartScheduled {
        delay: Duration::from_millis(200),
    };
    until(&mut events, |e| *e == second).await;
    assert_eq!(w.count("release"), 0, "never released silently");
    w.ready_fail.store(false, Ordering::SeqCst);
    until(&mut events, |e| {
        matches!(e, TunnelEvent::StartFinished { ok: true, .. })
    })
    .await;
    assert!(h.status().borrow().running);
    assert_eq!(w.count("release"), 0);
}

/// ks-a «Подключить»: a paused session retries at once, whatever the auto-restart setting; with
/// nothing paused there is nothing to retry.
#[tokio::test]
async fn retry_now_runs_the_paused_session_at_once() {
    let w = World::new();
    w.auto_restart.store(false, Ordering::SeqCst);
    let h = spawn(&w);
    assert!(!h.retry_now().await, "idle");
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    w.core(0).crash();
    let held = TunnelEvent::Status(TunStatusKind::KillSwitchActive);
    until(&mut events, |e| *e == held).await;
    assert!(h.retry_now().await);
    until(&mut events, |e| {
        matches!(e, TunnelEvent::StartFinished { ok: true, .. })
    })
    .await;
    assert!(h.status().borrow().running);
    assert_eq!(w.count("release"), 0);
}

/// Auto-restart off: the kill switch keeps blocking (`KillSwitchActive`), nothing released
/// until the user's full stop.
#[tokio::test]
async fn auto_restart_off_keeps_blocking() {
    let w = World::new();
    w.auto_restart.store(false, Ordering::SeqCst);
    let h = spawn(&w);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    w.core(0).crash();
    until(&mut events, |e| {
        *e == TunnelEvent::Status(TunStatusKind::KillSwitchActive)
    })
    .await;
    assert_eq!(w.count("release"), 0);
    let receipt = h.stop(StopOptions::default()).await;
    assert!(receipt.confirms_cleanup());
    assert_eq!(w.count("release"), 1);

    // Kill switch off: nothing to keep, the session ends.
    let w = World::new();
    w.auto_restart.store(false, Ordering::SeqCst);
    *w.guard.lock() = KillSwitchLevel::Off;
    let h = spawn(&w);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    w.core(0).crash();
    until(&mut events, |e| {
        *e == TunnelEvent::Status(TunStatusKind::Stopped)
    })
    .await;
    assert_eq!(w.count("release"), 1);
}

/// Xray slots: slot A starts and is probed before the TUN, the selector is read back before
/// running; an in-place switch stages B, selects, confirms, commits, then stops A.
#[tokio::test]
async fn slot_session_and_in_place_switch() {
    let w = World::new();
    let h = spawn(&w);
    let mut events = h.subscribe();
    let receipt = h
        .start(
            vpn_req(XRAY_KEY, EnginePref::Xray),
            CancellationToken::new(),
        )
        .await
        .expect("slot start");
    assert_eq!(receipt.engine.kind, Engine::Xray);
    // Forced Xray: the reason is the preference, shown with the run (no silent choice).
    assert_eq!(
        receipt.engine.reason,
        Some(crate::api::SelectReason::Preference)
    );
    assert!(w.at("begin:0") < w.at("xray-start:a"));
    assert!(w.at("xray-start:a") < w.at("spawn:4100"));
    // The slot's egress probe names the server it dials (the app's handshake budget keys on it).
    assert!(w.at("xray-start:a") < w.at("egress-via:203.0.113.10"));
    assert!(w.at("ready") < w.at("select:a"));
    assert!(w.at("select:a") < w.at("activate:a"));
    let status = h.status().borrow().clone();
    assert_eq!(status.profile_name.as_deref(), Some("Fake A"));
    assert!(status.session.as_ref().is_some_and(|s| s.probe.is_some()));

    let owner: crate::api::OwnerCheck = Arc::new(|| true);
    let next = vpn_req(XRAY_KEY_2, EnginePref::Xray);
    let sw = h
        .switch_upstream(next, CancellationToken::new(), owner.clone())
        .await
        .expect("in place");
    assert_eq!(sw.outcome, SwitchOutcome::Success, "{sw:?}");
    assert!(sw.verified());
    assert!(w.at("xray-start:b") < w.at("select:b"));
    assert!(w.at("xray-start:b") < w.at("egress-via:203.0.113.11"));
    assert!(w.at("activate:b") < w.at("xray-stop:a"));
    assert_eq!(h.status().borrow().profile_name.as_deref(), Some("Fake B"));
    let seen = drain(&mut events);
    assert!(seen.contains(&TunnelEvent::SwitchFinished {
        generation: 1,
        verified: true
    }));

    // A config-shaping change (stealth = another MTU) is not possible in place.
    let mut stealth = vpn_req(XRAY_KEY, EnginePref::Xray);
    stealth.stealth = true;
    let none = h
        .switch_upstream(stealth, CancellationToken::new(), owner)
        .await;
    assert!(none.is_none());
}

/// The engine and its reason travel through the receipt, the status and the switch receipt;
/// the Xray path's dropped settings (a packet encoding here) come with the start and with the
/// switch. Stealth is not one of them any more: its TLS tricks reach Xray (item 18).
#[tokio::test]
async fn engine_run_and_xray_warnings_are_visible() {
    use crate::api::{EngineRun, SelectReason};
    let encoded = |key: &str| key.replace("&type=tcp#", "&type=tcp&packetEncoding=packetaddr#");
    let w = World::new();
    let h = spawn(&w);
    let mut req = vpn_req(&encoded(XRAY_KEY), EnginePref::Xray);
    req.stealth = true;
    let receipt = h
        .start(req, CancellationToken::new())
        .await
        .expect("slot start");
    let run = EngineRun {
        kind: Engine::Xray,
        reason: Some(SelectReason::Preference),
    };
    assert_eq!(receipt.engine, run);
    let keys =
        |warnings: &[vpnte_base::Msg]| warnings.iter().map(|m| m.key.clone()).collect::<Vec<_>>();
    let dropped = ["engine.xray.warn.packetEncoding".to_owned()];
    assert_eq!(keys(&receipt.warnings), dropped, "{receipt:?}");
    assert_eq!(h.status().borrow().engine, Some(run));
    let mut next = vpn_req(&encoded(XRAY_KEY_2), EnginePref::Xray);
    next.stealth = true;
    let owner: crate::api::OwnerCheck = Arc::new(|| true);
    let sw = h
        .switch_upstream(next, CancellationToken::new(), owner)
        .await
        .expect("in place");
    assert!(sw.verified(), "{sw:?}");
    assert_eq!(sw.engine, Some(run));
    assert_eq!(keys(&sw.warnings), dropped, "{sw:?}");
    assert_eq!(h.status().borrow().engine, Some(run));
}

/// The server's own choice wins over the setting; forced Xray refuses a protocol Xray lacks
/// before any effect instead of starting sing-box.
#[tokio::test]
async fn server_override_and_xray_refusal() {
    use crate::api::{EngineRun, SelectReason};
    let w = World::new();
    let h = spawn(&w);
    let mut req = vpn_req(XRAY_KEY, EnginePref::Xray);
    if let crate::api::Mode::DirectVpn { profile } = &mut req.mode {
        profile.engine = EnginePref::SingBox;
    }
    let receipt = h
        .start(req, CancellationToken::new())
        .await
        .expect("sing-box start");
    let run = EngineRun {
        kind: Engine::SingBox,
        reason: Some(SelectReason::Preference),
    };
    assert_eq!(receipt.engine, run);
    assert_eq!(w.count("xray-start:a"), 0);
    h.stop(crate::api::StopOptions::default()).await;

    let w = World::new();
    let h = spawn(&w);
    let tuic = "tuic://00000000-0000-4000-8000-000000000003:fake-password@203.0.113.13:443?sni=example.com#Fake%20T";
    let err = h
        .start(vpn_req(tuic, EnginePref::Xray), CancellationToken::new())
        .await
        .expect_err("refused");
    assert_eq!(err.kind(), ErrorKind::Validation);
    assert_eq!(err.user_msg().key, "engine.xray.reject.noXrayClient");
    assert!(
        w.log().iter().all(|l| !l.starts_with("begin")),
        "{:?}",
        w.log()
    );
}

/// A native sing-box or local-proxy session never switches in place.
#[tokio::test]
async fn no_in_place_switch_without_slots() {
    let w = World::new();
    let h = spawn(&w);
    h.start(
        vpn_req(NATIVE_KEY, EnginePref::SingBox),
        CancellationToken::new(),
    )
    .await
    .expect("native start");
    let owner: crate::api::OwnerCheck = Arc::new(|| true);
    let next = vpn_req(XRAY_KEY, EnginePref::Xray);
    assert!(
        h.switch_upstream(next, CancellationToken::new(), owner)
            .await
            .is_none()
    );
}

/// The active slot's exit: upstream down at once, slot restarted, upstream back.
#[tokio::test]
async fn active_slot_exit_is_restarted() {
    let w = World::new();
    let h = spawn(&w);
    let mut events = h.subscribe();
    h.start(
        vpn_req(XRAY_KEY, EnginePref::Xray),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    drain(&mut events);
    let tx = w.xray_events.lock().clone().expect("slot events");
    w.running.lock()[0] = false;
    tx.send(XrayEvent::Exited {
        slot: Slot::A,
        pid: 1,
        code: Some(2),
        expected: false,
        graceful: false,
        tail: String::new(),
    })
    .await
    .unwrap();
    let seen = until(&mut events, |e| {
        *e == TunnelEvent::Status(TunStatusKind::Running)
    })
    .await;
    assert!(
        seen.iter()
            .any(|e| matches!(e, TunnelEvent::Status(TunStatusKind::ProxyDown { .. })))
    );
    assert_eq!(w.count("xray-restart:a"), 1);
    assert!(h.status().borrow().proxy_reachable);
}

/// §7.17: the fresh tunnel egress differs from the candidate's probe: failed, the previous
/// upstream re-selected and re-proven (verified), the candidate drained.
#[tokio::test]
async fn candidate_egress_mismatch_preserves_the_previous_upstream() {
    let w = World::new();
    let h = spawn(&w);
    h.start(
        vpn_req(XRAY_KEY, EnginePref::Xray),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    w.select_ignored.store(true, Ordering::SeqCst);
    let owner: crate::api::OwnerCheck = Arc::new(|| true);
    let next = vpn_req(XRAY_KEY_2, EnginePref::Xray);
    let sw = h
        .switch_upstream(next, CancellationToken::new(), owner)
        .await
        .expect("in place");
    assert_eq!(sw.outcome, SwitchOutcome::Failed);
    assert!(sw.previous_preserved && sw.candidate_stopped && !sw.committed);
    assert!(sw.verified());
    assert_eq!(sw.failures[0].phase, crate::api::SwitchPhase::Confirm);
    assert!(w.at("select:b") < w.at("xray-stop:b"));
    assert_eq!(h.status().borrow().profile_name.as_deref(), Some("Fake A"));
}

/// §7.17: a failed stage keeps the previous upstream but marks the standby port suspect: the
/// next request goes through the protected restart (`None`).
#[tokio::test]
async fn failed_stage_sends_the_next_switch_to_a_restart() {
    let w = World::new();
    let h = spawn(&w);
    h.start(
        vpn_req(XRAY_KEY, EnginePref::Xray),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    w.stage_fail.store(true, Ordering::SeqCst);
    let owner: crate::api::OwnerCheck = Arc::new(|| true);
    let sw = h
        .switch_upstream(
            vpn_req(XRAY_KEY_2, EnginePref::Xray),
            CancellationToken::new(),
            owner.clone(),
        )
        .await
        .expect("in place");
    assert!(sw.previous_preserved && sw.verified());
    w.stage_fail.store(false, Ordering::SeqCst);
    let next = vpn_req(XRAY_KEY_2, EnginePref::Xray);
    assert!(
        h.switch_upstream(next, CancellationToken::new(), owner)
            .await
            .is_none()
    );
}

/// §7.17 "native stop mid-switch": a runtime stop ends the switch's ownership at once —
/// cancelled, `ownership_lost`, the previous upstream neither re-selected nor re-proven — and
/// the stop then runs to a certified cleanup.
#[tokio::test]
async fn stop_mid_switch_ends_its_ownership() {
    let w = World::new();
    let h = spawn(&w);
    h.start(
        vpn_req(XRAY_KEY, EnginePref::Xray),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    w.stage_hold.store(true, Ordering::SeqCst);
    let switching = {
        let h = h.clone();
        let owner: crate::api::OwnerCheck = Arc::new(|| true);
        let next = vpn_req(XRAY_KEY_2, EnginePref::Xray);
        tokio::spawn(async move {
            h.switch_upstream(next, CancellationToken::new(), owner)
                .await
        })
    };
    while w.count("xray-start:b") == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let receipt = h.stop(StopOptions::default()).await;
    let sw = switching.await.expect("join").expect("in place");
    assert_eq!(sw.outcome, SwitchOutcome::Cancelled, "{sw:?}");
    assert!(sw.ownership_lost && !sw.previous_preserved && sw.active_slot.is_none());
    assert!(!sw.verified());
    assert_eq!(w.count("egress"), 0, "no re-proof after the stop");
    assert!(w.at("xray-stop:b") < w.at("terminate:4100"));
    assert!(receipt.confirms_cleanup(), "{receipt:?}");
}

/// §3.5 (d): every start but a crash recovery reopens the auto-restart window — a protected
/// restart (user, rotation, adaptive) included.
#[tokio::test]
async fn protected_restart_resets_the_crash_budget() {
    let w = World::new();
    let h = spawn(&w);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    w.core(0).crash();
    until(&mut events, |e| {
        matches!(e, TunnelEvent::StartFinished { generation: 2, .. })
    })
    .await;
    assert_eq!(h.status().borrow().restart_attempt, 1);
    h.restart_protected(
        "server switch".into(),
        local_req(),
        RestartOptions::default(),
    )
    .await
    .expect("restart");
    assert_eq!(h.status().borrow().restart_attempt, 0);
}

/// A failover policy over fixed siblings; `true` = that sibling's start fails (its capture
/// never gets ready).
struct Siblings {
    world: Arc<World>,
    left: Mutex<Vec<(crate::api::VpnProfile, bool)>>,
    committed: Mutex<Vec<String>>,
}

#[async_trait]
impl crate::runtime::Failover for Siblings {
    async fn next_live_sibling(&self, _: &CancellationToken) -> Option<crate::api::VpnProfile> {
        let mut left = self.left.lock();
        if left.is_empty() {
            return None;
        }
        let (profile, fails) = left.remove(0);
        self.world.ready_fail.store(fails, Ordering::SeqCst);
        Some(profile)
    }

    fn commit(&self, profile_id: &str) {
        self.committed.lock().push(profile_id.to_owned());
    }
}

fn sibling(uri: &str, id: &str) -> crate::api::VpnProfile {
    let crate::api::Mode::DirectVpn { profile } = vpn_req(uri, EnginePref::Auto).mode else {
        unreachable!("vpn_req builds a Direct VPN start");
    };
    crate::api::VpnProfile {
        id: id.into(),
        ..profile
    }
}

/// b8: a crash inside the freeze window fails over at once. A candidate that does not start is
/// never announced; the sibling that starts is named for the session right before its run's
/// finish (`FailedOver`), committed, and announced once to the user after it started.
#[tokio::test]
async fn failover_announces_only_the_sibling_that_started() {
    let w = World::new();
    let siblings = Arc::new(Siblings {
        world: w.clone(),
        left: Mutex::new(vec![
            (sibling(XRAY_KEY, "b"), true),
            (sibling(XRAY_KEY_2, "c"), false),
        ]),
        committed: Mutex::new(Vec::new()),
    });
    let mut d = deps(&w);
    d.failover = Some(siblings.clone());
    let h = TunnelHandle::spawn(d);
    let mut events = h.subscribe();
    let req = vpn_req(NATIVE_KEY, EnginePref::Auto);
    h.start(req, CancellationToken::new()).await.unwrap();
    drain(&mut events);
    w.core(0).crash();
    let announced = |e: &TunnelEvent| {
        matches!(
            e,
            TunnelEvent::Status(TunStatusKind::PostTrialFailover { .. })
        )
    };
    let seen = until(&mut events, announced).await;
    assert_eq!(seen.iter().filter(|e| announced(e)).count(), 1, "{seen:?}");
    assert_eq!(
        seen.last(),
        Some(&TunnelEvent::Status(TunStatusKind::PostTrialFailover {
            name: "Fake B".into()
        }))
    );
    let named: Vec<_> = (seen.iter().enumerate())
        .filter_map(|(i, e)| match e {
            TunnelEvent::FailedOver {
                generation,
                profile_id,
                cause,
            } => Some((i, *generation, profile_id.clone(), *cause)),
            _ => None,
        })
        .collect();
    let [(at, generation, id, cause)] = named.as_slice() else {
        panic!("one FailedOver expected: {seen:?}");
    };
    assert_eq!((id.as_str(), *cause), ("c", FailoverCause::ServerFault));
    assert_eq!(
        seen.get(at + 1),
        Some(&TunnelEvent::StartFinished {
            generation: *generation,
            ok: true
        })
    );
    assert_eq!(*siblings.committed.lock(), ["c"]);
}

/// b1: crashes with no outbound fault on record restart first; the failover that follows the
/// spent budget says what was seen (`RestartsSpent`), so no text blames the server.
#[tokio::test]
async fn a_failover_without_a_fault_names_the_spent_restarts() {
    let w = World::new();
    w.no_fault.store(true, Ordering::SeqCst);
    let siblings = Arc::new(Siblings {
        world: w.clone(),
        left: Mutex::new(vec![(sibling(XRAY_KEY_2, "c"), false)]),
        committed: Mutex::new(Vec::new()),
    });
    let mut d = deps(&w);
    d.failover = Some(siblings.clone());
    let h = TunnelHandle::spawn(d);
    let mut events = h.subscribe();
    let req = vpn_req(NATIVE_KEY, EnginePref::Auto);
    h.start(req, CancellationToken::new()).await.unwrap();
    // The first run and each of the three restarts crash inside the stable window.
    for run in 0..=crate::runtime::MAX_RESTARTS {
        let generation = u64::from(run) + 1;
        until(&mut events, |e| {
            matches!(e, TunnelEvent::StartFinished { generation: g, ok: true } if *g == generation)
        })
        .await;
        w.core(usize::from(run)).crash();
    }
    let seen = until(&mut events, |e| matches!(e, TunnelEvent::FailedOver { .. })).await;
    let Some(TunnelEvent::FailedOver {
        profile_id, cause, ..
    }) = seen.last()
    else {
        panic!("a failover expected: {seen:?}");
    };
    assert_eq!(
        (profile_id.as_str(), *cause),
        ("c", FailoverCause::RestartsSpent)
    );
    assert_eq!(*siblings.committed.lock(), ["c"]);
}
