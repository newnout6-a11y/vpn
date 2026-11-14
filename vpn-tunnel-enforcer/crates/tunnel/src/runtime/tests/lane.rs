//! Start ordering, compensation, stop and protected restart (tunnel-core §7.18 / §7.19).
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;

use super::*;
use crate::api::{Runtime, StopOptions, TunStatusKind, TunnelEvent};
use crate::runtime::TunnelHandle;

fn spawn(world: &Arc<World>) -> TunnelHandle {
    TunnelHandle::spawn(deps(world))
}

const PRESERVED: StopOptions = StopOptions {
    preserve_protection: true,
    preserve_last: true,
};

/// AT-02-002 / AT-00-004: protection before any engine, running only after the capture proof;
/// the status carries the session endpoints; the TUN form follows the WFP guard (standard:
/// dual-stack, native DNS).
#[tokio::test]
async fn start_publishes_running_only_after_the_capture_proof() {
    let w = World::new();
    let h = spawn(&w);
    let mut events = h.subscribe();
    let receipt = h
        .start(local_req(), CancellationToken::new())
        .await
        .expect("start");
    let log = w.log();
    assert_eq!(
        log,
        [
            "prepare:Ethernet 5",
            "probe:127.0.0.1:10808",
            "begin:1",
            "spawn:4100",
            "ready"
        ]
    );
    assert_eq!((receipt.generation, receipt.pid), (1, 4100));
    let status = h.status().borrow().clone();
    assert!(status.running && status.proxy_reachable);
    assert_eq!(status.pid, Some(4100));
    let session = status.session.expect("session endpoints");
    assert_eq!(session.tun_luid, Some(42));
    assert_eq!(session.tun_alias.as_deref(), Some("Ethernet 5"));
    assert_eq!(session.clash_secret.len(), 32);
    assert!(
        session.probe.is_none(),
        "local proxy mode has no probe inbound"
    );
    let config = w.configs.lock()[0].clone();
    assert_eq!(clash_port(&config), session.clash_port);
    let tun = &config["inbounds"][0];
    assert_eq!(tun["dns_mode"], "native");
    assert_eq!(tun["interface_name"], "Ethernet 5");
    assert_eq!(tun["address"].as_array().map(Vec::len), Some(2));
    let seen = drain(&mut events);
    let running = seen
        .iter()
        .position(|e| *e == TunnelEvent::Status(TunStatusKind::Running));
    let finished = seen
        .iter()
        .position(|e| matches!(e, TunnelEvent::StartFinished { ok: true, .. }));
    assert!(matches!(seen[0], TunnelEvent::StartBegan { generation: 1 }));
    assert!(running < finished, "{seen:?}");
}

/// A second start while running is refused before any effect.
#[tokio::test]
async fn second_start_is_refused() {
    let w = World::new();
    let h = spawn(&w);
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    let before = w.log().len();
    let err = h
        .start(local_req(), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Conflict);
    assert_eq!(err.user_msg().key, "tunnel.runtime.alreadyRunning");
    assert_eq!(w.log().len(), before);
}

/// Unready capture: compensation before anything is published; the error keeps its
/// `tunnel.runtime.tunSetup` key (history: tun-setup-failed).
#[tokio::test]
async fn unready_capture_is_compensated() {
    let w = World::new();
    w.ready_fail.store(true, Ordering::SeqCst);
    let h = spawn(&w);
    let mut events = h.subscribe();
    let err = h
        .start(local_req(), CancellationToken::new())
        .await
        .unwrap_err();
    assert!(err.user_msg().key.starts_with("tunnel.runtime.tunSetup"));
    let log = w.log();
    assert!(w.at("terminate:4100") < w.at("release"), "{log:?}");
    let seen = drain(&mut events);
    assert!(!seen.contains(&TunnelEvent::Status(TunStatusKind::Running)));
    assert!(seen.contains(&TunnelEvent::Status(TunStatusKind::Stopped)));
    assert!(seen.contains(&TunnelEvent::StartFinished {
        generation: 1,
        ok: false
    }));
    assert!(!h.status().borrow().running);
}

/// An unproven exit releases nothing, says so, and refuses the next start until the old run
/// is proven gone.
#[tokio::test]
async fn unproven_exit_retains_protection() {
    let w = World::new();
    w.ready_fail.store(true, Ordering::SeqCst);
    w.kill_ok.store(false, Ordering::SeqCst);
    let h = spawn(&w);
    let err = h
        .start(local_req(), CancellationToken::new())
        .await
        .unwrap_err();
    let warning = "tunnel.runtime.cleanup.exitUnproven";
    assert!(err.warnings.iter().any(|m| m.key == warning));
    assert_eq!(w.count("release"), 0);
    let again = h
        .start(local_req(), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(again.user_msg().key, "tunnel.runtime.previousNotStopped");
    w.kill_ok.store(true, Ordering::SeqCst);
    let receipt = h.stop(StopOptions::default()).await;
    assert!(receipt.confirms_cleanup(), "{receipt:?}");
    assert_eq!(w.count("release"), 1);
}

/// tc:3222-3251: a death on one of OUR loopback ports is retried once with fresh ports.
#[tokio::test]
async fn bind_failure_is_retried_once_with_fresh_ports() {
    let w = World::new();
    w.ready.lock().push_back(Ready::BindFail);
    let h = spawn(&w);
    h.start(local_req(), CancellationToken::new())
        .await
        .expect("second attempt starts");
    let configs = w.configs.lock().clone();
    assert_eq!(configs.len(), 2);
    assert_ne!(clash_port(&configs[0]), clash_port(&configs[1]));
    assert_eq!(h.status().borrow().pid, Some(4101));
    // Twice in a row is a real failure.
    let w = World::new();
    w.ready.lock().extend([Ready::BindFail, Ready::BindFail]);
    let h = spawn(&w);
    assert!(
        h.start(local_req(), CancellationToken::new())
            .await
            .is_err()
    );
    assert_eq!(w.configs.lock().len(), 2);
}

/// A stop cancels a start in flight and waits for its compensation (AT-02-005).
#[tokio::test]
async fn stop_cancels_a_start_and_waits_for_its_compensation() {
    let w = World::new();
    w.ready.lock().push_back(Ready::Hold);
    let h = spawn(&w);
    let starting = {
        let h = h.clone();
        tokio::spawn(async move { h.start(local_req(), CancellationToken::new()).await })
    };
    while w.count("spawn:4100") == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let receipt = h.stop(StopOptions::default()).await;
    let started = starting.await.expect("join");
    assert_eq!(started.unwrap_err().kind(), ErrorKind::Cancelled);
    assert!(receipt.ok && receipt.runtime_stopped);
    assert!(w.at("terminate:4100") < w.log().len());
    assert!(!h.status().borrow().running);
}

/// A stop requested after a start was requested cancels it even before admission.
#[tokio::test]
async fn caller_cancel_before_admission_has_no_effect() {
    let w = World::new();
    let h = spawn(&w);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let err = h.start(local_req(), cancel).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Cancelled);
    assert!(w.log().is_empty());
}

/// A full stop proves the exit, releases the protection, waits for the adapter; the receipt
/// certifies the cleanup and `StopFinished` carries the generation of the run it ended.
#[tokio::test]
async fn full_stop_certifies_cleanup() {
    let w = World::new();
    let h = spawn(&w);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    let receipt = h.stop(StopOptions::default()).await;
    assert!(receipt.confirms_cleanup() && receipt.adapter_gone && receipt.forced);
    assert!(receipt.operation_id.starts_with("stop_") && receipt.operation_id.len() == 37);
    assert!(w.at("terminate:4100") < w.at("release"));
    assert!(w.at("release") < w.at("wait-gone"));
    let seen = drain(&mut events);
    assert!(seen.iter().any(|e| matches!(e,
        TunnelEvent::StopFinished { generation: 1, preserved: false, receipt: r } if r.ok)));
    assert!(seen.contains(&TunnelEvent::Status(TunStatusKind::Stopped)));
    assert!(h.status().borrow().session.is_none());
    assert_eq!(h.last_exit().map(|e| e.user_initiated), Some(true));
}

/// Incomplete cleanup is reported: runtime stopped, protection not released, status error.
#[tokio::test]
async fn incomplete_cleanup_is_not_a_success() {
    let w = World::new();
    w.release_fail.store(true, Ordering::SeqCst);
    let h = spawn(&w);
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    let receipt = h.stop(StopOptions::default()).await;
    assert!(!receipt.ok && receipt.runtime_stopped);
    assert_eq!(receipt.protection_released, Some(false));
    assert!(!receipt.confirms_cleanup());
    let status = h.status().borrow().clone();
    assert_eq!(
        status.warning.map(|m| m.key.into_owned()).as_deref(),
        Some("tunnel.runtime.stopIncomplete")
    );
}

/// Concurrent stops share one cleanup and one receipt (§7.19, 200 queued stops).
#[tokio::test]
async fn concurrent_stops_share_one_receipt() {
    let w = World::new();
    w.slow_gone.store(true, Ordering::SeqCst);
    let h = spawn(&w);
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    let stops: Vec<_> = (0..200)
        .map(|_| {
            let h = h.clone();
            tokio::spawn(async move { h.stop(StopOptions::default()).await })
        })
        .collect();
    let mut ids = std::collections::BTreeSet::new();
    for s in stops {
        ids.insert(s.await.expect("join").operation_id);
    }
    assert!(
        ids.len() <= 2,
        "at most the running stop and one idle stop: {ids:?}"
    );
    assert_eq!(w.count("terminate:4100"), 1);
}

/// A full stop arriving during a preserved one runs after it; a preserved stop arriving during
/// a full one is refused (protection cannot be considered preserved).
#[tokio::test]
async fn stop_escalation_and_refusal() {
    let w = World::new();
    w.slow_gone.store(true, Ordering::SeqCst);
    let h = spawn(&w);
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    let full = {
        let h = h.clone();
        tokio::spawn(async move { h.stop(StopOptions::default()).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let late = h.stop(PRESERVED).await;
    let full = full.await.expect("join");
    assert!(full.ok);
    assert!(!late.ok);
    assert!(
        late.warnings
            .iter()
            .any(|m| m.key == "tunnel.runtime.fullStopRan")
    );

    let w = World::new();
    let h = spawn(&w);
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    let (preserved, full) = tokio::join!(h.stop(PRESERVED), h.stop(StopOptions::default()));
    assert!(preserved.ok && preserved.protection_released.is_none());
    assert!(full.confirms_cleanup());
    assert_ne!(preserved.operation_id, full.operation_id);
    assert_eq!(w.count("release"), 1);
}

/// Lab live-9 L9-2: a slow inputs snapshot (the service checking a handed-over Smart RU set)
/// runs beside the capture, slot A and its exit proof; the core's config waits for it.
#[tokio::test]
async fn the_inputs_are_read_beside_slot_a() {
    let w = World::new();
    w.inputs_ms.store(300, Ordering::SeqCst);
    let h = spawn(&w);
    let req = vpn_req(XRAY_KEY, vpnte_base::types::EnginePref::Xray);
    h.start(req, CancellationToken::new())
        .await
        .expect("slot start");
    let log = w.log();
    let at = |prefix: &str| {
        let found = log.iter().position(|l| l.starts_with(prefix));
        found.unwrap_or_else(|| panic!("no {prefix} in {log:?}"))
    };
    let (proof, inputs, core) = (at("egress-via:"), at("inputs-done"), at("spawn:"));
    assert!(proof < inputs && inputs < core, "{log:?}");
}
