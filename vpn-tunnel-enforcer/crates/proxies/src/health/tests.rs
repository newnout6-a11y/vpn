use super::*;
use crate::model::FRESH_WINDOW_MS;

const NOW: UnixMs = 1_762_800_000_000;

fn ok(ip: &str) -> ProbeOk {
    ProbeOk {
        egress_ip: ip.parse().unwrap(),
        latency_ms: 123,
    }
}

fn timeout() -> ProbeError {
    ProbeError::Transport("ConnectTimeout after 10000ms".into())
}

fn slot(n: u64) -> Slot {
    Slot::new(n).unwrap()
}

/// Spec external-proxy §7.6: failures back off 15 / 30 / 60 s without any restart; the 4th
/// consecutive one spends the budget, and the disabled slot keeps the probe's own error.
#[test]
fn cooldowns_then_the_failure_budget() {
    let timing = Timing::default();
    let mut route = Route::default();
    route.begin(false);
    let s = Duration::from_secs;
    let eof = ProbeError::Transport("EOF".into());
    assert_eq!(route.failed(&eof, NOW, &timing), Next::In(s(15)));
    assert_eq!(route.failed(&eof, NOW, &timing), Next::In(s(30)));
    assert_eq!(route.failed(&eof, NOW, &timing), Next::In(s(60)));
    assert_eq!(
        (route.health, route.lifecycle, route.consecutive_failures),
        (Health::Degraded, Lifecycle::Degraded, 3)
    );
    assert_eq!(route.failed(&eof, NOW, &timing), Next::Disable);
    route.disabled(NOW);
    assert_eq!(
        (route.health, route.lifecycle),
        (Health::Failed, Lifecycle::Failed)
    );
    assert_eq!(route.last_error.as_deref(), Some("EOF"));
    assert_eq!(
        route.degradation,
        Some(Degradation::HealthFailureBudgetExhausted)
    );
    assert_eq!(timing.cooldown(9), s(60));
}

/// Spec external-proxy §7.6: engine-log timeouts never shorten the cooldown of a degraded
/// route; while healthy they pull the probe in at most once per spacing, and only earlier.
#[test]
fn transport_hints_act_only_while_healthy() {
    let timing = Timing::default();
    let mut route = Route::default();
    route.begin(false);
    assert_eq!(
        route.failed(&timeout(), NOW, &timing),
        Next::In(Duration::from_secs(15))
    );
    for _ in 0..20 {
        assert_eq!(
            route.hint("context deadline exceeded", NOW + 1, &timing),
            None
        );
    }
    assert!(route.succeeded(ok("198.51.100.1"), NOW));
    route.next_check_at = Some(NOW + 45_000);
    let hint = route.hint("ERROR outbound: read: EOF", NOW + 1_000, &timing);
    assert_eq!(hint, Some(Duration::from_secs(15)));
    assert_eq!(route.hint("i/o timeout", NOW + 20_000, &timing), None);
    assert_eq!(route.hint("connection ok", NOW + 40_000, &timing), None);
    route.next_check_at = Some(NOW + 41_000);
    assert_eq!(route.hint("timed out", NOW + 40_000, &timing), None);
    assert!(is_transport_hint("ECONNRESET") && !is_transport_hint("started"));
}

/// B-5: a failure the route answered resets the budget; a refused listener kills the engine.
#[test]
fn service_and_listener_failures() {
    let timing = Timing::default();
    let mut route = Route::default();
    route.begin(false);
    route.failed(&timeout(), NOW, &timing);
    let service = ProbeError::Service("trace.test: HTTP 429".into());
    assert_eq!(
        route.failed(&service, NOW, &timing),
        Next::In(timing.recheck)
    );
    assert_eq!(route.consecutive_failures, 0);
    let refused = ProbeError::LocalInbound("refused".into());
    assert_eq!(route.failed(&refused, NOW, &timing), Next::Kill);
    assert_eq!(route.degradation, Some(Degradation::EgressProbeFailed));
}

/// Spec external-proxy §3.17 A/B: an exit that drifts without a rotation, or a rotation that
/// lands on the old exit, degrades the slot; a later probe seeing the stored IP heals it.
#[test]
fn drift_and_failed_rotation_degrade() {
    let mut route = Route::default();
    route.begin(false);
    assert!(route.succeeded(ok("198.51.100.1"), NOW));
    assert!(route.is_healthy(true, NOW + 59_999) && !route.is_healthy(true, NOW + 60_000));
    assert!(!route.succeeded(ok("198.51.100.2"), NOW + 1));
    assert_eq!(
        route.last_error.as_deref(),
        Some("Egress IP changed from 198.51.100.1 to 198.51.100.2 without a route rotation")
    );
    assert_eq!(route.lifecycle, Lifecycle::Degraded);
    assert!(route.succeeded(ok("198.51.100.2"), NOW + 2));
    assert_eq!(
        (route.health, route.last_error.clone()),
        (Health::Healthy, None)
    );

    route.begin(true);
    assert_eq!(route.health, Health::Rotating);
    assert_eq!(route.egress_ip, None);
    assert!(!route.succeeded(ok("198.51.100.2"), NOW + 3));
    assert_eq!(
        (route.degradation, route.last_error.as_deref()),
        (
            Some(Degradation::RotationDidNotChangeEgressIp),
            Some("Rotation kept the previous egress IP 198.51.100.2")
        )
    );
    route.begin(true);
    assert!(route.succeeded(ok("198.51.100.3"), NOW + 4));
    assert_eq!(route.rotation_prev_egress, None);
}

/// Spec external-proxy §3.17 / §7.9: who keeps a duplicate IP.
#[test]
fn duplicate_resolution_protects_leases() {
    assert_eq!(resolve_duplicate(false, &[]), None);
    assert_eq!(
        resolve_duplicate(false, &[(slot(1), false)]),
        Some(Duplicate::Quarantine { keeper: slot(1) })
    );
    assert_eq!(
        resolve_duplicate(true, &[(slot(3), false), (slot(1), false)]),
        Some(Duplicate::QuarantinePeer(slot(1)))
    );
    assert_eq!(
        resolve_duplicate(true, &[(slot(1), false), (slot(4), true)]),
        Some(Duplicate::Quarantine { keeper: slot(4) })
    );
    assert_eq!(
        resolve_duplicate(false, &[(slot(2), true), (slot(5), true)]),
        Some(Duplicate::Quarantine { keeper: slot(2) })
    );
}

/// B-30: every slot's success re-probe lands inside the 60 s freshness window; first probes
/// of a batch are spread by slot.
#[test]
fn schedule_keeps_routes_fresh() {
    let timing = Timing::default();
    for n in 1..=10 {
        assert!(ms(timing.after_success(slot(n))) + 10_000 < FRESH_WINDOW_MS);
    }
    assert_eq!(timing.after_success(slot(4)), Duration::from_millis(46_000));
    assert_eq!(timing.first(slot(3)), Duration::from_millis(300));
    let mut route = Route::default();
    route.process_failed("External proxy instance exited (1)".into(), NOW);
    assert_eq!(
        (route.health, route.degradation),
        (Health::Failed, Some(Degradation::ProcessFailed))
    );
    route.disable_blocked(NOW);
    assert_eq!(
        route.last_error.as_deref(),
        Some("External proxy instance exited (1)")
    );
    assert_eq!(Route::stopped(NOW).last_checked_at, Some(NOW));
}
