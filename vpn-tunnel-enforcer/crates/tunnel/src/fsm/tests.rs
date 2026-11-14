//! Ported vectors of the old `tunnelStateMachine.test.ts` (header "AT-00-002/008, F-019/F-195")
//! plus new vectors for rotation, seeding and the wire shape.
//!
//! A tiny lane emulation publishes operation records the way the old connection lane did
//! (running record, effect, confirmation on evidence, terminal record). Lane admission and
//! concurrency themselves (busy flags, ten async workers) belong to the lifecycle package.
use vpnte_base::ErrorKind;
use vpnte_base::types::Owner;
use vpnte_core::ops::{CorrelationId, Source};

use super::*;

const PID: u32 = 123;

/// What a start effect returned.
#[derive(Clone, Copy)]
enum Effect {
    Ok,
    /// Failure of a category (old `connectionFailure(category)`; a thrown failure is the same
    /// now that no connect keeps a previous session).
    Fail(ErrorKind),
}

/// The machine plus a fake OS whose evidence the tests mutate (or make unreadable).
struct H {
    fsm: Fsm,
    os: Evidence,
    unreadable: bool,
}

fn op(kind: OpKind) -> OpMeta {
    OpMeta {
        id: OpId::next(),
        correlation: CorrelationId::new(),
        owner: Owner::Manual,
        source: Source::Ui,
        kind,
        started_at: 1_000,
        deadline: Some(121_000),
        status: OpStatus::Running,
        category: None,
    }
}

fn ended(op: &OpMeta, status: OpStatus, category: Option<ErrorKind>) -> OpMeta {
    OpMeta {
        status,
        category,
        ..op.clone()
    }
}

/// Terminal status the lane derived from a failure category.
fn failure_status(kind: ErrorKind) -> OpStatus {
    if kind == ErrorKind::Cancelled {
        OpStatus::Cancelled
    } else {
        OpStatus::Error
    }
}

fn receipt() -> StopReceipt {
    StopReceipt {
        operation_id: format!("stop_{}", "0".repeat(32)),
        ok: true,
        runtime_stopped: true,
        forced: false,
        protection_released: Some(true),
        baseline_restored: Some(true),
        adapter_gone: true,
        warnings: Vec::new(),
    }
}

impl H {
    fn new() -> Self {
        Self {
            fsm: Fsm::new(),
            os: Evidence::default(),
            unreadable: false,
        }
    }

    fn e(&self) -> Option<Evidence> {
        (!self.unreadable).then_some(self.os)
    }

    fn snap(&self) -> TunnelSnapshot {
        self.fsm.snapshot().clone()
    }

    fn native_up(&mut self, pid: u32) {
        self.os.running = true;
        self.os.pid = Some(pid);
    }

    fn native_down(&mut self) {
        self.os.running = false;
        self.os.pid = None;
    }

    /// The lane's cleanup effect: nothing of ours is left.
    fn cleanup(&mut self) {
        self.os = Evidence::default();
    }

    fn runtime(&mut self, status: TunStatusKind) -> Result<(), Invalid> {
        let e = self.e();
        self.fsm.runtime(&status, e)
    }

    fn begin(&mut self, kind: OpKind) -> OpMeta {
        let op = op(kind);
        let e = self.e();
        self.fsm
            .op_changed(&op, e)
            .expect("running record accepted");
        op
    }

    fn end(
        &mut self,
        op: &OpMeta,
        status: OpStatus,
        kind: Option<ErrorKind>,
    ) -> Result<(), Invalid> {
        let e = self.e();
        self.fsm.op_changed(&ended(op, status, kind), e)
    }

    /// Old `lane.start(effect)`: confirmation needs evidence; a missing confirmation compensates
    /// (cleanup) and fails as internal; a thrown failure invalidates a kept read-back first.
    fn start(&mut self, effect: impl FnOnce(&mut Self, &OpMeta) -> Effect) -> bool {
        let op = self.begin(OpKind::Connect);
        let (status, kind) = match effect(self, &op) {
            Effect::Ok if self.fsm.can_confirm_start(self.e()) => (OpStatus::Success, None),
            Effect::Ok => {
                self.cleanup();
                (OpStatus::Error, Some(ErrorKind::Internal))
            }
            Effect::Fail(kind) => (failure_status(kind), Some(kind)),
        };
        self.end(&op, status, kind)
            .expect("terminal record accepted");
        status == OpStatus::Success
    }

    /// Old `h.connect()`: our TUN comes up with PID 123 and reports `running`.
    fn connect(&mut self) -> bool {
        self.start(|h, _| {
            h.native_up(PID);
            h.runtime(TunStatusKind::Running).expect("running accepted");
            Effect::Ok
        })
    }

    /// Soft (NOADMIN.md §2): our engine comes up behind its loopback proxy, then the tweaks
    /// point at it.
    fn connect_soft(&mut self) -> bool {
        self.start(|h, _| {
            h.native_up(PID);
            h.os.proxy_capture = true;
            h.runtime(TunStatusKind::Running).expect("running accepted");
            h.os.soft_applied = true;
            Effect::Ok
        })
    }

    /// Old `lane.stop(cleanup)`; `clean = false` is a stop effect that leaves the runtime alive.
    fn stop_with(&mut self, clean: bool) -> bool {
        let op = self.begin(OpKind::Disconnect);
        if clean {
            self.cleanup();
        }
        let confirmed = self.fsm.can_confirm_stop(self.e());
        let (status, kind) = if confirmed {
            (OpStatus::Success, None)
        } else {
            (OpStatus::Error, Some(ErrorKind::Internal))
        };
        self.end(&op, status, kind)
            .expect("terminal record accepted");
        confirmed
    }

    fn stop(&mut self) -> bool {
        self.stop_with(true)
    }
}

/// AT-00-002/008: a retained TUN is published only after upstream verification (both values).
#[test]
fn upstream_switch_publishes_retained_tun_only_when_verified() {
    for verified in [true, false] {
        let mut h = H::new();
        assert!(h.connect());
        h.fsm.native_start_began(1).unwrap();
        h.fsm.upstream_began(1, h.e()).unwrap();
        let s = h.snap();
        assert_eq!(s.state, TunnelState::Connected);
        assert_eq!(s.transition, Some(Transition::Reconnecting));
        assert_eq!((s.pid, s.process_state), (Some(PID), ProcessState::Running));
        h.fsm.upstream_finished(1, verified, h.e()).unwrap();
        let s = h.snap();
        let expected = if verified {
            TunnelState::Connected
        } else {
            TunnelState::Unknown
        };
        assert_eq!(s.state, expected);
        assert_eq!(s.transition, None);
        assert_eq!(s.pid, Some(PID));
        assert_eq!(s.mode, verified.then_some(TunnelMode::Tun));
        assert!(s.cleanup_required);
        assert_eq!(h.fsm.upstream_finished(1, true, h.e()), Err(Invalid));
    }
}

/// AT-00-002: upstream proof is rejected when the retained TUN changed (pid, startedAt, dead, soft).
#[test]
fn upstream_proof_rejected_when_retained_tun_changes() {
    let changes: [fn(&mut H); 4] = [
        |h| h.os.pid = Some(456),
        |h| h.os.started_at = Some(1234),
        |h| h.native_down(),
        |h| h.os.soft_applied = true,
    ];
    for change in changes {
        let mut h = H::new();
        assert!(h.connect());
        h.fsm.upstream_began(1, h.e()).unwrap();
        change(&mut h);
        h.fsm.upstream_finished(1, true, h.e()).unwrap();
        let s = h.snap();
        assert_eq!((s.state, s.transition), (TunnelState::Unknown, None));
        assert!(s.cleanup_required);
    }
}

/// AT-00-003: a late upstream receipt is fenced after a stop, a newer native start, a fault or
/// a lane operation superseded it; the snapshot does not change.
#[test]
fn late_upstream_receipt_is_fenced() {
    let supersede: [fn(&mut H); 4] = [
        |h| assert_eq!(h.runtime(TunStatusKind::Stopping), Err(Invalid)),
        |h| h.fsm.native_start_began(2).unwrap(),
        |h| {
            let e = h.e();
            h.fsm.fault(FaultState::Blocked, e);
        },
        |h| assert!(h.stop()),
    ];
    for step in supersede {
        let mut h = H::new();
        assert!(h.connect());
        h.fsm.native_start_began(1).unwrap();
        h.fsm.upstream_began(1, h.e()).unwrap();
        step(&mut h);
        let before = h.snap();
        assert_eq!(h.fsm.upstream_finished(1, true, h.e()), Err(Invalid));
        assert_eq!(h.snap(), before);
    }
}

/// AT-00-003 / AT-02-003: `adapting` and `restarting:1/3` hand the tunnel to native recovery;
/// the late upstream receipt cannot clear that, the native finish confirms on evidence.
#[test]
fn adapting_and_restarting_hand_over_to_native_recovery() {
    for status in [
        TunStatusKind::Adapting,
        TunStatusKind::Restarting { attempt: 1, max: 3 },
    ] {
        let mut h = H::new();
        assert!(h.connect());
        h.fsm.native_start_began(1).unwrap();
        h.fsm.upstream_began(1, h.e()).unwrap();
        h.native_down();
        h.runtime(status).unwrap();
        let reconnecting = h.snap();
        assert_eq!(reconnecting.transition, Some(Transition::Reconnecting));
        assert_eq!(reconnecting.process_state, ProcessState::Stopped);
        assert_eq!(h.fsm.upstream_finished(1, false, h.e()), Err(Invalid));
        assert_eq!(h.snap(), reconnecting);
        h.fsm.native_start_began(2).unwrap();
        h.native_up(456);
        h.fsm.native_start_finished(2, true, h.e()).unwrap();
        let s = h.snap();
        assert_eq!((s.state, s.transition), (TunnelState::Connected, None));
        assert_eq!((s.mode, s.pid), (Some(TunnelMode::Tun), Some(456)));
        assert_eq!(s.proxy_status, ProxyStatus::Running);
    }
}

/// fixauto-a1: restarts whose starts failed leave `Error`; the failover's sibling run that
/// follows (no restart announced) is still accepted and confirmed on its own evidence. Inside
/// an operation, or for another generation, it is not.
#[test]
fn a_failover_run_confirms_after_failed_restarts() {
    let mut h = H::new();
    assert!(h.connect());
    for generation in 1..=3 {
        h.native_down();
        h.runtime(TunStatusKind::Restarting { attempt: 1, max: 3 })
            .unwrap();
        h.fsm.native_start_began(generation).unwrap();
        h.fsm
            .native_start_finished(generation, false, h.e())
            .unwrap();
        assert_eq!(h.snap().state, TunnelState::Error);
    }
    h.fsm.native_start_began(4).unwrap();
    h.native_up(456);
    assert_eq!(h.fsm.native_failover(3, h.e()), Err(Invalid), "stale run");
    h.fsm.native_failover(4, h.e()).unwrap();
    h.fsm.native_start_finished(4, true, h.e()).unwrap();
    let s = h.snap();
    assert_eq!((s.state, s.transition), (TunnelState::Connected, None));
    assert_eq!((s.mode, s.pid), (Some(TunnelMode::Tun), Some(456)));

    let op = h.begin(OpKind::Rotation);
    h.fsm.native_start_began(5).unwrap();
    assert_eq!(
        h.fsm.native_failover(5, h.e()),
        Err(Invalid),
        "the operation decides"
    );
    assert_eq!(h.fsm.native_start_finished(5, true, h.e()), Err(Invalid));
    h.end(&op, OpStatus::Success, None).unwrap();
    assert_eq!(h.snap().state, TunnelState::Connected);
}

/// AT-00-007 / AT-02-011: an explicit stop wins over native recovery and both older receipts.
#[test]
fn explicit_stop_wins_over_native_recovery() {
    for status in [
        TunStatusKind::Adapting,
        TunStatusKind::Restarting { attempt: 1, max: 3 },
    ] {
        let mut h = H::new();
        assert!(h.connect());
        h.fsm.native_start_began(1).unwrap();
        h.fsm.upstream_began(1, h.e()).unwrap();
        h.native_down();
        h.runtime(status).unwrap();
        h.fsm.native_start_began(2).unwrap();
        assert!(h.stop());
        let stopped = h.snap();
        assert_eq!(
            (stopped.state, stopped.transition),
            (TunnelState::Disconnected, None)
        );
        assert_eq!((stopped.mode, stopped.pid), (None, None));
        assert_eq!(h.fsm.upstream_finished(1, true, h.e()), Err(Invalid));
        assert_eq!(h.fsm.native_start_finished(2, true, h.e()), Err(Invalid));
        assert_eq!(h.snap(), stopped);
    }
}

/// AT-00-003: stale and concurrent upstream generations are rejected; native generations are
/// an independent counter.
#[test]
fn stale_and_concurrent_upstream_generations_are_rejected() {
    let mut h = H::new();
    assert_eq!(h.fsm.upstream_began(1, h.e()), Err(Invalid));
    assert!(h.connect());
    h.fsm.native_start_began(1).unwrap();
    h.fsm.upstream_began(1, h.e()).unwrap();
    let before = h.snap();
    assert_eq!(h.fsm.upstream_began(2, h.e()), Err(Invalid));
    assert_eq!(h.fsm.upstream_finished(0, true, h.e()), Err(Invalid));
    assert_eq!(h.snap(), before);
    h.fsm.upstream_finished(1, true, h.e()).unwrap();
    assert_eq!(h.fsm.upstream_began(1, h.e()), Err(Invalid));
    assert_eq!(h.fsm.native_start_began(2), Ok(()));
}

/// AT-00-002/003/008: after a crash only a complete receipt of the current native generation's
/// full stop returns the machine to "disconnected" (the old `{baseline, firewall, adapters}`
/// triple is now `ok`, `runtime_stopped`, `protection_released`, `baseline_restored`).
#[test]
fn native_stop_receipt_must_be_complete_and_current() {
    let mut h = H::new();
    assert!(h.connect());
    h.fsm.native_start_began(1).unwrap();
    h.native_down();
    h.runtime(TunStatusKind::Adapting).unwrap();
    h.fsm.native_start_began(2).unwrap();
    h.fsm.native_start_finished(2, false, h.e()).unwrap();
    h.runtime(TunStatusKind::Stopped).unwrap();
    assert_eq!(h.snap().state, TunnelState::Unknown);
    let partial: [fn(&mut StopReceipt); 6] = [
        |r| r.ok = false,
        |r| r.runtime_stopped = false,
        |r| r.protection_released = Some(false),
        |r| r.baseline_restored = Some(false),
        // A receipt without the cleanup steps (old: no `networkCleanup`).
        |r| r.protection_released = None,
        |r| r.baseline_restored = None,
    ];
    for spoil in partial {
        let mut r = receipt();
        spoil(&mut r);
        assert_eq!(
            h.fsm.native_stop_finished(2, false, &r, h.e()),
            Err(Invalid)
        );
        assert_eq!(h.snap().state, TunnelState::Unknown);
    }
    assert_eq!(
        h.fsm.native_stop_finished(1, false, &receipt(), h.e()),
        Err(Invalid)
    );
    assert_eq!(
        h.fsm.native_stop_finished(2, true, &receipt(), h.e()),
        Err(Invalid)
    );
    assert_eq!(h.snap().state, TunnelState::Unknown);
    h.fsm
        .native_stop_finished(2, false, &receipt(), h.e())
        .unwrap();
    let s = h.snap();
    assert_eq!(
        (s.state, s.transition, s.mode),
        (TunnelState::Disconnected, None, None)
    );
    assert!(!s.cleanup_required);
    assert!(h.connect());
    assert_eq!(h.snap().state, TunnelState::Connected);
}

/// AT-00-003: native stop receipts cannot overtake an active connection owner or a live runtime.
#[test]
fn native_stop_receipt_cannot_overtake_owner_or_live_runtime() {
    let mut h = H::new();
    h.fsm.native_start_began(1).unwrap();
    assert!(h.start(|h, _| {
        let before = h.snap();
        assert_eq!(
            h.fsm.native_stop_finished(1, false, &receipt(), h.e()),
            Err(Invalid)
        );
        assert_eq!(h.snap(), before);
        h.native_up(PID);
        Effect::Ok
    }));
    assert_eq!(
        h.fsm.native_stop_finished(1, false, &receipt(), h.e()),
        Err(Invalid)
    );
    assert_eq!(h.snap().state, TunnelState::Connected);
}

/// AT-00-002 (NOADMIN.md §2, replaces the old "Soft = tweaks alone" vectors): Soft is confirmed
/// only on both proofs, the engine behind its loopback proxy and the applied tweaks.
#[test]
fn soft_needs_the_engine_and_the_tweaks() {
    type Setup = fn(&mut H);
    let half_proofs: [Setup; 3] = [
        // The tweaks alone (the old Soft): no engine carries the traffic.
        |h| h.os.soft_applied = true,
        // The engine alone: nothing points programs at it.
        |h| {
            h.native_up(PID);
            h.os.proxy_capture = true;
        },
        // Tweaks plus an engine without a real process id.
        |h| {
            h.native_up(0);
            h.os.soft_applied = true;
            h.os.proxy_capture = true;
        },
    ];
    for setup in half_proofs {
        let mut h = H::new();
        assert!(!h.start(|h, _| {
            setup(h);
            Effect::Ok
        }));
        assert_eq!(h.snap().state, TunnelState::Error);
    }
    let mut h = H::new();
    assert!(h.connect_soft());
    let s = h.snap();
    assert_eq!(
        (s.state, s.mode, s.proxy_status),
        (
            TunnelState::Connected,
            Some(TunnelMode::Soft),
            ProxyStatus::Running
        )
    );
    assert_eq!((s.process_state, s.pid), (ProcessState::Running, Some(PID)));
}

/// New (the old Soft refresh is gone): a connect while connected is refused in either mode,
/// and no connect may keep a previous session.
#[test]
fn connect_while_connected_is_refused_in_soft_too() {
    let mut h = H::new();
    assert!(h.connect_soft());
    assert!(!h.fsm.can_start());
    let before = h.snap();
    let last = before.operation.clone().expect("connect recorded").id;
    assert_eq!(h.fsm.keep_previous(last, h.e()), Err(Invalid));
    assert_eq!(h.snap(), before);
}

/// AT-00-002/008: a failed Soft start (refused strict, `Permission`, apply failure: every
/// category) never reads as connected, and a stop that cleans up returns to "disconnected".
#[test]
fn failed_soft_start_is_an_error() {
    for kind in [
        ErrorKind::Validation,
        ErrorKind::Permission,
        ErrorKind::Network,
        ErrorKind::Internal,
    ] {
        let mut h = H::new();
        assert!(!h.start(|h, _| {
            h.native_up(PID);
            h.os.proxy_capture = true;
            Effect::Fail(kind)
        }));
        let s = h.snap();
        assert_eq!((s.state, s.mode), (TunnelState::Error, None));
        assert_eq!(s.operation.and_then(|op| op.category), Some(kind));
        assert!(h.stop());
        assert_eq!(h.snap().state, TunnelState::Disconnected);
    }
}

/// AT-00-002: a connected Soft session loses its proof when the tweaks vanish or the engine
/// ends outside an operation; the state fails closed to unknown with cleanup owed.
#[test]
fn soft_proof_is_lost_with_the_tweaks_or_the_engine() {
    for lose_tweaks in [true, false] {
        let mut h = H::new();
        assert!(h.connect_soft());
        if lose_tweaks {
            h.os.soft_applied = false;
            h.runtime(TunStatusKind::Running).unwrap();
        } else {
            h.native_down();
            h.runtime(TunStatusKind::Stopped).unwrap();
        }
        let s = h.snap();
        assert_eq!((s.state, s.mode), (TunnelState::Unknown, None));
        assert!(s.cleanup_required);
        assert!(h.stop());
        assert_eq!(h.snap().state, TunnelState::Disconnected);
    }
}

/// AT-00-002/003 in Soft: an in-place upstream switch and a native reconnect confirm Soft again
/// only with both proofs; a switch that lost the tweaks is not confirmed.
#[test]
fn soft_switch_and_native_reconnect_keep_the_mode() {
    let mut h = H::new();
    assert!(h.connect_soft());
    h.fsm.upstream_began(1, h.e()).unwrap();
    h.fsm.upstream_finished(1, true, h.e()).unwrap();
    assert_eq!(h.snap().mode, Some(TunnelMode::Soft));
    assert_eq!(h.snap().state, TunnelState::Connected);

    h.native_down();
    h.runtime(TunStatusKind::Restarting { attempt: 1, max: 3 })
        .unwrap();
    h.fsm.native_start_began(1).unwrap();
    h.native_up(456);
    h.fsm.native_start_finished(1, true, h.e()).unwrap();
    let s = h.snap();
    assert_eq!(
        (s.state, s.mode, s.pid),
        (TunnelState::Connected, Some(TunnelMode::Soft), Some(456))
    );

    h.fsm.upstream_began(2, h.e()).unwrap();
    h.os.soft_applied = false;
    h.fsm.upstream_finished(2, true, h.e()).unwrap();
    assert_eq!(h.snap().state, TunnelState::Unknown);
}

/// ks-a (research 5.3 "VPN dropped by itself", "If the VPN drops"): a paused session stays
/// blocked and reconnecting through failed attempts, and the first native start that succeeds
/// confirms it again on its own evidence, in both modes; a lane operation is refused nothing.
#[test]
fn a_paused_session_reconnects_after_failed_attempts() {
    for soft in [false, true] {
        let mut h = H::new();
        assert!(if soft { h.connect_soft() } else { h.connect() });
        h.native_down();
        h.fsm.paused(h.e()).unwrap();
        let s = h.snap();
        let paused = (TunnelState::Blocked, Some(Transition::Reconnecting));
        assert_eq!((s.state, s.transition), paused);
        for generation in 1..=2 {
            h.fsm.native_start_began(generation).unwrap();
            h.fsm
                .native_start_finished(generation, false, h.e())
                .unwrap();
            h.fsm.paused(h.e()).unwrap();
        }
        h.fsm.native_start_began(3).unwrap();
        h.native_up(789);
        h.fsm.native_start_finished(3, true, h.e()).unwrap();
        let s = h.snap();
        assert_eq!(
            (s.state, s.pid),
            (TunnelState::Connected, Some(789)),
            "soft: {soft}"
        );
        h.native_down();
        h.fsm.paused(h.e()).unwrap();
        assert!(h.stop(), "«Продолжить без VPN» ends the pause");
        assert_eq!(h.snap().state, TunnelState::Disconnected);
    }
}

/// AT-00-002: a running native process is not "connected" until every effect of the start
/// finished and the lane confirmed it.
#[test]
fn native_running_is_not_connected_until_the_start_finishes() {
    let mut h = H::new();
    assert!(h.start(|h, _| {
        h.native_up(PID);
        h.runtime(TunStatusKind::Running).unwrap();
        let s = h.snap();
        assert_eq!(s.state, TunnelState::Disconnected);
        assert_eq!(s.transition, Some(Transition::Connecting));
        assert_eq!(s.process_state, ProcessState::Running);
        Effect::Ok
    }));
    let s = h.snap();
    assert_eq!((s.state, s.transition), (TunnelState::Connected, None));
    assert_eq!((s.health, s.pid), (Some(Health::Ok), Some(PID)));
}

/// Watchdog `running` and `competing-tun-cleared` never erase error / blocked / unknown.
#[test]
fn watchdog_and_competing_events_do_not_erase_faults() {
    for fault in [FaultState::Error, FaultState::Blocked, FaultState::Unknown] {
        let mut h = H::new();
        assert!(h.connect());
        let e = h.e();
        h.fsm.fault(fault, e);
        h.runtime(TunStatusKind::Running).unwrap();
        h.runtime(TunStatusKind::CompetingTunCleared).unwrap();
        assert_eq!(h.snap().state, TunnelState::from(fault));
        assert_eq!(h.snap().health, None);
    }
}

/// A fault is cleared only by a successful owned recovery (a confirmed stop).
#[test]
fn owned_recovery_clears_a_fault() {
    let mut h = H::new();
    assert!(h.connect());
    let e = h.e();
    h.fsm.fault(FaultState::Blocked, e);
    assert!(h.stop());
    assert_eq!(h.snap().state, TunnelState::Disconnected);
    assert!(h.connect());
    assert_eq!(h.snap().state, TunnelState::Connected);
}

/// A second connect over a native tunnel is not admitted (the lane asks these predicates
/// before any effect); asking does not change the snapshot.
#[test]
fn second_connect_over_native_is_not_admitted() {
    let mut h = H::new();
    assert!(h.connect());
    let before = h.snap();
    assert!(!h.fsm.can_start());
    assert!(!h.fsm.can_confirm_stop(h.e()));
    assert_eq!(h.snap(), before);
    // Only a disconnect may pre-empt a running operation.
    let stop = h.begin(OpKind::Disconnect);
    assert_eq!(h.fsm.op_changed(&op(OpKind::Connect), h.e()), Err(Invalid));
    assert_eq!(h.fsm.op_changed(&op(OpKind::Rotation), h.e()), Err(Invalid));
    h.cleanup();
    h.end(&stop, OpStatus::Success, None).unwrap();
    assert_eq!(h.snap().state, TunnelState::Disconnected);
}

/// A "successful" start or stop without evidence is published as an error, never as
/// protection or a clean exit.
#[test]
fn unconfirmed_start_and_stop_end_in_error() {
    let mut h = H::new();
    assert!(!h.start(|_, _| Effect::Ok));
    assert_eq!(h.snap().state, TunnelState::Error);
    assert!(h.connect());
    assert!(!h.stop_with(false));
    assert_eq!(h.snap().state, TunnelState::Error);
}

/// Lab live-7 F1: a start that failed on the network and left nothing of ours behind ends
/// disconnected (the start page offers «Подключить» at once, the failure stays on the
/// operation); one that left anything running stays an error to clean up.
#[test]
fn a_clean_network_failure_leaves_a_way_forward() {
    let mut h = H::new();
    assert!(!h.start(|_, _| Effect::Fail(ErrorKind::Network)));
    let s = h.snap();
    assert_eq!(
        (s.state, s.cleanup_required),
        (TunnelState::Disconnected, false)
    );
    assert_eq!(
        s.operation.and_then(|op| op.category),
        Some(ErrorKind::Network)
    );
    let mut h = H::new();
    assert!(!h.start(|h, _| {
        h.native_up(PID);
        Effect::Fail(ErrorKind::Network)
    }));
    assert_eq!(h.snap().state, TunnelState::Error);
}

/// `degraded` exists only inside connected; proxy failure stays separate from process liveness.
#[test]
fn degraded_only_inside_connected() {
    let mut h = H::new();
    assert!(h.connect());
    h.runtime(TunStatusKind::ProxyDown {
        reason: vpnte_base::Msg::new("tunnel.test.proxyDown"),
    })
    .unwrap();
    let s = h.snap();
    assert_eq!(
        (s.state, s.health),
        (TunnelState::Connected, Some(Health::Degraded))
    );
    assert_eq!(
        (s.proxy_status, s.process_state),
        (ProxyStatus::ProxyDown, ProcessState::Running)
    );
    h.runtime(TunStatusKind::CompetingTun {
        name: "wg0 (10.0.0.2)".into(),
    })
    .unwrap();
    assert_eq!(h.snap().competing_tun.as_deref(), Some("wg0 (10.0.0.2)"));
    let e = h.e();
    h.fsm.fault(FaultState::Unknown, e);
    assert_eq!(h.snap().health, None);
}

/// A raw `running` event does not confirm a native restart; the start receipt does.
#[test]
fn raw_running_event_does_not_confirm_a_restart() {
    let mut h = H::new();
    assert!(h.connect());
    h.runtime(TunStatusKind::Adapting).unwrap();
    h.fsm.native_start_began(1).unwrap();
    h.runtime(TunStatusKind::Running).unwrap();
    assert_eq!(h.snap().transition, Some(Transition::Reconnecting));
    h.fsm.native_start_finished(1, true, h.e()).unwrap();
    let s = h.snap();
    assert_eq!((s.state, s.transition), (TunnelState::Connected, None));
}

/// A late native receipt after a manual stop is ignored; rejections never mutate the snapshot.
#[test]
fn late_native_receipt_after_manual_stop_is_ignored() {
    let mut h = H::new();
    assert!(h.connect());
    h.runtime(TunStatusKind::Adapting).unwrap();
    h.fsm.native_start_began(1).unwrap();
    assert!(h.stop());
    let before = h.snap();
    assert_eq!(h.fsm.native_start_finished(1, true, h.e()), Err(Invalid));
    assert_eq!(h.snap(), before);
    let conflict: vpnte_base::AppError = Invalid.into();
    assert_eq!(conflict.kind, ErrorKind::Conflict);
}

/// Soft (NOADMIN.md §2) runs our engine: it shows its PID, and a stop must end the engine and
/// the tweaks before "disconnected".
#[test]
fn soft_shows_the_engine_and_stops_both() {
    let mut h = H::new();
    assert!(h.connect_soft());
    let s = h.snap();
    assert_eq!(
        (s.state, s.mode),
        (TunnelState::Connected, Some(TunnelMode::Soft))
    );
    assert_eq!((s.process_state, s.pid), (ProcessState::Running, Some(PID)));
    assert!(!h.stop_with(false));
    assert!(h.stop());
    assert_eq!(h.snap().state, TunnelState::Disconnected);
}

/// The receipt of an older native start is rejected once a newer restart owns confirmation.
#[test]
fn old_native_receipt_is_rejected_after_a_newer_restart() {
    let mut h = H::new();
    assert!(h.connect());
    h.runtime(TunStatusKind::Adapting).unwrap();
    h.fsm.native_start_began(1).unwrap();
    h.fsm.native_start_began(2).unwrap();
    let before = h.snap();
    assert_eq!(h.fsm.native_start_finished(1, true, h.e()), Err(Invalid));
    assert_eq!(h.snap(), before);
    assert_eq!(h.fsm.native_start_finished(2, true, h.e()), Ok(()));
    assert_eq!(h.snap().transition, None);
    assert_eq!(h.fsm.native_start_began(2), Err(Invalid));
}

/// AT-00-002: unreadable evidence fails closed: the start is not confirmed, the machine ends
/// `unknown` with cleanup owed and no transition, and a stop cannot be confirmed either.
#[test]
fn unreadable_evidence_fails_closed() {
    let mut h = H::new();
    h.unreadable = true;
    assert!(!h.start(|_, _| Effect::Ok));
    let s = h.snap();
    assert_eq!((s.state, s.transition), (TunnelState::Unknown, None));
    assert!(s.cleanup_required);
    assert!(!h.stop());
    assert_eq!(h.snap().transition, None);
}

/// A live unowned process never reads as disconnected; lost evidence never reads as connected.
#[test]
fn live_unowned_process_is_not_disconnected() {
    let mut h = H::new();
    h.native_up(PID);
    h.runtime(TunStatusKind::Running).unwrap();
    let s = h.snap();
    assert_eq!(s.state, TunnelState::Unknown);
    assert!(s.cleanup_required);
    assert!(h.stop());
    assert!(h.connect());
    h.native_down();
    h.runtime(TunStatusKind::CompetingTunCleared).unwrap();
    let s = h.snap();
    assert_eq!((s.state, s.health), (TunnelState::Unknown, None));
    assert!(s.cleanup_required);
}

/// A start whose process came up without a PID is not confirmed: the lane compensates once and
/// the machine ends in `error` with no transition.
#[test]
fn unconfirmed_start_is_compensated() {
    let mut h = H::new();
    let mut cleanups = 0;
    let op = h.begin(OpKind::Connect);
    h.os.running = true;
    if !h.fsm.can_confirm_start(h.e()) {
        h.cleanup();
        cleanups += 1;
    }
    h.end(&op, OpStatus::Error, Some(ErrorKind::Internal))
        .unwrap();
    assert_eq!(cleanups, 1);
    assert_eq!(h.os, Evidence::default());
    let s = h.snap();
    assert_eq!((s.state, s.transition), (TunnelState::Error, None));
}

/// A transient evidence failure during a start is retained until an owned recovery, even when
/// the evidence becomes readable again (this lane has no cleanup effect).
#[test]
fn transient_evidence_failure_is_retained_until_recovery() {
    let mut h = H::new();
    let op = h.begin(OpKind::Connect);
    h.unreadable = true;
    h.runtime(TunStatusKind::Running).unwrap();
    h.unreadable = false;
    h.native_up(PID);
    assert!(!h.fsm.can_confirm_start(h.e()));
    h.end(&op, OpStatus::Error, Some(ErrorKind::Internal))
        .unwrap();
    let s = h.snap();
    assert_eq!((s.state, s.transition), (TunnelState::Unknown, None));
}

/// Partial AT-00-002: every connect / stop / crash / connect tour of depth six against a fake
/// PID/TUN ledger. Statuses that are always rejected leave the snapshot untouched.
#[test]
fn tour_walk_depth_six() {
    for tour in 0..4u32.pow(6) {
        let mut h = H::new();
        let mut tun = false;
        let mut expected = TunnelState::Disconnected;
        let mut encoded = tour;
        for _ in 0..6 {
            match encoded % 4 {
                0 | 3 => {
                    if expected == TunnelState::Connected {
                        // The lane refuses before publishing anything.
                        assert!(!h.fsm.can_start());
                    } else {
                        assert!(h.fsm.can_start());
                        assert!(h.start(|h, _| {
                            assert_eq!(h.os.pid, None);
                            h.native_up(PID);
                            tun = true;
                            h.runtime(TunStatusKind::Running).unwrap();
                            Effect::Ok
                        }));
                        expected = TunnelState::Connected;
                    }
                }
                1 => {
                    tun = false;
                    assert!(h.stop());
                    expected = TunnelState::Disconnected;
                }
                _ => {
                    h.native_down();
                    tun = false;
                    h.runtime(TunStatusKind::Error {
                        warning: vpnte_base::Msg::new("tunnel.test.crash"),
                    })
                    .unwrap();
                    expected = TunnelState::Error;
                }
            }
            encoded /= 4;
            let s = h.snap();
            assert_eq!(s.state, expected, "tour {tour}");
            assert_eq!(s.transition, None);
            assert_eq!(tun, h.os.pid.is_some());
            for invalid in [
                TunStatusKind::Stopping,
                TunStatusKind::PostTrialFailover { name: "n".into() },
            ] {
                let before = h.snap();
                assert_eq!(h.runtime(invalid), Err(Invalid));
                assert_eq!(h.snap(), before);
            }
        }
    }
}

/// AT-00-007 (state-machine part): 200 seeded start / stop commands in batches of ten, issued
/// the way the lane serialises them (a start waits once, a stop pre-empts a waiting start whose
/// late terminal record is then stale). Old seed `0x5eed003`, drawn with the LCG of the lane
/// vectors (fast-check's generator is not portable). After every batch: no transition,
/// `tun == pid.is_some()`, `connected == running`; failures are only conflict / cancelled.
#[test]
fn seeded_command_batches_keep_the_invariants() {
    let mut seed: u32 = 0x5eed003;
    let mut commands: Vec<u32> = (0..200)
        .map(|_| {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (seed >> 16) % 3
        })
        .collect();
    assert!((0..3).all(|c| commands.contains(&c)));
    commands[199] = 1; // the final command is an accepted disconnect
    let mut h = H::new();
    let (mut next_pid, mut tun) = (100u32, false);
    let mut pending: Option<OpMeta> = None;
    let mut failures: Vec<ErrorKind> = Vec::new();
    let mut accepted_running = 0usize;
    for batch in commands.chunks(10) {
        for &command in batch {
            if command == 0 {
                if pending.is_some() || !h.fsm.can_start() {
                    failures.push(ErrorKind::Conflict);
                    continue;
                }
                let start = h.begin(OpKind::Connect);
                accepted_running += 1;
                assert_eq!(h.os.pid, None);
                next_pid += 1;
                h.native_up(next_pid);
                tun = true;
                pending = Some(start);
            } else {
                let stop = h.begin(OpKind::Disconnect);
                accepted_running += 1;
                if let Some(start) = pending.take() {
                    // The aborted start compensates, its cancelled terminal is stale.
                    h.cleanup();
                    let stale = h.end(&start, OpStatus::Cancelled, Some(ErrorKind::Cancelled));
                    assert_eq!(stale, Err(Invalid));
                    failures.push(ErrorKind::Cancelled);
                }
                h.cleanup();
                tun = false;
                assert!(h.fsm.can_confirm_stop(h.e()));
                h.end(&stop, OpStatus::Success, None).unwrap();
            }
        }
        if let Some(start) = pending.take() {
            assert!(h.fsm.can_confirm_start(h.e()));
            h.end(&start, OpStatus::Success, None).unwrap();
        }
        let s = h.snap();
        assert_eq!(s.transition, None);
        assert_eq!(tun, s.pid.is_some());
        assert_eq!(s.state == TunnelState::Connected, h.os.running);
    }
    assert!(accepted_running > 0);
    assert!(
        failures
            .iter()
            .all(|k| matches!(k, ErrorKind::Conflict | ErrorKind::Cancelled))
    );
    let s = h.snap();
    assert_eq!(
        (s.state, s.pid, s.transition),
        (TunnelState::Disconnected, None, None)
    );
    assert!(!tun);
}

/// New: a rotation is admitted only without a transition in connected / disconnected and is
/// confirmed only on evidence of the mode it started from.
#[test]
fn rotation_is_confirmed_only_on_evidence() {
    // Native rotation: the new run must be our TUN again.
    let mut h = H::new();
    assert!(h.connect());
    assert!(h.fsm.can_rotate());
    let rotation = h.begin(OpKind::Rotation);
    assert!(!h.fsm.can_rotate());
    assert_eq!(h.snap().transition, Some(Transition::Reconnecting));
    h.native_up(456);
    h.end(&rotation, OpStatus::Success, None).unwrap();
    let s = h.snap();
    assert_eq!(
        (s.state, s.mode, s.pid),
        (TunnelState::Connected, Some(TunnelMode::Tun), Some(456))
    );

    // Success claimed, but the new run is a Soft one: not the mode the rotation started from.
    let rotation = h.begin(OpKind::Rotation);
    h.os.proxy_capture = true;
    h.os.soft_applied = true;
    h.end(&rotation, OpStatus::Success, None).unwrap();
    assert_eq!(h.snap().state, TunnelState::Unknown);
    assert!(!h.fsm.can_rotate());

    // Rotation while disconnected only re-selects: success needs nothing of ours running.
    for leftover in [false, true] {
        let mut h = H::new();
        let rotation = h.begin(OpKind::Rotation);
        if leftover {
            h.native_up(PID);
        }
        h.end(&rotation, OpStatus::Success, None).unwrap();
        let expected = if leftover {
            TunnelState::Unknown
        } else {
            TunnelState::Disconnected
        };
        assert_eq!(h.snap().state, expected);
    }
}

/// New: a failed or cancelled rotation keeps the previous protection only when the evidence is
/// exactly the one the rotation started from (same process, same start time).
#[test]
fn failed_rotation_keeps_previous_only_when_unchanged() {
    for status in [OpStatus::Error, OpStatus::Cancelled] {
        let mut h = H::new();
        h.os.started_at = Some(5_000);
        assert!(h.connect());
        let rotation = h.begin(OpKind::Rotation);
        h.fsm.keep_previous(rotation.id, h.e()).unwrap();
        h.end(&rotation, status, Some(ErrorKind::Network)).unwrap();
        let s = h.snap();
        assert_eq!(
            (s.state, s.mode, s.transition),
            (TunnelState::Connected, Some(TunnelMode::Tun), None)
        );
        assert_eq!(s.started_at, Some(5_000));
        assert!(s.cleanup_required);
    }
    // The process changed before the read-back: refused.
    let mut h = H::new();
    assert!(h.connect());
    let rotation = h.begin(OpKind::Rotation);
    h.os.pid = Some(456);
    assert_eq!(h.fsm.keep_previous(rotation.id, h.e()), Err(Invalid));
    h.end(&rotation, OpStatus::Error, Some(ErrorKind::Network))
        .unwrap();
    assert_eq!(h.snap().state, TunnelState::Error);
    // The process changed after the read-back: the terminal re-checks and refuses.
    let mut h = H::new();
    assert!(h.connect());
    let rotation = h.begin(OpKind::Rotation);
    h.fsm.keep_previous(rotation.id, h.e()).unwrap();
    h.os.started_at = Some(9_000);
    h.end(&rotation, OpStatus::Error, Some(ErrorKind::Network))
        .unwrap();
    assert_eq!(h.snap().state, TunnelState::Error);
}

/// New: feature operations are not lane operations; the snapshot does not move.
#[test]
fn feature_operations_are_rejected() {
    let mut h = H::new();
    let before = h.snap();
    for kind in [OpKind::Refresh, OpKind::LeakCheck, OpKind::Snapshot] {
        assert_eq!(h.fsm.op_changed(&op(kind), h.e()), Err(Invalid));
    }
    assert_eq!(h.snap(), before);
}

/// New (lifecycle-app §6.5): a machine seeded in a fault (the lifecycle's start-up recovery
/// calls `fault(Unknown)` before any operation) owes cleanup until an owned stop.
#[test]
fn faulted_seed_owes_cleanup_until_an_owned_stop() {
    let mut h = H::new();
    let e = h.e();
    h.fsm.fault(FaultState::Unknown, e);
    let s = h.snap();
    assert_eq!(
        (s.state, s.transition, s.revision),
        (TunnelState::Unknown, None, 1)
    );
    assert!(s.cleanup_required);
    assert!(h.fsm.can_start());
    assert!(!h.fsm.can_rotate());
    h.native_up(PID); // an engine left over from the previous process
    assert!(h.stop());
    let s = h.snap();
    assert_eq!(s.state, TunnelState::Disconnected);
    assert!(!s.cleanup_required);
}

/// AT-00-008: the published snapshot keeps the old wire shape the UI and tray consume.
#[test]
fn snapshot_keeps_the_old_wire_shape() {
    let initial = serde_json::to_value(TunnelSnapshot::default()).unwrap();
    let expected = serde_json::json!({
        "version": 1, "revision": 0, "state": "disconnected", "transition": null,
        "health": null, "mode": null, "processState": "stopped", "proxyStatus": "stopped",
        "pid": null, "startedAt": null, "competingTun": null, "cleanupRequired": false,
        "operation": null
    });
    assert_eq!(initial, expected);
    let mut h = H::new();
    h.os.started_at = Some(1_700_000_000_000);
    assert!(h.connect());
    h.runtime(TunStatusKind::ProxyDown {
        reason: vpnte_base::Msg::new("tunnel.test.proxyDown"),
    })
    .unwrap();
    let json = serde_json::to_value(h.snap()).unwrap();
    assert_eq!(json["state"], "connected");
    assert_eq!(json["health"], "degraded");
    assert_eq!(json["mode"], "tun");
    assert_eq!(json["proxyStatus"], "proxy-down");
    assert_eq!(json["processState"], "running");
    assert_eq!(json["pid"], PID);
    assert_eq!(json["startedAt"], 1_700_000_000_000i64);
    assert_eq!(json["operation"]["kind"], "connect");
    assert_eq!(json["operation"]["status"], "success");
    let back: TunnelSnapshot = serde_json::from_value(json).unwrap();
    assert_eq!(&back, h.fsm.snapshot());
}

/// Evidence comes from the runtime status plus the Soft module's read-back.
#[test]
fn evidence_from_runtime_status() {
    let status = TunStatus {
        running: true,
        pid: Some(PID),
        started_at: Some(42),
        ..TunStatus::default()
    };
    let e = Evidence::from_status(&status, false);
    assert_eq!(
        e,
        Evidence {
            running: true,
            pid: Some(PID),
            soft_applied: false,
            started_at: Some(42),
            proxy_capture: false,
        }
    );
    assert!(e.tun_ready() && !e.soft_ready());
    assert!(!Evidence { pid: Some(0), ..e }.native_ready());
    // Soft: the engine of a proxy-capture session plus the tweaks; the tweaks alone prove nothing.
    let soft = TunStatus {
        capture: Some(CaptureKind::Proxy),
        ..status
    };
    let e = Evidence::from_status(&soft, true);
    assert!(e.proxy_capture && e.soft_ready() && !e.tun_ready());
    assert!(!Evidence::from_status(&soft, false).soft_ready());
    assert!(!Evidence::from_status(&TunStatus::default(), true).soft_ready());
}
