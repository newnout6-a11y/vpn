//! Session tracking and history rows (lifecycle-app §7.11, rows tagged AT-00-005 / AT-00-010).
use vpnte_base::ErrorKind;
use vpnte_base::types::{Owner, ProxyKind};
use vpnte_core::ops::{CorrelationId, OpStatus, Source};

use super::fakes::{Gate, Harness, eventually};
use super::{local, soft, user_stop};
use crate::fsm::{FaultState, TunnelMode, TunnelState};
use crate::history::{Entry, Route, SessionMode};
use crate::lifecycle::ConnectReq;
use crate::outcome::{Confidence, OutcomeKind};

fn kind(row: &Entry) -> OutcomeKind {
    row.outcome.as_ref().expect("outcome").kind
}

fn kinds(rows: &[Entry]) -> Vec<OutcomeKind> {
    rows.iter().map(kind).collect()
}

fn with_id(mut req: ConnectReq) -> (ConnectReq, CorrelationId) {
    let id = CorrelationId::new();
    req.correlation = Some(id.clone());
    (req, id)
}

/// AT-00-005: an owned Soft session (app window or tray) writes nothing while it lives and
/// exactly one row at the stop: Soft, no bytes, user-stop, provenance of the CONNECT action.
#[tokio::test]
async fn owned_soft_session_writes_one_row_at_stop() {
    for source in [Source::Ui, Source::Tray] {
        let h = Harness::new();
        *h.services.bytes.lock() = (10, 20);
        let (mut req, id) = with_id(soft(8080, ProxyKind::Http, Owner::Manual));
        req.source = source;
        h.lc.connect(req).await.expect("soft connect");
        assert_eq!(h.snap().mode, Some(TunnelMode::Soft));
        assert!(h.rows().is_empty());
        h.lc.disconnect(user_stop()).await.expect("stop");
        let rows = h.rows();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.mode, SessionMode::Soft);
        assert_eq!((row.bytes_down, row.bytes_up), (0, 0));
        assert_eq!(kind(row), OutcomeKind::UserStop);
        assert_eq!(row.correlation_id.as_ref(), Some(&id));
        assert_eq!(row.profile_id, "local-proxy-soft-http");
        let p = row.provenance.as_ref().expect("provenance");
        assert_eq!(
            (p.source, p.owner, p.route, p.confidence),
            (
                source,
                Some(Owner::Manual),
                Route::SoftEnv,
                Confidence::Observed
            )
        );
    }
}

/// AT-00-005: runtime stop / node-switch events never end a Soft session.
#[tokio::test]
async fn runtime_events_do_not_end_a_soft_session() {
    use crate::api::{TunStatusKind, TunnelEvent};
    let h = Harness::new();
    h.lc.connect(soft(8080, ProxyKind::Http, Owner::Manual))
        .await
        .unwrap();
    h.rt.emit(TunnelEvent::Status(TunStatusKind::Stopped));
    h.rt.emit(TunnelEvent::ProtectedRestart {
        reason: "server switch".into(),
    });
    h.settle().await;
    assert!(h.rows().is_empty());
    h.lc.disconnect(user_stop()).await.unwrap();
    assert_eq!(kinds(&h.rows()), [OutcomeKind::UserStop]);
}

/// AT-00-005: identical Soft refreshes stay one session; an address or protocol change splits.
#[tokio::test]
async fn soft_refreshes_split_on_address_or_protocol() {
    let h = Harness::new();
    let mut ids = Vec::new();
    for (port, kind) in [
        (8080, ProxyKind::Http),
        (8080, ProxyKind::Http),
        (8080, ProxyKind::Socks5),
        (10808, ProxyKind::Socks5),
    ] {
        let (req, id) = with_id(soft(port, kind, Owner::Manual));
        h.lc.connect(req).await.expect("refresh");
        ids.push(id);
    }
    h.lc.disconnect(user_stop()).await.unwrap();
    let rows = h.rows();
    assert_eq!(
        kinds(&rows),
        [
            OutcomeKind::ServerSwitch,
            OutcomeKind::ServerSwitch,
            OutcomeKind::UserStop
        ]
    );
    let row_ids: Vec<_> = rows.iter().map(|r| r.correlation_id.clone()).collect();
    assert_eq!(
        row_ids,
        [
            Some(ids[0].clone()),
            Some(ids[2].clone()),
            Some(ids[3].clone())
        ]
    );
}

/// AT-00-005: a failed refresh whose previous proxy is read back unchanged keeps the session;
/// the failure gets its own row under its own id.
#[tokio::test]
async fn failed_refresh_keeps_the_previous_soft_session() {
    let h = Harness::new();
    let (first, first_id) = with_id(soft(8080, ProxyKind::Http, Owner::Manual));
    h.lc.connect(first).await.unwrap();
    h.soft.state.lock().apply_failures = 1;
    let (refresh, failure_id) = with_id(soft(9090, ProxyKind::Http, Owner::Manual));
    let err = h.lc.connect(refresh).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Permission);
    let snap = h.snap();
    assert_eq!(
        (snap.state, snap.mode, snap.transition),
        (TunnelState::Connected, Some(TunnelMode::Soft), None)
    );
    assert_eq!(snap.operation.map(|o| o.status), Some(OpStatus::Error));
    h.lc.disconnect(user_stop()).await.unwrap();
    let rows = h.rows();
    assert_eq!(
        kinds(&rows),
        [OutcomeKind::StartFailed, OutcomeKind::UserStop]
    );
    assert_eq!(rows[0].correlation_id.as_ref(), Some(&failure_id));
    assert_eq!(rows[1].correlation_id.as_ref(), Some(&first_id));
}

/// AT-00-005: a failed refresh that cannot prove the previous proxy (changed, or unreadable)
/// ends that session as unknown, then records the failure; the state is unknown and a later
/// stop adds nothing.
#[tokio::test]
async fn failed_refresh_with_lost_settings_ends_the_session() {
    for clobber in [true, false] {
        let h = Harness::new();
        h.lc.connect(soft(8080, ProxyKind::Http, Owner::Manual))
            .await
            .unwrap();
        {
            let mut s = h.soft.state.lock();
            s.apply_failures = 1;
            s.failure_clears = clobber;
            s.read_back_fails = !clobber;
        }
        h.lc.connect(soft(9090, ProxyKind::Http, Owner::Manual))
            .await
            .unwrap_err();
        let rows = h.rows();
        assert_eq!(
            kinds(&rows),
            [OutcomeKind::Unknown, OutcomeKind::StartFailed]
        );
        assert_eq!(rows[0].mode, SessionMode::Soft);
        let p = rows[0].provenance.as_ref().unwrap();
        assert_eq!(p.confidence, Confidence::Indeterminate);
        let headline = &rows[0].outcome.as_ref().unwrap().headline;
        assert_eq!(
            headline.key,
            "tunnel.lifecycle.outcome.softRetainUnconfirmed"
        );
        let snap = h.snap();
        assert_eq!((snap.state, snap.transition), (TunnelState::Unknown, None));
        assert!(snap.cleanup_required);
        h.lc.disconnect(user_stop()).await.unwrap();
        assert_eq!(h.rows().len(), 2, "the stop adds nothing");
    }
}

/// AT-00-003 / AT-00-005: a stop during the refresh's endpoint read-back cancels it; nothing
/// late is written and the stop records exactly one user-stop of the original session.
#[tokio::test]
async fn cancellation_during_endpoint_read_back() {
    let h = Harness::new();
    let (first, first_id) = with_id(soft(8080, ProxyKind::Http, Owner::Manual));
    h.lc.connect(first).await.unwrap();
    let gate = Gate::new();
    {
        let mut s = h.soft.state.lock();
        s.apply_failures = 1;
        s.read_back_gate = Some(gate.clone());
    }
    let lc = h.lc.clone();
    let refresh =
        tokio::spawn(async move { lc.connect(soft(9090, ProxyKind::Http, Owner::Manual)).await });
    eventually("failed apply", || h.soft.state.lock().applies == 2).await;
    let lc = h.lc.clone();
    let stop = tokio::spawn(async move { lc.disconnect(user_stop()).await });
    assert_eq!(
        refresh.await.unwrap().unwrap_err().kind(),
        ErrorKind::Cancelled
    );
    gate.open();
    stop.await.unwrap().expect("stop");
    let rows = h.rows();
    assert_eq!(kinds(&rows), [OutcomeKind::UserStop]);
    assert_eq!(rows[0].correlation_id.as_ref(), Some(&first_id));
}

/// AT-00-005: a Soft session is recorded only once the user's proxy settings are back.
#[tokio::test]
async fn soft_session_waits_for_the_rollback() {
    let h = Harness::new();
    h.lc.connect(soft(8080, ProxyKind::Http, Owner::Manual))
        .await
        .unwrap();
    h.soft.state.lock().rollback_failures = 1;
    let err = h.lc.disconnect(user_stop()).await.unwrap_err();
    assert_eq!(
        err.user_msg().key,
        "tunnel.lifecycle.soft.envRollbackFailed"
    );
    assert!(h.rows().is_empty());
    h.lc.disconnect(user_stop()).await.expect("retry");
    assert_eq!(kinds(&h.rows()), [OutcomeKind::UserStop]);
}

/// AT-00-005: cancelled Soft starts stay out of history; the rollback runs once; a refreshed
/// session is closed by the stop under its first operation's id.
#[tokio::test]
async fn cancelled_soft_starts_stay_out_of_history() {
    for retained in [false, true] {
        let h = Harness::new();
        let mut first_id = None;
        if retained {
            let (first, id) = with_id(soft(8080, ProxyKind::Http, Owner::Manual));
            h.lc.connect(first).await.unwrap();
            first_id = Some(id);
        }
        let gate = Gate::new();
        h.soft.state.lock().apply_gate = Some(gate.clone());
        let lc = h.lc.clone();
        let start =
            tokio::spawn(
                async move { lc.connect(soft(9090, ProxyKind::Http, Owner::Manual)).await },
            );
        eventually("start in flight", || h.lc.busy()).await;
        let lc = h.lc.clone();
        let stop = tokio::spawn(async move { lc.disconnect(user_stop()).await });
        assert_eq!(
            start.await.unwrap().unwrap_err().kind(),
            ErrorKind::Cancelled
        );
        gate.open();
        stop.await.unwrap().expect("stop");
        assert_eq!(h.soft.state.lock().rollbacks, 1);
        let rows = h.rows();
        if retained {
            assert_eq!(kinds(&rows), [OutcomeKind::UserStop]);
            assert_eq!(rows[0].correlation_id, first_id);
        } else {
            assert!(rows.is_empty());
        }
    }
}

/// AT-00-005 + L-05 / L-15: a TUN start over an applied Soft proxy rolls it back first and
/// ends the Soft session as a mode switch; a refused rollback is a failed start with its own
/// row and leaves the Soft session open.
#[tokio::test]
async fn mode_switch_from_soft() {
    for rollback_ok in [true, false] {
        let h = Harness::new();
        h.lc.connect(soft(8080, ProxyKind::Http, Owner::Manual))
            .await
            .unwrap();
        h.lc.fault(FaultState::Unknown);
        h.soft.state.lock().rollback_failures = u32::from(!rollback_ok);
        let r = h.lc.connect(local(Owner::Manual)).await;
        let rows = h.rows();
        if rollback_ok {
            r.expect("tunnel start");
            assert_eq!(kinds(&rows), [OutcomeKind::ServerSwitch]);
            assert_eq!(rows[0].mode, SessionMode::Soft);
            let headline = &rows[0].outcome.as_ref().unwrap().headline;
            assert_eq!(headline.key, "tunnel.lifecycle.outcome.softModeSwitch");
            let live = h.lc.session().borrow().clone().unwrap();
            assert_eq!(live.mode, SessionMode::Hard);
        } else {
            let err = r.unwrap_err();
            assert_eq!(
                err.user_msg().key,
                "tunnel.lifecycle.soft.rollbackBeforeStart"
            );
            assert_eq!(kinds(&rows), [OutcomeKind::StartFailed]);
            assert_eq!(rows[0].profile_id, "local-proxy");
            assert_eq!(h.rt.script.lock().starts, 0, "the tunnel never started");
            let live = h.lc.session().borrow().clone().unwrap();
            assert_eq!(live.mode, SessionMode::Soft);
        }
    }
}

/// AT-00-005: a Soft session reconciled under recovery keeps that provenance.
#[tokio::test]
async fn recovery_soft_session_provenance() {
    let h = Harness::new();
    let mut req = soft(8080, ProxyKind::Http, Owner::Recovery);
    req.source = Source::Lifecycle;
    h.lc.connect(req).await.unwrap();
    h.lc.disconnect(user_stop()).await.unwrap();
    let p = h.rows()[0].provenance.unwrap();
    assert_eq!(
        (p.source, p.owner, p.route),
        (Source::Lifecycle, Some(Owner::Recovery), Route::SoftEnv)
    );
}

/// AT-00-005: provenance per source × owner (priority order) on TUN sessions.
#[tokio::test]
async fn provenance_per_source_and_owner() {
    let h = Harness::new();
    let owners = [
        Owner::AdaptiveRetry,
        Owner::Autopilot,
        Owner::Rotation,
        Owner::Schedule,
        Owner::Manual,
        Owner::Recovery,
    ];
    for source in [Source::Ui, Source::Tray, Source::Lifecycle] {
        for owner in owners {
            let mut req = local(owner);
            req.source = source;
            h.lc.connect(req).await.unwrap();
            h.lc.disconnect(user_stop()).await.unwrap();
            let rows = h.rows();
            let p = rows.last().unwrap().provenance.unwrap();
            assert_eq!(
                (p.source, p.owner, p.route, p.confidence),
                (source, Some(owner), Route::Tun, Confidence::Observed)
            );
        }
    }
    assert_eq!(h.rows().len(), 18);
}

/// AT-00-005: a session the runtime brought back by itself (after a node switch closed the old
/// one outside the lane) is rebuilt from the runtime status with runtime provenance and the
/// server-list id, never the display name (L-04).
#[tokio::test]
async fn runtime_rebuilt_session_has_runtime_provenance() {
    use crate::api::TunnelEvent;
    let h = Harness::new();
    h.profiles.add("srv-nl", "nl-1", true);
    h.lc.connect(super::direct(None, Owner::Manual))
        .await
        .unwrap();
    h.rt.emit(TunnelEvent::ProtectedRestart {
        reason: "server switch".into(),
    });
    h.settle().await;
    assert_eq!(kinds(&h.rows()), [OutcomeKind::ServerSwitch]);
    h.rt.auto_restart();
    h.settle().await;
    assert_eq!(h.snap().state, TunnelState::Connected);
    let live = h.lc.session().borrow().clone().expect("rebuilt session");
    assert_eq!(
        (live.profile_id.as_str(), live.owner),
        ("srv-nl", Owner::Recovery)
    );
    h.lc.disconnect(user_stop()).await.unwrap();
    let rows = h.rows();
    let p = rows[1].provenance.unwrap();
    assert_eq!(
        (p.source, p.owner, p.route, p.confidence),
        (Source::Runtime, None, Route::Tun, Confidence::Observed)
    );
    assert_eq!(
        (rows[1].profile_id.as_str(), rows[1].mode),
        ("srv-nl", SessionMode::Direct)
    );
}

/// AT-00-005 + L-04 / L-14: failed starts write one zero-duration row under the CONNECT id;
/// Direct rows use the server-list id; TUN bring-up failures are `tun-setup-failed`.
#[tokio::test]
async fn start_failures_write_rows() {
    use crate::api::TunError;
    use vpnte_base::Msg;
    use vpnte_base::types::OutboundFault;
    let h = Harness::new();
    let (req, none_id) = with_id(super::direct(None, Owner::Manual));
    let err = h.lc.connect(req).await.unwrap_err();
    assert_eq!(err.user_msg().key, "tunnel.lifecycle.server.none");
    let err =
        h.lc.connect(super::direct(Some("gone"), Owner::Manual))
            .await
            .unwrap_err();
    assert_eq!(err.user_msg().key, "tunnel.lifecycle.server.unavailable");
    h.profiles.add("srv-de", "de-1", true);
    {
        let mut s = h.rt.script.lock();
        s.start_error = Some(TunError::new(ErrorKind::Network, Msg::new("test.upstream")));
        s.fault = Some(OutboundFault::UpstreamUnreachable);
    }
    h.lc.connect(super::direct(None, Owner::Schedule))
        .await
        .unwrap_err();
    let wintun = Msg::new(format!("{}.wintun", crate::lifecycle::TUN_SETUP_KEY_PREFIX));
    h.rt.script.lock().start_error = Some(TunError::new(ErrorKind::Internal, wintun));
    h.lc.connect(local(Owner::Manual)).await.unwrap_err();
    let rows = h.rows();
    assert_eq!(
        kinds(&rows),
        [
            OutcomeKind::StartFailed,
            OutcomeKind::StartFailed,
            OutcomeKind::StartFailed,
            OutcomeKind::TunSetupFailed
        ]
    );
    assert_eq!(rows[0].correlation_id.as_ref(), Some(&none_id));
    assert_eq!(rows[0].profile_id, "direct-vpn");
    assert_eq!(rows[1].profile_id, "gone");
    assert_eq!(
        (rows[2].profile_id.as_str(), rows[2].profile_name.as_str()),
        ("srv-de", "de-1")
    );
    let evidence = &rows[2].outcome.as_ref().unwrap().evidence;
    assert_eq!(
        evidence.outbound_fault,
        Some(OutboundFault::UpstreamUnreachable)
    );
    assert_eq!(
        evidence.hint.as_ref().map(|m| m.key.as_ref()),
        Some("test.upstream")
    );
    for row in &rows {
        assert_eq!((row.duration_ms, row.bytes_down), (Some(0), 0));
        let p = row.provenance.as_ref().unwrap();
        assert_eq!(
            (p.route, p.confidence),
            (Route::Unconfirmed, kind(row).confidence())
        );
    }
    assert_eq!(
        rows[0].provenance.as_ref().unwrap().confidence,
        Confidence::Observed
    );
    assert_eq!(
        rows[2].provenance.as_ref().unwrap().owner,
        Some(Owner::Schedule)
    );
}

/// §3.5: an unexpected end is classified from what is known when it happens, its row written
/// once, the user told; monitoring keeps running, forensics stop.
#[tokio::test]
async fn unexpected_ends_are_classified() {
    use crate::api::{TunStatusKind, TunnelEvent};
    use crate::outcome::NetworkTransition;
    use vpnte_base::Msg;
    use vpnte_base::types::OutboundFault;
    let cases: [(&str, OutcomeKind); 6] = [
        ("crash", OutcomeKind::SingboxCrash),
        ("sleep", OutcomeKind::SystemSleep),
        ("network", OutcomeKind::NetworkLost),
        ("fault", OutcomeKind::ServerDown),
        ("proxy", OutcomeKind::ProxyUnreachable),
        ("killswitch", OutcomeKind::Killswitch),
    ];
    for (case, expected) in cases {
        let h = Harness::new();
        h.lc.connect(local(Owner::Manual)).await.unwrap();
        match case {
            "sleep" => h.lc.resumed(),
            "network" => h.lc.network_changed(NetworkTransition::AdapterRemoved),
            "fault" => h.rt.script.lock().fault = Some(OutboundFault::UpstreamUnreachable),
            "proxy" => h.rt.emit(TunnelEvent::Status(TunStatusKind::ProxyDown {
                reason: Msg::new("test.down"),
            })),
            _ => {}
        }
        // Inputs and runtime events come from different sources: let the input land first.
        h.settle().await;
        if case == "killswitch" {
            h.rt.bring_down();
            h.rt.emit(TunnelEvent::Status(TunStatusKind::KillSwitchActive));
        } else {
            h.rt.crash(3);
        }
        h.settle().await;
        let rows = h.rows();
        assert_eq!(kinds(&rows), [expected], "{case}");
        let evidence = &rows[0].outcome.as_ref().unwrap().evidence;
        if case == "crash" {
            assert_eq!(evidence.singbox_exit_code, Some(3));
        }
        if case == "network" {
            assert_eq!(
                evidence.network_transition,
                Some(NetworkTransition::AdapterRemoved)
            );
        }
        assert!(h.lc.session().borrow().is_none());
        let stopped = "tunnel.lifecycle.notice.stopped.title".to_owned();
        assert!(h.notifier.titles().contains(&stopped), "{case}");
        assert_eq!(h.services.counters.lock().monitor_stops, 0);
        eventually("forensics stopped", || {
            h.services.counters.lock().forensics_stops == 1
        })
        .await;
        h.lc.disconnect(user_stop()).await.unwrap();
        assert_eq!(h.rows().len(), 1, "{case}: the stop adds nothing");
    }
}

/// Session events: `Up` with the holder and the engine run, `Ended` with the outcome.
#[tokio::test]
async fn session_events() {
    use crate::lifecycle::SessionEvent;
    let h = Harness::new();
    let mut events = h.lc.events();
    h.lc.connect(local(Owner::Schedule)).await.unwrap();
    let Ok(SessionEvent::Up(view)) = events.recv().await else {
        panic!("expected Up");
    };
    assert_eq!(
        (view.owner, view.mode),
        (Owner::Schedule, SessionMode::Hard)
    );
    assert!(view.generation.is_some());
    h.lc.disconnect(user_stop()).await.unwrap();
    let Ok(SessionEvent::Ended { session, outcome }) = events.recv().await else {
        panic!("expected Ended");
    };
    assert_eq!(
        (session.owner, outcome),
        (Owner::Schedule, OutcomeKind::UserStop)
    );
}
