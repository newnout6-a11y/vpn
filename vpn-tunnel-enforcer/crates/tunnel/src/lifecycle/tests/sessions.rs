//! Session tracking and history rows (lifecycle-app §7.11, rows tagged AT-00-005 / AT-00-010).
use std::time::Duration;

use vpnte_base::ErrorKind;
use vpnte_base::types::{KillSwitchLevel, Owner, ProxyKind};
use vpnte_core::ops::{CorrelationId, Source};

use super::fakes::{Gate, Harness, SOFT_PORT, eventually, soft_addr};
use super::{local, soft, soft_vpn, user_stop};
use crate::api::{CaptureKind, Mode};
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
        // The name names the upstream; the mode («Прокси») is the row's own field.
        assert_eq!(row.profile_name, "Proxy 127.0.0.1:8080");
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

/// NOADMIN.md §2: a Soft connect starts the engine with the proxy capture for either upstream
/// kind and points the tweaks (HTTP) at the session's mixed port; a server keeps its own id.
#[tokio::test]
async fn soft_runs_the_engine_and_points_the_tweaks_at_it() {
    let h = Harness::new();
    h.profiles.add("srv-a", "Server A", true);
    h.lc.connect(soft_vpn(None, Owner::Manual))
        .await
        .expect("soft over a server");
    let req = h.rt.script.lock().requests.last().cloned().expect("start");
    assert_eq!(req.capture, CaptureKind::Proxy);
    let applied = h.soft.state.lock().applied.clone();
    assert_eq!(applied, Some((soft_addr(SOFT_PORT), ProxyKind::Http)));
    let live = h.lc.session().borrow().clone().expect("session");
    assert_eq!(live.mode, SessionMode::Soft);
    assert_eq!(live.profile_id, "srv-a");
    assert_eq!(
        live.server_id(),
        Some("srv-a"),
        "a server session over the proxy"
    );
    assert!(live.generation.is_some(), "a Soft session is an engine run");
    // Proxy mode never claims that all traffic goes through the VPN.
    let titles = h.notifier.titles();
    assert!(titles.contains(&"tunnel.lifecycle.notice.softConnected.title".to_owned()));
    assert!(!titles.contains(&"tunnel.lifecycle.notice.connected.title".to_owned()));
    h.lc.disconnect(user_stop()).await.unwrap();
    assert_eq!(h.soft.state.lock().applied, None);
    let rows = h.rows();
    let route = rows[0].provenance.as_ref().map(|p| p.route);
    assert_eq!(
        (rows[0].mode, route),
        (SessionMode::Soft, Some(Route::SoftEnv))
    );
    assert_eq!(rows[0].profile_id, "srv-a");

    h.lc.connect(soft(10808, ProxyKind::Socks5, Owner::Manual))
        .await
        .expect("soft over a local proxy");
    let req = h.rt.script.lock().requests.last().cloned().expect("start");
    assert_eq!(req.capture, CaptureKind::Proxy);
    assert!(matches!(req.mode, Mode::LocalProxy { .. }));
    let live = h.lc.session().borrow().clone().expect("session");
    assert_eq!(live.profile_id, "local-proxy-soft-socks5");
    assert_eq!(
        live.server_id(),
        None,
        "a local proxy is not a server of the list"
    );
}

/// p-follow (ks-b follow-up): a restart on the same port keeps tweaks that still point at it
/// without a write, and leaves a system proxy another program took meanwhile alone (the start
/// page's «Вернуть» lets the user decide); the session goes on either way.
#[tokio::test]
async fn a_restart_leaves_a_taken_system_proxy_alone() {
    let h = Harness::new();
    h.lc.connect(soft(10808, ProxyKind::Socks5, Owner::Manual))
        .await
        .expect("soft session");
    let restart = || {
        h.lc.restart_with_last("settings changed: stealth", Owner::Manual, Source::Ui)
    };
    restart().await.expect("restart");
    h.settle().await;
    let ours = Some((soft_addr(SOFT_PORT), ProxyKind::Http));
    assert_eq!(h.soft.state.lock().applied, ours, "still ours");
    assert_eq!(h.soft.state.lock().applies, 1, "kept without a write");
    let taken = Some(("10.9.8.7:3128".to_owned(), ProxyKind::Http));
    h.soft.state.lock().applied = taken.clone();
    h.soft.state.lock().foreign = true;
    restart().await.expect("restart");
    h.settle().await;
    assert_eq!(h.rt.script.lock().restarts, 2);
    assert_eq!(h.soft.state.lock().applied, taken, "left to the user");
    assert_eq!(
        h.soft.state.lock().applies,
        1,
        "never written back by a restart"
    );
    assert_eq!(h.snap().state, TunnelState::Connected);
}

/// fix-follow (pfollow-a3): a read-back that only says "not ours" is no proof that another
/// program took the system proxy (the read may have failed): a same-port restart writes it
/// again and reads it back, and when that fails it fails closed instead of reading connected.
#[tokio::test]
async fn a_restart_takes_no_unproven_proxy_for_taken() {
    let h = Harness::new();
    h.lc.connect(soft(10808, ProxyKind::Socks5, Owner::Manual))
        .await
        .expect("soft session");
    let restart = || {
        h.lc.restart_with_last("settings changed: stealth", Owner::Manual, Source::Ui)
    };
    let ours = Some((soft_addr(SOFT_PORT), ProxyKind::Http));
    let unproven = Some(("10.9.8.7:3128".to_owned(), ProxyKind::Http));
    h.soft.state.lock().applied = unproven.clone();
    restart().await.expect("restart");
    h.settle().await;
    assert_eq!(h.soft.state.lock().applied, ours, "written again");
    assert_eq!(h.soft.state.lock().applies, 2);
    assert_eq!(h.snap().state, TunnelState::Connected);

    h.soft.state.lock().applied = unproven;
    h.soft.state.lock().apply_failures = 1;
    assert!(restart().await.is_err(), "not confirmed without its proof");
    h.settle().await;
    assert_eq!(h.soft.state.lock().applies, 3);
    assert_ne!(h.snap().state, TunnelState::Connected);
}

/// NOADMIN.md §2: disconnect rolls the tweaks back before the engine stops.
#[tokio::test]
async fn soft_disconnect_rolls_back_before_the_engine_stops() {
    let h = Harness::new();
    h.lc.connect(soft(10808, ProxyKind::Socks5, Owner::Manual))
        .await
        .unwrap();
    let gate = Gate::new();
    h.rt.script.lock().stop_gate = Some(gate.clone());
    let lc = h.lc.clone();
    let stop = tokio::spawn(async move { lc.disconnect(user_stop()).await });
    eventually("runtime stop called", || h.rt.script.lock().stops == 1).await;
    assert_eq!(h.soft.state.lock().applied, None, "tweaks first");
    assert!(h.rt.running(), "the engine still runs");
    gate.open();
    stop.await.unwrap().expect("stop");
    assert!(!h.rt.running());
    assert_eq!(h.snap().state, TunnelState::Disconnected);
}

/// New (the old Soft refresh is gone): a connect while connected in Soft is refused as in Hard
/// mode; the session stays one.
#[tokio::test]
async fn soft_connect_while_connected_is_refused() {
    let h = Harness::new();
    h.lc.connect(soft(10808, ProxyKind::Socks5, Owner::Manual))
        .await
        .unwrap();
    let err =
        h.lc.connect(soft(9090, ProxyKind::Http, Owner::Manual))
            .await
            .unwrap_err();
    assert_eq!(
        err.user_msg().key,
        "tunnel.lifecycle.lane.stateRefusesStart"
    );
    assert_eq!(h.rt.script.lock().starts, 1);
    h.lc.disconnect(user_stop()).await.unwrap();
    assert_eq!(kinds(&h.rows()), [OutcomeKind::UserStop]);
}

/// NOADMIN.md §2: a failed apply (or read-back) leaves no tweak behind and stops the engine this
/// start ran; the failure gets its own row.
#[tokio::test]
async fn failed_tweaks_leave_nothing_behind() {
    for unread in [false, true] {
        let h = Harness::new();
        {
            let mut s = h.soft.state.lock();
            s.apply_failures = u32::from(!unread);
            s.failure_clears = true;
            s.read_back_fails = unread;
        }
        let err =
            h.lc.connect(soft(10808, ProxyKind::Socks5, Owner::Manual))
                .await
                .unwrap_err();
        let kind = if unread {
            ErrorKind::Internal
        } else {
            ErrorKind::Permission
        };
        assert_eq!(err.kind(), kind);
        eventually("cleanup", || {
            !h.rt.running() && h.soft.state.lock().applied.is_none() && !h.lc.busy()
        })
        .await;
        assert_eq!(kinds(&h.rows()), [OutcomeKind::StartFailed]);
        assert_ne!(h.snap().state, TunnelState::Connected);
    }
}

/// ks-a (owner decision 12.11.2026): "Always" is not offered in proxy mode; a stored `strict`
/// connects there as "If the VPN drops" instead of being refused.
#[tokio::test]
async fn strict_works_as_on_drop_in_soft() {
    let h = Harness::new();
    h.settings
        .update(|s| s.kill_switch = KillSwitchLevel::Strict)
        .unwrap();
    h.lc.connect(soft(10808, ProxyKind::Socks5, Owner::Manual))
        .await
        .expect("connect");
    let req = h.rt.script.lock().requests.last().cloned().expect("start");
    assert_eq!(req.kill_switch, KillSwitchLevel::Standard);
    assert_eq!(h.snap().state, TunnelState::Connected);
}

/// NOADMIN.md §2 with ks-a: a Soft engine the runtime lets go (kill switch `off`) ends the
/// session and rolls the tweaks back at once with one notice; with "If the VPN drops" the
/// runtime holds and so does the session: the tweaks stay on the port (paused), no row, until
/// the disconnect rolls them back.
#[tokio::test]
async fn soft_engine_loss_follows_the_kill_switch() {
    for level in [KillSwitchLevel::Off, KillSwitchLevel::Standard] {
        let h = Harness::new();
        h.settings.update(|s| s.kill_switch = level).unwrap();
        h.lc.connect(soft(10808, ProxyKind::Socks5, Owner::Manual))
            .await
            .unwrap();
        let titles = || h.notifier.titles();
        let noticed = |name: &str| {
            let title = format!("tunnel.lifecycle.notice.{name}.title");
            titles().contains(&title)
        };
        if level == KillSwitchLevel::Off {
            h.rt.crash(1);
            eventually("session ended", || h.rows().len() == 1).await;
            h.settle().await;
            assert_eq!(h.soft.state.lock().applied, None);
            assert!(noticed("softRestored"), "{:?}", titles());
            assert!(!noticed("stopped"), "one notice: {:?}", titles());
            assert_eq!(h.snap().state, TunnelState::Unknown);
            assert_eq!(h.rows()[0].mode, SessionMode::Soft);
        } else {
            h.rt.crash_held(Duration::from_secs(60));
            h.settle().await;
            let tweaks = Some((soft_addr(SOFT_PORT), ProxyKind::Http));
            assert_eq!(h.soft.state.lock().applied, tweaks);
            assert_eq!(h.snap().state, TunnelState::Blocked);
            assert!(h.lc.kill_switch().borrow().pause.is_some());
            assert!(h.rows().is_empty(), "the paused session stays open");
            h.lc.disconnect(user_stop()).await.expect("stop");
            assert_eq!(h.soft.state.lock().applied, None);
            assert_eq!(h.snap().state, TunnelState::Disconnected);
            assert_eq!(kinds(&h.rows()), [OutcomeKind::UserStop]);
        }
    }
}

/// NOADMIN §2 with the RU freeze window: kill switch `off` → a crash restart that must wait
/// longer than the plain backoff rolls the tweaks back at once (programs connect directly) and
/// points them at the run again when it is back; a short backoff or "If the VPN drops" (its
/// pause) keeps them. The session continues either way; nothing is told within 10 s.
#[tokio::test]
async fn long_restart_wait_pauses_the_soft_tweaks_with_the_kill_switch_off() {
    for (level, wait, paused) in [
        (KillSwitchLevel::Off, Duration::from_secs(130), true),
        (KillSwitchLevel::Off, Duration::from_secs(10), false),
        (KillSwitchLevel::Standard, Duration::from_secs(130), false),
    ] {
        let h = Harness::new();
        h.settings.update(|s| s.kill_switch = level).unwrap();
        h.profiles.add("srv-a", "Server A", true);
        h.lc.connect(soft_vpn(None, Owner::Manual)).await.unwrap();
        let tweaks = Some((soft_addr(SOFT_PORT), ProxyKind::Http));
        h.rt.crash_with_restart_in(wait);
        h.settle().await;
        let during = h.soft.state.lock().applied.clone();
        assert_eq!(during.is_none(), paused, "{level:?} {wait:?}");
        let held = h.lc.kill_switch().borrow().pause.is_some();
        assert_eq!(held, level == KillSwitchLevel::Standard, "{level:?}");
        h.rt.come_back();
        h.settle().await;
        assert_eq!(h.soft.state.lock().applied, tweaks, "{level:?} {wait:?}");
        assert_eq!(h.snap().state, TunnelState::Connected, "{level:?} {wait:?}");
        assert!(h.lc.kill_switch().borrow().pause.is_none());
        let told = |n: &str| {
            let title = format!("tunnel.lifecycle.notice.{n}.title");
            h.notifier.titles().contains(&title)
        };
        assert!(!told("reconnecting") && !told("paused") && !told("restored"));
        assert!(h.rows().is_empty(), "the session continues");
        assert_eq!(
            h.lc.session().borrow().as_ref().map(|s| s.owner),
            Some(Owner::Manual)
        );
    }
}

/// A paused session whose tweaks cannot be pointed at the new run is not called connected: the
/// proxy is rolled back again (nothing half-set) and the user is told.
#[tokio::test]
async fn failed_soft_resume_is_not_connected() {
    let h = Harness::new();
    h.settings
        .update(|s| s.kill_switch = KillSwitchLevel::Off)
        .unwrap();
    h.lc.connect(soft(10808, ProxyKind::Socks5, Owner::Manual))
        .await
        .unwrap();
    h.rt.crash_with_restart_in(Duration::from_secs(130));
    h.settle().await;
    h.soft.state.lock().read_back_fails = true;
    h.rt.come_back();
    h.settle().await;
    assert_eq!(h.soft.state.lock().applied, None);
    assert_ne!(h.snap().state, TunnelState::Connected);
    let failed = "tunnel.lifecycle.notice.softResumeFailed.title".to_owned();
    assert!(h.notifier.titles().contains(&failed));
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

/// AT-00-005: a cancelled Soft start stays out of history; the compensating stop rolls the
/// tweaks it applied back once and ends its engine.
#[tokio::test]
async fn cancelled_soft_start_stays_out_of_history() {
    let h = Harness::new();
    let gate = Gate::new();
    h.soft.state.lock().apply_gate = Some(gate.clone());
    let lc = h.lc.clone();
    let start =
        tokio::spawn(async move { lc.connect(soft(9090, ProxyKind::Http, Owner::Manual)).await });
    eventually("apply in flight", || {
        h.soft.state.lock().apply_gate.is_none()
    })
    .await;
    let lc = h.lc.clone();
    let stop = tokio::spawn(async move { lc.disconnect(user_stop()).await });
    assert_eq!(
        start.await.unwrap().unwrap_err().kind(),
        ErrorKind::Cancelled
    );
    gate.open();
    stop.await.unwrap().expect("stop");
    assert_eq!(h.soft.state.lock().rollbacks, 1);
    assert_eq!(h.soft.state.lock().applied, None);
    assert!(!h.rt.running());
    assert!(h.rows().is_empty());
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
            // Only the Soft session's engine ever started; it still runs.
            assert_eq!(h.rt.script.lock().starts, 1, "the tunnel never started");
            assert!(h.rt.running());
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

/// The same rebuild in Proxy mode (review): the running capture decides the mode, so the row
/// is a Soft row (route soft-env), never a Direct one.
#[tokio::test]
async fn runtime_rebuilt_soft_session_stays_soft() {
    use crate::api::TunnelEvent;
    let h = Harness::new();
    h.profiles.add("srv-nl", "nl-1", true);
    h.lc.connect(soft_vpn(None, Owner::Manual)).await.unwrap();
    h.rt.emit(TunnelEvent::ProtectedRestart {
        reason: "server switch".into(),
    });
    h.settle().await;
    h.rt.auto_restart();
    h.settle().await;
    let live = h.lc.session().borrow().clone().expect("rebuilt session");
    assert_eq!(
        (live.profile_id.as_str(), live.mode),
        ("srv-nl", SessionMode::Soft)
    );
    h.lc.disconnect(user_stop()).await.unwrap();
    let rows = h.rows();
    let route = rows[1].provenance.as_ref().map(|p| p.route);
    assert_eq!(
        (rows[1].mode, route),
        (SessionMode::Soft, Some(Route::SoftEnv))
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
    // ks-a: a held block (`KillSwitchActive`) no longer ends the session: it pauses it
    // (`killswitch::ks_row_3_*`), so no "killswitch" row comes from the lane.
    let cases: [(&str, OutcomeKind); 5] = [
        ("crash", OutcomeKind::SingboxCrash),
        ("sleep", OutcomeKind::SystemSleep),
        ("network", OutcomeKind::NetworkLost),
        ("fault", OutcomeKind::ServerDown),
        ("proxy", OutcomeKind::ProxyUnreachable),
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
        h.rt.crash(3);
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
    let Ok(SessionEvent::Ended {
        session,
        outcome,
        continues,
    }) = events.recv().await
    else {
        panic!("expected Ended");
    };
    assert_eq!(
        (session.owner, outcome, continues),
        (Owner::Schedule, OutcomeKind::UserStop, false)
    );
}

/// Review speed2-a4: the live session names the identity of the key it dialled (a key check
/// credits the session only while the row still holds that key); a stop clears it and a local
/// proxy has none.
#[tokio::test]
async fn the_session_names_the_key_it_dialled() {
    let h = Harness::new();
    h.profiles.add("srv-de", "de-1", true);
    h.lc.connect(super::direct(None, Owner::Manual))
        .await
        .expect("connect");
    h.settle().await;
    let dialled = super::fakes::server("srv-de", "de-1")
        .server
        .profile
        .identity();
    assert_eq!(h.lc.session_key(), Some(dialled));
    h.lc.disconnect(user_stop()).await.expect("stop");
    h.settle().await;
    assert_eq!(h.lc.session_key(), None);
    h.lc.connect(local(Owner::Manual))
        .await
        .expect("local proxy");
    h.settle().await;
    assert_eq!(h.lc.session_key(), None);
}

/// speed3 S3-12: the Soft tweaks stay before «Подключено»: the connect answers only after the
/// system read the proxy address back (the timing lines measure this path, nothing moves out
/// of it).
#[tokio::test]
async fn a_soft_connect_answers_only_after_the_read_back() {
    let h = Harness::new();
    let gate = Gate::new();
    h.soft.state.lock().read_back_gate = Some(gate.clone());
    let lc = h.lc.clone();
    let start =
        tokio::spawn(async move { lc.connect(soft(9090, ProxyKind::Http, Owner::Manual)).await });
    eventually("read-back in flight", || {
        h.soft.state.lock().read_back_gate.is_none()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!start.is_finished(), "answered before the read-back");
    assert_eq!(h.soft.state.lock().applies, 1, "applied first");
    gate.open();
    start.await.unwrap().expect("connected");
}
