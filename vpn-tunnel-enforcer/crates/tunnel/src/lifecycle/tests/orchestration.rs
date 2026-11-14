//! Orchestration (lifecycle-app §6.4, §3.9-§3.13): what connect / stop / switch / restart do
//! around the runtime, the one `on_connected` hook (H-05), runtime-driven notices.
use vpnte_base::ErrorKind;
use vpnte_base::types::{AdaptiveMode, EnginePref, KillSwitchLevel, Owner, ProxyKind};
use vpnte_core::ops::Source;

use super::fakes::{Gate, Harness};
use super::{direct, local, soft, user_stop};
use crate::api::{Mode, Origin, SwitchOutcome, SwitchReceipt, TunStatusKind, TunnelEvent};
use crate::fsm::{TunnelMode, TunnelState};
use crate::history::{Entry, SessionMode};
use crate::lifecycle::{NoticeKind, SwitchReq};
use crate::outcome::OutcomeKind;

fn kinds(rows: &[Entry]) -> Vec<OutcomeKind> {
    rows.iter()
        .map(|r| r.outcome.as_ref().expect("outcome").kind)
        .collect()
}

fn notice(h: &Harness, name: &str) -> Option<(vpnte_base::types::Notice, NoticeKind)> {
    let title = format!("tunnel.lifecycle.notice.{name}.title");
    let notices = h.notifier.notices.lock();
    notices.iter().find(|(n, _)| n.title.key == title).cloned()
}

/// §3.9: a Direct connect runs the server from the server list with the current settings and
/// the caller's adaptive mode; the start origin follows the owner. `on_connected` starts
/// monitoring and forensics and announces the tunnel.
#[tokio::test]
async fn direct_connect_uses_settings_and_starts_services() {
    let h = Harness::new();
    h.profiles.add("srv-nl", "nl-1", true);
    h.settings
        .update(|s| {
            s.kill_switch = KillSwitchLevel::Strict;
            s.stealth_mode = true;
            s.public_wifi_compatibility = false;
            s.proxy_engine = EnginePref::Xray;
        })
        .unwrap();
    let mut req = direct(None, Owner::Schedule);
    req.adaptive = AdaptiveMode::TlsCompatibility;
    h.lc.connect(req).await.expect("connect");
    let sent = h.rt.script.lock().requests[0].clone();
    let Mode::DirectVpn { profile } = &sent.mode else {
        panic!("direct mode expected");
    };
    assert_eq!(profile.id, "srv-nl");
    assert_eq!(
        (
            sent.kill_switch,
            sent.stealth,
            sent.public_wifi,
            sent.engine,
            sent.origin
        ),
        (
            // ks-a: a stored "strict" works as "If the VPN drops" until the helper service.
            KillSwitchLevel::Standard,
            true,
            false,
            EnginePref::Xray,
            Origin::Schedule
        )
    );
    assert_eq!(sent.adaptive, AdaptiveMode::TlsCompatibility);
    let c = h.services.counters.lock();
    assert_eq!(
        (c.suppressed, c.monitor_starts, c.forensics_starts),
        (1, 1, 1)
    );
    drop(c);
    let (n, kind) = notice(&h, "connected").expect("connected notice");
    assert_eq!(kind, NoticeKind::VpnConnect);
    assert_eq!(
        n.body.unwrap().key,
        "tunnel.lifecycle.notice.connected.body"
    );
    let live = h.lc.session().borrow().clone().unwrap();
    assert_eq!(
        (live.profile_id.as_str(), live.mode),
        ("srv-nl", SessionMode::Direct)
    );
    assert_eq!(live.adaptive, AdaptiveMode::TlsCompatibility);
}

/// appsplit-b2 (p-live2): under «Только выбранные приложения» the connect notice says that
/// the selected apps go through the VPN, in both modes; under «Все приложения» it stays.
#[tokio::test]
async fn the_connect_notice_follows_the_app_scope() {
    for (scope, soft_mode, body) in [
        (
            vpnte_core::settings::AppScope::OnlyListed,
            false,
            "tunnel.lifecycle.notice.connected.bodyListed",
        ),
        (
            vpnte_core::settings::AppScope::OnlyListed,
            true,
            "tunnel.lifecycle.notice.softConnected.bodyListed",
        ),
        (
            vpnte_core::settings::AppScope::All,
            false,
            "tunnel.lifecycle.notice.connected.body",
        ),
    ] {
        let h = Harness::new();
        h.profiles.add("srv-nl", "nl-1", true);
        h.settings.update(|s| s.app_scope = scope).unwrap();
        let req = if soft_mode {
            super::soft_vpn(None, Owner::Manual)
        } else {
            direct(None, Owner::Manual)
        };
        h.lc.connect(req).await.expect("connect");
        let name = if soft_mode {
            "softConnected"
        } else {
            "connected"
        };
        let (n, _) = notice(&h, name).expect("connect notice");
        assert_eq!(n.body.unwrap().key, body);
    }
}

/// §3.10: a full stop ends forensics, external proxies and monitoring after the runtime proved
/// its exit, leaves an unapplied Soft proxy alone and tells the user.
#[tokio::test]
async fn stop_runs_every_cleanup() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    h.lc.disconnect(user_stop()).await.unwrap();
    let c = h.services.counters.lock();
    assert_eq!(
        (c.forensics_stops, c.proxies_stops, c.monitor_stops),
        (1, 1, 1)
    );
    drop(c);
    assert_eq!(h.soft.state.lock().rollbacks, 0);
    let (_, kind) = notice(&h, "disconnected").expect("disconnected notice");
    assert_eq!(kind, NoticeKind::VpnDisconnect);
}

/// Session evidence is captured before the stop (the monitor forgets the VPN IP when stopped)
/// and a leak seen during the session is kept.
#[tokio::test]
async fn stop_rows_keep_egress_and_leak_evidence() {
    let h = Harness::new();
    *h.services.egress_ip.lock() = Some("203.0.113.7".into());
    *h.services.bytes.lock() = (1_000, 2_000);
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    h.lc.leak_detected();
    h.lc.disconnect(user_stop()).await.unwrap();
    let row = h.rows().remove(0);
    assert_eq!((row.bytes_down, row.bytes_up), (1_000, 2_000));
    let evidence = row.outcome.unwrap().evidence;
    assert_eq!(evidence.egress_ip.as_deref(), Some("203.0.113.7"));
    assert_eq!(evidence.leak_detected_during_session, Some(true));
}

fn connected_on_a(h: &Harness) -> SwitchReq {
    h.profiles.add("srv-a", "a-1", true);
    h.profiles.add("srv-b", "b-1", false);
    SwitchReq::new("srv-b", Owner::Manual, Source::Ui)
}

/// AT-02-002: an in-place upstream switch keeps the engine run; the old server's session ends
/// as a server switch and the new one continues under the same holder.
#[tokio::test]
async fn in_place_switch_keeps_the_engine_run() {
    let h = Harness::new();
    let req = connected_on_a(&h);
    h.lc.connect(direct(None, Owner::Schedule)).await.unwrap();
    let before = h.lc.session().borrow().clone().unwrap();
    h.rt.script.lock().in_place = Some(SwitchReceipt {
        outcome: SwitchOutcome::Success,
        committed: true,
        ..SwitchReceipt::default()
    });
    h.lc.switch_upstream(req).await.expect("switch");
    assert_eq!(kinds(&h.rows()), [OutcomeKind::ServerSwitch]);
    let after = h.lc.session().borrow().clone().unwrap();
    assert_eq!(after.profile_id, "srv-b");
    assert_eq!(after.generation, before.generation, "same engine run");
    assert_eq!(after.owner, Owner::Schedule, "the holder is kept");
    let s = h.rt.script.lock();
    assert_eq!((s.switches, s.restarts), (1, 0));
    drop(s);
    assert_eq!(h.snap().state, TunnelState::Connected);
}

/// A rotation that cannot switch in place is a protected restart; the session ends as a
/// rotation once (the runtime's own restart event inside the operation adds nothing).
#[tokio::test]
async fn rotation_by_protected_restart() {
    let h = Harness::new();
    let mut req = connected_on_a(&h);
    req.owner = Owner::Rotation;
    h.lc.connect(direct(None, Owner::Manual)).await.unwrap();
    let before = h.lc.session().borrow().clone().unwrap();
    h.lc.rotate(req).await.expect("rotate");
    h.settle().await;
    assert_eq!(kinds(&h.rows()), [OutcomeKind::Rotation]);
    let after = h.lc.session().borrow().clone().unwrap();
    assert_eq!(
        (after.profile_id.as_str(), after.owner),
        ("srv-b", Owner::Manual)
    );
    assert_ne!(after.generation, before.generation);
    let snap = h.snap();
    assert_eq!(
        (snap.state, snap.mode, snap.transition),
        (TunnelState::Connected, Some(TunnelMode::Tun), None)
    );
    let sent = h.rt.script.lock().requests.last().cloned().unwrap();
    assert_eq!(sent.origin, Origin::Rotation);
}

/// A failed protected restart ends in a full stop: the session ends as the rotation and a
/// recovery stop releases what the old tunnel held (forensics, external proxies, monitoring),
/// then confirms the clean state.
#[tokio::test]
async fn failed_rotation_ends_the_session() {
    let h = Harness::new();
    let req = connected_on_a(&h);
    h.lc.connect(direct(None, Owner::Manual)).await.unwrap();
    h.rt.script.lock().restart_error = true;
    let err = h.lc.rotate(req).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Network);
    super::fakes::eventually("recovery stop", || !h.lc.busy()).await;
    h.settle().await;
    assert_eq!(kinds(&h.rows()), [OutcomeKind::Rotation]);
    assert!(h.lc.session().borrow().is_none());
    let c = h.services.counters.lock();
    assert_eq!(
        (c.forensics_stops, c.proxies_stops, c.monitor_stops),
        (1, 1, 1)
    );
    drop(c);
    let snap = h.snap();
    assert_eq!(
        (snap.state, snap.transition),
        (TunnelState::Disconnected, None)
    );
}

/// A restart the runtime refuses before touching the run (no last start, unreadable settings)
/// keeps the tunnel, the session and the connected state: nothing is stopped or recorded.
#[tokio::test]
async fn refused_restart_keeps_the_tunnel() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    h.rt.script.lock().restart_refusal = Some(crate::api::TunError::new(
        ErrorKind::Conflict,
        vpnte_base::Msg::new("test.noLastStart"),
    ));
    let err =
        h.lc.restart_with_last("settings changed: mtu", Owner::Manual, Source::Ui)
            .await
            .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Conflict);
    h.settle().await;
    assert!(h.rows().is_empty());
    assert!(h.lc.session().borrow().is_some());
    assert_eq!(h.rt.script.lock().stops, 0);
    assert!(h.rt.running());
    let snap = h.snap();
    assert_eq!(
        (snap.state, snap.transition),
        (TunnelState::Connected, None)
    );
}

/// A failed in-place switch that re-proved the previous upstream keeps the tunnel and the
/// session as they were (keep-previous).
#[tokio::test]
async fn preserved_upstream_keeps_the_session() {
    let h = Harness::new();
    let req = connected_on_a(&h);
    h.lc.connect(direct(None, Owner::Manual)).await.unwrap();
    h.rt.script.lock().in_place = Some(SwitchReceipt {
        previous_preserved: true,
        ..SwitchReceipt::default()
    });
    let err = h.lc.switch_upstream(req).await.unwrap_err();
    assert_eq!(err.user_msg().key, "tunnel.lifecycle.lane.switchFailed");
    h.settle().await;
    assert!(h.rows().is_empty());
    assert_eq!(h.lc.session().borrow().clone().unwrap().profile_id, "srv-a");
    let snap = h.snap();
    assert_eq!(
        (snap.state, snap.transition),
        (TunnelState::Connected, None)
    );
}

/// Nothing running: a rotation only validates the server (the caller commits the selection);
/// an unknown server is refused.
#[tokio::test]
async fn rotation_while_disconnected_is_idle() {
    let h = Harness::new();
    let req = connected_on_a(&h);
    h.lc.rotate(req).await.expect("idle rotation");
    assert_eq!(h.snap().state, TunnelState::Disconnected);
    assert_eq!(h.rt.script.lock().restarts, 0);
    let missing = SwitchReq::new("nope", Owner::Rotation, Source::Lifecycle);
    let err = h.lc.rotate(missing).await.unwrap_err();
    assert_eq!(err.user_msg().key, "tunnel.lifecycle.server.unavailable");
    assert!(h.rows().is_empty());
    assert_eq!(h.snap().state, TunnelState::Disconnected, "no error state");
}

/// §3.2 rotate: a switch refused before touching anything (unknown server or sibling) keeps the
/// running tunnel, its session and the connected state; nothing is stopped or recorded.
#[tokio::test]
async fn refused_switch_keeps_the_running_tunnel() {
    let h = Harness::new();
    connected_on_a(&h);
    h.lc.connect(direct(None, Owner::Manual)).await.unwrap();
    let missing = SwitchReq::new("nope", Owner::Manual, Source::Ui);
    let err = h.lc.switch_upstream(missing).await.unwrap_err();
    assert_eq!(err.user_msg().key, "tunnel.lifecycle.server.unavailable");
    let sibling = Some("nope".to_owned());
    let err =
        h.lc.restart_adaptive(AdaptiveMode::Baseline, sibling, Owner::AdaptiveRetry)
            .await
            .unwrap_err();
    assert_eq!(err.user_msg().key, "tunnel.lifecycle.server.unavailable");
    h.settle().await;
    let snap = h.snap();
    assert_eq!(
        (snap.state, snap.mode, snap.transition),
        (TunnelState::Connected, Some(TunnelMode::Tun), None)
    );
    assert_eq!(h.lc.session().borrow().clone().unwrap().profile_id, "srv-a");
    assert!(h.rows().is_empty());
    assert_eq!(h.rt.script.lock().stops, 0);
}

/// A-07: settings restarts go through the lane and continue the session; with nothing running
/// they succeed without touching anything.
#[tokio::test]
async fn restart_with_last_continues_the_session() {
    let h = Harness::new();
    h.lc.restart_with_last("settings changed: stealth", Owner::Manual, Source::Ui)
        .await
        .expect("no-op restart");
    assert_eq!(h.rt.script.lock().restarts, 0);
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    let before = h.lc.session().borrow().clone().unwrap();
    h.lc.restart_with_last("settings changed: stealth", Owner::Manual, Source::Ui)
        .await
        .expect("restart");
    h.settle().await;
    assert_eq!(h.rt.script.lock().restarts, 1);
    assert!(h.rows().is_empty());
    let after = h.lc.session().borrow().clone().unwrap();
    assert_eq!(after.started_at, before.started_at);
    assert_ne!(after.generation, before.generation);
    assert_eq!(h.snap().state, TunnelState::Connected);
}

/// Adaptive restarts run in the lane: same server in another mode, or a sibling server.
#[tokio::test]
async fn adaptive_restarts() {
    let h = Harness::new();
    let err =
        h.lc.restart_adaptive(AdaptiveMode::MtuCompatibility, None, Owner::AdaptiveRetry)
            .await;
    assert_eq!(
        err.unwrap_err().user_msg().key,
        "tunnel.lifecycle.lane.notRunning"
    );
    assert_eq!(h.snap().state, TunnelState::Disconnected, "no error state");
    connected_on_a(&h);
    h.lc.connect(direct(None, Owner::Manual)).await.unwrap();
    h.lc.restart_adaptive(AdaptiveMode::TlsCompatibility, None, Owner::AdaptiveRetry)
        .await
        .expect("mode restart");
    let live = h.lc.session().borrow().clone().unwrap();
    assert_eq!(
        (live.adaptive, live.profile_id.as_str()),
        (AdaptiveMode::TlsCompatibility, "srv-a")
    );
    h.lc.restart_adaptive(
        AdaptiveMode::Baseline,
        Some("srv-b".into()),
        Owner::AdaptiveRetry,
    )
    .await
    .expect("sibling restart");
    h.settle().await;
    assert_eq!(kinds(&h.rows()), [OutcomeKind::ServerSwitch]);
    assert_eq!(h.lc.session().borrow().clone().unwrap().profile_id, "srv-b");
}

/// H-05: the runtime's own crash restart goes through the same hook: the session continues on
/// the new engine run, monitoring restarts; nothing is recorded, and a short restart stays
/// silent (ks-a: one notice only for an outage that lasts).
#[tokio::test]
async fn native_auto_restart_continues_the_session() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    let mut events = h.lc.events();
    let before = h.lc.session().borrow().clone().unwrap();
    let generation = h.rt.auto_restart();
    h.settle().await;
    assert_eq!(h.snap().state, TunnelState::Connected);
    let after = h.lc.session().borrow().clone().unwrap();
    assert_eq!(
        (after.started_at, after.generation),
        (before.started_at, Some(generation))
    );
    assert!(h.rows().is_empty());
    assert_eq!(h.services.counters.lock().monitor_starts, 2);
    assert!(notice(&h, "restored").is_none());
    assert!(notice(&h, "reconnecting").is_none());
    assert!(matches!(
        events.recv().await,
        Ok(crate::lifecycle::SessionEvent::Up(_))
    ));
}

/// Runtime statuses the user must hear about become notices of their category. A failover
/// status alone is none (fixauto-b1): its notice comes only with the session following the
/// sibling, never for a run the lifecycle did not take over.
#[tokio::test]
async fn runtime_statuses_become_notices() {
    let h = Harness::new();
    h.rt.emit(TunnelEvent::Status(TunStatusKind::PostTrialFailover {
        name: "nl-2".into(),
    }));
    let warning = vpnte_base::Msg::new("test.restartFailed");
    h.rt.emit(TunnelEvent::Status(TunStatusKind::Error {
        warning: warning.clone(),
    }));
    h.settle().await;
    assert!(notice(&h, "failover").is_none(), "no run was taken over");
    let (n, kind) = notice(&h, "restartFailed").expect("restart failed notice");
    assert_eq!((kind, n.body), (NoticeKind::ConnectionError, Some(warning)));
    assert_eq!(h.snap().state, TunnelState::Error);
}

/// A crash whose cleanup failed (`Error` with no engine left) ends the TUN session there and
/// then, classified as the crash; a later stop records nothing more.
#[tokio::test]
async fn crash_with_failed_cleanup_ends_the_session() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    h.rt.script.lock().exit = Some(crate::api::ExitInfo {
        at: vpnte_base::types::now_ms(),
        code: Some(1),
        stderr_tail: "fatal: outbound failed".into(),
        user_initiated: false,
        graceful: false,
    });
    h.rt.bring_down();
    let warning = vpnte_base::Msg::new("test.protectionNotReleased");
    h.rt.emit(TunnelEvent::Status(TunStatusKind::Error { warning }));
    h.settle().await;
    assert_eq!(kinds(&h.rows()), [OutcomeKind::SingboxCrash]);
    assert!(h.lc.session().borrow().is_none());
    assert!(notice(&h, "stopped").is_some() && notice(&h, "restartFailed").is_some());
    h.lc.disconnect(user_stop()).await.unwrap();
    assert_eq!(h.rows().len(), 1);
}

/// L-05: a start that ran out of time while a Soft session was still open (after a fault) ends
/// that session with its real cause (unknown, "timed out"), not as a user stop.
#[tokio::test]
async fn timeout_compensation_records_its_cause() {
    let h = Harness::new();
    h.lc.connect(soft(8080, ProxyKind::Http, Owner::Manual))
        .await
        .unwrap();
    h.lc.fault(crate::fsm::FaultState::Unknown);
    let gate = Gate::new();
    h.rt.script.lock().start_gate = Some(gate.clone());
    let mut req = soft(9090, ProxyKind::Http, Owner::Manual);
    req.timeout = std::time::Duration::from_millis(30);
    let err = h.lc.connect(req).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Timeout);
    gate.open();
    super::fakes::eventually("compensated", || !h.lc.busy()).await;
    h.settle().await;
    let rows = h.rows();
    assert_eq!(kinds(&rows), [OutcomeKind::Unknown]);
    let headline = &rows[0].outcome.as_ref().unwrap().headline;
    assert_eq!(headline.key, "tunnel.lifecycle.outcome.timeout");
    assert_eq!(h.snap().state, TunnelState::Disconnected);
}

/// L-05 / §6.4: a Soft start over a TUN left running (after a fault) runs the full stop first
/// (forensics, external proxies and monitoring go with the tunnel); the Hard session ends as a
/// mode switch, not as a user stop, with the evidence read before the stop.
#[tokio::test]
async fn soft_start_over_a_running_tunnel_is_a_mode_switch() {
    let h = Harness::new();
    *h.services.egress_ip.lock() = Some("203.0.113.9".into());
    h.lc.connect(local(Owner::Manual)).await.unwrap();
    h.lc.fault(crate::fsm::FaultState::Unknown);
    h.lc.connect(soft(8080, ProxyKind::Http, Owner::Manual))
        .await
        .expect("soft start");
    assert_eq!(h.rt.script.lock().stops, 1);
    let c = h.services.counters.lock();
    assert_eq!(
        (c.forensics_stops, c.proxies_stops, c.monitor_stops),
        (1, 1, 1)
    );
    drop(c);
    let rows = h.rows();
    assert_eq!(kinds(&rows), [OutcomeKind::ServerSwitch]);
    assert_eq!(rows[0].mode, SessionMode::Hard);
    let evidence = &rows[0].outcome.as_ref().unwrap().evidence;
    assert_eq!(evidence.egress_ip.as_deref(), Some("203.0.113.9"));
    let snap = h.snap();
    assert_eq!(
        (snap.state, snap.mode),
        (TunnelState::Connected, Some(TunnelMode::Soft))
    );
    assert_eq!(
        h.lc.session().borrow().clone().unwrap().mode,
        SessionMode::Soft
    );
}

/// A higher owner can take the running session over; a lower one cannot.
#[tokio::test]
async fn adopt_raises_the_holder_only() {
    let h = Harness::new();
    h.lc.connect(local(Owner::Autopilot)).await.unwrap();
    h.lc.adopt(Owner::Schedule);
    h.lc.adopt(Owner::Rotation);
    h.settle().await;
    assert_eq!(
        h.lc.session().borrow().clone().unwrap().owner,
        Owner::Schedule
    );
}
