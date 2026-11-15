//! ks-a: the kill switch's event table (research killswitch §5.3) for "Off" and "If the VPN
//! drops", in Tunnel and Proxy capture, at the lane (runtime faked). Tags `AT-03-KS-<row>`
//! name the table's rows; the WFP side of the same rows is in `vpnte-winnet` (wfp protection
//! tests), the crash policy in the runtime. AT-03-001 / AT-03-002 keep their own tests there.
use std::time::Duration;

use vpnte_base::types::{KillSwitchLevel, OutboundFault, Owner, ProxyKind};

use super::fakes::{Harness, SOFT_PORT, eventually, soft_addr};
use super::{local, soft, user_stop};
use crate::fsm::TunnelState;
use crate::lifecycle::ConnectReq;
use crate::outcome::OutcomeKind;

const LEVELS: [KillSwitchLevel; 2] = [KillSwitchLevel::Off, KillSwitchLevel::Standard];

fn harness(level: KillSwitchLevel) -> Harness {
    let h = Harness::new();
    h.settings
        .update(|s| s.kill_switch = level)
        .expect("settings");
    h
}

/// Tunnel (`tun = true`) or Proxy capture.
fn connect_req(tun: bool) -> ConnectReq {
    match tun {
        true => local(Owner::Manual),
        false => soft(10808, ProxyKind::Socks5, Owner::Manual),
    }
}

fn told(h: &Harness, name: &str) -> usize {
    let title = format!("tunnel.lifecycle.notice.{name}.title");
    h.notifier.titles().iter().filter(|t| **t == title).count()
}

fn paused(h: &Harness) -> bool {
    h.lc.kill_switch().borrow().pause.is_some()
}

fn tweaks(h: &Harness) -> Option<(String, ProxyKind)> {
    h.soft.state.lock().applied.clone()
}

/// AT-03-KS-1 "first connect fails": both levels, both captures leave the internet as it was
/// (nothing paused, no tweaks left) and say the connect failed.
#[tokio::test]
async fn ks_row_1_a_first_connect_that_fails_leaves_the_internet_alone() {
    for level in LEVELS {
        for tun in [true, false] {
            let h = harness(level);
            let error = crate::api::TunError::new(
                vpnte_base::ErrorKind::Network,
                vpnte_base::Msg::new("test.unreachable"),
            );
            h.rt.script.lock().start_error = Some(error);
            let err = h.lc.connect(connect_req(tun)).await.expect_err("fails");
            assert_eq!(err.user_msg().key, "test.unreachable");
            h.settle().await;
            assert!(!paused(&h), "{level:?} tun={tun}");
            assert_eq!(tweaks(&h), None, "{level:?} tun={tun}");
            assert_ne!(h.snap().state, TunnelState::Blocked, "{level:?} tun={tun}");
            let kinds: Vec<_> = h.rows().iter().filter_map(|r| r.outcome.clone()).collect();
            assert_eq!(kinds.len(), 1);
            assert!(kinds[0].kind.never_connected(), "{level:?} tun={tun}");
        }
    }
}

/// AT-03-KS-2 "planned reconnect" (settings restart): the session continues on the new run,
/// nothing pauses, Proxy capture keeps the system proxy on its port (no rollback, no gap).
#[tokio::test]
async fn ks_row_2_a_planned_reconnect_keeps_the_session_without_a_gap() {
    for level in LEVELS {
        for tun in [true, false] {
            let h = harness(level);
            h.lc.connect(connect_req(tun)).await.expect("connect");
            let before = tweaks(&h);
            h.lc.restart_with_last("settings", Owner::Manual, vpnte_core::ops::Source::Ui)
                .await
                .expect("restart");
            h.settle().await;
            assert_eq!(
                h.snap().state,
                TunnelState::Connected,
                "{level:?} tun={tun}"
            );
            assert!(!paused(&h));
            assert_eq!(tweaks(&h), before, "{level:?} tun={tun}");
            assert_eq!(h.soft.state.lock().rollbacks, 0, "{level:?} tun={tun}");
            assert!(h.rows().is_empty(), "the session continues");
        }
    }
}

/// AT-03-KS-2b "a planned reconnect that fails becomes a drop": with "If the VPN drops" the
/// runtime holds and the session stays open and paused (no recovery stop, tweaks kept); with
/// the kill switch off the lane rolls back to a proven state as before.
#[tokio::test]
async fn ks_row_2_b_a_failed_planned_reconnect_counts_as_a_drop() {
    for level in LEVELS {
        for tun in [true, false] {
            let h = harness(level);
            h.lc.connect(connect_req(tun)).await.expect("connect");
            {
                let mut s = h.rt.script.lock();
                s.restart_error = true;
                s.restart_held = level != KillSwitchLevel::Off;
            }
            let stops = h.rt.script.lock().stops;
            let source = vpnte_core::ops::Source::Ui;
            let result =
                h.lc.restart_with_last("settings", Owner::Manual, source)
                    .await;
            assert!(result.is_err(), "{level:?} tun={tun}");
            h.settle().await;
            let held = level != KillSwitchLevel::Off;
            assert_eq!(paused(&h), held, "{level:?} tun={tun}");
            if held {
                assert_eq!(h.rt.script.lock().stops, stops, "no recovery stop");
                assert!(h.lc.session().borrow().is_some(), "session open");
                assert_eq!(h.snap().state, TunnelState::Blocked);
                if !tun {
                    assert_eq!(tweaks(&h), Some((soft_addr(SOFT_PORT), ProxyKind::Http)));
                }
            } else {
                eventually("released", || tweaks(&h).is_none()).await;
                assert!(h.lc.session().borrow().is_none());
            }
        }
    }
}

/// AT-03-KS-3 "engine crash / TUN lost / server unreachable, by itself": off -> the session
/// ends, programs go direct, one notice; "If the VPN drops" -> paused (session open, Proxy
/// capture keeps the system proxy on its port) until «Продолжить без VPN».
#[tokio::test]
async fn ks_row_3_a_drop_by_itself_pauses_only_with_the_kill_switch_on() {
    for level in LEVELS {
        for tun in [true, false] {
            let h = harness(level);
            h.lc.connect(connect_req(tun)).await.expect("connect");
            if level == KillSwitchLevel::Off {
                h.rt.crash(1);
                eventually("session ended", || h.rows().len() == 1).await;
                h.settle().await;
                assert!(!paused(&h));
                assert_eq!(tweaks(&h), None, "tun={tun}");
                let notices = told(&h, "stopped") + told(&h, "softRestored");
                assert_eq!(notices, 1, "one notice, tun={tun}");
            } else {
                h.rt.crash_held(Duration::from_secs(60));
                h.settle().await;
                assert!(paused(&h), "tun={tun}");
                let next =
                    h.lc.kill_switch()
                        .borrow()
                        .clone()
                        .pause
                        .and_then(|p| p.next_attempt);
                assert!(next.is_some(), "the countdown is shown");
                assert!(h.rows().is_empty(), "the paused session stays open");
                assert_eq!(h.snap().state, TunnelState::Blocked);
                if !tun {
                    assert_eq!(tweaks(&h), Some((soft_addr(SOFT_PORT), ProxyKind::Http)));
                }
                h.lc.disconnect(user_stop())
                    .await
                    .expect("continue without VPN");
                assert!(!paused(&h));
                assert_eq!(tweaks(&h), None);
                assert_eq!(h.snap().state, TunnelState::Disconnected);
                let kinds: Vec<_> = h.rows().iter().filter_map(|r| r.outcome.clone()).collect();
                assert_eq!(kinds[0].kind, OutcomeKind::UserStop);
            }
        }
    }
}

/// AT-03-KS-4 "server blocked or frozen, engine alive": nothing to pause, nothing leaks; the
/// session stays connected while the upstream is reported down.
#[tokio::test]
async fn ks_row_4_a_blocked_server_with_a_live_engine_pauses_nothing() {
    for level in LEVELS {
        let h = harness(level);
        h.lc.connect(connect_req(false)).await.expect("connect");
        let reason = vpnte_base::Msg::new("tunnel.runtime.watchdog.proxyMode.upstreamDown");
        let kind = crate::api::TunStatusKind::ProxyDown { reason };
        h.rt.emit(crate::api::TunnelEvent::Status(kind));
        h.settle().await;
        assert!(!paused(&h), "{level:?}");
        assert!(h.rows().is_empty());
        assert!(h.lc.session().borrow().is_some());
    }
}

/// AT-03-KS-5 "key rejected": the paused state says so (the user must act), and the outage's
/// one notice is the key notice.
#[tokio::test]
async fn ks_row_5_a_rejected_key_is_named_in_the_pause() {
    let h = harness(KillSwitchLevel::Standard);
    h.lc.connect(connect_req(true)).await.expect("connect");
    h.rt.script.lock().fault = Some(OutboundFault::RealityKeyMismatch);
    h.rt.crash_held(Duration::from_secs(60));
    h.settle().await;
    let pause = h.lc.kill_switch().borrow().pause.clone().expect("paused");
    assert!(pause.key_rejected);
    eventually("key notice", || told(&h, "keyRejected") == 1).await;
    assert_eq!(told(&h, "paused"), 0);
}

/// AT-03-KS-6 «Подключить» / «Продолжить без VPN»: the first retries the paused session at once
/// through the runtime; the second is a disconnect that gives the internet back at once.
#[tokio::test]
async fn ks_row_6_the_paused_state_buttons() {
    let h = harness(KillSwitchLevel::Standard);
    assert!(!h.lc.retry_now().await, "nothing paused");
    h.lc.connect(connect_req(false)).await.expect("connect");
    h.rt.crash_held(Duration::from_secs(300));
    h.settle().await;
    assert!(h.lc.retry_now().await);
    assert_eq!(h.rt.script.lock().retries_now, 1);
    h.rt.come_back();
    h.settle().await;
    assert!(!paused(&h), "a reconnect ends the pause");
    assert_eq!(h.snap().state, TunnelState::Connected);
    h.rt.crash_held(Duration::from_secs(300));
    h.settle().await;
    h.lc.disconnect(user_stop())
        .await
        .expect("continue without VPN");
    assert!(!paused(&h) && tweaks(&h).is_none());
}

/// AT-03-KS-7 "quit": the app's shutdown gives the internet back at once, also while paused.
#[tokio::test]
async fn ks_row_7_quit_ends_the_pause() {
    for tun in [true, false] {
        let h = harness(KillSwitchLevel::Standard);
        h.lc.connect(connect_req(tun)).await.expect("connect");
        h.rt.crash_held(Duration::from_secs(60));
        h.settle().await;
        let report = h.lc.shutdown(Duration::from_secs(5)).await;
        assert!(report.engines_stopped, "tun={tun}");
        assert!(!paused(&h) && tweaks(&h).is_none(), "tun={tun}");
    }
}

/// AT-03-KS-8 "another full-tunnel VPN is active" (Proxy capture; Tunnel mode refuses such a
/// connect): "If the VPN drops" does not arm, the start page gets one line naming it.
#[tokio::test]
async fn ks_row_8_another_vpn_means_no_pause() {
    let h = harness(KillSwitchLevel::Standard);
    *h.foreign.name.lock() = Some("Happ (10.0.0.2)".into());
    h.lc.connect(connect_req(false)).await.expect("connect");
    let req = h.rt.script.lock().requests.last().cloned().expect("start");
    assert_eq!(req.kill_switch, KillSwitchLevel::Off);
    let view = h.lc.kill_switch().borrow().clone();
    assert_eq!(view.foreign_vpn.as_deref(), Some("Happ (10.0.0.2)"));
    h.lc.disconnect(user_stop()).await.expect("stop");
    assert_eq!(h.lc.kill_switch().borrow().foreign_vpn, None);
}

/// AT-03-KS-9 "one notice per pause, only when it lasts": a pause that ends quickly is silent;
/// one that lasts is told once, and its end is told as `restored`.
#[tokio::test]
async fn ks_row_9_one_notice_per_lasting_pause() {
    let h = harness(KillSwitchLevel::Standard);
    h.lc.connect(connect_req(true)).await.expect("connect");
    h.rt.crash_held(Duration::from_secs(60));
    h.rt.come_back();
    h.settle().await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    h.settle().await;
    assert_eq!(
        told(&h, "paused") + told(&h, "restored"),
        0,
        "short: silent"
    );
    h.rt.crash_held(Duration::from_secs(60));
    h.settle().await;
    eventually("one pause notice", || told(&h, "paused") == 1).await;
    h.rt.crash_held(Duration::from_secs(120));
    tokio::time::sleep(Duration::from_millis(400)).await;
    h.settle().await;
    assert_eq!(told(&h, "paused"), 1, "once per pause");
    h.rt.come_back();
    h.settle().await;
    assert_eq!(told(&h, "restored"), 1);
}
