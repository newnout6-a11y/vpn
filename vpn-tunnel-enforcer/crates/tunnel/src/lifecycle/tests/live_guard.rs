//! fix-ks a1 / b1: the live session's kill switch follows the level the user picks and the other
//! VPN as it is now, not as they were at connect (runtime faked; the joint tests run the real
//! runtime's side).
use std::time::Duration;

use vpnte_base::types::{KillSwitchLevel, Owner, ProxyKind};

use super::fakes::{Harness, SOFT_PORT, eventually, soft_addr};
use super::{soft, user_stop};

/// Longer than the short-restart hold, as a frozen server's quiet window (130 s).
const FREEZE: Duration = Duration::from_secs(130);

fn harness(level: KillSwitchLevel) -> Harness {
    let h = Harness::new();
    h.settings
        .update(|s| s.kill_switch = level)
        .expect("settings");
    h
}

/// What the user does in Settings: the level is stored, then the session is told.
fn pick(h: &Harness, level: KillSwitchLevel) {
    h.settings
        .update(|s| s.kill_switch = level)
        .expect("settings");
    h.lc.kill_switch_changed();
}

async fn connect_proxy(h: &Harness) {
    let req = soft(10808, ProxyKind::Socks5, Owner::Manual);
    h.lc.connect(req).await.expect("connect");
}

fn paused(h: &Harness) -> bool {
    h.lc.kill_switch().borrow().pause.is_some()
}

fn tweaks(h: &Harness) -> Option<(String, ProxyKind)> {
    h.soft.state.lock().applied.clone()
}

fn pushed(h: &Harness) -> Vec<KillSwitchLevel> {
    h.rt.script.lock().kill_switches.clone()
}

/// fix-ks a1: «При обрыве» at connect, «Выключен» picked while connected: a long restart wait
/// no longer holds the system proxy on the dead port and nothing pauses; the runtime's crash
/// policy got the new level (it releases once its budget is spent).
#[tokio::test]
async fn level_off_while_connected_reaches_the_session() {
    let h = harness(KillSwitchLevel::Standard);
    connect_proxy(&h).await;
    pick(&h, KillSwitchLevel::Off);
    h.settle().await;
    assert_eq!(pushed(&h), [KillSwitchLevel::Off]);
    h.rt.crash_with_restart_in(FREEZE);
    h.settle().await;
    assert!(!paused(&h), "the level is off: no pause");
    assert_eq!(tweaks(&h), None, "programs go direct during the long wait");
    h.lc.disconnect(user_stop()).await.expect("stop");
}

/// fix-ks a1, the other way: «Выключен» at connect, «При обрыве» picked while connected: the
/// drop pauses with the system proxy kept on the session's port, and the runtime got the level.
#[tokio::test]
async fn level_on_while_connected_reaches_the_session() {
    let h = harness(KillSwitchLevel::Off);
    connect_proxy(&h).await;
    pick(&h, KillSwitchLevel::Standard);
    h.settle().await;
    assert_eq!(pushed(&h), [KillSwitchLevel::Standard]);
    h.rt.crash_with_restart_in(FREEZE);
    h.settle().await;
    assert!(paused(&h), "the level holds now");
    assert_eq!(tweaks(&h), Some((soft_addr(SOFT_PORT), ProxyKind::Http)));
    assert_eq!(h.soft.state.lock().rollbacks, 0);
    h.lc.disconnect(user_stop())
        .await
        .expect("continue without VPN");
    assert!(!paused(&h) && tweaks(&h).is_none());
}

/// fix-ks b1: the session connected next to another full-tunnel VPN (no pause), then that VPN
/// went away: the drop is judged against the VPN as it is now — paused, proxy kept, the
/// runtime holds, and the «Другой VPN» line is gone.
#[tokio::test]
async fn the_other_vpn_gone_before_a_drop_means_a_pause() {
    let h = harness(KillSwitchLevel::Standard);
    *h.foreign.name.lock() = Some("Happ (10.0.0.2)".into());
    connect_proxy(&h).await;
    assert!(h.lc.kill_switch().borrow().foreign_vpn.is_some());
    *h.foreign.name.lock() = None;
    h.rt.crash_with_restart_in(FREEZE);
    h.settle().await;
    assert!(paused(&h), "nothing else carries the traffic any more");
    assert_eq!(tweaks(&h), Some((soft_addr(SOFT_PORT), ProxyKind::Http)));
    assert_eq!(pushed(&h).last(), Some(&KillSwitchLevel::Standard));
    assert_eq!(h.lc.kill_switch().borrow().foreign_vpn, None);
    h.lc.disconnect(user_stop()).await.expect("stop");
}

/// fix-ks b1: while connected, the «Другой VPN» line follows a live look at the adapters: it
/// goes when that VPN goes, and the session arms again without a drop.
#[tokio::test]
async fn the_other_vpn_line_follows_a_live_scan() {
    let h = harness(KillSwitchLevel::Standard);
    *h.foreign.name.lock() = Some("Happ (10.0.0.2)".into());
    connect_proxy(&h).await;
    *h.foreign.name.lock() = None;
    eventually("line gone", || {
        h.lc.kill_switch().borrow().foreign_vpn.is_none()
    })
    .await;
    assert_eq!(pushed(&h), [KillSwitchLevel::Standard]);
    h.lc.disconnect(user_stop()).await.expect("stop");
}
