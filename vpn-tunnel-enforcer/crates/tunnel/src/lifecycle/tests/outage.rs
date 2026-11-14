//! fix-ks a3 / b4: what the paused state and the outage's one notice say — only what is true:
//! nothing retries with auto-restart off, and programs go where they really go meanwhile.
use std::time::Duration;

use vpnte_base::types::{KillSwitchLevel, Owner, ProxyKind};

use super::fakes::{Harness, eventually};
use super::{local, soft, user_stop};
use crate::lifecycle::Pause;

fn harness(level: KillSwitchLevel) -> Harness {
    let h = Harness::new();
    h.settings
        .update(|s| s.kill_switch = level)
        .expect("settings");
    h
}

fn pause(h: &Harness) -> Option<Pause> {
    h.lc.kill_switch().borrow().pause.clone()
}

/// The body key of the outage notice, once it was shown.
async fn told_body(h: &Harness, name: &str) -> String {
    let title = format!("tunnel.lifecycle.notice.{name}.title");
    eventually(name, || h.notifier.titles().contains(&title)).await;
    h.notifier.bodies().pop().expect("a body")
}

/// fix-ks a3: auto-restart off — the runtime holds the block and schedules nothing: the pause
/// says so (no «переподключается»), and so does its notice.
#[tokio::test]
async fn nothing_retrying_asks_for_connect() {
    let h = harness(KillSwitchLevel::Standard);
    h.lc.connect(local(Owner::Manual)).await.expect("connect");
    h.rt.crash_blocked();
    h.settle().await;
    let p = pause(&h).expect("paused");
    assert!(p.manual && p.next_attempt.is_none(), "{p:?}");
    let body = told_body(&h, "paused").await;
    assert_eq!(body, "tunnel.lifecycle.notice.paused.manual");
    h.lc.disconnect(user_stop()).await.expect("stop");
}

/// fix-ks a3: a slow retry was due, then auto-restart went off and the runtime only kept the
/// block: the countdown goes instead of standing at 0:00.
#[tokio::test]
async fn a_countdown_gives_way_when_nothing_retries() {
    let h = harness(KillSwitchLevel::Standard);
    h.lc.connect(local(Owner::Manual)).await.expect("connect");
    h.rt.crash_held(Duration::from_secs(60));
    h.settle().await;
    let p = pause(&h).expect("paused");
    assert!(!p.manual && p.next_attempt.is_some(), "{p:?}");
    h.rt.crash_blocked();
    h.settle().await;
    let p = pause(&h).expect("still paused");
    assert!(p.manual && p.next_attempt.is_none(), "{p:?}");
    h.lc.disconnect(user_stop()).await.expect("stop");
}

/// fix-ks b4: with nothing held, the notice says where programs go: around the VPN only when a
/// proxy session's tweaks were rolled back (through the other VPN when one carries the route);
/// a proxy kept on the dead port, or a TUN (whose leak protection may block DNS), gets the
/// neutral line.
#[tokio::test]
async fn the_outage_notice_says_what_programs_do() {
    let long = Duration::from_secs(130);
    let short = Duration::from_secs(2);
    let proxy = || soft(10808, ProxyKind::Socks5, Owner::Manual);
    for (level, other, tun, wait, want) in [
        (KillSwitchLevel::Off, false, true, short, "body"),
        (KillSwitchLevel::Off, false, false, short, "body"),
        (KillSwitchLevel::Off, false, false, long, "direct"),
        (KillSwitchLevel::Standard, true, false, long, "other"),
    ] {
        let h = harness(level);
        if other {
            *h.foreign.name.lock() = Some("Happ (10.0.0.2)".into());
        }
        let req = if tun { local(Owner::Manual) } else { proxy() };
        h.lc.connect(req).await.expect("connect");
        h.rt.crash_with_restart_in(wait);
        h.settle().await;
        assert!(pause(&h).is_none(), "nothing held");
        let body = told_body(&h, "reconnecting").await;
        let want = format!("tunnel.lifecycle.notice.reconnecting.{want}");
        assert_eq!(body, want, "{level:?} other={other} tun={tun} {wait:?}");
        h.lc.disconnect(user_stop()).await.expect("stop");
    }
}
