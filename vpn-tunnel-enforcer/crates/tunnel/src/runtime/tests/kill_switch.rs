//! fix-ks a1 / a2: the crash policy of a running session follows its kill switch as it is now —
//! a level the protection carries live (TUN) or the lifecycle hands over (proxy capture) — and
//! a restart of a proxy session keeps the session's own level; «Подключить» keeps the RU
//! discipline (fix-ks a4).
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::KillSwitchLevel;

use super::*;
use crate::api::{CaptureKind, Runtime, TunStatusKind, TunnelEvent};
use crate::runtime::TunnelHandle;

fn proxy_req(level: KillSwitchLevel) -> StartRequest {
    StartRequest {
        capture: CaptureKind::Proxy,
        kill_switch: level,
        ..local_req()
    }
}

/// Crashes the running core with auto-restart off and returns what the policy ended in:
/// `Stopped` (released) or `KillSwitchActive` (held).
async fn crash_without_restart(w: &Arc<World>, h: &TunnelHandle, core: usize) -> TunStatusKind {
    w.auto_restart.store(false, Ordering::SeqCst);
    let mut events = h.subscribe();
    w.core(core).crash();
    let end = |e: &TunnelEvent| {
        matches!(
            e,
            TunnelEvent::Status(TunStatusKind::Stopped | TunStatusKind::KillSwitchActive)
        )
    };
    match until(&mut events, end).await.pop() {
        Some(TunnelEvent::Status(kind)) => kind,
        other => panic!("no terminal status: {other:?}"),
    }
}

/// fix-ks a1 (TUN, as in the helper service): the filters were set to «Выключен» during the
/// session; the crash releases instead of holding a block the user turned off.
#[tokio::test]
async fn a_tun_crash_follows_the_level_in_force() {
    let w = World::new();
    let h = TunnelHandle::spawn(deps(&w));
    h.start(local_req(), CancellationToken::new())
        .await
        .expect("start");
    *w.guard.lock() = KillSwitchLevel::Off;
    let end = crash_without_restart(&w, &h, 0).await;
    assert_eq!(end, TunStatusKind::Stopped);
    assert_eq!(w.count("release"), 1);
}

/// fix-ks a1 (proxy capture): the lifecycle hands the new level over; the crash then follows
/// it both ways.
#[tokio::test]
async fn a_proxy_crash_follows_the_level_handed_over() {
    for (from, to, want) in [
        (
            KillSwitchLevel::Standard,
            KillSwitchLevel::Off,
            TunStatusKind::Stopped,
        ),
        (
            KillSwitchLevel::Off,
            KillSwitchLevel::Standard,
            TunStatusKind::KillSwitchActive,
        ),
    ] {
        let w = World::new();
        let h = TunnelHandle::spawn(deps(&w));
        h.start(proxy_req(from), CancellationToken::new())
            .await
            .expect("start");
        h.set_kill_switch(to).await;
        // An answered command (nothing paused: a no-op) runs after the one queued before it.
        assert!(!h.retry_now().await);
        assert_eq!(
            crash_without_restart(&w, &h, 0).await,
            want,
            "{from:?} -> {to:?}"
        );
    }
}

/// fix-ks a2: a proxy session next to another VPN runs with the kill switch off; a settings
/// restart keeps that (the stored level is «При обрыве»), so a later crash releases instead of
/// holding a pause nothing can keep.
#[tokio::test]
async fn a_settings_restart_keeps_the_proxy_sessions_level() {
    let w = World::new();
    let h = TunnelHandle::spawn(deps(&w));
    h.start(proxy_req(KillSwitchLevel::Off), CancellationToken::new())
        .await
        .expect("start");
    let restarted = h.restart_with_last("stealth".into()).await;
    assert!(matches!(restarted, Ok(Some(_))), "{restarted:?}");
    assert_eq!(
        crash_without_restart(&w, &h, 1).await,
        TunStatusKind::Stopped
    );
}

/// A crashed direct session (the fake core reports an outbound fault) with auto-restart off,
/// paused by its kill switch; `tune` adjusts the timings.
async fn paused_direct(tune: impl FnOnce(&mut Timings)) -> (Arc<World>, TunnelHandle) {
    let w = World::new();
    w.auto_restart.store(false, Ordering::SeqCst);
    let mut d = deps(&w);
    tune(&mut d.timings);
    let h = TunnelHandle::spawn(d);
    let mut events = h.subscribe();
    let req = vpn_req(NATIVE_KEY, vpnte_base::types::EnginePref::Auto);
    h.start(req, CancellationToken::new()).await.expect("start");
    w.core(0).crash();
    let held = TunnelEvent::Status(TunStatusKind::KillSwitchActive);
    until(&mut events, |e| *e == held).await;
    (w, h)
}

/// The time from now until the next recovery start begins, and what came before it.
async fn next_attempt(h: &TunnelHandle) -> (Duration, Vec<TunnelEvent>) {
    let mut events = h.subscribe();
    let asked = tokio::time::Instant::now();
    assert!(h.retry_now().await, "accepted");
    let seen = until(&mut events, |e| matches!(e, TunnelEvent::StartBegan { .. })).await;
    (asked.elapsed(), seen)
}

/// fix-ks a4: «Подключить» inside the frozen server's quiet window does not dial it; the
/// attempt runs at the window's end (announced as the next attempt), auto-restart off or not.
#[tokio::test]
async fn an_asked_retry_waits_out_the_freeze_window() {
    let (_w, h) = paused_direct(|t| t.freeze = Duration::from_millis(600)).await;
    let (waited, seen) = next_attempt(&h).await;
    assert!(waited >= Duration::from_millis(450), "{waited:?}");
    let scheduled = |e: &TunnelEvent| matches!(e, TunnelEvent::RestartScheduled { .. });
    assert!(seen.iter().any(scheduled), "{seen:?}");
}

/// fix-ks a4: presses right after an attempt keep the per-server spacing (RU: ~3 handshakes a
/// minute); without a freeze window the first press dials at once.
#[tokio::test]
async fn asked_retries_keep_the_spacing() {
    let (w, h) = paused_direct(|t| {
        t.freeze = Duration::ZERO;
        t.retry_spacing = Duration::from_millis(600);
    })
    .await;
    w.ready_fail.store(true, Ordering::SeqCst);
    let mut events = h.subscribe();
    let (first, _) = next_attempt(&h).await;
    assert!(first < Duration::from_millis(300), "at once: {first:?}");
    // The attempt failed: paused again.
    let held = TunnelEvent::Status(TunStatusKind::KillSwitchActive);
    until(&mut events, |e| *e == held).await;
    let (second, _) = next_attempt(&h).await;
    assert!(second >= Duration::from_millis(300), "spaced: {second:?}");
}
