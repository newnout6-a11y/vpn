//! What a session leaves behind once it ended: a restore of the previous server on its way, the
//! kill switch's block of a kept stop, an adaptive preparation of a start nobody waits for.
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::watch;
use vpnte_automation::adaptive::{Adaptive, AdaptiveDoc, AdaptiveHost, Phase};
use vpnte_automation::coordinator::{Coordinator, SwitchError};
use vpnte_base::types::Owner;
use vpnte_core::ops::Source;
use vpnte_core::store::Store;
use vpnte_probes::public_ip::IpReader;
use vpnte_tunnel::api::TunStatus;
use vpnte_tunnel::history::SessionMode;
use vpnte_tunnel::lifecycle::{ConnectTarget, DisconnectReq, StopCause};

use super::coord::{Rig, rig};
use crate::svc_auto::coord::Hooks;
use crate::svc_auto::host::{Fingerprints, ServerHost};
use crate::svc_auto::lane::Lane;

/// Polls `f` for up to two seconds.
async fn eventually(what: &str, f: impl Fn() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn host(r: &Rig) -> Arc<ServerHost> {
    Arc::new(ServerHost::new(
        r.servers.clone(),
        r.settings.clone(),
        watch::channel(TunStatus::default()).1,
        Arc::new(IpReader::new()),
        Fingerprints::default(),
        r.lane.clone(),
    ))
}

fn stops(r: &Rig) -> Vec<String> {
    (r.lane.calls().into_iter())
        .filter(|c| c.starts_with("disconnect"))
        .collect()
}

/// fixauto-a3: a stop that lands while a lost switch's restore waits for the lane wins: the
/// user's Disconnect (straight at the lane) and the end of the owner's run (the scheduler's
/// stop, with no session left to name) leave nothing running afterwards.
#[tokio::test]
async fn a_restore_never_undoes_a_stop_that_came_while_it_waited() {
    for owner in [Owner::Manual, Owner::Schedule] {
        let r = rig(&format!("restore-stop-{owner:?}"));
        let (a, b) = (r.ids[0].clone(), r.ids[1].clone());
        r.lane.up(SessionMode::Soft, &a, owner);
        r.lane.hold_until_released.store(true, Ordering::SeqCst);
        *r.lane.switch_fails.lock() = Some(true);
        let coord = r.coord.clone();
        let switch = tokio::spawn(async move { coord.switch_profile(Owner::Rotation, &b).await });
        eventually("the restore waits", || r.coord.left_by() == Some(owner)).await;
        if owner == Owner::Manual {
            // What the dashboard's power button does (svc_tunnel ops).
            r.coord.user_stops();
            let req = DisconnectReq::new(StopCause::User, Owner::Manual, Source::Ui);
            r.lane.disconnect(req).await.expect("user stop");
        } else {
            r.coord
                .disconnect(Owner::Schedule)
                .await
                .expect("the run's end");
        }
        r.lane.release_hold();
        let lost = switch.await.expect("switch task");
        assert!(
            matches!(
                lost,
                Err(SwitchError::Failed {
                    restored_previous: false,
                    ..
                })
            ),
            "{owner:?}: {lost:?}"
        );
        assert!(r.coord.session().is_none(), "{owner:?}");
        let starts = r
            .lane
            .calls()
            .iter()
            .filter(|c| c.starts_with("connect"))
            .count();
        assert_eq!(starts, 0, "{owner:?}: nothing restarted");
        assert_eq!(r.coord.left_by(), None, "{owner:?}");
    }
}

/// fixauto-a4/b3: an abandoned check's kept stop leaves the kill switch's block with no session.
/// The coordinator names its holder; a lower owner's stop leaves it, the holder's stop (the
/// schedule's run end) releases it with a full stop, and no session's end is waited for.
#[tokio::test]
async fn a_kept_block_is_released_by_its_holders_stop() {
    let r = rig("kept-block");
    let a = r.ids[0].clone();
    r.lane.kill_switch.store(true, Ordering::SeqCst);
    r.lane.up(SessionMode::Soft, &a, Owner::Schedule);
    host(&r).abandon().await;
    assert!(r.coord.session().is_none());
    assert_eq!(r.coord.left_by(), Some(Owner::Schedule));
    r.coord
        .disconnect(Owner::Rotation)
        .await
        .expect("nothing of its own");
    assert_eq!(
        r.coord.left_by(),
        Some(Owner::Schedule),
        "not the rotation's"
    );
    r.coord.disconnect(Owner::Schedule).await.expect("released");
    assert_eq!(r.coord.left_by(), None);
    assert_eq!(
        stops(&r),
        [
            "disconnect Failed AdaptiveRetry",
            "disconnect Schedule Schedule"
        ]
    );
    assert!(r.coord.pending_stop.lock().is_none(), "no session ended");
}

/// fixauto-a5: a start dropped while the lane connects (a reaction cancelled mid-restore) ends
/// its adaptive preparation, so the next start's failure shows as failed at once.
#[tokio::test]
async fn a_dropped_start_releases_its_adaptive_preparation() {
    let r = rig("dropped-start");
    // No network identity lookups: the preparation alone is what this test is about.
    r.settings
        .update(|s| s.adaptive_bypass = false)
        .expect("settings");
    let host = host(&r);
    let learning = Arc::new(Store::<AdaptiveDoc>::open(&r.dir()));
    let settings = r.settings.clone();
    let adaptive = Arc::new(Adaptive::new(
        r.coord.clone(),
        host.clone(),
        settings,
        learning,
    ));
    let hooks = Hooks {
        adaptive: adaptive.clone(),
        host,
    };
    assert!(r.coord.hooks.set(hooks).is_ok());
    let a = r.ids[0].clone();
    let target = || ConnectTarget::SoftVpn {
        profile_id: Some(a.clone()),
    };
    r.lane.connect_hangs.store(true, Ordering::SeqCst);
    let start = r
        .coord
        .start(target(), Owner::AdaptiveRetry, Source::Lifecycle);
    let dropped = tokio::time::timeout(Duration::from_millis(50), start).await;
    assert!(dropped.is_err(), "the caller gave up");
    r.lane.hold_until_released.store(true, Ordering::SeqCst);
    r.lane.hold();
    let refused = r.coord.start(target(), Owner::Manual, Source::Ui).await;
    assert!(refused.is_err(), "the lane holds");
    assert_eq!(adaptive.status().borrow().phase, Phase::Failed);
}
