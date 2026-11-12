use std::collections::HashSet;

use serde_json::json;
use tokio::sync::Notify;

use super::*;
use crate::coordinator::SessionKind;
use crate::coordinator::testing::{Call, FakeCoordinator};
use crate::test_support::TempDir;

#[derive(Default)]
struct FakeProfiles {
    facts: Mutex<Vec<ProfileFacts>>,
    reachable: Mutex<HashSet<String>>,
    probes: Mutex<Vec<String>>,
    selected: Mutex<Option<String>>,
    /// While set, every probe waits for one notification (a slow ping).
    hold: Mutex<Option<Arc<Notify>>>,
    entered: Notify,
}

impl RotationProfiles for FakeProfiles {
    fn facts(&self, id: &str) -> Option<ProfileFacts> {
        self.facts.lock().iter().find(|p| p.id == id).cloned()
    }

    fn all(&self) -> Vec<ProfileFacts> {
        self.facts.lock().clone()
    }

    fn reachable(&self, id: &str) -> impl Future<Output = bool> + Send {
        self.probes.lock().push(id.to_owned());
        let hold = self.hold.lock().clone();
        let up = self.reachable.lock().contains(id);
        async move {
            if let Some(hold) = hold {
                self.entered.notify_one();
                hold.notified().await;
            }
            up
        }
    }

    fn select(&self, id: &str) -> AppResult<()> {
        *self.selected.lock() = Some(id.to_owned());
        Ok(())
    }
}

fn profile(id: &str) -> ProfileFacts {
    ProfileFacts {
        id: id.into(),
        name: format!("Profile {}", id.to_uppercase()),
        enabled: true,
        archived: false,
        has_outbound: true,
        status: ProfileStatus::Unknown,
        checked_at: None,
        udp: false,
    }
}

struct Fixture {
    _dir: TempDir,
    store: Arc<Store<RotationConfig>>,
    coord: Arc<FakeCoordinator>,
    profiles: Arc<FakeProfiles>,
    rotation: Arc<Rotation<FakeCoordinator, FakeProfiles>>,
}

fn fixture(ids: &[&str], current_index: usize, order: RotationOrder) -> Fixture {
    let dir = TempDir::new("rotation");
    let store = Arc::new(Store::<RotationConfig>::open(dir.path()));
    let cfg = RotationConfig {
        enabled: true,
        order,
        profile_ids: ids.iter().map(|s| s.to_string()).collect(),
        current_index,
        ..RotationConfig::default()
    };
    store.replace(cfg).unwrap();
    let coord = FakeCoordinator::new();
    let profiles = Arc::new(FakeProfiles::default());
    *profiles.facts.lock() = ids.iter().map(|id| profile(id)).collect();
    let rotation = Arc::new(Rotation::new(
        store.clone(),
        coord.clone(),
        profiles.clone(),
    ));
    Fixture {
        _dir: dir,
        store,
        coord,
        profiles,
        rotation,
    }
}

impl Fixture {
    fn reachable(&self, ids: &[&str]) {
        *self.profiles.reachable.lock() = ids.iter().map(|s| s.to_string()).collect();
    }

    fn live_on(&self, id: &str) {
        self.coord
            .set_session(SessionKind::Direct, Owner::Manual, Some(id));
    }

    fn switches(&self) -> Vec<String> {
        let calls = self.coord.calls();
        calls
            .into_iter()
            .filter_map(|c| match c {
                Call::Switch(_, id) => Some(id),
                _ => None,
            })
            .collect()
    }
}

fn rotated(id: &str) -> RotationOutcome {
    RotationOutcome::Rotated {
        profile_id: id.into(),
    }
}

/// `clampInterval` vectors.
#[test]
fn interval_is_clamped() {
    for v in [
        0.0,
        -10.0,
        4.0,
        1.0,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ] {
        assert_eq!(clamp_interval(v), 5, "{v}");
    }
    for v in [1441.0, 9999.0, 100000.0] {
        assert_eq!(clamp_interval(v), 1440, "{v}");
    }
    for v in [5, 30, 60, 720, 1440] {
        assert_eq!(clamp_interval(f64::from(v)), v);
    }
    assert_eq!(clamp_interval(7.6), 8);
}

#[test]
fn candidate_order_never_includes_the_current_index() {
    let mut rng = fastrand::Rng::with_seed(7);
    assert_eq!(
        candidate_order(4, 0, RotationOrder::Sequential, &mut rng),
        vec![1, 2, 3]
    );
    assert_eq!(
        candidate_order(4, 2, RotationOrder::Sequential, &mut rng),
        vec![3, 0, 1]
    );
    assert_eq!(
        candidate_order(1, 0, RotationOrder::Sequential, &mut rng),
        Vec::<usize>::new()
    );
    let mut random = candidate_order(4, 1, RotationOrder::Random, &mut rng);
    random.sort_unstable();
    assert_eq!(random, vec![0, 2, 3]);
    assert!(candidate_order(0, 0, RotationOrder::Random, &mut rng).is_empty());
}

/// `getNextAvailableProfile` vectors over ids a, b, c, d (idle "rotate now": selection only).
#[tokio::test]
async fn next_available_profile_vectors() {
    use RotationOrder::{Random, Sequential};
    let cases: [(usize, RotationOrder, &[&str], RotationOutcome); 8] = [
        (0, Sequential, &["a", "b", "c", "d"], rotated("b")),
        (0, Sequential, &["a", "c", "d"], rotated("c")),
        (3, Sequential, &["a", "b", "c", "d"], rotated("a")),
        (2, Sequential, &["b", "c"], rotated("b")),
        (0, Sequential, &[], RotationOutcome::NoneAvailable),
        (0, Random, &["a", "c"], rotated("c")),
        (0, Random, &[], RotationOutcome::NoneAvailable),
        // Old code "rotated" onto the current profile; Rust does nothing (fix R5).
        (0, Random, &["a"], RotationOutcome::NothingToRotate),
    ];
    for (index, order, up, expected) in cases {
        let fx = fixture(&["a", "b", "c", "d"], index, order);
        fx.reachable(up);
        let outcome = fx.rotation.rotate(RotationTrigger::User).await;
        assert_eq!(outcome, expected, "{index} {order:?} {up:?}");
        let selected = fx.profiles.selected.lock().clone();
        match outcome {
            RotationOutcome::Rotated { profile_id } => assert_eq!(selected, Some(profile_id)),
            _ => assert_eq!(selected, None),
        }
    }
    let fx = fixture(&["a", "b", "c", "d"], 0, Random);
    fx.reachable(&["a", "b", "c", "d"]);
    let RotationOutcome::Rotated { profile_id } = fx.rotation.rotate(RotationTrigger::User).await
    else {
        panic!("expected a rotation");
    };
    assert!(["b", "c", "d"].contains(&profile_id.as_str()));
    let empty = fixture(&[], 0, Sequential);
    assert_eq!(
        empty.rotation.rotate(RotationTrigger::User).await,
        RotationOutcome::NoProfiles
    );
}

/// "Rotates a running direct VPN tunnel": unknown statuses checked 3 min ago need no probe
/// while live; the switch goes through the coordinator; index and countdown are persisted and
/// the announcement follows the commit.
#[tokio::test]
async fn rotates_a_running_direct_tunnel() {
    let fx = fixture(&["profile-a", "profile-b"], 0, RotationOrder::Sequential);
    for p in fx.profiles.facts.lock().iter_mut() {
        p.checked_at = Some(now_ms() - 180_000);
    }
    fx.live_on("profile-a");
    let before = now_ms();
    assert_eq!(
        fx.rotation.rotate(RotationTrigger::Timer).await,
        rotated("profile-b")
    );
    assert!(fx.profiles.probes.lock().is_empty());
    assert_eq!(
        fx.coord.calls(),
        vec![Call::Switch(Owner::Rotation, "profile-b".into())]
    );
    let cfg = fx.rotation.config();
    assert_eq!(cfg.current_index, 1);
    assert!(
        cfg.next_rotation_at
            .is_some_and(|t| t >= before + 30 * 60_000)
    );
    let (category, notice) = fx.coord.notices.lock()[0].clone();
    assert_eq!(category, NoticeCategory::ProfileRotation);
    let body = notice.body.unwrap();
    assert_eq!(
        body,
        Msg::new("automation.rotation.switched").arg("name", "Profile PROFILE-B")
    );
}

/// Enabling with an empty list seeds every usable profile (no outbound, archived and disabled
/// profiles are left out — R4 for the archive / disabled part).
#[test]
fn enabling_an_empty_list_seeds_usable_profiles() {
    let fx = fixture(&[], 0, RotationOrder::Sequential);
    fx.rotation
        .set_config(RotationPatch {
            enabled: Some(false),
            ..Default::default()
        })
        .unwrap();
    let mut all = vec![
        profile("profile-a"),
        profile("profile-b"),
        profile("no-outbound"),
        profile("old"),
        profile("off"),
    ];
    all[2].has_outbound = false;
    all[3].archived = true;
    all[4].enabled = false;
    *fx.profiles.facts.lock() = all;
    let cfg = fx
        .rotation
        .set_config(RotationPatch {
            enabled: Some(true),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(cfg.profile_ids, vec!["profile-a", "profile-b"]);
    assert!(cfg.next_rotation_at.is_some());
}

/// "Skips explicitly offline profiles while rotating a running tunnel": B offline, C unknown → C.
#[tokio::test]
async fn live_rotation_skips_offline_profiles() {
    let fx = fixture(&["a", "b", "c"], 0, RotationOrder::Sequential);
    fx.profiles.facts.lock()[1].status = ProfileStatus::Offline;
    fx.live_on("a");
    assert_eq!(
        fx.rotation.rotate(RotationTrigger::User).await,
        rotated("c")
    );
}

/// R1: a failed switch restores the previous server; the index stays, the countdown re-arms,
/// one failure notice names both profiles; without a restore the notice warns of exposure.
#[tokio::test]
async fn failed_switch_keeps_the_index_and_says_what_happened() {
    for restored in [true, false] {
        let fx = fixture(&["a", "b"], 0, RotationOrder::Sequential);
        fx.live_on("a");
        let failure = SwitchError::Failed {
            reason: OpError::Timeout,
            restored_previous: restored,
        };
        fx.coord.switch_results.lock().push_back(Err(failure));
        let outcome = fx.rotation.rotate(RotationTrigger::Timer).await;
        let expected = RotationOutcome::Failed {
            profile_id: "b".into(),
            reason: OpError::Timeout.reason(),
            restored_previous: restored,
        };
        assert_eq!(outcome, expected);
        let cfg = fx.rotation.config();
        assert_eq!(cfg.current_index, 0);
        assert!(cfg.next_rotation_at.is_some());
        let notices = fx.coord.notices.lock().clone();
        assert_eq!(notices.len(), 1);
        let (category, notice) = &notices[0];
        assert_eq!(*category, NoticeCategory::ConnectionError);
        let title = if restored {
            Msg::new("automation.rotation.failedRestored")
                .arg("name", "Profile B")
                .arg("previous", "Profile A")
        } else {
            Msg::new("automation.rotation.failedUnprotected").arg("name", "Profile B")
        };
        assert_eq!(notice.title, title);
        assert_eq!(
            notice.level,
            if restored { Level::Warn } else { Level::Error }
        );
        assert_eq!(notice.body, Some(OpError::Timeout.reason()));
    }
}

/// A switch refused before the tunnel was touched keeps it: no exposure warning; "busy" is quiet.
#[tokio::test]
async fn refused_switch_keeps_the_tunnel() {
    let fx = fixture(&["a", "b"], 0, RotationOrder::Sequential);
    fx.live_on("a");
    let preflight = OpError::Failed(vpnte_base::AppError::new(vpnte_base::ErrorKind::Internal));
    fx.coord
        .switch_results
        .lock()
        .push_back(Err(SwitchError::NotStarted(preflight)));
    let outcome = fx.rotation.rotate(RotationTrigger::User).await;
    assert!(
        matches!(outcome, RotationOutcome::NotStarted { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        fx.coord.notice_keys()[0],
        "automation.rotation.failedNotStarted"
    );
    assert_eq!(
        fx.coord.session().and_then(|s| s.profile_id).as_deref(),
        Some("a")
    );

    let busy = fixture(&["a", "b"], 0, RotationOrder::Sequential);
    busy.live_on("a");
    busy.coord
        .switch_results
        .lock()
        .push_back(Err(SwitchError::NotStarted(OpError::Conflict)));
    let outcome = busy.rotation.rotate(RotationTrigger::Timer).await;
    assert_eq!(
        outcome,
        RotationOutcome::NotStarted {
            reason: OpError::Conflict.reason()
        }
    );
    assert!(busy.coord.notice_keys().is_empty());
}

/// Empty list → no switch and no re-arm; all pings fail → none available (re-armed); then
/// pings answer → b ("an unavailable offline rotation keeps the confirmed idle state").
#[tokio::test]
async fn unavailable_then_available() {
    let empty = fixture(&[], 0, RotationOrder::Sequential);
    let outcome = empty.rotation.rotate(RotationTrigger::User).await;
    assert_eq!(outcome, RotationOutcome::NoProfiles);
    assert_eq!(empty.rotation.config().next_rotation_at, None);
    assert!(empty.coord.calls().is_empty());

    let fx = fixture(&["a", "b"], 0, RotationOrder::Sequential);
    assert_eq!(
        fx.rotation.rotate(RotationTrigger::User).await,
        RotationOutcome::NoneAvailable
    );
    assert!(fx.rotation.config().next_rotation_at.is_some());
    fx.reachable(&["b"]);
    assert_eq!(
        fx.rotation.rotate(RotationTrigger::User).await,
        rotated("b")
    );
    assert!(fx.switches().is_empty(), "idle: selection only");
}

/// R2 / R8: local-proxy sessions are never rotated; the timer needs a session over a server.
/// Sessions over the server list rotate whatever their capture (NOADMIN §2: the system
/// proxy over a list server is the main mode without administrator rights).
#[tokio::test]
async fn only_sessions_over_a_server_rotate() {
    let fx = fixture(&["a", "b"], 0, RotationOrder::Sequential);
    fx.reachable(&["a", "b"]);
    assert_eq!(
        fx.rotation.rotate(RotationTrigger::Timer).await,
        RotationOutcome::NotDirect
    );
    for kind in [SessionKind::LocalProxyHard, SessionKind::Soft] {
        fx.coord.set_session(kind, Owner::Manual, None);
        for trigger in [RotationTrigger::Timer, RotationTrigger::User] {
            assert_eq!(
                fx.rotation.rotate(trigger).await,
                RotationOutcome::NotDirect
            );
        }
    }
    assert!(fx.coord.calls().is_empty());
    assert!(
        fx.profiles.probes.lock().is_empty(),
        "the idle timer pings nothing (R8)"
    );
    fx.coord
        .set_session(SessionKind::SoftDirect, Owner::Manual, Some("a"));
    assert_eq!(
        fx.rotation.rotate(RotationTrigger::Timer).await,
        rotated("b")
    );
    assert_eq!(
        fx.coord.calls(),
        vec![Call::Switch(Owner::Rotation, "b".into())]
    );
}

/// R4: archived or disabled profiles are never chosen, live or idle.
#[tokio::test]
async fn archived_and_disabled_profiles_are_never_chosen() {
    let fx = fixture(&["a", "b", "c", "d"], 0, RotationOrder::Sequential);
    fx.profiles.facts.lock()[1].archived = true;
    fx.profiles.facts.lock()[2].enabled = false;
    fx.live_on("a");
    assert_eq!(
        fx.rotation.rotate(RotationTrigger::User).await,
        rotated("d")
    );
}

/// Starts an idle "rotate now" whose first probe hangs until released; returns its task.
async fn held_rotation(fx: &Fixture) -> (tokio::task::JoinHandle<RotationOutcome>, Arc<Notify>) {
    let hold = Arc::new(Notify::new());
    *fx.profiles.hold.lock() = Some(hold.clone());
    let task = tokio::spawn({
        let rotation = fx.rotation.clone();
        async move { rotation.rotate(RotationTrigger::User).await }
    });
    fx.profiles.entered.notified().await;
    (task, hold)
}

/// Disabling during a held probe cancels: nothing selected, committed, announced or re-armed.
#[tokio::test]
async fn config_change_cancels_a_rotation_in_flight() {
    let fx = fixture(&["a", "b"], 0, RotationOrder::Sequential);
    fx.reachable(&["b"]);
    let (task, _hold) = held_rotation(&fx).await;
    fx.rotation
        .set_config(RotationPatch {
            enabled: Some(false),
            ..Default::default()
        })
        .unwrap();
    let outcome = task.await.unwrap();
    assert_eq!(
        outcome,
        RotationOutcome::Aborted {
            reason: OpError::Cancelled.reason()
        }
    );
    assert_eq!(*fx.profiles.selected.lock(), None);
    assert!(fx.coord.notice_keys().is_empty());
    let cfg = fx.rotation.config();
    assert_eq!((cfg.current_index, cfg.next_rotation_at), (0, None));
}

/// Unchanged patches neither abort the rotation in flight nor move the countdown; a second
/// rotation meanwhile is refused (single flight).
#[tokio::test]
async fn unchanged_patches_keep_the_rotation_in_flight() {
    let fx = fixture(&["a", "b"], 0, RotationOrder::Sequential);
    fx.rotation
        .set_config(RotationPatch {
            interval_minutes: Some(5.0),
            ..Default::default()
        })
        .unwrap();
    let countdown = fx.rotation.config().next_rotation_at;
    fx.reachable(&["b"]);
    let (task, hold) = held_rotation(&fx).await;
    let ids = Some(vec!["a".to_string(), "b".to_string()]);
    for patch in [
        RotationPatch::default(),
        RotationPatch {
            enabled: Some(true),
            ..Default::default()
        },
        RotationPatch {
            interval_minutes: Some(5.0),
            ..Default::default()
        },
        RotationPatch {
            profile_ids: ids,
            ..Default::default()
        },
    ] {
        fx.rotation.set_config(patch).unwrap();
        assert_eq!(fx.rotation.config().next_rotation_at, countdown);
    }
    let busy = fx.rotation.rotate(RotationTrigger::User).await;
    assert_eq!(
        busy,
        RotationOutcome::NotStarted {
            reason: Msg::new("automation.rotation.busy")
        }
    );
    hold.notify_one();
    assert_eq!(task.await.unwrap(), rotated("b"));
}

/// R6: a future stored instant survives a restart; a past or missing one restarts from now.
#[test]
fn countdown_honours_a_future_stored_instant() {
    let fx = fixture(&["a", "b"], 0, RotationOrder::Sequential);
    let future = now_ms() + 10 * 60_000;
    fx.store
        .update(|c| c.next_rotation_at = Some(future))
        .unwrap();
    assert_eq!(fx.rotation.arm(), Some(future));
    fx.store
        .update(|c| c.next_rotation_at = Some(now_ms() - 1))
        .unwrap();
    let rearmed = fx.rotation.arm().unwrap();
    assert!(rearmed >= now_ms() + 29 * 60_000);
    assert_eq!(fx.rotation.config().next_rotation_at, Some(rearmed));
    fx.rotation
        .set_config(RotationPatch {
            enabled: Some(false),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(fx.rotation.arm(), None);
}

/// R7: ids are deduplicated on save and on load; an out-of-range index falls back to 0.
#[test]
fn ids_are_deduplicated() {
    let fx = fixture(&["a"], 0, RotationOrder::Sequential);
    let ids = ["b", "a", "b", "", "c", "a"].map(String::from).to_vec();
    let cfg = fx
        .rotation
        .set_config(RotationPatch {
            profile_ids: Some(ids),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(cfg.profile_ids, vec!["b", "a", "c"]);
    let dir = TempDir::new("rotation-file");
    let text =
        r#"{"schemaVersion":1,"enabled":true,"intervalMinutes":99999,"profileIds":["x","x","y"]}"#;
    std::fs::write(dir.path().join("rotation.json"), text).unwrap();
    let loaded = Store::<RotationConfig>::open(dir.path()).snapshot();
    assert_eq!(
        (loaded.interval_minutes, loaded.profile_ids.len()),
        (1440, 2)
    );
    std::fs::write(
        dir.path().join("rotation.json"),
        r#"{"intervalMinutes":"abc"}"#,
    )
    .unwrap();
    assert_eq!(
        Store::<RotationConfig>::open(dir.path())
            .snapshot()
            .interval_minutes,
        30
    );
}

/// One-time import: clamp, dedup, index range, `nextRotationAt` dropped.
#[test]
fn legacy_import() {
    let legacy = json!({ "rotation": { "enabled": true, "intervalMinutes": 2, "order": "random",
        "profileIds": ["a", "a", "b"], "currentIndex": 5, "nextRotationAt": 123 } });
    let cfg = RotationConfig::from_legacy(&legacy);
    let expected = RotationConfig {
        enabled: true,
        interval_minutes: 5,
        order: RotationOrder::Random,
        profile_ids: vec!["a".into(), "b".into()],
        current_index: 0,
        next_rotation_at: None,
    };
    assert_eq!(cfg, expected);
    assert_eq!(
        RotationConfig::from_legacy(&json!({})),
        RotationConfig::default()
    );
}

/// The timer loop fires at a stored instant, rotates the live session and re-arms.
#[tokio::test]
async fn timer_loop_rotates_when_due() {
    let fx = fixture(&["a", "b"], 0, RotationOrder::Sequential);
    fx.live_on("a");
    fx.store
        .update(|c| c.next_rotation_at = Some(now_ms() + 100))
        .unwrap();
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let (rotation, cancel) = (fx.rotation.clone(), cancel.clone());
        async move { rotation.run(cancel).await }
    });
    let mut changes = fx.rotation.subscribe();
    let switched = async {
        while fx.switches().is_empty() {
            changes.changed().await.unwrap();
        }
    };
    tokio::time::timeout(Duration::from_secs(10), switched)
        .await
        .unwrap();
    assert_eq!(fx.switches(), vec!["b"]);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        fx.rotation
            .config()
            .next_rotation_at
            .is_some_and(|t| t > now_ms() + 60_000)
    );
}

/// A server a check ruled out on this network (banned, frozen, offline) is never rotated to.
#[tokio::test]
async fn servers_ruled_out_on_this_network_are_skipped() {
    let f = fixture(&["a", "b", "c"], 0, RotationOrder::Sequential);
    let verdicts = Arc::new(Verdicts::scripted(false, &["b"]));
    let rotation =
        Rotation::new(f.store.clone(), f.coord.clone(), f.profiles.clone()).with_verdicts(verdicts);
    f.live_on("a");
    assert_eq!(rotation.rotate(RotationTrigger::Timer).await, rotated("c"));
    assert_eq!(f.switches(), ["c"]);
}

/// While UDP is cut on this network, a TCP-based profile is preferred over the next UDP one;
/// without the cut the list order holds.
#[tokio::test]
async fn tcp_profiles_go_first_while_udp_is_blocked() {
    let f = fixture(&["a", "hy2", "c"], 0, RotationOrder::Sequential);
    f.profiles.facts.lock()[1].udp = true;
    let blocked = Rotation::new(f.store.clone(), f.coord.clone(), f.profiles.clone())
        .with_verdicts(Arc::new(Verdicts::scripted(true, &[])));
    f.live_on("a");
    assert_eq!(blocked.rotate(RotationTrigger::Timer).await, rotated("c"));
    let open = Rotation::new(f.store.clone(), f.coord.clone(), f.profiles.clone())
        .with_verdicts(Arc::new(Verdicts::scripted(false, &[])));
    assert_eq!(open.rotate(RotationTrigger::Timer).await, rotated("a"));
    f.live_on("a");
    assert_eq!(open.rotate(RotationTrigger::Timer).await, rotated("hy2"));
}
