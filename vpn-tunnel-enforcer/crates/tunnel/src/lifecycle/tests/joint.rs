//! The lane over the REAL runtime actor: `runtime::TunnelHandle` driven by the runtime package's
//! fake engines and capture. Each package's own tests fake the other side of the `Runtime` seam;
//! these check the seam itself (event order, native generations, error keys, who notifies).
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use vpnte_base::types::{EnginePref, Owner, ProxyKind};
use vpnte_core::ops::Source;
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;

use super::fakes::{FakeNotifier, FakeProfiles, FakeSoft, Services, eventually};
use super::user_stop;
use crate::api::VpnProfile;
use crate::fsm::TunnelState;
use crate::history::History;
use crate::lifecycle::{
    ConnectReq, ConnectTarget, Lifecycle, LifecycleDeps, ServerChoice, SwitchReq,
};
use crate::outcome::OutcomeKind;
use crate::runtime::TunnelHandle;
use crate::runtime::tests::{World, XRAY_KEY, XRAY_KEY_2};
use crate::test_support::TempDir;

/// A loopback port no real proxy uses (the runtime's watchdog would only probe it after
/// `proxy_watch`, 600 s in the runtime's test timings, so nothing is contacted).
const PROXY: &str = "127.0.0.1:20808";

struct Joint {
    lc: Lifecycle,
    world: Arc<World>,
    profiles: Arc<FakeProfiles>,
    settings: Arc<Store<Settings>>,
    notifier: Arc<FakeNotifier>,
    history: History,
    _dir: TempDir,
}

impl Joint {
    fn new() -> Self {
        let dir = TempDir::new("joint");
        let world = World::new();
        let runtime = TunnelHandle::spawn(crate::runtime::tests::deps(&world));
        let profiles = Arc::new(FakeProfiles::default());
        let settings = Arc::new(Store::<Settings>::open(&dir.0));
        let services = Arc::new(Services::default());
        let notifier = Arc::new(FakeNotifier::default());
        let history = History::open(&dir.0);
        let deps = LifecycleDeps {
            runtime: Arc::new(runtime),
            profiles: profiles.clone(),
            soft: Arc::new(FakeSoft::default()),
            monitor: services.clone(),
            forensics: services.clone(),
            proxies: services,
            notifier: notifier.clone(),
            history: history.clone(),
            settings: settings.clone(),
        };
        Self {
            lc: Lifecycle::spawn(deps),
            world,
            profiles,
            settings,
            notifier,
            history,
            _dir: dir,
        }
    }

    fn state(&self) -> TunnelState {
        self.lc.snapshot().borrow().state
    }

    fn kinds(&self) -> Vec<OutcomeKind> {
        let rows = self.history.list();
        rows.iter()
            .filter_map(|r| r.outcome.as_ref().map(|o| o.kind))
            .collect()
    }

    fn noticed(&self, name: &str) -> bool {
        let title = format!("tunnel.lifecycle.notice.{name}.title");
        self.notifier.titles().contains(&title)
    }

    fn ran(&self, step: &str) -> bool {
        self.world.log().iter().any(|l| l == step)
    }
}

fn proxy() -> ConnectReq {
    let target = ConnectTarget::LocalProxy {
        addr: PROXY.into(),
        kind: ProxyKind::Socks5,
    };
    ConnectReq::new(target, Owner::Manual, Source::Ui)
}

/// AT-02-005 across the seam: connected only on the runtime's receipt (native generation 1),
/// a user stop runs the runtime's full cleanup and writes one `user-stop` row.
#[tokio::test]
async fn connect_and_stop() {
    let j = Joint::new();
    j.lc.connect(proxy()).await.expect("connect");
    assert_eq!(j.state(), TunnelState::Connected);
    let session = j.lc.session().borrow().clone().expect("session");
    assert_eq!(session.generation, Some(1));
    assert!(j.noticed("connected"));
    j.lc.disconnect(user_stop()).await.expect("disconnect");
    assert_eq!(j.state(), TunnelState::Disconnected);
    assert!(j.lc.session().borrow().is_none());
    assert_eq!(j.kinds(), [OutcomeKind::UserStop]);
    for step in [
        "spawn:4100",
        "ready",
        "terminate:4100",
        "release",
        "wait-gone",
    ] {
        assert!(j.ran(step), "{step} in {:?}", j.world.log());
    }
}

/// L-14 across the seam: the runtime's `tunnel.runtime.tunSetup.*` error reaches the caller,
/// the row is `tun-setup-failed`, the runtime compensated and the lane admits the next start.
#[tokio::test]
async fn tun_setup_failure_is_recorded_as_such() {
    let j = Joint::new();
    j.world.ready_fail.store(true, Ordering::SeqCst);
    let err =
        j.lc.connect(proxy())
            .await
            .expect_err("capture never ready");
    assert_eq!(err.user_msg().key, "tunnel.runtime.tunSetup.adapter");
    assert_eq!(j.kinds(), [OutcomeKind::TunSetupFailed]);
    assert_ne!(j.state(), TunnelState::Connected);
    assert!(j.ran("terminate:4100") && j.ran("release"));
    j.world.ready_fail.store(false, Ordering::SeqCst);
    j.lc.connect(proxy()).await.expect("next connect");
    assert_eq!(j.state(), TunnelState::Connected);
}

/// H-05 across the seam: the runtime restarts a crashed engine itself (native generation 2);
/// the lane keeps the session, tells the user once per step and records nothing.
#[tokio::test]
async fn crash_restart_continues_the_session() {
    let j = Joint::new();
    j.lc.connect(proxy()).await.expect("connect");
    j.world.core(0).crash();
    eventually("restored notice", || j.noticed("restored")).await;
    assert!(j.noticed("crashRestarting"));
    assert_eq!(j.state(), TunnelState::Connected);
    let session = j.lc.session().borrow().clone().expect("session");
    assert_eq!(session.generation, Some(2));
    assert!(j.kinds().is_empty());
    j.lc.disconnect(user_stop()).await.expect("disconnect");
    assert_eq!(j.kinds(), [OutcomeKind::UserStop]);
}

/// Crash table across the seam: auto-restart off + standard kill switch keeps blocking; the
/// lane ends the session (the fake engine reports an unreachable upstream, which the end
/// classification puts first: `server-down`) and warns; a user stop then releases protection.
#[tokio::test]
async fn crash_without_restart_keeps_blocking_until_stopped() {
    let j = Joint::new();
    j.world.auto_restart.store(false, Ordering::SeqCst);
    j.lc.connect(proxy()).await.expect("connect");
    j.world.core(0).crash();
    eventually("session row", || !j.kinds().is_empty()).await;
    assert_eq!(j.kinds(), [OutcomeKind::ServerDown]);
    eventually("blocked notice", || j.noticed("crashBlocked")).await;
    assert!(!j.ran("release"), "protection kept: {:?}", j.world.log());
    assert_ne!(j.state(), TunnelState::Connected);
    j.lc.disconnect(user_stop()).await.expect("disconnect");
    assert!(j.ran("release"));
    assert_eq!(j.state(), TunnelState::Disconnected);
    assert_eq!(j.kinds().len(), 1, "no second row for the stop");
}

/// A-06 across the seam: shutdown stops the real runtime within its budget, `app-quit` row.
#[tokio::test]
async fn shutdown_stops_the_runtime() {
    let j = Joint::new();
    j.lc.connect(proxy()).await.expect("connect");
    let report = j.lc.shutdown(Duration::from_secs(5)).await;
    assert!(report.engines_stopped && !report.timed_out, "{report:?}");
    assert_eq!(j.kinds(), [OutcomeKind::AppQuit]);
    assert!(j.ran("release"));
}

/// A server-list entry from one of the runtime tests' fake Xray keys.
fn xray_server(id: &str, uri: &str) -> ServerChoice {
    let profile = vpnte_profiles::uri::parse_uri(uri).expect("fake key parses");
    ServerChoice {
        server: VpnProfile {
            id: id.to_owned(),
            profile: Arc::new(profile),
            device: None,
        },
        country: None,
    }
}

/// AT-02-002 across the seam: on Xray slots the real runtime swaps the upstream in place
/// (stage B, select, commit); the lane closes the old server's session as a server switch and
/// keeps the engine run (same native generation, one sing-box process).
#[tokio::test]
async fn in_place_switch_on_xray_slots() {
    let j = Joint::new();
    j.settings
        .update(|s| s.proxy_engine = EnginePref::Xray)
        .expect("settings");
    for (id, uri) in [("srv-a", XRAY_KEY), ("srv-b", XRAY_KEY_2)] {
        let entry = xray_server(id, uri);
        j.profiles.servers.lock().insert(id.to_owned(), entry);
    }
    let target = ConnectTarget::DirectVpn {
        profile_id: Some("srv-a".into()),
    };
    let connect = ConnectReq::new(target, Owner::Manual, Source::Ui);
    j.lc.connect(connect).await.expect("connect");
    let before = j.lc.session().borrow().clone().expect("session");
    let switch = SwitchReq::new("srv-b", Owner::Manual, Source::Ui);
    j.lc.switch_upstream(switch).await.expect("switch");
    assert_eq!(j.kinds(), [OutcomeKind::ServerSwitch]);
    let after = j.lc.session().borrow().clone().expect("session");
    assert_eq!(after.profile_id, "srv-b");
    assert_eq!(after.generation, before.generation, "same engine run");
    assert!(j.ran("select:b"), "{:?}", j.world.log());
    assert_eq!(j.world.cores.lock().len(), 1, "sing-box untouched");
    assert_eq!(j.state(), TunnelState::Connected);
}
