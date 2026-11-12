//! The coordinator over a fake lane: owner admission, proxy sessions over a list server, switch
//! outcomes, the adaptive restart's `Started`, events forwarded from the lane.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_automation::coordinator::{
    ConnectOutcome, ConnectRequest, Coordinator, LifecycleEvent, OpError, SessionKind,
    StopCause as AutoStop, SwitchError,
};
use vpnte_base::types::{AdaptiveMode, ClientDevice, Owner};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_servers::store::{AddTarget, Servers};
use vpnte_tunnel::history::SessionMode;
use vpnte_tunnel::lifecycle::{
    ConnError, ConnectReq, ConnectTarget, DisconnectReq, Done, SessionEvent, SessionView,
    StopCause, SwitchReq,
};
use vpnte_tunnel::outcome::OutcomeKind;

use super::pure::view;
use crate::api_settings::test_support::TempDir;
use crate::svc_auto::coord::{AppCoordinator, Detect};
use crate::svc_auto::events;
use crate::svc_auto::lane::Lane;
use crate::svc_core::notify::Notifier;

/// A lane that does what it is told and records every call.
pub struct FakeLane {
    session: watch::Sender<Option<SessionView>>,
    events: broadcast::Sender<SessionEvent>,
    calls: Mutex<Vec<String>>,
    generation: AtomicU64,
    busy: AtomicBool,
    /// The next switch fails; `true` = the session was lost with it.
    switch_fails: Mutex<Option<bool>>,
}

impl FakeLane {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            session: watch::Sender::new(None),
            events: broadcast::channel(16).0,
            calls: Mutex::new(Vec::new()),
            generation: AtomicU64::new(0),
            busy: AtomicBool::new(false),
            switch_fails: Mutex::new(None),
        })
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().clone()
    }

    fn up(&self, mode: SessionMode, id: &str, owner: Owner) {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let view = view(mode, id, owner, generation);
        self.session.send_replace(Some(view.clone()));
        let _ = self.events.send(SessionEvent::Up(view));
    }

    fn end(&self, outcome: OutcomeKind) {
        if let Some(session) = self.session.send_replace(None) {
            let _ = self.events.send(SessionEvent::Ended { session, outcome });
        }
    }
}

#[async_trait]
impl Lane for FakeLane {
    async fn connect(&self, req: ConnectReq) -> Result<Done, ConnError> {
        self.calls
            .lock()
            .push(format!("connect {:?} {:?}", req.target, req.owner));
        let (mode, id) = match &req.target {
            ConnectTarget::DirectVpn { profile_id } => (SessionMode::Direct, profile_id.clone()),
            ConnectTarget::SoftVpn { profile_id } => (SessionMode::Soft, profile_id.clone()),
            ConnectTarget::LocalProxy { .. } => (SessionMode::Hard, Some("local-proxy".into())),
            ConnectTarget::Soft { .. } => (SessionMode::Soft, Some("local-proxy-soft-http".into())),
        };
        self.up(mode, &id.unwrap_or_default(), req.owner);
        Ok(Done::default())
    }

    async fn disconnect(&self, req: DisconnectReq) -> Result<Done, ConnError> {
        self.calls
            .lock()
            .push(format!("disconnect {:?} {:?}", req.cause, req.owner));
        let outcome = match req.cause {
            StopCause::User => OutcomeKind::UserStop,
            StopCause::Schedule => OutcomeKind::Schedule,
            _ => OutcomeKind::Unknown,
        };
        self.end(outcome);
        Ok(Done::default())
    }

    async fn switch(&self, req: SwitchReq, rotation: bool) -> Result<Done, ConnError> {
        self.calls
            .lock()
            .push(format!("switch {} rotation={rotation}", req.profile_id));
        let failed = self.switch_fails.lock().take();
        if let Some(lost) = failed {
            if lost {
                self.end(OutcomeKind::ServerSwitch);
            }
            return Err(ConnError::Refused(Msg::new("x.switchFailed")));
        }
        let current = self.session.borrow().clone().expect("a session to switch");
        self.end(OutcomeKind::ServerSwitch);
        self.up(current.mode, &req.profile_id, current.owner);
        Ok(Done::default())
    }

    async fn restart_adaptive(
        &self,
        mode: AdaptiveMode,
        sibling: Option<String>,
        owner: Owner,
    ) -> Result<Done, ConnError> {
        self.calls
            .lock()
            .push(format!("adaptive {mode:?} {sibling:?} {owner:?}"));
        let current = self.session.borrow().clone().expect("a session to restart");
        self.up(current.mode, &current.profile_id, current.owner);
        Ok(Done::default())
    }

    fn session(&self) -> watch::Receiver<Option<SessionView>> {
        self.session.subscribe()
    }

    fn events(&self) -> broadcast::Receiver<SessionEvent> {
        self.events.subscribe()
    }

    fn busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    fn adopt(&self, owner: Owner) {
        self.calls.lock().push(format!("adopt {owner:?}"));
    }
}

pub struct Rig {
    pub lane: Arc<FakeLane>,
    pub coord: Arc<AppCoordinator>,
    pub servers: Arc<Servers>,
    pub settings: Arc<Store<Settings>>,
    pub ids: Vec<String>,
    _dir: TempDir,
}

/// Two servers in the list; no TUN (unelevated, the normal case).
pub fn rig(name: &str) -> Rig {
    let dir = TempDir::new(&format!("auto-coord-{name}"));
    let settings = Arc::new(Store::<Settings>::open(&dir.0));
    settings
        .update(|s| s.desktop_notifications = false)
        .expect("settings");
    let servers = Arc::new(Servers::open(&dir.0));
    let keys = ["a", "b"].map(|n| {
        let uri = format!(
            "vless://00000000-0000-4000-8000-000000000001@198.51.100.{}:443?security=tls&sni={n}.test&type=tcp#{n}",
            u8::from(n == "b") + 1
        );
        vpnte_profiles::uri::parse_uri(&uri).expect("fake key parses")
    });
    let target = AddTarget::Keys {
        group: None,
        device: ClientDevice::Pc,
    };
    let report = servers.add(keys.to_vec(), target).expect("servers");
    let ids = report.added.iter().map(|id| id.0.clone()).collect();
    let lane = FakeLane::new();
    let notifier = Arc::new(Notifier::new(settings.clone()).expect("notifier"));
    let detect: Detect = Arc::new(|| Box::pin(async { None }));
    let coord = Arc::new(AppCoordinator::new(
        lane.clone(),
        servers.clone(),
        notifier,
        detect,
        false,
    ));
    Rig {
        lane,
        coord,
        servers,
        settings,
        ids,
        _dir: dir,
    }
}

fn proxy(id: &str) -> ConnectRequest {
    ConnectRequest::SoftDirect {
        profile_id: id.into(),
    }
}

/// NOADMIN §2: a proxy session over a list server starts without administrator rights; a TUN
/// request answers `Permission` up front (never a silent Soft); an unknown server is refused
/// before the lane is asked.
#[tokio::test]
async fn proxy_sessions_over_a_server_start_unelevated() {
    let r = rig("start");
    let a = r.ids[0].clone();
    let outcome = r
        .coord
        .connect(Owner::Schedule, proxy(&a))
        .await
        .expect("proxy session");
    assert_eq!(outcome, ConnectOutcome::Connected);
    let session = r.coord.session().expect("session");
    assert_eq!(
        (session.kind, session.owner),
        (SessionKind::SoftDirect, Owner::Schedule)
    );
    assert_eq!(session.profile_id.as_deref(), Some(a.as_str()));
    r.lane.end(OutcomeKind::UserStop);
    let tun = ConnectRequest::Direct {
        profile_id: a.clone(),
    };
    let err = r
        .coord
        .connect(Owner::Schedule, tun)
        .await
        .expect_err("no TUN");
    assert!(
        matches!(&err, OpError::Failed(e) if e.kind == ErrorKind::Permission),
        "{err:?}"
    );
    let err = r
        .coord
        .connect(Owner::Schedule, proxy("gone"))
        .await
        .expect_err("unknown");
    assert!(matches!(err, OpError::ProfileUnavailable));
    let local = ConnectRequest::Soft { endpoint: None };
    let err = r
        .coord
        .connect(Owner::Schedule, local)
        .await
        .expect_err("no local proxy");
    assert!(matches!(err, OpError::NoLocalProxy));
    assert_eq!(r.lane.calls().len(), 1, "{:?}", r.lane.calls());
}

/// Owner order: the very session is adopted by a higher caller; a lower owner never takes or
/// stops a higher owner's session; another kind is replaced (stop, then start) for an owner at
/// least as high.
#[tokio::test]
async fn owners_pre_empt_lower_owners_only() {
    let r = rig("owners");
    let (a, b) = (r.ids[0].clone(), r.ids[1].clone());
    r.lane.up(SessionMode::Soft, &a, Owner::Schedule);
    let again = r.coord.connect(Owner::Manual, proxy(&a)).await.unwrap();
    assert_eq!(again, ConnectOutcome::AlreadyConnected);
    assert_eq!(r.lane.calls(), ["adopt Manual"]);
    r.lane.up(SessionMode::Soft, &a, Owner::Manual);
    let refused = r.coord.connect(Owner::Schedule, proxy(&b)).await;
    assert!(matches!(refused, Err(OpError::Conflict)));
    assert!(matches!(
        r.coord.disconnect(Owner::Schedule).await,
        Err(OpError::Conflict)
    ));
    r.lane
        .up(SessionMode::Soft, "local-proxy-soft-http", Owner::Autopilot);
    r.coord
        .connect(Owner::Schedule, proxy(&b))
        .await
        .expect("replaced");
    let calls = r.lane.calls();
    assert!(
        calls[1].starts_with("disconnect Schedule Schedule"),
        "{calls:?}"
    );
    assert!(calls[2].starts_with("connect SoftVpn"), "{calls:?}");
    r.coord
        .disconnect(Owner::Schedule)
        .await
        .expect("own session");
    assert!(r.coord.session().is_none());
    r.coord
        .disconnect(Owner::AdaptiveRetry)
        .await
        .expect("nothing runs: quiet");
}

/// A switch keeps the capture and the owner and commits the selection only on success; one that
/// never took leaves the previous server running (`NotStarted`); one that lost it brings the
/// previous server back under the session's owner.
#[tokio::test]
async fn switches_restore_the_previous_server() {
    let r = rig("switch");
    let (a, b) = (r.ids[0].clone(), r.ids[1].clone());
    r.lane.up(SessionMode::Soft, &a, Owner::Manual);
    r.coord
        .switch_profile(Owner::Rotation, &b)
        .await
        .expect("switched");
    let session = r.coord.session().expect("session");
    assert_eq!(
        (session.kind, session.owner),
        (SessionKind::SoftDirect, Owner::Manual)
    );
    assert_eq!(r.servers.active().map(|s| s.row.id.0), Some(b.clone()));
    assert!(
        r.lane
            .calls()
            .contains(&format!("switch {b} rotation=true"))
    );

    *r.lane.switch_fails.lock() = Some(false);
    let kept = r.coord.switch_profile(Owner::AdaptiveRetry, &a).await;
    assert!(
        matches!(kept, Err(SwitchError::NotStarted(OpError::Conflict))),
        "{kept:?}"
    );

    *r.lane.switch_fails.lock() = Some(true);
    let lost = r.coord.switch_profile(Owner::AdaptiveRetry, &a).await;
    assert!(
        matches!(
            lost,
            Err(SwitchError::Failed {
                restored_previous: true,
                ..
            })
        ),
        "{lost:?}"
    );
    let back = r.coord.session().expect("previous server back");
    assert_eq!(
        (back.profile_id.as_deref(), back.owner),
        (Some(b.as_str()), Owner::Manual)
    );
    let local = r
        .coord
        .connect(Owner::Manual, ConnectRequest::Soft { endpoint: None })
        .await;
    assert!(local.is_err(), "no local proxy detected in this rig");
}

/// The session forwarder turns lane changes into lifecycle events (a switch only `Started`, a
/// stop this coordinator asked for names its owner), and the adaptive restart answers only once
/// its run's `Started` went out.
#[tokio::test]
async fn lane_changes_reach_automation_in_order() {
    let r = rig("events");
    let (a, b) = (r.ids[0].clone(), r.ids[1].clone());
    let cancel = CancellationToken::new();
    tokio::spawn(events::sessions(r.coord.clone(), None, cancel.clone()));
    tokio::task::yield_now().await;
    let mut seen = r.coord.events();
    r.coord.connect(Owner::Schedule, proxy(&a)).await.unwrap();
    r.coord.switch_profile(Owner::Rotation, &b).await.unwrap();
    let runtime = r
        .coord
        .adaptive_restart(Owner::AdaptiveRetry, AdaptiveMode::TlsCompatibility, None)
        .await
        .expect("restarted");
    r.coord.disconnect(Owner::Schedule).await.unwrap();
    let mut got = Vec::new();
    while got.len() < 4 {
        got.push(seen.recv().await.expect("event"));
    }
    let started: Vec<_> = got
        .iter()
        .filter_map(|e| match e {
            LifecycleEvent::Started {
                runtime_id,
                profile_id,
                ..
            } => Some((runtime_id.0, profile_id.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        started,
        [
            (1, Some(a.clone())),
            (2, Some(b.clone())),
            (3, Some(b.clone()))
        ]
    );
    assert_eq!(runtime.0, 3);
    assert!(matches!(
        got[3],
        LifecycleEvent::Stopped {
            cause: AutoStop::Requested(Owner::Schedule),
            ..
        }
    ));
    cancel.cancel();
}

/// `busy` mirrors the lane; an error of the lane keeps its own message.
#[tokio::test]
async fn busy_and_failures_come_from_the_lane() {
    let r = rig("busy");
    assert!(!r.coord.busy());
    r.lane.busy.store(true, Ordering::SeqCst);
    assert!(r.coord.busy());
    let failed = crate::svc_auto::decide::op_error(ConnError::Failed(
        AppError::msg(ErrorKind::Internal, Msg::new("x.engine")).into(),
    ));
    assert_eq!(failed.reason().key, "x.engine");
}
