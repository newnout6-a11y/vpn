//! Action flows over a fake tunnel and a throw-away backend: what each action publishes, and
//! when (the UI renders only pushed views).
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, KillSwitchLevel};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::ops::{OperationRegistry, Source};
use vpnte_core::paths::DataDirs;
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::rulesets::{RuleSetService, RuleSetsDoc};
use vpnte_forensics::traffic::TrafficStats;
use vpnte_probes::geo::Geo;
use vpnte_probes::ip_monitor::IpEvidence;
use vpnte_probes::key_health::ProbeCtx;
use vpnte_probes::leak::CheckReport;
use vpnte_probes::ping::PingSample;
use vpnte_servers::model::ProfileId;
use vpnte_servers::refresh::RefreshCtx;
use vpnte_servers::store::Servers;
use vpnte_servers::subscription::{Hwids, SubscriptionFetcher};
use vpnte_tunnel::api::{TunError, TunStatus};
use vpnte_tunnel::fsm::{Transition, TunnelSnapshot, TunnelState};
use vpnte_tunnel::history::History;
use vpnte_tunnel::lifecycle::{ConnError, Done, SessionView, ShutdownReport};
use vpnte_winnet::wfp::{ExceptionKind, KillSwitchException, RemoveReport, Toggles};

use super::{Hub, feeds};
use crate::services::{Backend, Engines, KillSwitchStatus, TunnelOps};
use crate::svc_core::docs::{ProtectionDoc, SoftDoc, ThemesDoc};
use crate::svc_core::notify::Notifier;

/// A throw-away data dir under %TEMP%, removed on drop.
pub(super) struct TempDir(pub PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("vpnte-app-dashboard-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A backend over `dir` without logging (the process-wide subscriber is app-base's test's).
fn backend(dir: &TempDir, tunnel: Arc<dyn TunnelOps>) -> Arc<Backend> {
    let resources = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
    let dirs = DataDirs::new(dir.0.join("data"), dir.0.join("legacy"), resources);
    dirs.ensure().expect("dirs");
    let root = dirs.root.clone();
    let settings = Arc::new(Store::<Settings>::open(&root));
    let ops = OperationRegistry::new();
    let fetcher = Arc::new(SubscriptionFetcher::new(Hwids::current(), settings.clone()));
    let backend = Backend {
        lock: dirs.lock().expect("data lock"),
        log: Mutex::new(None),
        elevated: false,
        engines: Engines {
            singbox: dirs.resources.join("sing-box.exe"),
            xray: dirs.resources.join("xray.exe"),
        },
        protection: Arc::new(Store::<ProtectionDoc>::open(&root)),
        themes: Arc::new(Store::<ThemesDoc>::open(&root)),
        soft: Arc::new(Store::<SoftDoc>::open(&root)),
        rules: Arc::new(Store::<RulesDoc>::open(&root)),
        rule_sets: Arc::new(RuleSetService::new(
            Arc::new(Store::<RuleSetsDoc>::open(&root)),
            &dirs,
        )),
        history: History::open(&root),
        servers: Arc::new(Servers::open(&root)),
        refresh: RefreshCtx::new(fetcher, ops.clone()),
        ops,
        geo: Geo::new(false),
        notifier: Arc::new(Notifier::new(settings.clone()).expect("notifier")),
        settings,
        import: None,
        shutdown: CancellationToken::new(),
        clipboard: OnceLock::new(),
        tunnel: OnceLock::new(),
        dirs,
    };
    let _ = backend.tunnel.set(tunnel);
    Arc::new(backend)
}

/// A tunnel whose connect / switch run until [`TunnelOps::cancel`], then end cancelled.
pub(super) struct FakeTunnel {
    pub snapshot: watch::Sender<TunnelSnapshot>,
    pub session: watch::Sender<Option<SessionView>>,
    pub status: watch::Sender<TunStatus>,
    pub evidence: watch::Sender<IpEvidence>,
    pub traffic: watch::Sender<TrafficStats>,
    /// Released by `cancel`.
    pub gate: Mutex<CancellationToken>,
    /// What the next disconnect / leak check / shutdown answer.
    pub disconnect_warnings: Vec<Msg>,
    pub leak: Mutex<Option<CheckReport>>,
    pub shutdown: Mutex<ShutdownReport>,
}

impl FakeTunnel {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            snapshot: watch::Sender::new(TunnelSnapshot::default()),
            session: watch::Sender::new(None),
            status: watch::Sender::new(TunStatus::default()),
            evidence: watch::Sender::new(IpEvidence::default()),
            traffic: watch::Sender::new(TrafficStats::default()),
            gate: Mutex::new(CancellationToken::new()),
            disconnect_warnings: vec![Msg::new("w.one"), Msg::new("w.two")],
            leak: Mutex::new(None),
            shutdown: Mutex::new(ShutdownReport::default()),
        })
    }

    pub fn transition(&self, state: TunnelState, transition: Option<Transition>) {
        self.snapshot.send_modify(|s| {
            s.revision += 1;
            s.state = state;
            s.transition = transition;
        });
    }

    /// Holds a lane call until cancelled; ends it cancelled with a recovery warning.
    async fn held(&self, transition: Transition) -> Result<Done, ConnError> {
        let gate = {
            let mut gate = self.gate.lock();
            *gate = CancellationToken::new();
            gate.clone()
        };
        self.transition(TunnelState::Disconnected, Some(transition));
        gate.cancelled().await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        self.transition(TunnelState::Disconnected, None);
        let err = TunError::new(ErrorKind::Cancelled, Msg::new("errors.cancelled"))
            .with_warning(Msg::new("w.recovery"));
        Err(ConnError::Failed(err))
    }
}

#[async_trait]
impl TunnelOps for FakeTunnel {
    async fn connect(&self, _source: Source) -> Result<Done, ConnError> {
        self.held(Transition::Connecting).await
    }
    async fn disconnect(&self, _source: Source) -> Result<Done, ConnError> {
        self.transition(TunnelState::Disconnected, None);
        Ok(Done {
            warnings: self.disconnect_warnings.clone(),
        })
    }
    fn cancel(&self) {
        self.gate.lock().cancel();
    }
    async fn switch_server(&self, _id: ProfileId, _source: Source) -> Result<Done, ConnError> {
        match self.held(Transition::Reconnecting).await {
            Ok(done) => Ok(done),
            Err(_) => Err(ConnError::Cancelled(Msg::new("errors.cancelled"))),
        }
    }
    async fn apply_settings_change(
        &self,
        _old: Settings,
        _new: Settings,
    ) -> Result<Done, ConnError> {
        Ok(Done {
            warnings: Vec::new(),
        })
    }
    fn snapshot(&self) -> watch::Receiver<TunnelSnapshot> {
        self.snapshot.subscribe()
    }
    fn session(&self) -> watch::Receiver<Option<SessionView>> {
        self.session.subscribe()
    }
    fn runtime_status(&self) -> watch::Receiver<TunStatus> {
        self.status.subscribe()
    }
    async fn kill_switch(&self) -> KillSwitchStatus {
        KillSwitchStatus {
            settings: Default::default(),
            wfp: None,
        }
    }
    async fn set_kill_switch_level(&self, _level: KillSwitchLevel) -> AppResult<()> {
        Err(crate::svc_core::needs_admin())
    }
    async fn set_protection_toggles(&self, _toggles: Toggles) -> AppResult<()> {
        Err(crate::svc_core::needs_admin())
    }
    async fn add_exception(
        &self,
        _kind: ExceptionKind,
        _value: String,
        _label: String,
    ) -> AppResult<KillSwitchException> {
        Err(crate::svc_core::needs_admin())
    }
    async fn remove_exception(&self, _id: String) -> AppResult<()> {
        Err(crate::svc_core::needs_admin())
    }
    async fn release_kill_switch(&self) -> AppResult<RemoveReport> {
        Err(crate::svc_core::needs_admin())
    }
    fn ip_evidence(&self) -> watch::Receiver<IpEvidence> {
        self.evidence.subscribe()
    }
    async fn leak_check(&self, _cancel: CancellationToken) -> AppResult<CheckReport> {
        self.leak
            .lock()
            .clone()
            .ok_or_else(|| AppError::new(ErrorKind::Network))
    }
    fn traffic(&self) -> watch::Receiver<TrafficStats> {
        self.traffic.subscribe()
    }
    async fn ping(
        &self,
        ids: Vec<ProfileId>,
        _cancel: CancellationToken,
    ) -> AppResult<Vec<(ProfileId, Option<PingSample>)>> {
        Ok(ids.into_iter().map(|id| (id, None)).collect())
    }
    fn probe_ctx(&self, _device: ClientDevice) -> ProbeCtx {
        unreachable!("not used by the start page")
    }
    fn tun_available(&self) -> bool {
        false
    }
    async fn shutdown(&self, _budget: Duration) -> ShutdownReport {
        *self.shutdown.lock()
    }
}

/// A hub over a fake tunnel with its feeds running.
pub(super) fn setup(name: &str) -> (Arc<Hub>, Arc<FakeTunnel>, TempDir) {
    let dir = TempDir::new(name);
    let fake = FakeTunnel::new();
    let hub = Hub::new(backend(&dir, fake.clone()));
    feeds::spawn(&hub);
    (hub, fake, dir)
}

/// Fails the test instead of hanging it.
async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .expect("timed out")
}

mod cases {
    use vpnte_base::types::Verdict;
    use vpnte_core::ops::{FeatureKind, RunOpts};
    use vpnte_probes::leak::CheckStatus;
    use vpnte_ui::dashboard::DashboardApi;
    use vpnte_ui::panels::{PanelsApi, Selected};
    use vpnte_ui::tray::{QuitMode, TrayApi};
    use vpnte_view::swiss::{self, Busy};

    use super::super::traits::{Dashboard, Panels, Tray};
    use super::*;

    /// AT-00-003 / AT-00-008 #16-17: «Отмена» shows at once, holds until the connect is over,
    /// and answers with the recovery warning; the connect itself ends quietly cancelled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_is_held_until_the_connect_is_over() {
        let (hub, _fake, _dir) = setup("cancel");
        let dash = Dashboard(hub.clone());
        let mut view = dash.state();
        let (connect, (answer, saw_cancelling)) = within(async {
            tokio::join!(dash.connect(), async {
                let connecting = Some(swiss::Transition::Connecting);
                let _ = view.wait_for(|v| v.conn.transition == connecting).await;
                let mut watch = dash.state();
                tokio::join!(dash.cancel(), async {
                    let held = |v: &vpnte_ui::dashboard::DashboardView| {
                        v.conn.cancelling && v.conn.busy() == Some(Busy::Disconnecting)
                    };
                    watch.wait_for(held).await.is_ok()
                })
            })
        })
        .await;
        assert_eq!(connect.unwrap_err().kind, ErrorKind::Cancelled);
        assert_eq!(answer.unwrap().map(|m| m.key), Some("w.recovery".into()));
        assert!(saw_cancelling);
        let last = dash.state().borrow().clone();
        assert!(!last.conn.cancelling && last.conn.busy().is_none());
        assert_eq!(last.conn.state, swiss::TunnelState::Disconnected);
        assert!(!hub.servers.borrow().locked);
    }

    /// The panel's selection is published (and the list locked) before the switch runs; a
    /// cancelled switch answers `Cancelled` and unlocks the list.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn select_publishes_first_and_maps_a_cancelled_switch() {
        let (hub, fake, _dir) = setup("select");
        let panels = Panels(hub.clone());
        let mut servers = panels.servers();
        let mut snap = fake.snapshot.subscribe();
        let (selected, saw_optimistic) = within(async {
            tokio::join!(panels.select_server("p-1"), async {
                let optimistic = servers
                    .wait_for(|v| v.active_id.as_deref() == Some("p-1") && v.locked)
                    .await
                    .is_ok();
                let _ = snap.wait_for(|s| s.transition.is_some()).await;
                fake.cancel();
                optimistic
            })
        })
        .await;
        assert!(saw_optimistic);
        assert_eq!(selected.unwrap(), Selected::Cancelled);
        let last = panels.servers().borrow().clone();
        assert_eq!(last.active_id, None, "no server list: nothing selected");
        assert!(!last.locked);
    }

    /// The exit cleanup: a failed Soft rollback refuses the exit under «Restore»; «Выйти без
    /// восстановления» exits and closes the feature operations.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quit_refuses_a_failed_restore_and_exits_when_skipped() {
        let (hub, fake, _dir) = setup("quit");
        let tray = Tray(hub.clone());
        *fake.shutdown.lock() = ShutdownReport {
            engines_stopped: true,
            ..ShutdownReport::default()
        };
        let refused = within(tray.quit(QuitMode::Restore)).await.unwrap_err();
        assert_eq!(refused.user_msg().key, "app.dashboard.restoreFailed");
        assert!(hub.backend.shutdown.is_cancelled());
        within(tray.quit(QuitMode::SkipRestore))
            .await
            .expect("exit allowed");
        let late = hub
            .backend
            .ops
            .run(FeatureKind::LeakCheck, RunOpts::default(), |_| async {
                Ok(())
            })
            .await;
        assert_eq!(late.unwrap_err().kind, ErrorKind::Conflict, "ops closed");
    }

    /// The leak fact holds the last check's verdict; every transition clears it, and a failed
    /// run leaves none.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn leak_verdict_lands_and_a_transition_clears_it() {
        let (hub, fake, _dir) = setup("leak");
        let dash = Dashboard(hub.clone());
        let report = |summary| CheckReport {
            ran_at: 0,
            summary,
            headline: Msg::new("probes.leak.check.summary.warn"),
            items: Vec::new(),
        };
        *fake.leak.lock() = Some(report(CheckStatus::Warn));
        assert_eq!(within(dash.run_leak_check()).await.unwrap(), Verdict::Warn);
        assert_eq!(dash.state().borrow().leak, Verdict::Warn);

        let mut view = dash.state();
        fake.transition(TunnelState::Disconnected, Some(Transition::Connecting));
        let _ = within(view.wait_for(|v| v.leak == Verdict::NotChecked)).await;
        fake.transition(TunnelState::Disconnected, None);
        let _ = within(view.wait_for(|v| v.conn.transition.is_none())).await;

        *fake.leak.lock() = Some(report(CheckStatus::Fail));
        assert_eq!(within(dash.run_leak_check()).await.unwrap(), Verdict::Fail);
        *fake.leak.lock() = None;
        assert!(within(dash.run_leak_check()).await.is_err());
        assert_eq!(dash.state().borrow().leak, Verdict::NotChecked);
    }

    /// Disconnect answers its first recovery warning; Smart RU is saved and published before
    /// the call returns; the external-proxy column stays empty and says why.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disconnect_smart_ru_and_the_empty_proxy_column() {
        let (hub, _fake, _dir) = setup("misc");
        let dash = Dashboard(hub.clone());
        let warning = within(dash.disconnect()).await.unwrap();
        assert_eq!(warning.map(|m| m.key), Some("w.one".into()));

        let before = dash.state().borrow().smart_ru;
        within(dash.set_smart_ru(!before)).await.unwrap();
        assert_eq!(dash.state().borrow().smart_ru, !before);
        assert_eq!(hub.backend.settings.read(|s| s.smart_ru_split), !before);

        let panels = Panels(hub.clone());
        assert_eq!(*panels.proxies().borrow(), Default::default());
        let err = within(panels.proxy_start(1, "p-1")).await.unwrap_err();
        assert_eq!(err.user_msg().key, "app.dashboard.proxiesUnavailable");
        assert!(within(panels.proxy_refresh()).await.is_ok());
    }
}
