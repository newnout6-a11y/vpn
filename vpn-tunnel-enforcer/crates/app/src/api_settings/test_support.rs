//! Test doubles shared by the Settings, wizard and Logs tests: a throw-away backend, a fake
//! tunnel that records what it was asked, and a fake autostart value (no real `Run` key).
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
use vpnte_tunnel::api::TunStatus;
use vpnte_tunnel::fsm::TunnelSnapshot;
use vpnte_tunnel::history::History;
use vpnte_tunnel::lifecycle::{ConnError, Done, SessionView, ShutdownReport};
use vpnte_winnet::autostart::{AutostartOs, AutostartState};
use vpnte_winnet::wfp::{
    ExceptionKind, KillSwitchException, ProtectionSettings, RemoveReport, Toggles,
};

use crate::services::{Backend, Engines, KillSwitchStatus, TunnelOps};
use crate::svc_core::docs::{ProtectionDoc, SoftDoc, ThemesDoc};
use crate::svc_core::needs_admin;
use crate::svc_core::notify::Notifier;

/// A throw-away directory under %TEMP%, removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("vpnte-app-settings-{name}-{}", std::process::id()));
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

/// A backend over `dir` with `tunnel` set, without logging (the process-wide subscriber is
/// app-base's test's) and without network activity.
pub fn backend(dir: &TempDir, tunnel: Arc<dyn TunnelOps>) -> Arc<Backend> {
    let resources = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
    let dirs = DataDirs::new(dir.0.join("data"), dir.0.join("legacy"), resources);
    dirs.ensure().expect("dirs");
    let root = dirs.root.clone();
    let settings = Arc::new(Store::<Settings>::open(&root));
    // Notices of the flows go to the in-app list only: no real toast on this desktop.
    settings
        .update(|s| s.desktop_notifications = false)
        .expect("settings");
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

/// An unelevated tunnel (no TUN, no WFP) that records the calls the Settings page makes.
pub struct FakeTunnel {
    pub tun: bool,
    pub snapshot: watch::Sender<TunnelSnapshot>,
    pub session: watch::Sender<Option<SessionView>>,
    pub status: watch::Sender<TunStatus>,
    pub evidence: watch::Sender<IpEvidence>,
    pub traffic: watch::Sender<TrafficStats>,
    pub level: Mutex<KillSwitchLevel>,
    /// `(old, new)` of every `apply_settings_change`.
    pub applied: Mutex<Vec<(Settings, Settings)>>,
    /// What the next `apply_settings_change` does with an open session.
    pub restart: Mutex<Restart>,
}

/// Behaviour of `apply_settings_change` while a session is open.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Restart {
    /// The engine is restarted (the session's generation moves on).
    Restarts,
    /// Nothing tunnel-shaping changed.
    Keeps,
    /// The restart fails.
    Fails,
}

impl FakeTunnel {
    pub fn new(tun: bool) -> Arc<Self> {
        Arc::new(Self {
            tun,
            snapshot: watch::Sender::new(TunnelSnapshot::default()),
            session: watch::Sender::new(None),
            status: watch::Sender::new(TunStatus::default()),
            evidence: watch::Sender::new(IpEvidence::default()),
            traffic: watch::Sender::new(TrafficStats::default()),
            level: Mutex::new(KillSwitchLevel::Off),
            applied: Mutex::new(Vec::new()),
            restart: Mutex::new(Restart::Keeps),
        })
    }

    /// Opens a session on engine run `generation`.
    pub fn open_session(&self, generation: u64) {
        self.session.send_replace(Some(SessionView {
            owner: vpnte_base::types::Owner::Manual,
            profile_id: "direct-vpn".into(),
            profile_name: "Test".into(),
            mode: vpnte_tunnel::history::SessionMode::Soft,
            generation: Some(generation),
            adaptive: vpnte_base::types::AdaptiveMode::Baseline,
            started_at: 1,
        }));
    }
}

#[async_trait]
impl TunnelOps for FakeTunnel {
    async fn connect(&self, _source: Source) -> Result<Done, ConnError> {
        Err(ConnError::Refused(Msg::new("test.notUsed")))
    }
    async fn disconnect(&self, _source: Source) -> Result<Done, ConnError> {
        Err(ConnError::Refused(Msg::new("test.notUsed")))
    }
    fn cancel(&self) {}
    async fn switch_server(&self, _id: ProfileId, _source: Source) -> Result<Done, ConnError> {
        Err(ConnError::Refused(Msg::new("test.notUsed")))
    }
    async fn apply_settings_change(&self, old: Settings, new: Settings) -> Result<Done, ConnError> {
        self.applied.lock().push((old, new));
        let open = self.session.borrow().is_some();
        match *self.restart.lock() {
            Restart::Restarts if open => {
                self.session.send_modify(|s| {
                    if let Some(s) = s {
                        s.generation = s.generation.map(|g| g + 1);
                    }
                });
                Ok(Done {
                    warnings: Vec::new(),
                })
            }
            Restart::Fails if open => Err(ConnError::Refused(Msg::new("test.restartFailed"))),
            _ => Ok(Done {
                warnings: Vec::new(),
            }),
        }
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
            settings: ProtectionSettings {
                level: *self.level.lock(),
                ..ProtectionSettings::default()
            },
            wfp: None,
        }
    }
    async fn set_kill_switch_level(&self, level: KillSwitchLevel) -> AppResult<()> {
        // Soft behaviour without WFP: off / standard only (SERVICES.md, app-tunnel).
        if level == KillSwitchLevel::Strict && !self.tun {
            return Err(needs_admin());
        }
        *self.level.lock() = level;
        Ok(())
    }
    async fn set_protection_toggles(&self, _toggles: Toggles) -> AppResult<()> {
        Err(needs_admin())
    }
    async fn add_exception(
        &self,
        _kind: ExceptionKind,
        _value: String,
        _label: String,
    ) -> AppResult<KillSwitchException> {
        Err(needs_admin())
    }
    async fn remove_exception(&self, _id: String) -> AppResult<()> {
        Err(needs_admin())
    }
    async fn release_kill_switch(&self) -> AppResult<RemoveReport> {
        Err(needs_admin())
    }
    fn ip_evidence(&self) -> watch::Receiver<IpEvidence> {
        self.evidence.subscribe()
    }
    async fn leak_check(&self, _cancel: CancellationToken) -> AppResult<CheckReport> {
        Err(AppError::new(ErrorKind::Network))
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
        unreachable!("not used by the Settings page")
    }
    fn tun_available(&self) -> bool {
        self.tun
    }
    async fn shutdown(&self, _budget: Duration) -> ShutdownReport {
        ShutdownReport::default()
    }
}

/// The `Run` value in memory; `user_off` = switched off in Task Manager.
#[derive(Default)]
pub struct FakeAutostart {
    pub present: Mutex<bool>,
    pub user_off: bool,
    pub fail: bool,
}

impl AutostartOs for FakeAutostart {
    fn apply(&self, enabled: bool) -> windows::core::Result<()> {
        if self.fail {
            return Err(windows::core::Error::from(
                windows::Win32::Foundation::E_ACCESSDENIED,
            ));
        }
        *self.present.lock() = enabled;
        Ok(())
    }
    fn read(&self) -> windows::core::Result<AutostartState> {
        Ok(match (*self.present.lock(), self.user_off) {
            (false, _) => AutostartState::Absent,
            (true, false) => AutostartState::Present { matches_exe: true },
            (true, true) => AutostartState::DisabledByUser { matches_exe: true },
        })
    }
    fn remove_legacy_task(&self) -> windows::core::Result<bool> {
        Ok(false)
    }
}
