//! The API over a real backend: throw-away data dir, real server list (DPAPI as the current
//! user), a fake tunnel. No network: geo lookups are off, pings are answered by the fake.
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::i18n::Lang;
use vpnte_base::types::{ClientDevice, EnginePref, KillSwitchLevel, Owner};
use vpnte_base::{AppResult, Msg};
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
use vpnte_probes::ping::{NetPath, PingPath, PingSample};
use vpnte_servers::model::ProfileId;
use vpnte_servers::refresh::RefreshCtx;
use vpnte_servers::store::{SelectBy, Servers};
use vpnte_servers::subscription::{Hwids, SubscriptionFetcher};
use vpnte_tunnel::api::TunStatus;
use vpnte_tunnel::fsm::{TunnelSnapshot, TunnelState};
use vpnte_tunnel::history::{History, SessionMode};
use vpnte_tunnel::lifecycle::{ConnError, Done, SessionView, ShutdownReport};
use vpnte_winnet::wfp::{
    ExceptionKind, KillSwitchException, ProtectionSettings, RemoveReport, Toggles,
};

use vpnte_ui::servers::ServersView;

use crate::services::{Backend, Engines, KillSwitchStatus, TunnelOps};
use crate::svc_core::docs::{ProtectionDoc, SoftDoc, ThemesDoc};
use crate::svc_core::needs_admin;
use crate::svc_core::notify::Notifier;

/// The tunnel as the Servers page sees it: selection through the real list, a live switch that
/// waits for its cancel, pings answered with 33 ms and recorded like the real tunnel does.
pub(super) struct FakeTunnel {
    servers: Arc<Servers>,
    pub snapshot: watch::Sender<TunnelSnapshot>,
    pub session: watch::Sender<Option<SessionView>>,
    status: watch::Sender<TunStatus>,
    evidence: watch::Sender<IpEvidence>,
    traffic: watch::Sender<TrafficStats>,
    cancel: Notify,
}

impl FakeTunnel {
    /// Pretends our tunnel runs on `id`.
    pub fn connect_to(&self, id: &str) {
        self.session.send_replace(Some(SessionView {
            owner: Owner::Manual,
            profile_id: id.to_owned(),
            profile_name: id.to_owned(),
            mode: SessionMode::Soft,
            generation: Some(1),
            adaptive: Default::default(),
            started_at: 1,
            engine: None,
        }));
        self.snapshot
            .send_modify(|s| s.state = TunnelState::Connected);
    }
}

#[async_trait]
impl TunnelOps for FakeTunnel {
    async fn connect(&self, _source: Source) -> Result<Done, ConnError> {
        Err(ConnError::Refused(Msg::new("errors.conflict")))
    }
    async fn disconnect(&self, _source: Source) -> Result<Done, ConnError> {
        Err(ConnError::Refused(Msg::new("errors.conflict")))
    }
    fn cancel(&self) {
        self.cancel.notify_one();
    }
    async fn switch_server(&self, id: ProfileId, _source: Source) -> Result<Done, ConnError> {
        let selected = self.servers.select(&id, SelectBy::User);
        selected.map_err(|err| ConnError::Refused(err.user_msg()))?;
        if self.session.borrow().is_some() {
            self.cancel.notified().await;
            return Err(ConnError::Cancelled(Msg::new("errors.cancelled")));
        }
        Ok(Done {
            warnings: Vec::new(),
        })
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
            settings: ProtectionSettings::default(),
            wfp: None,
        }
    }
    async fn set_kill_switch_level(&self, _level: KillSwitchLevel) -> AppResult<()> {
        Err(needs_admin())
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
        Err(needs_admin())
    }
    fn traffic(&self) -> watch::Receiver<TrafficStats> {
        self.traffic.subscribe()
    }
    async fn ping(
        &self,
        ids: Vec<ProfileId>,
        _cancel: CancellationToken,
    ) -> AppResult<Vec<(ProfileId, Option<PingSample>)>> {
        let sample = PingSample {
            ms: 33,
            path: PingPath::Tcp,
        };
        for id in &ids {
            self.servers.record_ping(id, Some(sample.ms));
        }
        Ok(ids.into_iter().map(|id| (id, Some(sample))).collect())
    }
    fn probe_ctx(&self, device: ClientDevice) -> ProbeCtx {
        ProbeCtx {
            singbox_exe: PathBuf::new(),
            xray_exe: PathBuf::new(),
            engine_pref: EnginePref::Auto,
            device,
            net: NetPath::default(),
            dns_bootstrap_in: None,
        }
    }
    fn tun_available(&self) -> bool {
        false
    }
    async fn shutdown(&self, _budget: Duration) -> ShutdownReport {
        ShutdownReport::default()
    }
}

/// A backend over throw-away dirs (removed on drop) with the fake tunnel stored in it.
pub(super) struct Env {
    pub backend: Arc<Backend>,
    pub tunnel: Arc<FakeTunnel>,
    root: PathBuf,
}

impl Env {
    pub fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("vpnte-app-servers-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let resources = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
        let dirs = DataDirs::new(root.join("data"), root.join("legacy"), resources.clone());
        dirs.ensure().unwrap();
        let settings = Arc::new(Store::<Settings>::open(&dirs.root));
        settings
            .update(|s| {
                s.disable_geo_lookup = true;
                s.locale = Some(Lang::En);
            })
            .unwrap();
        let servers = Arc::new(Servers::open(&dirs.root));
        let ops = OperationRegistry::new();
        let fetcher = Arc::new(SubscriptionFetcher::new(Hwids::current(), settings.clone()));
        let rule_sets = Arc::new(Store::<RuleSetsDoc>::open(&dirs.root));
        let tunnel = Arc::new(FakeTunnel {
            servers: servers.clone(),
            snapshot: watch::Sender::new(TunnelSnapshot::default()),
            session: watch::Sender::new(None),
            status: watch::Sender::new(TunStatus::default()),
            evidence: watch::Sender::new(IpEvidence::default()),
            traffic: watch::Sender::new(TrafficStats::default()),
            cancel: Notify::new(),
        });
        let backend = Backend {
            lock: dirs.lock().unwrap(),
            log: Mutex::new(None),
            elevated: false,
            engines: Engines {
                singbox: resources.join("sing-box.exe"),
                xray: resources.join("xray.exe"),
            },
            protection: Arc::new(Store::<ProtectionDoc>::open(&dirs.root)),
            themes: Arc::new(Store::<ThemesDoc>::open(&dirs.root)),
            soft: Arc::new(Store::<SoftDoc>::open(&dirs.root)),
            rules: Arc::new(Store::<RulesDoc>::open(&dirs.root)),
            rule_sets: Arc::new(RuleSetService::new(rule_sets, &dirs)),
            history: History::open(&dirs.root),
            refresh: RefreshCtx::new(fetcher, ops.clone()),
            ops,
            geo: Geo::new(false),
            notifier: Arc::new(Notifier::new(settings.clone()).unwrap()),
            settings,
            servers,
            import: None,
            shutdown: CancellationToken::new(),
            clipboard: OnceLock::new(),
            tunnel: OnceLock::new(),
            dirs,
        };
        let shared: Arc<dyn TunnelOps> = tunnel.clone();
        let _ = backend.tunnel.set(shared);
        Self {
            backend: Arc::new(backend),
            tunnel,
            root,
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.backend.shutdown.cancel();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Waits (bounded) until the published snapshot satisfies `done`.
pub(super) async fn until(
    state: &mut watch::Receiver<ServersView>,
    done: impl Fn(&ServersView) -> bool,
) -> ServersView {
    let wait = state.wait_for(|v| done(v));
    let view = tokio::time::timeout(Duration::from_secs(5), wait).await;
    view.expect("snapshot in time")
        .expect("sender alive")
        .clone()
}
