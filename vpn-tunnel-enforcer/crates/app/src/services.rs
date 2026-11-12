//! The keystone of the app crate (type definitions only): [`Backend`], everything the API packages
//! share, built by `svc_core::build`; and [`TunnelOps`], the app-level tunnel contract that
//! `svc_tunnel` implements and the API packages call. `crates/app/SERVICES.md` maps every field
//! and method to the UI traits it serves.
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::types::{ClientDevice, KillSwitchLevel};
use vpnte_cleanup::legacy::CleanupMarker;
use vpnte_core::logging::LogGuard;
use vpnte_core::ops::{OperationRegistry, Source};
use vpnte_core::paths::{DataDirs, DataLock};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::rulesets::RuleSetService;
use vpnte_forensics::traffic::TrafficStats;
use vpnte_probes::geo::Geo;
use vpnte_probes::ip_monitor::IpEvidence;
use vpnte_probes::key_health::ProbeCtx;
use vpnte_probes::leak::CheckReport;
use vpnte_probes::live::LiveCheckService;
use vpnte_probes::ping::PingSample;
use vpnte_servers::model::ProfileId;
use vpnte_servers::refresh::RefreshCtx;
use vpnte_servers::store::Servers;
use vpnte_tunnel::api::TunStatus;
use vpnte_tunnel::fsm::TunnelSnapshot;
use vpnte_tunnel::history::History;
use vpnte_tunnel::lifecycle::{ConnError, Done, SessionView, ShutdownReport};
use vpnte_winnet::clipboard::SecretClipboard;
use vpnte_winnet::wfp::{
    ExceptionKind, KillSwitchException, ProtectionSettings, ProtectionStatus, RemoveReport, Toggles,
};

use crate::import::ImportReport;
use crate::svc_core::docs::{ProtectionDoc, SoftDoc, ThemesDoc};
use crate::svc_core::notify::Notifier;
use crate::svc_proxies::ProxySlots;

/// Everything the application shares, built once by `svc_core::build` and handed around as
/// `Arc<Backend>`. Stores are the single in-process copy of each document: never open a second
/// `Store` of the same type.
pub struct Backend {
    /// Data root, logs, history, cache, legacy Electron dir (read only), resources.
    pub dirs: DataDirs,
    /// Exclusive lock on the data dir, held for the life of the process.
    pub lock: DataLock,
    /// The app log writer: take and drop it as the last step of shutdown to drain the queue.
    pub log: Mutex<Option<LogGuard>>,
    /// The process runs elevated: privileged operations (TUN, WFP) are available in-process.
    /// `false` is the normal case: they return `ErrorKind::Permission` (NOADMIN §0).
    pub elevated: bool,
    /// The bundled engine executables.
    pub engines: Engines,
    /// `settings.json`.
    pub settings: Arc<Store<Settings>>,
    /// `protection.json`: kill-switch level, leak-protection switches, exceptions.
    pub protection: Arc<Store<ProtectionDoc>>,
    /// `themes.json`: custom themes (the active id is `Settings::active_theme_id`).
    pub themes: Arc<Store<ThemesDoc>>,
    /// `soft.json`: the dev tools a Soft session also configures.
    pub soft: Arc<Store<SoftDoc>>,
    /// `legacy-network-cleanup.json`: the old version's network cleanup, shared by the elevated
    /// start-up run and the maintenance page.
    pub cleanup: Arc<Store<CleanupMarker>>,
    /// `rules.json`: split tunnel, DNS profiles and the active choice, domain rules.
    pub rules: Arc<Store<RulesDoc>>,
    /// Smart RU rule sets (`cache/rulesets.json` + `cache/rulesets/`): the active set and refresh.
    pub rule_sets: Arc<RuleSetService>,
    /// Connection history (`history/connections.json`).
    pub history: History,
    /// The server list (`profiles.json`).
    pub servers: Arc<Servers>,
    /// Subscription fetcher + operation registry for adding and refreshing servers.
    pub refresh: RefreshCtx,
    /// Long feature operations: single flight per resource, cancel, list.
    pub ops: OperationRegistry,
    /// Country / ASN lookups: one cache and backoff for the process; enabled =
    /// `!settings.disable_geo_lookup` (whoever saves that setting calls `geo.set_enabled`).
    pub geo: Geo,
    /// Windows toasts with the in-app list.
    pub notifier: Arc<Notifier>,
    /// What the one-time legacy import did at this start (`None`: nothing to import).
    pub import: Option<ImportReport>,
    /// Cancelled once at app exit: background tasks run under child tokens.
    pub shutdown: CancellationToken,
    /// Secret clipboard, started on first use by `Backend::clipboard` (needs the tokio runtime).
    pub clipboard: OnceLock<SecretClipboard>,
    /// The tunnel, set once by the caller of `svc_tunnel::build` right after `svc_core::build`;
    /// read it with `Backend::tunnel`.
    pub tunnel: OnceLock<Arc<dyn TunnelOps>>,
}

/// The bundled engines under the resources dir: canonical paths when the files exist (WFP
/// permits match the image path an engine runs from), else the expected path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Engines {
    pub singbox: PathBuf,
    pub xray: PathBuf,
}

/// The kill switch as the settings page and the start page read it.
#[derive(Debug, Clone)]
pub struct KillSwitchStatus {
    /// Saved level, switches and exceptions (`protection.json`).
    pub settings: ProtectionSettings,
    /// A fresh WFP read-back; `None` when this process hosts no WFP protection (not elevated):
    /// strict, leak protection and exceptions are then unavailable.
    pub wfp: Option<ProtectionStatus>,
}

/// The tunnel as the application uses it. Lane operations (connect, disconnect, switch, settings
/// restart) go through the lifecycle actor, so admission, history and notices stay in one place.
/// Every method may be called from any task; futures are `Send`.
#[async_trait]
pub trait TunnelOps: Send + Sync + 'static {
    /// Connects as the user (`Owner::Manual`) to what the saved settings select: connection mode x
    /// routing mode, the active server or the configured / detected local proxy. Hard without TUN
    /// capture fails with `Permission` and a message that offers Soft.
    async fn connect(&self, source: Source) -> Result<Done, ConnError>;
    /// Stops the tunnel as the user (`StopCause::User`, `Owner::Manual`).
    async fn disconnect(&self, source: Source) -> Result<Done, ConnError>;
    /// The "Cancel" button: stops a connect, switch or reconnect in flight; a no-op otherwise.
    fn cancel(&self);
    /// Selects server `id` as the user's choice and, while a tunnel runs on a server, switches the
    /// tunnel there (protected switch, cancellable with [`TunnelOps::cancel`]).
    async fn switch_server(&self, id: ProfileId, source: Source) -> Result<Done, ConnError>;
    /// Applies a saved settings change: restarts the running tunnel through the lifecycle only
    /// when a tunnel-shaping field changed, and hands a changed kill-switch level to the protection.
    async fn apply_settings_change(&self, old: Settings, new: Settings) -> Result<Done, ConnError>;
    /// The published connection state (lifecycle FSM snapshot).
    fn snapshot(&self) -> watch::Receiver<TunnelSnapshot>;
    /// The open session (holder, server, mode, start); `None` while idle.
    fn session(&self) -> watch::Receiver<Option<SessionView>>;
    /// Runtime details: restart attempt, warning, proxy reachability, profile, start time. Its
    /// `session` field holds the Clash secret and proxy passwords: never log or display it.
    fn runtime_status(&self) -> watch::Receiver<TunStatus>;
    /// The kill switch now: saved settings plus, when this process hosts WFP, a fresh read-back.
    async fn kill_switch(&self) -> KillSwitchStatus;
    /// Applies, verifies and persists the kill-switch level; `Permission` when this process cannot
    /// enforce it (strict needs WFP; without it only Soft's off / standard behaviour exists).
    async fn set_kill_switch_level(&self, level: KillSwitchLevel) -> AppResult<()>;
    /// Applies and persists the protection switches (leak protection, public Wi-Fi, LAN) and
    /// restarts a running tunnel whose shape they change; `Permission` without WFP.
    async fn set_protection_toggles(&self, toggles: Toggles) -> AppResult<()>;
    /// Validates, applies and persists a new kill-switch exception (fresh id); `Permission`
    /// without WFP, `Validation` with the field message for bad input.
    async fn add_exception(
        &self,
        kind: ExceptionKind,
        value: String,
        label: String,
    ) -> AppResult<KillSwitchException>;
    /// Removes the exception `id`, applies and persists the list; `Permission` without WFP.
    async fn remove_exception(&self, id: String) -> AppResult<()>;
    /// Removes every filter of ours outside a session (the start page's "release"); `Conflict`
    /// during a session, `Permission` without WFP.
    async fn release_kill_switch(&self) -> AppResult<RemoveReport>;
    /// Exit-IP evidence of the current session (public-IP monitor); `NotChecked` while idle.
    fn ip_evidence(&self) -> watch::Receiver<IpEvidence>;
    /// Runs the leak check (public IP, self-test, engine log, DNS) for the current state, at most
    /// 15 s; a cancelled token returns `Cancelled`.
    async fn leak_check(&self, cancel: CancellationToken) -> AppResult<CheckReport>;
    /// Traffic counters of the running session, about once a second (`running: false` while idle).
    fn traffic(&self) -> watch::Receiver<TrafficStats>;
    /// Pings the servers `ids` over the path the current session allows, records every result in
    /// the server list as it lands (`ServersEvent::Ping`) and returns them (`None` = no answer).
    async fn ping(
        &self,
        ids: Vec<ProfileId>,
        cancel: CancellationToken,
    ) -> AppResult<Vec<(ProfileId, Option<PingSample>)>>;
    /// What a server probe (key health, ping) needs right now: the engines, the engine choice and,
    /// while our TUN runs, its authenticated direct-out and DNS bootstrap, so probe traffic
    /// bypasses the tunnel. `device` = the client device of the probed server's group.
    fn probe_ctx(&self, device: ClientDevice) -> ProbeCtx;
    /// Whether this process can capture traffic with the TUN (Hard mode): elevated, this phase.
    fn tun_available(&self) -> bool;
    /// Bounded app-exit cleanup: stops the tunnel as app-quit, rolls Soft back and closes the
    /// dynamic WFP session (strict filters stay).
    async fn shutdown(&self, budget: Duration) -> ShutdownReport;
    /// Clears the traffic (domain) history and its site-name cache, which the tunnel side owns
    /// (`forensics::domains::HistoryService::clear`, `Enricher::clear`); the Logs page's «clear
    /// all» calls it (added by app-settings). The default reports it as not available, so an
    /// implementation that does not host the domain history is honest without overriding it.
    async fn clear_traffic_history(&self) -> AppResult<()> {
        Err(vpnte_base::AppError::msg(
            vpnte_base::ErrorKind::Conflict,
            vpnte_base::Msg::new("app.logs.trafficUnavailable"),
        ))
    }
    /// The machine woke from sleep or the user unlocked the session (`winnet::power`, fed by
    /// app-main): session evidence for the outcome of a tunnel that dies soon after
    /// (`Lifecycle::resumed`). Added by app-main; the default ignores it, so an implementation
    /// without a lifecycle stays correct.
    fn resumed(&self) {}
    /// The external proxy slots this tunnel hosts (built with it: the lifecycle stops them with
    /// the VPN). The default hosts none: the proxy column stays empty and its actions say so.
    fn proxies(&self) -> Option<ProxySlots> {
        None
    }
    /// The live server check this tunnel hosts (it reads the tunnel's state). The default hosts
    /// none: the Servers page reports the check as unavailable.
    fn live_checks(&self) -> Option<Arc<LiveCheckService>> {
        None
    }
}
