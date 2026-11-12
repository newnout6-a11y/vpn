//! [`ServerApi`] over the backend (work package `app-servers`): the server list projected into the
//! page's snapshot, imports with their report, subscription refresh, selection and live switch
//! with cancel, pings, key health, country checks, key copy and export, archive and groups.
//!
//! Nothing here needs administrator rights (NOADMIN §0): stores live under the user's data dir,
//! keys are sealed with the user's DPAPI key, probe engines listen on loopback only, pings use
//! ICMP helpers / plain sockets, the clipboard and the Save dialog belong to the user's session.
//! The live check and «start as proxies» run on the runner and the slots the tunnel hosts
//! (`TunnelOps::live_checks` / `proxies`); without them they answer `Conflict`, never a fake result.
mod checks;
mod detail;
mod export;
mod import;
mod live;
mod live_view;
mod phones;
mod project;
mod proxies;
mod qr;
mod relays;
#[cfg(test)]
mod tests;
mod verdict;

pub use phones::LinkInbox;

use std::any::Any;
use std::future::Future;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, EnginePref, Level, Notice};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::ops::Source;
use vpnte_engine::xray_config::{Decision, select_engine, server_pref};
use vpnte_probes::live::LiveCheckService;
use vpnte_servers::model::{GroupId, ProfileId};
use vpnte_servers::store::Servers;
use vpnte_tunnel::lifecycle::ConnError;
use vpnte_ui::servers::{
    AddTarget, BatchProgress, BatchResult, CountryCheck, ExportReport, GeoInfo, HealthReport,
    ImportReport, LinkSchemes, LiveCheck, LiveMode, LiveProgress, ProbeReport, ProxyStartReport,
    QrCode, RefreshOutcome, SelectOutcome, ServersApi, ServersView, SubscriptionRequest,
};
use vpnte_winnet::url_scheme::Registrar;

use crate::services::Backend;
use crate::support::{blocking, changed_opt, detached, joined, unavailable};

/// Coalesces bursts of store events (a ping-all, a refresh) into one projection.
const DEBOUNCE: Duration = Duration::from_millis(60);

/// The UI contexts of this package: `Rc<dyn ServersApi>` and the [`LinkInbox`] the root hands
/// links to. Call it inside the tokio runtime (the projection task starts here) after
/// `backend.tunnel` was set.
pub fn contexts(backend: &Arc<Backend>) -> Vec<Box<dyn Any>> {
    // Subscription refreshes may now try the session's route and a spare slot (ru-2026 item 3).
    let relays = Arc::new(relays::AppRelays::new(backend));
    backend.refresh.fetcher.set_relays(relays);
    let servers = ServersBackend::start(backend.clone());
    let links = servers.links.clone();
    let api: Rc<dyn ServersApi> = Rc::new(servers);
    vec![Box::new(api), Box::new(links)]
}

/// [`ServersApi`] implementation; every action runs in a backend task.
pub struct ServersBackend {
    shared: Arc<Shared>,
    /// Links Windows handed over, until the page takes them.
    links: LinkInbox,
    /// This user's link schemes (a throw-away key in tests).
    registrar: Registrar,
}

/// State shared by the API object, its actions and the projection task.
struct Shared {
    backend: Arc<Backend>,
    state: watch::Sender<ServersView>,
    /// Serialises projections, so a later one never loses to an older one.
    publishing: Mutex<()>,
    /// The server a switch is moving to (`switching_to`).
    switching: Mutex<Option<String>>,
    /// Resolved addresses of the IP column.
    ips: checks::IpBook,
}

impl ServersBackend {
    /// Publishes the first snapshot and starts the task that keeps it current.
    pub fn start(backend: Arc<Backend>) -> Self {
        Self::start_with(backend, Registrar::current_user())
    }

    /// [`ServersBackend::start`] over the link schemes of `registrar`.
    fn start_with(backend: Arc<Backend>, registrar: Registrar) -> Self {
        let shared = Arc::new(Shared {
            backend,
            state: watch::Sender::new(ServersView::default()),
            publishing: Mutex::new(()),
            switching: Mutex::new(None),
            ips: checks::IpBook::default(),
        });
        shared.publish();
        tokio::spawn(pump(shared.clone()));
        Self {
            shared,
            links: LinkInbox::default(),
            registrar,
        }
    }
}

impl Shared {
    /// Projects the current backend state into the page snapshot and sends it when it changed.
    fn publish(&self) {
        let _order = self.publishing.lock();
        let view = project::current(self);
        self.state.send_if_modified(|old| {
            let changed = *old != view;
            if changed {
                *old = view;
            }
            changed
        });
    }

    /// The id of the list server our tunnel runs on (`None`: idle, or a local-proxy session).
    fn session_server(&self) -> Option<ProfileId> {
        let session = self.backend.tunnel().ok()?.session().borrow().clone()?;
        let id = ProfileId::from(session.profile_id);
        self.backend.servers.get(&id).map(|_| id)
    }

    fn set_switching(&self, id: Option<String>) {
        *self.switching.lock() = id;
        self.publish();
    }
}

/// Keeps the snapshot current on server-list events, tunnel state and session, and settings
/// (language, geo switch); actions publish their own changes directly. Ends at app exit.
async fn pump(shared: Arc<Shared>) {
    let backend = shared.backend.clone();
    let mut events = backend.servers.subscribe();
    let mut settings = Some(backend.settings.subscribe());
    let (mut snapshot, mut session) = match backend.tunnel() {
        Ok(tunnel) => (Some(tunnel.snapshot()), Some(tunnel.session())),
        Err(_) => (None, None),
    };
    loop {
        tokio::select! {
            () = backend.shutdown.cancelled() => return,
            event = events.recv() => {
                if let Err(tokio::sync::broadcast::error::RecvError::Closed) = event {
                    return;
                }
            }
            () = changed_opt(&mut settings) => {}
            () = changed_opt(&mut snapshot) => {}
            () = changed_opt(&mut session) => {}
        }
        tokio::time::sleep(DEBOUNCE).await;
        while events.try_recv().is_ok() {}
        shared.publish();
    }
}

/// Runs a probe or an export in a backend task under a token of its own: dropping the returned
/// future cancels the token, and the work stops through its own cancellation path (the
/// probes and the operation registry store nothing for a cancelled run).
async fn cancellable<T, F, Fut>(shutdown: &CancellationToken, work: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce(CancellationToken) -> Fut,
    Fut: Future<Output = AppResult<T>> + Send + 'static,
{
    let token = shutdown.child_token();
    let _cancel_on_drop = token.clone().drop_guard();
    joined(tokio::spawn(work(token)).await)
}

/// `Conflict servers.notFound`: the row is gone (the servers crate's own key).
fn server_not_found() -> AppError {
    AppError::conflict(Msg::new("servers.notFound"))
}

/// `Conflict servers.group.notFound`: the group is gone (the servers crate's own key).
fn group_not_found() -> AppError {
    AppError::conflict(Msg::new("servers.group.notFound"))
}

#[async_trait::async_trait(?Send)]
impl ServersApi for ServersBackend {
    fn state(&self) -> watch::Receiver<ServersView> {
        self.shared.state.subscribe()
    }

    fn expanded_groups(&self) -> Vec<String> {
        let settings = &self.shared.backend.settings;
        settings.read(|s| s.ui.expanded_groups.clone())
    }

    async fn save_expanded_groups(&self, ids: Vec<String>) -> AppResult<()> {
        let settings = self.shared.backend.settings.clone();
        blocking(move || settings.update(|s| s.ui.expanded_groups = ids)).await
    }

    async fn resolve_ips(&self) -> AppResult<()> {
        detached(checks::resolve_ips(self.shared.clone())).await
    }

    async fn add(
        &self,
        input: String,
        target: AddTarget,
        device: ClientDevice,
        request: SubscriptionRequest,
    ) -> AppResult<ImportReport> {
        let shared = self.shared.clone();
        detached(import::add(shared, input, target, device, request)).await
    }

    async fn remove(&self, id: &str) -> AppResult<()> {
        self.edit(id, |servers, id| servers.remove(id)).await
    }

    async fn restore(&self, id: &str) -> AppResult<()> {
        self.edit(id, |servers, id| servers.restore(id)).await
    }

    async fn purge(&self, id: &str) -> AppResult<()> {
        self.edit(id, |servers, id| servers.purge(id)).await
    }

    async fn select(&self, id: &str) -> AppResult<SelectOutcome> {
        detached(switch(self.shared.clone(), ProfileId::from(id))).await
    }

    async fn cancel_switch(&self) -> AppResult<()> {
        self.shared.backend.tunnel()?.cancel();
        Ok(())
    }

    async fn ping_one(&self, id: &str) -> AppResult<Option<u32>> {
        let (shared, id) = (self.shared.clone(), ProfileId::from(id));
        let shutdown = &self.shared.backend.shutdown;
        cancellable(shutdown, |token| checks::ping_one(shared, id, token)).await
    }

    async fn ping_many(
        &self,
        ids: Vec<String>,
        results: mpsc::UnboundedSender<(String, Option<u32>)>,
    ) -> AppResult<()> {
        let shared = self.shared.clone();
        let shutdown = &self.shared.backend.shutdown;
        cancellable(shutdown, |token| {
            checks::ping_many(shared, ids, results, token)
        })
        .await
    }

    async fn verify_country(&self, id: &str) -> AppResult<CountryCheck> {
        let (shared, id) = (self.shared.clone(), ProfileId::from(id));
        let shutdown = &self.shared.backend.shutdown;
        cancellable(shutdown, |token| checks::verify_country(shared, id, token)).await
    }

    async fn copy_key(&self, id: &str) -> AppResult<Duration> {
        detached(export::copy_key(self.shared.clone(), ProfileId::from(id))).await
    }

    async fn save_key(&self, id: &str) -> AppResult<Option<String>> {
        let (shared, id) = (self.shared.clone(), ProfileId::from(id));
        let shutdown = &self.shared.backend.shutdown;
        cancellable(shutdown, |token| export::save_key(shared, id, token)).await
    }

    async fn export_all_keys(&self) -> AppResult<Option<ExportReport>> {
        let shared = self.shared.clone();
        let shutdown = &self.shared.backend.shutdown;
        cancellable(shutdown, |token| export::all_keys(shared, token)).await
    }

    async fn export_proxy_list(&self) -> AppResult<Option<ExportReport>> {
        let shared = self.shared.clone();
        let shutdown = &self.shared.backend.shutdown;
        cancellable(shutdown, |token| export::proxy_list(shared, token)).await
    }

    async fn start_proxies(&self, ids: Vec<String>) -> AppResult<ProxyStartReport> {
        let slots = self
            .shared
            .backend
            .tunnel()?
            .proxies()
            .ok_or_else(|| unavailable("app.servers.proxiesUnavailable"))?;
        detached(async move { Ok(proxies::report(slots.ops.start_profiles(ids).await)) }).await
    }

    async fn refresh_group(&self, id: &str) -> AppResult<RefreshOutcome> {
        detached(import::refresh(self.shared.clone(), GroupId::from(id))).await
    }

    async fn set_refresh_interval(&self, id: &str, minutes: Option<NonZeroU32>) -> AppResult<()> {
        // Out-of-range values reach the store's own check (`servers.group.overrideInvalid`).
        let minutes = minutes.map(|m| u16::try_from(m.get()).unwrap_or(u16::MAX));
        self.edit_group(id, move |servers, id| {
            servers.set_refresh_override(id, minutes)
        })
        .await
    }

    async fn rename_group(&self, id: &str, name: String) -> AppResult<()> {
        self.edit_group(id, move |servers, id| servers.rename_group(id, &name))
            .await
    }

    async fn set_send_hwid(&self, id: &str, on: bool) -> AppResult<()> {
        self.edit_group(id, move |servers, id| servers.set_group_send_hwid(id, on))
            .await
    }

    async fn set_own_device_id(&self, id: &str, own: bool) -> AppResult<()> {
        self.edit_group(id, move |servers, id| servers.set_own_device_id(id, own))
            .await
    }

    async fn set_request_headers(&self, id: &str, lines: String) -> AppResult<Vec<String>> {
        let (shared, id) = (self.shared.clone(), GroupId::from(id));
        blocking(move || {
            let names = shared.backend.servers.set_group_headers(&id, &lines)?;
            shared.publish();
            Ok(names)
        })
        .await
    }

    async fn delete_group(&self, id: &str, delete_servers: bool) -> AppResult<()> {
        self.edit_group(id, move |servers, id| {
            servers.delete_group(id, delete_servers)
        })
        .await
    }

    async fn check_group_health(&self, id: &str) -> AppResult<HealthReport> {
        let (shared, id) = (self.shared.clone(), GroupId::from(id));
        let shutdown = &self.shared.backend.shutdown;
        cancellable(shutdown, |token| checks::group_health(shared, id, token)).await
    }

    async fn set_device(&self, id: &str, device: ClientDevice) -> AppResult<()> {
        detached(set_device(self.shared.clone(), ProfileId::from(id), device)).await
    }

    async fn set_engine(&self, id: &str, engine: EnginePref) -> AppResult<()> {
        detached(set_engine(self.shared.clone(), ProfileId::from(id), engine)).await
    }

    async fn probe(&self, id: &str) -> AppResult<ProbeReport> {
        let (shared, id) = (self.shared.clone(), ProfileId::from(id));
        let shutdown = &self.shared.backend.shutdown;
        cancellable(shutdown, |token| detail::probe(shared, id, token)).await
    }

    async fn geo(&self, id: &str) -> AppResult<Option<GeoInfo>> {
        let (shared, id) = (self.shared.clone(), ProfileId::from(id));
        let shutdown = &self.shared.backend.shutdown;
        cancellable(shutdown, |token| detail::geo(shared, id, token)).await
    }

    async fn live_check(
        &self,
        id: &str,
        mode: LiveMode,
        progress: mpsc::UnboundedSender<LiveProgress>,
    ) -> AppResult<LiveCheck> {
        let (service, id, lang) = (self.live()?, id.to_owned(), self.shared.backend.lang());
        let shutdown = &self.shared.backend.shutdown;
        cancellable(shutdown, |token| {
            live::single(service, id, mode, lang, progress, token)
        })
        .await
    }

    async fn live_history(&self, id: &str) -> AppResult<Vec<LiveCheck>> {
        let service = self.live()?;
        Ok(live::history(&service, id, self.shared.backend.lang()))
    }

    async fn live_batch(
        &self,
        ids: Vec<String>,
        stop: CancellationToken,
        progress: mpsc::UnboundedSender<BatchProgress>,
    ) -> AppResult<BatchResult> {
        let (service, lang) = (self.live()?, self.shared.backend.lang());
        let shutdown = &self.shared.backend.shutdown;
        cancellable(shutdown, |token| {
            live::batch(service, ids, stop, lang, progress, token)
        })
        .await
    }

    async fn open_url(&self, url: String) -> AppResult<()> {
        detached(async move { vpnte_winnet::shell::open_url(&url).await }).await
    }

    async fn copy_text(&self, text: String) -> AppResult<()> {
        let backend = self.shared.backend.clone();
        // The blocking pool runs inside the runtime, which the clipboard's first start needs.
        blocking(move || backend.clipboard().copy(&text).map(drop)).await
    }

    fn link_arrivals(&self) -> watch::Receiver<u64> {
        self.links.arrivals()
    }

    fn take_link(&self) -> Option<String> {
        self.links.take()
    }

    async fn read_clipboard(&self) -> AppResult<String> {
        phones::read_clipboard().await
    }

    async fn read_key_file(&self) -> AppResult<Option<String>> {
        phones::read_key_file(self.shared.backend.lang()).await
    }

    async fn scan_qr_file(&self) -> AppResult<Option<String>> {
        phones::scan_qr_file(self.shared.backend.lang()).await
    }

    async fn scan_qr_screen(&self, captured: oneshot::Sender<()>) -> AppResult<String> {
        phones::scan_qr_screen(captured).await
    }

    async fn key_qr(&self, id: &str) -> AppResult<QrCode> {
        phones::key_qr(self.shared.clone(), ProfileId::from(id)).await
    }

    async fn link_schemes(&self) -> AppResult<LinkSchemes> {
        phones::link_schemes(self.registrar.clone()).await
    }

    async fn adopt_link_schemes(&self) -> AppResult<LinkSchemes> {
        phones::adopt_link_schemes(self.registrar.clone()).await
    }

    async fn set_link_scheme(&self, scheme: String, on: bool) -> AppResult<LinkSchemes> {
        phones::set_link_scheme(self.registrar.clone(), scheme, on).await
    }
}

impl ServersBackend {
    /// The live-check runner the tunnel hosts; `Conflict` when it hosts none.
    fn live(&self) -> AppResult<Arc<LiveCheckService>> {
        self.shared
            .backend
            .tunnel()?
            .live_checks()
            .ok_or_else(|| unavailable("app.servers.liveUnavailable"))
    }

    /// A row change on the blocking pool, published before it answers.
    async fn edit<F>(&self, id: &str, change: F) -> AppResult<()>
    where
        F: FnOnce(&Servers, &ProfileId) -> AppResult<()> + Send + 'static,
    {
        let (shared, id) = (self.shared.clone(), ProfileId::from(id));
        blocking(move || {
            change(&shared.backend.servers, &id)?;
            shared.publish();
            Ok(())
        })
        .await
    }

    /// A group change on the blocking pool, published before it answers.
    async fn edit_group<F>(&self, id: &str, change: F) -> AppResult<()>
    where
        F: FnOnce(&Servers, &GroupId) -> AppResult<()> + Send + 'static,
    {
        let (shared, id) = (self.shared.clone(), GroupId::from(id));
        blocking(move || {
            change(&shared.backend.servers, &id)?;
            shared.publish();
            Ok(())
        })
        .await
    }
}

/// Selects `id`; while our tunnel runs on a server this is a protected live switch that the user
/// can cancel here or on the start page. The marker (`active_id`) moves only once the session
/// does; `switching_to` shows the target meanwhile.
async fn switch(shared: Arc<Shared>, id: ProfileId) -> AppResult<SelectOutcome> {
    let tunnel = shared.backend.tunnel()?.clone();
    let live = shared.session_server().is_some();
    if live {
        shared.set_switching(Some(id.to_string()));
    }
    let result = tunnel.switch_server(id, Source::Ui).await;
    if live {
        shared.set_switching(None);
    } else {
        shared.publish();
    }
    match result {
        Ok(done) => {
            warn(&shared, done.warnings);
            Ok(SelectOutcome::Switched)
        }
        Err(ConnError::Cancelled(_)) => Ok(SelectOutcome::Cancelled),
        Err(err) => Err(err.into()),
    }
}

/// Sets a hand-added key's device persona (feed rows follow their group: the store refuses them
/// with `servers.deviceFollowsGroup`); the server our tunnel runs on reconnects with it.
async fn set_device(shared: Arc<Shared>, id: ProfileId, device: ClientDevice) -> AppResult<()> {
    let servers = shared.backend.servers.clone();
    let row = id.clone();
    blocking(move || servers.set_profile_device(&row, device)).await?;
    shared.publish();
    if shared.session_server().as_ref() == Some(&id) {
        // Switching to the same server re-reads its profile, so the new persona applies now.
        let done = shared
            .backend
            .tunnel()?
            .switch_server(id, Source::Ui)
            .await
            .map_err(AppError::from)?;
        warn(&shared, done.warnings);
    }
    Ok(())
}

/// Sets the server's own engine. A forced engine that cannot run the key is refused with the
/// selection's own sentence (nothing stored); the server our tunnel runs on reconnects with it.
async fn set_engine(shared: Arc<Shared>, id: ProfileId, engine: EnginePref) -> AppResult<()> {
    let backend = &shared.backend;
    let row = backend.servers.get(&id).ok_or_else(server_not_found)?;
    if engine != EnginePref::Auto {
        let profile = blocking(move || row.profile()).await?;
        let setting = backend.settings.read(|s| s.proxy_engine);
        if let Decision::Rejected(reject) = select_engine(&profile, server_pref(setting, engine)) {
            return Err(reject.into());
        }
    }
    let servers = backend.servers.clone();
    let target = id.clone();
    blocking(move || servers.set_profile_engine(&target, engine)).await?;
    shared.publish();
    if shared.session_server().as_ref() == Some(&id) {
        // Switching to the same server re-reads its row, so the new engine applies now.
        let done = backend
            .tunnel()?
            .switch_server(id, Source::Ui)
            .await
            .map_err(AppError::from)?;
        warn(&shared, done.warnings);
    }
    Ok(())
}

/// Extra messages of a finished lane operation go to the in-app list (and toasts per settings).
fn warn(shared: &Shared, warnings: Vec<Msg>) {
    for msg in warnings {
        shared
            .backend
            .notifier
            .notify(Notice::new(Level::Warn, msg), None);
    }
}
