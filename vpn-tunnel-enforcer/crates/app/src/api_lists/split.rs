//! Apps page: the split-tunnel entries of `rules.json` (a program by its path or a process by
//! its name, each with its rule), installed-app discovery and the native Open dialog; and Happ
//! routing profiles imported into the user's domain rules on the user's click (`routing`).
//!
//! A running session takes a changed list at its next engine start (the tunnel reads
//! `rules.json` on every start), as the Settings page's domain rules do; so does the switch
//! «Только выбранные приложения» (`Settings::app_scope`, re-check item 16).
mod routing;
#[cfg(test)]
mod scope_tests;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::runtime::Handle;
use tokio::sync::{broadcast, watch};
use uuid::Uuid;
use vpnte_base::types::UnixMs;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::settings::{self, RoutingMode};
use vpnte_engine::apps;
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::process::{self as engine, AppPath, Probe, ProcessName, SplitTarget};
use vpnte_servers::store::ServersEvent;
use vpnte_service::proto::SCOPE_PROTOCOL;
use vpnte_tunnel::api::CaptureKind;
use vpnte_ui::split_tunnel::{
    AppKind, AppRule, AppScope, RoutingImported, RoutingOffer, RoutingPreview, RoutingSource,
    SplitApp, SplitSnapshot, SplitTunnelApi,
};
use vpnte_ui::widgets::{Load, UiError};

use super::refused;
use crate::services::Backend;
use crate::support::files::pick_program;
use crate::support::{blocking, changed_opt, detached};

/// [`SplitTunnelApi`] over the routing rules store.
pub struct SplitService(Arc<Shared>);

/// State shared by the actions and the projection task.
struct Shared {
    backend: Arc<Backend>,
    /// `state()` runs on the UI thread: the first discovery is spawned on this runtime.
    runtime: Handle,
    state: watch::Sender<SplitSnapshot>,
    /// The page's first look happened (an empty list then runs discovery, once).
    looked: AtomicBool,
    /// One rescan at a time: a second one waits and then finds nothing new.
    scan: tokio::sync::Mutex<()>,
    /// Projection and send as one step, so a slower projection never sends an older list
    /// after a newer one (actions and the projection task both publish).
    publishing: Mutex<()>,
    /// The subscriptions with a Happ routing profile, re-read when the server list changes.
    offers: Mutex<Vec<RoutingOffer>>,
    /// Routing previews and their import.
    routing: routing::Imports,
    /// The scope the running session started with.
    run: Mutex<RunScope>,
}

/// The scope a running session started with (appsplit-b5): read when the run appears and kept
/// while it runs, since a flip of the switch applies from the next connection.
#[derive(Debug, Default)]
struct RunScope {
    started: Option<UnixMs>,
    listed: bool,
}

/// What the switch shows besides the list.
#[derive(Debug, Clone, Copy, PartialEq)]
struct ScopeView {
    scope: AppScope,
    pending: bool,
    proxy: bool,
    older_service: bool,
}

impl ScopeView {
    /// Writes the view into `snap`; whether anything changed.
    fn apply(self, snap: &mut SplitSnapshot) -> bool {
        let now = ScopeView {
            scope: snap.scope,
            pending: snap.pending,
            proxy: snap.proxy,
            older_service: snap.older_service,
        };
        (snap.scope, snap.pending, snap.proxy) = (self.scope, self.pending, self.proxy);
        snap.older_service = self.older_service;
        now != self
    }
}

impl SplitService {
    /// Publishes the stored list and starts the projection task. Call it inside the tokio
    /// runtime.
    pub fn start(backend: Arc<Backend>) -> Self {
        let shared = Arc::new(Shared {
            backend,
            runtime: Handle::current(),
            state: watch::Sender::new(SplitSnapshot::default()),
            looked: AtomicBool::new(false),
            scan: tokio::sync::Mutex::new(()),
            publishing: Mutex::new(()),
            offers: Mutex::new(Vec::new()),
            routing: routing::Imports::default(),
            run: Mutex::new(RunScope::default()),
        });
        shared.read_offers();
        shared.publish();
        tokio::spawn(follow(shared.clone()));
        Self(shared)
    }

    /// Adds the program at `path` (rule «Нет»), what `add_app` does with the dialog's answer;
    /// an entry with the same path is returned as it is.
    pub(super) async fn add_program(&self, path: PathBuf) -> AppResult<SplitApp> {
        let shared = self.0.clone();
        blocking(move || shared.add_path(&path.to_string_lossy())).await
    }
}

impl Shared {
    /// Projects the stored entries in order, the routing offers and the scope; sends only a
    /// changed snapshot.
    fn publish(&self) {
        let _one = self.publishing.lock();
        let apps = self.backend.rules.read(project);
        let offers = self.offers.lock().clone();
        let view = self.scope();
        self.state.send_if_modified(|current| {
            let next = Load::Ready(apps);
            let listed = current.apps != next || current.offers != offers;
            if listed {
                current.apps = next;
                current.offers = offers;
            }
            view.apply(current) || listed
        });
    }

    /// Projects the scope alone (a settings change, a new link to the service): the list stays
    /// as shown, a running discovery's «loading» included.
    fn publish_scope(&self) {
        let _one = self.publishing.lock();
        let view = self.scope();
        self.state.send_if_modified(|current| view.apply(current));
    }

    /// The saved scope, whether the running session keeps the other one, the mode the hint
    /// describes (the running session's, else the saved one) and whether Tunnel mode runs in a
    /// service too old for the scope.
    fn scope(&self) -> ScopeView {
        let s = self.backend.settings.snapshot();
        let tunnel = self.backend.tunnel().ok();
        let protocol = tunnel.as_ref().and_then(|t| t.service_protocol());
        let (started, capture) = tunnel.map_or((None, None), |t| {
            let status = t.runtime_status();
            let status = status.borrow();
            (status.started_at.filter(|_| status.running), status.capture)
        });
        let listed = s.app_scope == settings::AppScope::OnlyListed;
        let mut run = self.run.lock();
        if run.started != started {
            *run = RunScope { started, listed };
        }
        let proxy = match capture.filter(|_| started.is_some()) {
            Some(capture) => capture == CaptureKind::Proxy,
            None => s.routing_mode == RoutingMode::Soft,
        };
        ScopeView {
            scope: ui_scope(s.app_scope),
            pending: started.is_some() && run.listed != listed,
            proxy,
            older_service: older_service(protocol),
        }
    }

    /// Re-reads which subscriptions carry a routing profile (parses each stored value).
    fn read_offers(&self) {
        let lang = self.backend.lang();
        let offers = self.backend.servers.read(|doc| routing::offers(doc, lang));
        *self.offers.lock() = offers;
    }

    /// Scans the installed apps and merges the new ones (rule «Нет»; rules kept, entries the
    /// user removed stay removed); returns how many were added.
    async fn rescan(&self) -> AppResult<usize> {
        let _one = self.scan.lock().await;
        let found = blocking(|| Ok(apps::discover())).await?;
        let rules = self.backend.rules.clone();
        let added = blocking(move || rules.update(|doc| doc.merge_discovered(&found))).await?;
        self.publish();
        Ok(added)
    }

    /// Adds the program at `raw` (rule «Нет»); an entry with the same path is returned as it
    /// is. Blocking: probes the file.
    fn add_path(&self, raw: &str) -> AppResult<SplitApp> {
        let path = AppPath::parse(raw)?;
        if !matches!(engine::probe_fs(&path), Probe::File { .. }) {
            return Err(AppError::validation(Msg::new("app.lists.apps.fileMissing")));
        }
        // An empty name lets the engine name it after its folder or file (`fallback_name`).
        let id = self.backend.rules.update(|doc| doc.add_app(path, ""))?;
        self.publish();
        self.entry(id)
    }

    /// The entry `id` as the page shows it.
    fn entry(&self, id: Uuid) -> AppResult<SplitApp> {
        self.backend
            .rules
            .read(|doc| {
                doc.split_tunnel
                    .apps
                    .iter()
                    .find(|app| app.id == id)
                    .map(view)
            })
            .ok_or_else(gone)
    }
}

/// The entry is no longer in the list (removed meanwhile, or an id the store never had).
fn gone() -> AppError {
    refused("app.lists.apps.gone")
}

/// The import names a preview that is not the latest one (or was imported already).
fn stale_preview() -> AppError {
    refused("app.lists.routing.stale")
}

/// The subscription no longer carries the routing profile the page offered.
fn offer_gone() -> AppError {
    refused("app.lists.routing.gone")
}

#[async_trait(?Send)]
impl SplitTunnelApi for SplitService {
    fn state(&self) -> watch::Receiver<SplitSnapshot> {
        // The service's protocol is known once the app linked to it, without a store change.
        self.0.publish_scope();
        let rx = self.0.state.subscribe();
        let first = !self.0.looked.swap(true, Ordering::SeqCst);
        if first
            && self
                .0
                .backend
                .rules
                .read(|doc| doc.split_tunnel.apps.is_empty())
        {
            // The first look at an empty list finds the installed apps (the old page did too).
            self.0
                .state
                .send_modify(|current| current.apps = Load::Loading);
            let shared = self.0.clone();
            self.0.runtime.spawn(async move {
                if let Err(err) = shared.rescan().await {
                    tracing::warn!(error = %err, "app discovery failed");
                    shared
                        .state
                        .send_modify(|current| current.apps = Load::Failed(UiError::from(err)));
                }
            });
        }
        rx
    }

    async fn reload(&self) -> AppResult<()> {
        self.0.publish();
        Ok(())
    }

    async fn refresh(&self) -> AppResult<usize> {
        let shared = self.0.clone();
        detached(async move { shared.rescan().await }).await
    }

    async fn add_app(&self) -> AppResult<Option<SplitApp>> {
        let Some(path) = pick_program(self.0.backend.lang()).await? else {
            return Ok(None);
        };
        self.add_program(path).await.map(Some)
    }

    async fn add_process(&self, name: String) -> AppResult<SplitApp> {
        // Quotes stripped, the leaf of a pasted path, `.exe` appended; a bad name is a
        // `Validation` error with the engine's example (shown under the input).
        let name = ProcessName::parse(&name)?;
        let shared = self.0.clone();
        blocking(move || {
            let id = shared.backend.rules.update(|doc| doc.add_command(name))?;
            shared.publish();
            shared.entry(id)
        })
        .await
    }

    async fn set_rule(&self, id: String, rule: AppRule) -> AppResult<()> {
        let id = Uuid::parse_str(&id).map_err(|_| gone())?;
        let shared = self.0.clone();
        blocking(move || {
            let found = shared
                .backend
                .rules
                .update(|doc| doc.set_app_rule(id, engine_rule(rule)))?;
            shared.publish();
            if found { Ok(()) } else { Err(gone()) }
        })
        .await
    }

    async fn set_scope(&self, scope: AppScope) -> AppResult<()> {
        let shared = self.0.clone();
        blocking(move || {
            let stored = stored_scope(scope);
            shared.backend.settings.update(|s| s.app_scope = stored)?;
            tracing::info!(?stored, "apps scope saved");
            shared.publish_scope();
            Ok(())
        })
        .await
    }

    async fn remove(&self, id: String) -> AppResult<()> {
        // An id the store does not know is removed already: the end state is the asked one.
        let Ok(id) = Uuid::parse_str(&id) else {
            return Ok(());
        };
        let shared = self.0.clone();
        blocking(move || {
            shared.backend.rules.update(|doc| doc.remove_app(id))?;
            shared.publish();
            Ok(())
        })
        .await
    }

    async fn preview_routing(&self, source: RoutingSource) -> AppResult<RoutingPreview> {
        let shared = self.0.clone();
        blocking(move || shared.routing.preview(&shared.backend, &source)).await
    }

    async fn import_routing(&self, token: u64) -> AppResult<RoutingImported> {
        let shared = self.0.clone();
        // Detached: leaving the page mid-import never leaves half of it done.
        detached(
            async move { blocking(move || shared.routing.import(&shared.backend, token)).await },
        )
        .await
    }
}

/// Re-projects on every change of `rules.json` (this page, the Settings page, an import), of the
/// server list (a subscription's routing profile), of the settings (the scope, the routing
/// mode) and of the connection (a new link to the service) until `backend.shutdown`.
async fn follow(shared: Arc<Shared>) {
    let mut rules = shared.backend.rules.subscribe();
    let mut servers = shared.backend.servers.subscribe();
    let mut settings = shared.backend.settings.subscribe();
    let mut tunnel = shared.backend.tunnel().ok().map(|t| t.snapshot());
    let mut status = shared.backend.tunnel().ok().map(|t| t.runtime_status());
    let shutdown = shared.backend.shutdown.clone();
    // A session that started between the first projection and these subscriptions.
    shared.publish_scope();
    loop {
        let alive = tokio::select! {
            () = shutdown.cancelled() => false,
            changed = rules.changed() => changed.is_ok(),
            changed = settings.changed() => {
                if changed.is_err() {
                    return;
                }
                shared.publish_scope();
                continue;
            }
            () = changed_opt(&mut tunnel) => {
                shared.publish_scope();
                continue;
            }
            () = changed_opt(&mut status) => {
                shared.publish_scope();
                continue;
            }
            event = servers.recv() => match event {
                // Pings and refresh starts change no stored routing value.
                Ok(ServersEvent::Changed | ServersEvent::RefreshFinished(_))
                | Err(broadcast::error::RecvError::Lagged(_)) => {
                    shared.read_offers();
                    true
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Closed) => false,
            },
        };
        if !alive {
            return;
        }
        shared.publish();
    }
}

/// Tunnel mode runs in a helper service (linked, speaking `protocol`) too old to route by the
/// scope: there every app keeps the VPN (`Request::speak` leaves the scope out) until the
/// service is updated. Whatever the saved mode: a schedule starts Tunnel sessions of its own
/// (appsplit-a2), and the line names Tunnel mode.
fn older_service(protocol: Option<u32>) -> bool {
    protocol.is_some_and(|p| p < SCOPE_PROTOCOL)
}

fn ui_scope(scope: settings::AppScope) -> AppScope {
    match scope {
        settings::AppScope::All => AppScope::All,
        settings::AppScope::OnlyListed => AppScope::OnlyListed,
    }
}

fn stored_scope(scope: AppScope) -> settings::AppScope {
    match scope {
        AppScope::All => settings::AppScope::All,
        AppScope::OnlyListed => settings::AppScope::OnlyListed,
    }
}

/// The stored entries in order.
fn project(doc: &RulesDoc) -> Vec<SplitApp> {
    doc.split_tunnel.apps.iter().map(view).collect()
}

/// One entry as the page shows it: the full path of a program, the name of a process. Icons
/// are not extracted (the page shows the first letter).
fn view(app: &engine::SplitApp) -> SplitApp {
    let (path, kind) = match &app.target {
        SplitTarget::App(path) => (path.as_str().to_owned(), AppKind::App),
        SplitTarget::Command(name) => (name.as_str().to_owned(), AppKind::Process),
    };
    SplitApp {
        id: app.id.to_string(),
        name: app.name.clone(),
        path,
        icon: None,
        rule: ui_rule(app.rule),
        kind,
    }
}

fn ui_rule(rule: engine::AppRule) -> AppRule {
    match rule {
        engine::AppRule::Vpn => AppRule::Vpn,
        engine::AppRule::Direct => AppRule::Direct,
        engine::AppRule::None => AppRule::None,
    }
}

fn engine_rule(rule: AppRule) -> engine::AppRule {
    match rule {
        AppRule::Vpn => engine::AppRule::Vpn,
        AppRule::Direct => engine::AppRule::Direct,
        AppRule::None => engine::AppRule::None,
    }
}
