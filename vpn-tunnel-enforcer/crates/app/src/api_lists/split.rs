//! Apps page: the split-tunnel entries of `rules.json` (a program by its path or a process by
//! its name, each with its rule), installed-app discovery and the native Open dialog.
//!
//! A running session takes a changed list at its next engine start (the tunnel reads
//! `rules.json` on every start), as the Settings page's domain rules do.
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::runtime::Handle;
use tokio::sync::watch;
use uuid::Uuid;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_engine::apps;
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::process::{self as engine, AppPath, Probe, ProcessName, SplitTarget};
use vpnte_ui::split_tunnel::{AppKind, AppRule, SplitApp, SplitSnapshot, SplitTunnelApi};
use vpnte_ui::widgets::{Load, UiError};

use super::refused;
use crate::api_settings::dialog::{self, FileDialog};
use crate::api_settings::{blocking, detached};
use crate::services::Backend;

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
        });
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
    /// Projects the stored entries in order; sends only a changed snapshot.
    fn publish(&self) {
        let _one = self.publishing.lock();
        let apps = self.backend.rules.read(project);
        self.state.send_if_modified(|current| {
            let next = Load::Ready(apps);
            let changed = current.apps != next;
            if changed {
                current.apps = next;
            }
            changed
        });
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

#[async_trait(?Send)]
impl SplitTunnelApi for SplitService {
    fn state(&self) -> watch::Receiver<SplitSnapshot> {
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
            self.0.state.send_replace(SplitSnapshot {
                apps: Load::Loading,
            });
            let shared = self.0.clone();
            self.0.runtime.spawn(async move {
                if let Err(err) = shared.rescan().await {
                    tracing::warn!(error = %err, "app discovery failed");
                    shared.state.send_replace(SplitSnapshot {
                        apps: Load::Failed(UiError::from(err)),
                    });
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
        let picker = FileDialog::open(
            dialog::lang(&self.0.backend),
            "app.settings.dialog.pickApp",
            &[
                ("app.settings.dialog.programs", "*.exe"),
                ("app.settings.dialog.allFiles", "*.*"),
            ],
        );
        let Some(path) = dialog::show(picker).await? else {
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
}

/// Re-projects on every change of `rules.json` (this page, the Settings page, an import) until
/// `backend.shutdown`.
async fn follow(shared: Arc<Shared>) {
    let mut rules = shared.backend.rules.subscribe();
    let shutdown = shared.backend.shutdown.clone();
    loop {
        let alive = tokio::select! {
            () = shutdown.cancelled() => false,
            changed = rules.changed() => changed.is_ok(),
        };
        if !alive {
            return;
        }
        shared.publish();
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
