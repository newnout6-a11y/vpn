//! The Maintenance page («Починка», advanced mode) over the backend (work package
//! `app-maintenance`): [`MaintenanceApi`] and [`contexts`].
//!
//! The page renders one pushed snapshot (`project`): tunnel phase, capture, the last caught
//! error and the old version's leftovers are re-projected by a task; protection, repair and
//! export progress are published by the actions that produce them. Privileged operations exist
//! only when the process is elevated (NOADMIN §0): otherwise they answer «Доступно, только если
//! приложение запущено от имени администратора» (`Permission`, or a `blocked` repair step) and
//! are never reported as done. Every mutation is refused while the tunnel connects, switches or
//! disconnects; state-changing work runs as a backend task, so leaving the page never stops it
//! half-way.
mod export;
mod legacy;
mod project;
mod protection;
mod repair;
mod report;
mod selftest;

#[cfg(test)]
mod tests;

use std::any::Any;
use std::rc::Rc;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_cleanup::legacy::CleanupMarker;
use vpnte_core::store::Store;
use vpnte_ui::maintenance::{
    CaptureView, ExportDone, LeakTestView, MaintenanceApi, MaintenanceState, ProtectionView,
    RepairView, RouteTestView, SecretsImport, SystemReport,
};

use crate::services::Backend;
pub(crate) use repair::{RepairHost, WindowsHost};

/// The UI context of this package for `vpnte_ui::launch`: `Rc<dyn MaintenanceApi>`. Call it
/// inside the tokio runtime after `backend.tunnel` was set (the projection task starts here
/// and stops with `backend.shutdown`).
pub fn contexts(backend: &Arc<Backend>) -> Vec<Box<dyn Any>> {
    let shared = Shared::start(backend.clone(), Arc::new(WindowsHost));
    let api: Rc<dyn MaintenanceApi> = Rc::new(MaintenanceService(shared));
    vec![Box::new(api)]
}

/// The fragments of this package and of `app-clickjack` (its Save dialog): `svc_core`'s list
/// names only the packages wired before them.
const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../../locales/app-clickjack.ru.json"),
        include_str!("../../locales/app-clickjack.en.json"),
    ),
    (
        include_str!("../../locales/app-maintenance.ru.json"),
        include_str!("../../locales/app-maintenance.en.json"),
    ),
];

/// Every locale layer of the app plus [`LOCALES`] (each once), for the one
/// `vpnte_ui::lang::init_locales` call at start.
pub fn locale_layers() -> Vec<(&'static str, &'static str)> {
    let mut layers = crate::svc_core::locale_layers();
    for pair in LOCALES {
        if !layers.contains(pair) {
            layers.push(*pair);
        }
    }
    layers
}

/// [`MaintenanceApi`] over the backend.
pub struct MaintenanceService(Arc<Shared>);

/// State shared by the actions and the projection task.
pub(crate) struct Shared {
    pub backend: Arc<Backend>,
    pub state: watch::Sender<MaintenanceState>,
    /// The old version's network-cleanup marker (`legacy-network-cleanup.json`). This package
    /// is the only one that opens it: a later start-up cleanup must share this copy.
    pub marker: Arc<Store<CleanupMarker>>,
    /// What the repair does to the machine (Windows; fakes in tests).
    pub host: Arc<dyn RepairHost>,
    /// The last system report as JSON, for the diagnostics export.
    pub last_report: Mutex<Option<serde_json::Value>>,
    /// Wakes the projection for a change no store event announces (an action of this page).
    pub dirty: Notify,
}

impl Shared {
    /// Publishes the first snapshot and starts the projection task.
    pub fn start(backend: Arc<Backend>, host: Arc<dyn RepairHost>) -> Arc<Self> {
        let marker = Arc::new(Store::<CleanupMarker>::open(&backend.dirs.root));
        let shared = Arc::new(Self {
            backend,
            state: watch::Sender::new(MaintenanceState::default()),
            marker,
            host,
            last_report: Mutex::new(None),
            dirty: Notify::new(),
        });
        project::spawn(&shared);
        shared
    }

    /// Asks the projection to re-read what an action may have changed.
    pub fn touch(&self) {
        self.dirty.notify_one();
    }
}

/// A refusal of this page: `Conflict` with its own sentence (shown as a warning).
pub(crate) fn refused(key: &'static str) -> AppError {
    AppError::msg(ErrorKind::Conflict, Msg::new(key))
}

#[async_trait(?Send)]
impl MaintenanceApi for MaintenanceService {
    fn state(&self) -> watch::Receiver<MaintenanceState> {
        self.0.state.subscribe()
    }

    async fn system_report(&self, cancel: CancellationToken) -> AppResult<SystemReport> {
        report::run(&self.0, cancel).await
    }

    async fn verify_protection(&self) -> AppResult<ProtectionView> {
        protection::verify(&self.0).await
    }

    async fn repair(&self) -> AppResult<RepairView> {
        repair::run(self.0.clone()).await
    }

    async fn leak_self_test(&self, cancel: CancellationToken) -> AppResult<LeakTestView> {
        selftest::leak(&self.0, cancel).await
    }

    async fn routing_self_test(&self, cancel: CancellationToken) -> AppResult<RouteTestView> {
        selftest::route(&self.0, cancel).await
    }

    async fn export_diagnostics(&self, cancel: CancellationToken) -> AppResult<Option<ExportDone>> {
        export::run(self.0.clone(), cancel).await
    }

    async fn restart_capture(&self) -> AppResult<CaptureView> {
        project::settled(&self.0)?;
        Err(project::capture_refusal(self.0.backend.elevated))
    }

    async fn open_snapshots_folder(&self) -> AppResult<()> {
        legacy::open_snapshots(&self.0).await
    }

    async fn delete_legacy_data(&self) -> AppResult<()> {
        legacy::delete(self.0.clone()).await
    }

    async fn retry_secrets_import(&self) -> AppResult<SecretsImport> {
        project::settled(&self.0)?;
        // The one-time import keeps no re-import primitive: never pretend keys were restored.
        Err(refused("app.maintenance.legacy.retryUnavailable"))
    }

    async fn set_aside_corrupt(&self, id: String) -> AppResult<()> {
        legacy::set_aside(self.0.clone(), id).await
    }
}
