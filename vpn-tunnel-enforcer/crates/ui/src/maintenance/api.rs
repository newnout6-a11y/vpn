//! [`MaintenanceApi`]: what the Maintenance page needs from the backend.
use async_trait::async_trait;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;

use super::model::{
    CaptureView, ExportDone, LeakTestView, MaintenanceState, ProtectionView, RepairView,
    RouteTestView, SecretsImport, SystemReport,
};

/// Backend of the Maintenance page. The app implements it over probes, protection, forensics,
/// lifecycle and storage; [`super::demo::DemoMaintenanceApi`] fakes it.
///
/// Refusals are `ErrorKind::Conflict` with a message; `Cancelled` errors are never shown.
#[async_trait(?Send)]
pub trait MaintenanceApi: 'static {
    /// Pushed state of the page (latest value).
    fn state(&self) -> watch::Receiver<MaintenanceState>;

    /// Runs the system diagnostics checklist (monitoring §3.7).
    async fn system_report(&self, cancel: CancellationToken) -> AppResult<SystemReport>;

    /// Reads the protection back from Windows (filters, BFE, Windows Firewall profiles),
    /// publishes it in [`MaintenanceState::protection`] and returns it.
    async fn verify_protection(&self) -> AppResult<ProtectionView>;

    /// The auto-repair: refused unless the tunnel is idle; runs the steps of
    /// [`super::RepairStep::ALL`] in order, each independent of the others' outcome. It must run
    /// in its own task: dropping the returned future (the page went away) must not stop it
    /// between two privileged steps. Progress and outcomes go to [`MaintenanceState::repair`];
    /// the future resolves after the last step with the final view (the value published last).
    async fn repair(&self) -> AppResult<RepairView>;

    /// The leak self-test (physical-adapter probes, IP cross-check).
    async fn leak_self_test(&self, cancel: CancellationToken) -> AppResult<LeakTestView>;

    /// The routing self-test (VPN exit vs direct exit, Smart-RU).
    async fn routing_self_test(&self, cancel: CancellationToken) -> AppResult<RouteTestView>;

    /// Builds the diagnostics ZIP: the app asks where to save it (title «Сохранить диагностику»,
    /// Desktop, `vpn-tunnel-enforcer-diagnostics-<timestamp>.zip`); `Ok(None)` = the user
    /// dismissed the dialog. Single flight app-wide (a second call while one runs is a
    /// `Conflict`); progress goes to [`MaintenanceState::export`].
    async fn export_diagnostics(&self, cancel: CancellationToken) -> AppResult<Option<ExportDone>>;

    /// Stops and starts the packet capture of the current session; returns (and pushes) the new
    /// status.
    async fn restart_capture(&self) -> AppResult<CaptureView>;

    /// Opens the snapshots folder in Explorer.
    async fn open_snapshots_folder(&self) -> AppResult<()>;

    /// Deletes the old version's data directory (`%APPDATA%\vpn-tunnel-enforcer`).
    async fn delete_legacy_data(&self) -> AppResult<()>;

    /// Retries decrypting the keys still held by the old version's files.
    async fn retry_secrets_import(&self) -> AppResult<SecretsImport>;

    /// Renames a corrupt document aside (`<name>.corrupt-<unix>.json`) and starts it empty.
    async fn set_aside_corrupt(&self, id: String) -> AppResult<()>;
}
