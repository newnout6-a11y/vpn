//! [`ServersApi`]: everything the Servers page asks of the backend. The app implements it over
//! the profiles / servers / probes / proxies / tunnel crates and provides it as
//! `Rc<dyn ServersApi>` in context; [`super::demo::DemoServersApi`] fakes it for the demo.
use std::num::NonZeroU32;
use std::rc::Rc;
use std::time::Duration;

use dioxus::prelude::*;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::types::{ClientDevice, EnginePref};

use super::live_model::{BatchProgress, BatchResult, LiveCheck, LiveMode, LiveProgress};
use super::model::{
    AddTarget, CountryCheck, ExportReport, GeoInfo, HealthReport, ImportReport, ProbeReport,
    ProxyStartReport, RefreshOutcome, SelectOutcome, ServersView,
};

/// Backend surface of the Servers page. Every action may be cancelled by dropping its future
/// (the page owns long work, dialogs own theirs); `ErrorKind::Cancelled` is shown nowhere.
#[async_trait::async_trait(?Send)]
pub trait ServersApi: 'static {
    /// The store snapshot, pushed on every change (no polling).
    fn state(&self) -> watch::Receiver<ServersView>;
    /// Group ids the user left expanded (persisted UI state).
    fn expanded_groups(&self) -> Vec<String>;
    /// Persists the expanded group ids.
    async fn save_expanded_groups(&self, ids: Vec<String>) -> AppResult<()>;
    /// Resolves every host for the IP column (single flight; answers arrive through `state`).
    async fn resolve_ips(&self) -> AppResult<()>;

    /// Imports a key, a key list, JSON or a subscription URL (fetched as `device`).
    async fn add(
        &self,
        input: String,
        target: AddTarget,
        device: ClientDevice,
    ) -> AppResult<ImportReport>;
    /// Soft delete: archived for the user, not selectable, purged after 30 days unless restored.
    async fn remove(&self, id: &str) -> AppResult<()>;
    /// Brings an archived server back.
    async fn restore(&self, id: &str) -> AppResult<()>;
    /// Deletes an archived server for good.
    async fn purge(&self, id: &str) -> AppResult<()>;
    /// Makes `id` the selected server; while connected this is a live switch.
    async fn select(&self, id: &str) -> AppResult<SelectOutcome>;
    /// Cancels the switch in flight (its `select` then answers `Cancelled`).
    async fn cancel_switch(&self) -> AppResult<()>;

    /// Direct ping around the tunnel, never cached; `None` = no answer.
    async fn ping_one(&self, id: &str) -> AppResult<Option<u32>>;
    /// Pings `ids` five at a time and sends each answer as it lands. Pings measured while the
    /// tunnel runs are never persisted (they would show a fake 2 ms after disconnect).
    async fn ping_many(
        &self,
        ids: Vec<String>,
        results: mpsc::UnboundedSender<(String, Option<u32>)>,
    ) -> AppResult<()>;
    /// Looks the exit country up through the server.
    async fn verify_country(&self, id: &str) -> AppResult<CountryCheck>;

    /// Copies the share key to the clipboard; answers when the clipboard clears itself again.
    async fn copy_key(&self, id: &str) -> AppResult<Duration>;
    /// Asks for a file and saves the share key there; `None` = the Save dialog was dismissed.
    async fn save_key(&self, id: &str) -> AppResult<Option<String>>;
    /// Asks for a file and saves every key; `None` = dismissed.
    async fn export_all_keys(&self) -> AppResult<Option<ExportReport>>;
    /// Asks for a file and saves a proxy list (one proxy per line); `None` = dismissed.
    async fn export_proxy_list(&self) -> AppResult<Option<ExportReport>>;
    /// Starts an external loopback proxy for each server.
    async fn start_proxies(&self, ids: Vec<String>) -> AppResult<ProxyStartReport>;

    async fn refresh_group(&self, id: &str) -> AppResult<RefreshOutcome>;
    /// `None` = provider / default interval.
    async fn set_refresh_interval(&self, id: &str, minutes: Option<NonZeroU32>) -> AppResult<()>;
    /// Trims and caps the name at 60 characters.
    async fn rename_group(&self, id: &str, name: String) -> AppResult<()>;
    /// Also for recovered (orphan) group ids: applies the choice to the servers carrying the id.
    async fn delete_group(&self, id: &str, delete_servers: bool) -> AppResult<()>;
    /// Checks the keys of the group's current (not removed) servers; keys that could not be
    /// checked now (handshake budget, probe setup) are counted in the report.
    async fn check_group_health(&self, id: &str) -> AppResult<HealthReport>;

    /// Device persona of a server; the connected server reconnects.
    async fn set_device(&self, id: &str, device: ClientDevice) -> AppResult<()>;
    /// The server's own engine (`Auto` = the setting); the connected server reconnects, and a
    /// choice the engine cannot run is refused there with its reason.
    async fn set_engine(&self, id: &str, engine: EnginePref) -> AppResult<()>;
    /// Passive endpoint facts (no TLS / HTTP to the endpoint).
    async fn probe(&self, id: &str) -> AppResult<ProbeReport>;
    /// Geolocation of the resolved address; `None` when lookups are off or nothing is known.
    async fn geo(&self, id: &str) -> AppResult<Option<GeoInfo>>;
    /// Runs a live check; progress arrives in channel order. Dropping the future aborts it and
    /// nothing is stored.
    async fn live_check(
        &self,
        id: &str,
        mode: LiveMode,
        progress: mpsc::UnboundedSender<LiveProgress>,
    ) -> AppResult<LiveCheck>;
    /// Stored receipts of the server's host:port, newest first, at most 20.
    async fn live_history(&self, id: &str) -> AppResult<Vec<LiveCheck>>;
    /// Sequential extended checks of up to 12 servers. `stop` = finish with the receipts so far
    /// (`cancelled: true`); dropping the future aborts.
    async fn live_batch(
        &self,
        ids: Vec<String>,
        stop: CancellationToken,
        progress: mpsc::UnboundedSender<BatchProgress>,
    ) -> AppResult<BatchResult>;

    /// Opens an `http(s)` link in the user's browser.
    async fn open_url(&self, url: String) -> AppResult<()>;
}

/// The [`ServersApi`] from context.
pub fn use_servers_api() -> Rc<dyn ServersApi> {
    use_context::<Rc<dyn ServersApi>>()
}
