//! The kill switch as the host uses it: a seam over winnet's WFP `Protection` (blocking BFE work
//! on the blocking pool) so the pipe logic is testable without WFP. The settings are persisted in
//! the service's data folder: `strict` must hold from the next boot on, before any app runs.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::broadcast;
use vpnte_base::types::{KillSwitchLevel, Notice};
use vpnte_base::{AppError, AppResult};
use vpnte_winnet::wfp::{Protection, ProtectionSettings, RemoveReport};

use crate::proto::ProtectionWire;

/// What the host needs from the kill switch.
#[async_trait]
pub trait KillSwitch: Send + Sync {
    /// Applies validated settings (toggles, exceptions, level) and persists them.
    async fn apply(&self, settings: ProtectionSettings) -> AppResult<()>;
    /// The current level.
    fn level(&self) -> KillSwitchLevel;
    /// Fresh status.
    async fn status(&self) -> ProtectionWire;
    /// Notices (traffic blocked, exception skipped, protection unverified).
    fn notices(&self) -> broadcast::Receiver<Notice>;
    /// Removes every object of our provider (refused while a session runs).
    async fn cleanup(&self) -> AppResult<RemoveReport>;
}

/// The real kill switch.
pub struct WfpKillSwitch {
    protection: Arc<Protection>,
    store: PathBuf,
}

impl WfpKillSwitch {
    /// Wraps a started `protection`; settings changes are saved to `store`.
    pub fn new(protection: Arc<Protection>, store: PathBuf) -> Self {
        Self { protection, store }
    }
}

/// The persisted settings (`Default` when missing or unreadable: kill switch off).
pub fn load_settings(store: &Path) -> ProtectionSettings {
    std::fs::read(store)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_settings(store: &Path, settings: &ProtectionSettings) -> AppResult<()> {
    let tmp = store.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(settings).map_err(AppError::internal)?;
    std::fs::write(&tmp, bytes).map_err(AppError::internal)?;
    std::fs::rename(&tmp, store).map_err(AppError::internal)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> AppResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(AppError::internal)
}

#[async_trait]
impl KillSwitch for WfpKillSwitch {
    async fn apply(&self, settings: ProtectionSettings) -> AppResult<()> {
        let (protection, store) = (self.protection.clone(), self.store.clone());
        blocking(move || {
            let persist = |s: &ProtectionSettings| save_settings(&store, s);
            protection.update_settings(settings.toggles())?;
            protection.set_exceptions(settings.exceptions, &persist)?;
            protection.set_level(settings.level, &persist)?;
            save_settings(&store, &protection.settings())
        })
        .await?
    }

    fn level(&self) -> KillSwitchLevel {
        self.protection.settings().level
    }

    async fn status(&self) -> ProtectionWire {
        let protection = self.protection.clone();
        match blocking(move || ProtectionWire::from(&protection.status())).await {
            Ok(status) => status,
            Err(_) => ProtectionWire::unknown(self.level()),
        }
    }

    fn notices(&self) -> broadcast::Receiver<Notice> {
        self.protection.notices()
    }

    async fn cleanup(&self) -> AppResult<RemoveReport> {
        let (protection, store) = (self.protection.clone(), self.store.clone());
        blocking(move || {
            let persist = |s: &ProtectionSettings| save_settings(&store, s);
            protection.reset(&persist).map_err(AppError::from)
        })
        .await?
    }
}
