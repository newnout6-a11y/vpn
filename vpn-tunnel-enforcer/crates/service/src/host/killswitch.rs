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
    /// The stored level.
    fn level(&self) -> KillSwitchLevel;
    /// The level the filters enforce: a stored `strict` works as `standard` until "Always" can
    /// be kept safe (`Protection::set_always_available`).
    fn level_in_force(&self) -> KillSwitchLevel;
    /// Fresh status.
    async fn status(&self) -> ProtectionWire;
    /// Notices (traffic blocked, exception skipped, protection unverified).
    fn notices(&self) -> broadcast::Receiver<Notice>;
    /// Removes every object of our provider (refused while a session runs).
    async fn cleanup(&self) -> AppResult<RemoveReport>;
    /// The last user leaves: the level goes to off (saved, so a later start-up removes leftovers
    /// instead of applying them again), then every WFP object of ours goes. An error keeps the
    /// service and its user (review 4555679938).
    async fn remove_all(&self) -> AppResult<()>;
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

/// The persisted settings: `Default` (kill switch off) when there are none. A file that exists
/// but cannot be read whole (a power loss mid-write, damage) fails closed: level `strict`, so the
/// start-up never lifts a block because of it (review service-a9).
pub fn load_settings(store: &Path) -> ProtectionSettings {
    let bytes = match std::fs::read(store) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ProtectionSettings::default(),
        Err(e) => return unreadable(store, &e),
    };
    serde_json::from_slice(&bytes).unwrap_or_else(|e| unreadable(store, &e))
}

fn unreadable(store: &Path, error: &dyn std::fmt::Display) -> ProtectionSettings {
    tracing::error!(path = %store.display(), %error, "kill-switch settings unreadable: strict");
    ProtectionSettings {
        level: KillSwitchLevel::Strict,
        ..ProtectionSettings::default()
    }
}

/// Written through a sibling file that reaches the disk before it replaces the old one (one
/// writer at a time: every caller runs under the host's state lock).
fn save_settings(store: &Path, settings: &ProtectionSettings) -> AppResult<()> {
    let tmp = store.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(settings).map_err(AppError::internal)?;
    let written = (|| {
        let mut file = std::fs::File::create(&tmp)?;
        std::io::Write::write_all(&mut file, &bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, store)
    })();
    written.map_err(AppError::internal)
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

    fn level_in_force(&self) -> KillSwitchLevel {
        self.protection.level_in_force()
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

    async fn remove_all(&self) -> AppResult<()> {
        let (protection, store) = (self.protection.clone(), self.store.clone());
        blocking(move || {
            let persist = |s: &ProtectionSettings| save_settings(&store, s);
            protection.set_level(KillSwitchLevel::Off, &persist)?;
            vpnte_winnet::wfp::remove_all()
                .map(drop)
                .map_err(AppError::from)
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review service-a9: no file is "off", a damaged one is "strict", a saved one reads back.
    #[test]
    fn damaged_settings_fail_closed() {
        let dir = std::env::temp_dir().join(format!("vpnte-ks-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let store = dir.join("protection.json");
        let _ = std::fs::remove_file(&store);
        assert_eq!(load_settings(&store).level, KillSwitchLevel::Off);
        for torn in [&b""[..], b"\0\0\0\0", br#"{"level":"str"#] {
            std::fs::write(&store, torn).expect("torn file");
            assert_eq!(load_settings(&store).level, KillSwitchLevel::Strict);
        }
        let standard = ProtectionSettings {
            level: KillSwitchLevel::Standard,
            ..ProtectionSettings::default()
        };
        save_settings(&store, &standard).expect("save");
        assert_eq!(load_settings(&store).level, KillSwitchLevel::Standard);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
