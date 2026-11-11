//! The kill switch. WFP [`Protection`] exists only when this process is elevated (NOADMIN §0);
//! otherwise the level keeps its Soft-mode meaning (off / standard act through the system proxy,
//! strict needs WFP) and every WFP-only operation answers `needs_admin()`. Every method blocks
//! (WFP calls, store writes): call them from `spawn_blocking`.
use std::path::PathBuf;
use std::sync::Arc;

use vpnte_base::types::{KillSwitchLevel, Level, Notice};
use vpnte_base::{AppError, AppResult};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_winnet::wfp::{
    self, EnginePaths, ExceptionKind, KillSwitchException, Protection, ProtectionSettings,
    RemoveReport, Toggles,
};

use crate::services::{Engines, KillSwitchStatus};
use crate::svc_core::docs::ProtectionDoc;
use crate::svc_core::needs_admin;
use crate::svc_core::notify::Notifier;

/// The kill-switch owner: keeps `protection.json` and `Settings::kill_switch` in step.
pub(super) struct Guard {
    pub wfp: Option<Arc<Protection>>,
    settings: Arc<Store<Settings>>,
    doc: Arc<Store<ProtectionDoc>>,
    notifier: Arc<Notifier>,
}

impl Guard {
    /// The protection of an elevated process, else none. A level that differs between the two
    /// stores (a crash between the two writes) is taken from `protection.json`, the WFP model.
    /// Never fails the start: a read-only settings store keeps its value (logged), and an exe
    /// path WFP cannot use leaves the process without WFP (Hard unavailable, Soft works).
    pub fn new(
        elevated: bool,
        engines: &Engines,
        settings: Arc<Store<Settings>>,
        doc: Arc<Store<ProtectionDoc>>,
        notifier: Arc<Notifier>,
    ) -> Self {
        let saved = doc.read(|d| d.settings.clone());
        if settings.read(|s| s.kill_switch) != saved.level
            && let Err(e) = settings.update(|s| s.kill_switch = saved.level)
        {
            tracing::warn!(error = %e, "kill-switch level not synced into settings");
        }
        let wfp = if elevated {
            match self_exe() {
                Ok(exe) => {
                    let paths = EnginePaths {
                        singbox: engines.singbox.clone(),
                        xray: Some(engines.xray.clone()),
                        external_proxy: None,
                    };
                    Some(Arc::new(Protection::new(paths, exe, saved)))
                }
                Err(e) => {
                    tracing::error!(error = %e, "own exe not usable for WFP; running without it");
                    None
                }
            }
        } else {
            None
        };
        Self {
            wfp,
            settings,
            doc,
            notifier,
        }
    }

    /// Writes what the protection decided into both stores (runs under the protection lock).
    fn persist(&self, s: &ProtectionSettings) -> AppResult<()> {
        self.doc.update(|d| d.settings = s.clone())?;
        self.settings.update(|x| x.kill_switch = s.level)
    }

    fn wfp(&self) -> AppResult<&Arc<Protection>> {
        self.wfp.as_ref().ok_or_else(needs_admin)
    }

    /// Start-up: strict filters set, leftovers of a crashed run removed.
    pub fn startup(&self) -> AppResult<()> {
        match &self.wfp {
            Some(p) => p.startup().map_err(AppError::from),
            None => Ok(()),
        }
    }

    /// Saved settings only (no read-back).
    pub fn saved_status(&self) -> KillSwitchStatus {
        KillSwitchStatus {
            settings: self.doc.read(|d| d.settings.clone()),
            wfp: None,
        }
    }

    /// Saved settings plus, with WFP, a fresh read-back.
    pub fn status(&self) -> KillSwitchStatus {
        KillSwitchStatus {
            settings: self.doc.read(|d| d.settings.clone()),
            wfp: self.wfp.as_ref().map(|p| p.status()),
        }
    }

    /// Applies and persists `level`. Without WFP only off / standard exist (Soft behaviour).
    /// A refused level puts the saved one back into the settings (the caller may have written it).
    pub fn set_level(&self, level: KillSwitchLevel) -> AppResult<()> {
        let result = match &self.wfp {
            Some(p) => p
                .set_level(level, &|s| self.persist(s))
                .map_err(AppError::from),
            None if level == KillSwitchLevel::Strict => Err(needs_admin()),
            None => {
                let mut next = self.doc.read(|d| d.settings.clone());
                next.level = level;
                self.persist(&next)
            }
        };
        if result.is_err() {
            let saved = self.doc.read(|d| d.settings.level);
            if let Err(e) = self.settings.update(|s| s.kill_switch = saved) {
                tracing::warn!(error = %e, "kill-switch level not restored in settings");
            }
        }
        result
    }

    /// Applies and persists the protection switches; `true` when leak protection changed (the
    /// TUN form follows it, so a running TUN session must restart).
    pub fn set_toggles(&self, toggles: Toggles) -> AppResult<bool> {
        let p = self.wfp()?;
        let before = self.doc.read(|d| d.settings.leak_protection);
        p.update_settings(toggles)?;
        self.doc.update(|d| {
            d.settings.leak_protection = toggles.leak_protection;
            d.settings.public_wifi_compat = toggles.public_wifi_compat;
            d.settings.allow_lan = toggles.allow_lan;
        })?;
        Ok(before != toggles.leak_protection)
    }

    /// Validates, applies and persists a new exception with a fresh id.
    pub fn add_exception(
        &self,
        kind: ExceptionKind,
        value: &str,
        label: &str,
    ) -> AppResult<KillSwitchException> {
        let p = self.wfp()?;
        let (target, label) = wfp::validate_exception(kind, value, label)?;
        if let Some(warning) = wfp::broad_warning(&target) {
            self.notifier
                .notify(Notice::new(Level::Warn, warning), None);
        }
        let exception = KillSwitchException {
            id: uuid::Uuid::new_v4().simple().to_string(),
            target,
            label,
        };
        p.add_exception(exception.clone(), &|s| self.persist(s))?;
        Ok(exception)
    }

    /// Removes the exception `id`, applies and persists the list.
    pub fn remove_exception(&self, id: &str) -> AppResult<()> {
        let p = self.wfp()?;
        Ok(p.remove_exception(id, &|s| self.persist(s))?)
    }

    /// Removes every filter of ours (outside a session: `Conflict` during one).
    pub fn release(&self) -> AppResult<RemoveReport> {
        let p = self.wfp()?;
        Ok(p.reset(&|s| self.persist(s))?)
    }

    /// App exit: closes the dynamic session (strict filters stay).
    pub fn shutdown(&self) {
        if let Some(p) = &self.wfp {
            p.shutdown();
        }
    }
}

/// This executable in the spelling WFP app ids match (canonical long path, no `\\?\`).
fn self_exe() -> AppResult<PathBuf> {
    let exe = std::env::current_exe().map_err(AppError::internal)?;
    let real = std::fs::canonicalize(&exe).unwrap_or(exe);
    let text = real.to_string_lossy();
    Ok(wfp::canonical_exe(
        text.strip_prefix(r"\\?\").unwrap_or(&text),
    )?)
}
