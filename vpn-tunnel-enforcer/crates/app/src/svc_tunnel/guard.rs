//! The kill switch. With the helper service installed it applies the filters (`remote`, owner
//! decision 12.11.2026) and "Always" (stored `strict`) is offered: the service keeps it across
//! app exits and reboots. Without the service, WFP [`Protection`] exists only when this process
//! is elevated; otherwise the level keeps its proxy-mode meaning (off / "If the VPN drops" act
//! through the system proxy) and every WFP-only operation answers `needs_admin()`. Where nothing
//! keeps "Always" safe, a stored `strict` works as "If the VPN drops" and choosing it is refused
//! with one calm line. Every method blocks (WFP calls, pipe calls, store writes): call them from
//! `spawn_blocking`.
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_winnet::wfp::{
    self, EnginePaths, ExceptionKind, KillSwitchException, Protection, ProtectionSettings,
    RemoveReport, Toggles,
};

use super::remote::Remote;
use crate::services::{Engines, KillSwitchStatus};
use crate::svc_core::docs::ProtectionDoc;
use crate::svc_core::needs_admin;

/// "Always" is chosen where nothing can keep it safe yet.
fn needs_service() -> AppError {
    AppError::msg(
        ErrorKind::Permission,
        Msg::new("app.tunnel.alwaysNeedsService"),
    )
}

/// The kill-switch owner: keeps `protection.json` and `Settings::kill_switch` in step.
pub(super) struct Guard {
    pub wfp: Option<Arc<Protection>>,
    settings: Arc<Store<Settings>>,
    doc: Arc<Store<ProtectionDoc>>,
    /// "Always" can be kept safe (the helper service holds it); the lifecycle reads the same
    /// flag.
    pub always: Arc<AtomicBool>,
    /// The helper service: while it is installed the filters are its.
    remote: Remote,
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
        remote: Remote,
    ) -> Self {
        let saved = doc.read(|d| d.settings.clone());
        if settings.read(|s| s.kill_switch) != saved.level
            && let Err(e) = settings.update(|s| s.kill_switch = saved.level)
        {
            tracing::warn!(error = %e, "kill-switch level not synced into settings");
        }
        // One owner of our WFP objects: with the service installed it is the service, also when
        // this process happens to be elevated.
        let wfp = if elevated && !remote.installed() {
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
            always: Arc::new(AtomicBool::new(remote.installed())),
            remote,
        }
    }

    /// "Always" can be kept safe in this process (see the module doc).
    pub fn always_available(&self) -> bool {
        self.always.load(Ordering::Relaxed)
    }

    /// Tunnel mode can run: through the service, or in this elevated process.
    pub fn tun_available(&self) -> bool {
        self.wfp.is_some() || self.remote.installed()
    }

    /// The service was installed from Settings: "Always" is kept safe from now on.
    pub fn service_installed(&self) {
        self.always.store(true, Ordering::Relaxed);
    }

    /// The service's filters, when it is installed.
    fn service(&self) -> Option<&Remote> {
        (self.wfp.is_none() && self.remote.installed()).then_some(&self.remote)
    }

    /// Applies `next` where the filters live (the service) and saves it.
    fn apply_remote(&self, remote: &Remote, next: &ProtectionSettings) -> AppResult<()> {
        remote.apply_protection(next.clone())?;
        self.persist(next)
    }

    /// Writes what the protection decided into both stores (runs under the protection lock).
    fn persist(&self, s: &ProtectionSettings) -> AppResult<()> {
        self.doc.update(|d| d.settings = s.clone())?;
        self.settings.update(|x| x.kill_switch = s.level)
    }

    fn wfp(&self) -> AppResult<&Arc<Protection>> {
        self.wfp.as_ref().ok_or_else(needs_admin)
    }

    /// Start-up: "Always" filters set where they are kept safe, persistent leftovers removed.
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

    /// Saved settings plus, with WFP (here or in the service), a fresh read-back.
    pub fn status(&self) -> KillSwitchStatus {
        let wfp = match self.service() {
            Some(remote) => remote
                .protection_status()
                .inspect_err(|e| tracing::warn!(error = %e, "service kill-switch read failed"))
                .ok(),
            None => self.wfp.as_ref().map(|p| p.status()),
        };
        KillSwitchStatus {
            settings: self.doc.read(|d| d.settings.clone()),
            wfp,
        }
    }

    /// Applies and persists `level`. "Always" only where it can be kept safe (the helper
    /// service); without WFP the other levels act through the system proxy (proxy mode). A
    /// refused level puts the saved one back into the settings (the caller may have written it).
    pub fn set_level(&self, level: KillSwitchLevel) -> AppResult<()> {
        let result = match &self.wfp {
            _ if level == KillSwitchLevel::Strict && !self.always_available() => {
                Err(needs_service())
            }
            Some(p) => p
                .set_level(level, &|s| self.persist(s))
                .map_err(AppError::from),
            None if self.service().is_some() => {
                let mut next = self.doc.read(|d| d.settings.clone());
                next.level = level;
                self.apply_remote(&self.remote, &next)
            }
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
        let before = self.doc.read(|d| d.settings.leak_protection);
        if let Some(remote) = self.service() {
            let mut next = self.doc.read(|d| d.settings.clone());
            next.leak_protection = toggles.leak_protection;
            next.public_wifi_compat = toggles.public_wifi_compat;
            next.allow_lan = toggles.allow_lan;
            self.apply_remote(remote, &next)?;
            return Ok(before != toggles.leak_protection);
        }
        let p = self.wfp()?;
        p.update_settings(toggles)?;
        self.doc.update(|d| {
            d.settings.leak_protection = toggles.leak_protection;
            d.settings.public_wifi_compat = toggles.public_wifi_compat;
            d.settings.allow_lan = toggles.allow_lan;
        })?;
        Ok(before != toggles.leak_protection)
    }

    /// Validates, applies and persists a new exception with a fresh id. A broad network is no
    /// reason to stop or warn: the settings page shows a hint under it (research 5.8).
    pub fn add_exception(
        &self,
        kind: ExceptionKind,
        value: &str,
        label: &str,
    ) -> AppResult<KillSwitchException> {
        let remote = self.service();
        let local = match remote {
            Some(_) => None,
            None => Some(self.wfp()?),
        };
        let (target, label) = wfp::validate_exception(kind, value, label)?;
        let exception = KillSwitchException {
            id: uuid::Uuid::new_v4().simple().to_string(),
            target,
            label,
        };
        match (remote, local) {
            (Some(remote), _) => {
                let mut next = self.doc.read(|d| d.settings.clone());
                next.exceptions.push(exception.clone());
                self.apply_remote(remote, &next)?;
            }
            (None, Some(p)) => p.add_exception(exception.clone(), &|s| self.persist(s))?,
            (None, None) => return Err(needs_admin()),
        }
        Ok(exception)
    }

    /// Removes the exception `id`, applies and persists the list.
    pub fn remove_exception(&self, id: &str) -> AppResult<()> {
        if let Some(remote) = self.service() {
            let mut next = self.doc.read(|d| d.settings.clone());
            next.exceptions.retain(|e| e.id != id);
            return self.apply_remote(remote, &next);
        }
        let p = self.wfp()?;
        Ok(p.remove_exception(id, &|s| self.persist(s))?)
    }

    /// Removes every filter of ours (outside a session: `Conflict` during one). An "Always" in
    /// force goes off with its filters; the saved level follows what now holds.
    pub fn release(&self) -> AppResult<RemoveReport> {
        if let Some(remote) = self.service() {
            let report = remote.cleanup()?;
            let level = remote.protection_status()?.level;
            if self.doc.read(|d| d.settings.level) != level {
                let mut next = self.doc.read(|d| d.settings.clone());
                next.level = level;
                self.persist(&next)?;
            }
            return Ok(report);
        }
        let p = self.wfp()?;
        Ok(p.reset(&|s| self.persist(s))?)
    }

    /// App exit: closes the dynamic session ("Always" filters, where in force, stay).
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
