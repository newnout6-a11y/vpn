//! User settings: level, exceptions, switches and the maintenance reset.
use vpnte_base::types::KillSwitchLevel;

use super::{Persist, Protection, persist_failed};
use crate::wfp::backend::RemoveReport;
use crate::wfp::model::{KillSwitchException, ProtectionError, Toggles, Unconfirmed};
use crate::wfp::validate;

impl Protection {
    /// Changes the level. Entering "Always" (where it is in force) saves the choice before any
    /// effect; leaving it installs the new set, then removes the persistent one, then saves, and
    /// any failure on the way stays "Always" (fail closed). Other switches apply, then save; a
    /// failed save re-applies the previous level. A stored `strict` without the service works
    /// as `standard` ([`Protection::set_always_available`]).
    pub fn set_level(
        &self,
        level: KillSwitchLevel,
        persist: Persist,
    ) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        if g.settings.level == level {
            return Ok(());
        }
        let prev = g.target();
        let mut next = prev.clone();
        next.settings.level = level;
        if level.effective(g.always_available) == KillSwitchLevel::Strict {
            persist(&next.settings).map_err(persist_failed)?;
            g.settings.level = level;
            let (d, skipped) = g.plan(&next)?;
            g.sync(&d, true)?;
            self.note_skipped(&mut g, skipped);
            return Ok(());
        }
        let applied = g
            .plan(&next)
            .and_then(|(d, skipped)| g.sync(&d, false).map(|()| skipped));
        let skipped = match applied {
            Ok(skipped) => skipped,
            Err(e) => {
                if let Err(again) = g.restore(&prev) {
                    tracing::warn!(error = %again, "restoring the previous level failed");
                }
                return Err(e);
            }
        };
        if let Err(e) = persist(&next.settings) {
            let err = persist_failed(e);
            return match g.restore(&prev) {
                Ok(()) => Err(err),
                Err(_) => Err(g.unconfirmed(Unconfirmed::Level)),
            };
        }
        g.settings.level = level;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }

    /// Replaces the exception list: validated as a whole, applied to the active filters,
    /// then saved; a failed save re-applies the previous list.
    pub fn set_exceptions(
        &self,
        list: Vec<KillSwitchException>,
        persist: Persist,
    ) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        let skipped = g.replace_exceptions(list, persist)?;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }

    /// Appends one exception (build it from [`validate::validate_exception`] and a new id).
    pub fn add_exception(
        &self,
        exception: KillSwitchException,
        persist: Persist,
    ) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        let mut list = g.settings.exceptions.clone();
        list.push(exception);
        let skipped = g.replace_exceptions(list, persist)?;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }

    /// Removes the exception with this id.
    pub fn remove_exception(&self, id: &str, persist: Persist) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        let mut list = g.settings.exceptions.clone();
        let before = list.len();
        list.retain(|e| e.id != id);
        if list.len() == before {
            return Err(validate::ValidationError::NotFound.into());
        }
        let skipped = g.replace_exceptions(list, persist)?;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }

    /// Applies new switches; the caller saves them after `Ok`. On failure the previous
    /// switches and filters stay.
    pub fn update_settings(&self, toggles: Toggles) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        let prev = g.target();
        let mut next = prev.clone();
        next.settings.leak_protection = toggles.leak_protection;
        next.settings.public_wifi_compat = toggles.public_wifi_compat;
        next.settings.allow_lan = toggles.allow_lan;
        match g
            .plan(&next)
            .and_then(|(d, skipped)| g.sync(&d, false).map(|()| skipped))
        {
            Ok(skipped) => {
                g.settings = next.settings;
                self.note_skipped(&mut g, skipped);
                Ok(())
            }
            Err(e) => {
                if let Err(again) = g.restore(&prev) {
                    tracing::warn!(error = %again, "restoring the previous switches failed");
                }
                Err(e)
            }
        }
    }

    /// "Reset network protection" (maintenance, `--cleanup` equivalent): deletes every object
    /// of ours; refused while a TUN session exists. An "Always" level in force is switched off
    /// and saved, since its filters are gone; if saving fails the level stays and the watchdog
    /// re-installs it (fail closed).
    pub fn reset(&self, persist: Persist) -> Result<RemoveReport, ProtectionError> {
        let mut g = self.inner.lock();
        if g.conn.in_session() {
            return Err(ProtectionError::SessionActive);
        }
        g.drop_dynamic();
        g.persistent = None;
        g.sublayer_weight = None;
        let report = match g.backend.remove_all() {
            Ok(report) => report,
            Err(e) => return Err(g.wfp_failed(e)),
        };
        g.persistent = Some(Vec::new());
        g.last_error = None;
        if g.level_in_force() == KillSwitchLevel::Strict {
            let mut next = g.settings.clone();
            next.level = KillSwitchLevel::Off;
            persist(&next).map_err(persist_failed)?;
            g.settings.level = KillSwitchLevel::Off;
        }
        Ok(report)
    }
}
