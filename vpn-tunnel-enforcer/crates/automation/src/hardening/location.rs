//! Windows location privacy (spec §2.13, §3.8, §6.8 `LocationPrivacy`): while a protected session
//! runs, apps get no geolocation. The user's consent is set to deny and the machine policy turns
//! the location provider off (owner question Q2: both, as before; the policy covers every account
//! of the PC while it is applied).
//!
//! Session-scoped (fix L2): the lifecycle applies it after a successful connect when the setting
//! is on and rolls it back on disconnect, shutdown and startup recovery; a toggle while connected
//! applies or rolls back at once. Nothing here rewrites the setting. "Applied by us" comes from
//! the journal; the OS state, which the user may have chosen himself, is reported next to it
//! (fix L3).
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::system::System;
use super::{admissible, needs_admin, short_text};
use crate::tweaks::journal::{
    Feature, Journal, RegHive, RollbackReport, Target, TweakError, TweakState, Val,
};
use crate::tweaks::run_blocking;

/// The user's location consent: `(hive, key, value name)`, `REG_SZ` `Allow` / `Deny`.
pub const CONSENT: (RegHive, &str, &str) = (
    RegHive::Hkcu,
    r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
    "Value",
);
/// The machine policy key (`HKLM`) of the two location policies.
pub const POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors";
/// The two `REG_DWORD` policies, 1 while applied.
pub const POLICY_VALUES: [&str; 2] = ["DisableLocation", "DisableWindowsLocationProvider"];

/// The three values and what we write (LP:13-14, 207-211).
pub fn plan() -> Vec<(Feature, Target, Val)> {
    let (hive, key, name) = CONSENT;
    let mut plan = vec![(
        Feature::LocationPrivacy,
        Target::Reg {
            hive,
            key: key.to_owned(),
            name: name.to_owned(),
        },
        Val::Sz("Deny".to_owned()),
    )];
    plan.extend(
        POLICY_VALUES.map(|name| (Feature::LocationPrivacy, policy_target(name), Val::Dword(1))),
    );
    plan
}

fn policy_target(name: &str) -> Target {
    Target::Reg {
        hive: RegHive::Hklm,
        key: POLICY_KEY.to_owned(),
        name: name.to_owned(),
    }
}

/// Allow-list part of [`super::admit`]: the consent as a string, the policies as DWORDs.
pub(crate) fn admits(hive: RegHive, key: &str, name: &str, value: &Val) -> bool {
    let is = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    match hive {
        RegHive::Hkcu => is(key, CONSENT.1) && is(name, CONSENT.2) && short_text(value),
        RegHive::Hklm => {
            is(key, POLICY_KEY)
                && POLICY_VALUES.iter().any(|n| is(name, n))
                && matches!(value, Val::Absent | Val::Dword(_))
        }
    }
}

/// Location privacy as the UI shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationStatus {
    /// Our values: `Off` (none journalled), `On`, `Drifted` (changed since), `Unknown`.
    pub ours: TweakState,
    /// The user's consent denies location to apps (`None` = could not be read).
    pub user_denied: Option<bool>,
    /// A machine policy switches location off (`None` = could not be read).
    pub policy_disabled: Option<bool>,
}

impl LocationStatus {
    /// Windows gives apps no location now, whoever decided it (`None` = not checked).
    pub fn os_denied(&self) -> Option<bool> {
        match (self.user_denied, self.policy_disabled) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), Some(false)) => Some(false),
            _ => None,
        }
    }
}

/// For the stop result when a rollback left values for a retry (LP:259).
pub fn rollback_failure_msg(report: &RollbackReport) -> Option<Msg> {
    (!report.is_complete()).then(|| Msg::new("automation.hardening.location.rollbackFailed"))
}

/// Location privacy over the shared journal. Cheap to clone.
#[derive(Clone)]
pub struct Location {
    journal: Arc<Journal>,
    sys: Arc<dyn System>,
}

impl Location {
    /// Location privacy on the machine `sys`.
    pub fn new(journal: Arc<Journal>, sys: Arc<dyn System>) -> Self {
        Self { journal, sys }
    }

    /// Denies location (needs elevation). Nothing is written when a current value cannot be
    /// read; a failed write undoes the others. Applying again keeps the original baselines.
    pub async fn apply(&self) -> AppResult<LocationStatus> {
        let this = self.clone();
        run_blocking(move || this.apply_blocking()).await?
    }

    /// Puts our values back; a value changed by someone else since is kept, a failure stays
    /// journalled for the next attempt ([`rollback_failure_msg`]).
    pub async fn rollback(&self) -> AppResult<RollbackReport> {
        let this = self.clone();
        run_blocking(move || this.rollback_blocking()).await
    }

    /// Reads our values and the OS state.
    pub async fn status(&self) -> AppResult<LocationStatus> {
        let this = self.clone();
        run_blocking(move || this.status_blocking()).await
    }

    /// Whether location values are journalled (the obligation disconnect and recovery look at).
    pub fn is_applied(&self) -> bool {
        self.journal.is_applied(Feature::LocationPrivacy)
    }

    /// Blocking form of [`Location::apply`].
    pub fn apply_blocking(&self) -> AppResult<LocationStatus> {
        if !self.sys.elevated() {
            return Err(needs_admin());
        }
        // The consent lives in HKCU: as another administrator it would land in the wrong profile.
        self.sys.check_user()?;
        let plan = plan();
        for (_, target, _) in &plan {
            let current = self
                .sys
                .read(target)
                .map_err(|e| apply_error(TweakError::Unreadable(target.label(), e)))?;
            // A baseline outside the allow-list would be dropped from the journal at the next
            // start and our value would stay for good: refuse instead.
            if !admissible(target, &current) {
                tracing::warn!(target = %target.label(), "location value of an unexpected type; not applied");
                return Err(AppError::msg(
                    ErrorKind::Conflict,
                    Msg::new("automation.hardening.location.foreignValue"),
                ));
            }
        }
        self.journal.apply(&*self.sys, &plan).map_err(apply_error)?;
        Ok(self.status_blocking())
    }

    /// Blocking form of [`Location::rollback`].
    pub fn rollback_blocking(&self) -> RollbackReport {
        self.journal
            .rollback(&*self.sys, &[Feature::LocationPrivacy])
    }

    /// Blocking form of [`Location::status`].
    pub fn status_blocking(&self) -> LocationStatus {
        let (hive, key, name) = CONSENT;
        let consent = self.sys.read(&Target::Reg {
            hive,
            key: key.to_owned(),
            name: name.to_owned(),
        });
        let user_denied = consent
            .ok()
            .map(|v| matches!(&v, Val::Sz(s) | Val::ExpandSz(s) if s.eq_ignore_ascii_case("deny")));
        let policies = POLICY_VALUES.map(|name| self.sys.read(&policy_target(name)));
        let policy_disabled = if policies.iter().any(|v| matches!(v, Ok(Val::Dword(1)))) {
            Some(true)
        } else if policies.iter().all(Result::is_ok) {
            Some(false)
        } else {
            None
        };
        LocationStatus {
            ours: self.journal.status(&*self.sys, Feature::LocationPrivacy),
            user_denied,
            policy_disabled,
        }
    }
}

/// The user-facing error of a failed apply (nothing of it is left in place).
fn apply_error(e: TweakError) -> AppError {
    let (kind, _) = e.describe();
    let msg = match &e {
        TweakError::Journal(_) => return e.into(),
        // The label starts with the hive (`Hkcu\…` / `Hklm\…`).
        TweakError::Unreadable(label, _) => {
            let hive = if label.starts_with("Hklm") {
                "HKLM"
            } else {
                "HKCU"
            };
            Msg::new("automation.hardening.location.unreadable").arg("hive", hive)
        }
        _ => Msg::new("automation.hardening.location.failed"),
    };
    AppError::msg(kind, msg).with_source(e)
}

#[cfg(test)]
mod tests;
