//! Computing the filter sets of a target state and syncing them to BFE.
use std::path::PathBuf;
use std::sync::Arc;

use vpnte_base::types::{KillSwitchLevel, now_ms};

use super::{Inner, Persist, Target, same_ids};
use crate::wfp::desired::{Change, Desired, Plan, desired};
use crate::wfp::engine::WfpError;
use crate::wfp::model::{ExceptionTarget, KillSwitchException, ProtectionError, Unconfirmed};
use crate::wfp::spec::FilterSpec;
use crate::wfp::validate;

impl Inner {
    pub(super) fn target(&self) -> Target {
        Target {
            settings: self.settings.clone(),
            conn: self.conn,
            tun_luid: self.tun_luid,
            session: self.session.clone(),
            tun_addrs: self.tun_addrs.clone(),
            armed: self.armed,
        }
    }

    pub(super) fn commit_conn(&mut self, t: &Target) {
        self.conn = t.conn;
        self.tun_luid = t.tun_luid;
        self.session.clone_from(&t.session);
        self.tun_addrs.clone_from(&t.tun_addrs);
        self.armed = t.armed;
    }

    /// The stored level as the filters enforce it ([`KillSwitchLevel::effective`]).
    pub(super) fn level_in_force(&self) -> KillSwitchLevel {
        self.settings.level.effective(self.always_available)
    }

    /// Resolves app IDs and computes the filter sets of `t`, plus the ids of app exceptions
    /// skipped because their file is missing (less is allowed: the safe direction).
    pub(super) fn plan(&mut self, t: &Target) -> Result<(Desired, Vec<String>), ProtectionError> {
        let s = &t.settings;
        let level = s.level.effective(self.always_available);
        let strict = level == KillSwitchLevel::Strict;
        let session = t.conn.in_session();
        let on_drop = level == KillSwitchLevel::Standard && t.armed;
        if !strict && !(session && (on_drop || s.leak_protection)) {
            return Ok((Desired::default(), Vec::new()));
        }
        let mut plan = Plan {
            level,
            armed: t.armed,
            leak_protection: s.leak_protection,
            public_wifi_compat: s.public_wifi_compat,
            allow_lan: s.allow_lan,
            conn: t.conn,
            tun_luid: t.tun_luid,
            tun_addrs: t.tun_addrs.clone(),
            ..Plan::default()
        };
        let engines: Vec<PathBuf> = self.engines.all().map(PathBuf::from).collect();
        for path in &engines {
            match self.backend.app_id(path) {
                Ok(id) => plan.engines.push(id),
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "engine not permitted: no app ID")
                }
            }
        }
        match self.backend.app_id(&self.self_exe) {
            Ok(id) => plan.own = Some(id),
            Err(e) => tracing::warn!(error = %e, "own executable not permitted: no app ID"),
        }
        if session {
            for path in &t.session {
                let id = self
                    .backend
                    .app_id(path)
                    .map_err(|_| ProtectionError::EngineMissing(path.clone()))?;
                plan.session.push(id);
            }
        }
        let mut skipped = Vec::new();
        for e in &s.exceptions {
            match &e.target {
                ExceptionTarget::Ip(net) => plan.exception_nets.push(*net),
                ExceptionTarget::App(path) => match self.backend.app_id(path) {
                    Ok(id) => plan.exception_apps.push(id),
                    Err(_) => skipped.push(e.id.clone()),
                },
            }
        }
        Ok((desired(&plan), skipped))
    }

    /// Brings both sessions to `d`; steps already in sync are skipped. Entering strict wants
    /// the persistent set first, everything else the dynamic set first (so leaving strict adds
    /// the standard set before the persistent one goes). A change is read back afterwards.
    pub(super) fn sync(
        &mut self,
        d: &Desired,
        persistent_first: bool,
    ) -> Result<(), ProtectionError> {
        let changed = if persistent_first {
            let persistent = self.sync_persistent(&d.persistent)?;
            self.sync_dynamic(&d.dynamic)? || persistent
        } else {
            let dynamic = self.sync_dynamic(&d.dynamic)?;
            self.sync_persistent(&d.persistent)? || dynamic
        };
        self.last_error = None;
        if changed {
            self.verify();
        }
        Ok(())
    }

    /// Read-back after a commit, from a fresh enumeration. A mismatch is left to the watchdog
    /// (re-apply); either way `last_verified` moves only when the read-back matched.
    pub(super) fn verify(&mut self) {
        match self.backend.census() {
            Ok(c) => {
                let dynamic_ok = same_ids(&c.dynamic, &self.dynamic);
                let persistent_ok = self
                    .persistent
                    .as_ref()
                    .is_some_and(|p| same_ids(&c.persistent, p));
                if dynamic_ok && persistent_ok {
                    self.last_verified = Some(now_ms());
                    return;
                }
                tracing::warn!(
                    dynamic_ok,
                    persistent_ok,
                    "WFP read-back differs from the committed set"
                );
                self.dynamic_dirty |= !dynamic_ok;
                if !persistent_ok {
                    self.persistent = None;
                }
            }
            Err(e) => tracing::debug!(error = %e, "WFP read-back not possible"),
        }
    }

    /// The dynamic session is gone (closed, or BFE restarted): none of its filters exist.
    pub(super) fn drop_dynamic(&mut self) {
        self.backend.close_dynamic();
        self.dynamic.clear();
        self.dynamic_dirty = false;
    }

    /// `Ok(true)` when something was applied.
    pub(super) fn sync_dynamic(&mut self, specs: &[FilterSpec]) -> Result<bool, ProtectionError> {
        let change = match self.dynamic_dirty {
            true => Change::replace(&self.dynamic, specs),
            false => Change::between(&self.dynamic, specs),
        };
        if change.is_noop() {
            // Nothing of ours to delete and nothing wanted: no doubt left either.
            self.dynamic_dirty = false;
            return Ok(false);
        }
        let mut result = self.try_dynamic(change);
        if matches!(&result, Err(e) if e.engine_lost()) {
            // BFE restarted: the old session and its filters are gone; reopen once.
            self.drop_dynamic();
            self.sublayer_weight = None;
            result = self.try_dynamic(Change::between(&[], specs));
        }
        self.dynamic_dirty = result.is_err();
        result.map(|()| true).map_err(|e| self.wfp_failed(e))
    }

    fn try_dynamic(&mut self, change: Change) -> Result<(), WfpError> {
        if !change.add.is_empty() {
            self.ensure()?;
        }
        let ids = self.backend.change_dynamic(&change.delete, &change.add)?;
        self.dynamic = change.installed(ids);
        self.bfe_running = Some(true);
        Ok(())
    }

    /// `Ok(true)` when something was applied. An unknown persistent set (startup, a failure)
    /// is replaced as a whole: every persistent filter of ours goes.
    pub(super) fn sync_persistent(
        &mut self,
        specs: &[FilterSpec],
    ) -> Result<bool, ProtectionError> {
        let change = self.persistent.as_ref().map(|p| Change::between(p, specs));
        if change.as_ref().is_some_and(Change::is_noop) {
            return Ok(false);
        }
        let change = change.unwrap_or_else(|| Change::replace(&[], specs));
        let result = match change.add.is_empty() {
            true => Ok(()),
            false => self.ensure(),
        }
        .and_then(|()| {
            let delete = self
                .persistent
                .is_some()
                .then_some(change.delete.as_slice());
            self.backend.change_persistent(delete, &change.add)
        });
        match result {
            Ok(ids) => {
                self.persistent = Some(change.installed(ids));
                self.bfe_running = Some(true);
                Ok(true)
            }
            Err(e) => {
                self.persistent = None;
                Err(self.wfp_failed(e))
            }
        }
    }

    pub(super) fn ensure(&mut self) -> Result<(), WfpError> {
        if self.sublayer_weight.is_none() {
            self.sublayer_weight = Some(self.backend.ensure()?);
        }
        Ok(())
    }

    pub(super) fn wfp_failed(&mut self, e: WfpError) -> ProtectionError {
        let err = ProtectionError::from(e);
        let repeated = self.last_error.as_ref().map(ToString::to_string) == Some(err.to_string());
        if repeated {
            tracing::debug!(error = %e, "WFP change failed again");
        } else {
            tracing::warn!(error = %e, "WFP change failed; the previous filters stay");
        }
        if e.is_rpc_failure() {
            self.bfe_running = Some(false);
        }
        // Provider or sublayer may be gone (a cleanup ran): check them again next time.
        self.sublayer_weight = None;
        self.last_error = Some(err.clone());
        err
    }

    /// Re-applies the sets of `prev` after a later step failed; `Err` means the previous
    /// protection could not be restored either.
    pub(super) fn restore(&mut self, prev: &Target) -> Result<(), ProtectionError> {
        let (d, _) = self.plan(prev)?;
        let strict =
            prev.settings.level.effective(self.always_available) == KillSwitchLevel::Strict;
        self.sync(&d, strict)
    }

    /// A transition of the connection state; `always` commits it even when applying fails
    /// (it reports a fact, e.g. the TUN is gone), otherwise a failure leaves the state as is.
    pub(super) fn transition(
        &mut self,
        t: Target,
        always: bool,
    ) -> Result<Vec<String>, ProtectionError> {
        let result = self
            .plan(&t)
            .and_then(|(d, skipped)| self.sync(&d, false).map(|()| skipped));
        if result.is_ok() || always {
            self.commit_conn(&t);
        }
        result
    }

    /// Validates a new exception list: labels and IPs of every entry, the path of every app
    /// entry that is new (a stored entry whose file vanished stays and is skipped), equivalents
    /// and the 256 limit, all before anything is applied or stored.
    pub(super) fn checked_list(
        &self,
        list: Vec<KillSwitchException>,
    ) -> Result<Vec<KillSwitchException>, ProtectionError> {
        let mut out = Vec::with_capacity(list.len());
        for mut e in list {
            e.label = validate::check_label(&e.label)?.to_owned();
            match &e.target {
                ExceptionTarget::Ip(_) => {
                    e.target = ExceptionTarget::Ip(validate::parse_ip_or_cidr(&e.target.value())?);
                }
                ExceptionTarget::App(path) => {
                    if !self
                        .settings
                        .exceptions
                        .iter()
                        .any(|old| old.id == e.id && old.target == e.target)
                    {
                        let raw = path.to_str().ok_or(validate::ValidationError::Unreadable)?;
                        e.target = ExceptionTarget::App(validate::canonical_exe(raw)?);
                    }
                }
            }
            out.push(e);
        }
        validate::check_list(&out)?;
        Ok(out)
    }

    pub(super) fn replace_exceptions(
        &mut self,
        list: Vec<KillSwitchException>,
        persist: Persist,
    ) -> Result<Vec<String>, ProtectionError> {
        let list = self.checked_list(list)?;
        let prev = self.target();
        let mut next = prev.clone();
        next.settings.exceptions = list;
        let applied = self
            .plan(&next)
            .and_then(|(d, skipped)| self.sync(&d, false).map(|()| skipped));
        let skipped = match applied {
            Ok(skipped) => skipped,
            Err(e) => {
                if let Err(again) = self.restore(&prev) {
                    tracing::warn!(error = %again, "restoring the previous exception filters failed");
                }
                return Err(e);
            }
        };
        if let Err(e) = persist(&next.settings) {
            tracing::warn!(error = %e, "exception list not saved; restoring the previous filters");
            return match self.restore(&prev) {
                Ok(()) => Err(ProtectionError::Persist(Arc::new(e))),
                Err(_) => Err(self.unconfirmed(Unconfirmed::Exceptions)),
            };
        }
        self.settings.exceptions = next.settings.exceptions;
        Ok(skipped)
    }

    pub(super) fn unconfirmed(&mut self, what: Unconfirmed) -> ProtectionError {
        let err = ProtectionError::Unconfirmed(what);
        self.last_error = Some(err.clone());
        err
    }
}
