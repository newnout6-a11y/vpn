//! Status for the UI and the watchdog that re-checks our filters.
use std::sync::Arc;

use vpnte_base::types::{KillSwitchLevel, Level, Notice, now_ms};

use super::{Inner, Protection, WATCHDOG_PERIOD, same_ids};
use crate::adapters;
use crate::wfp::backend::Census;
use crate::wfp::fwpolicy;
use crate::wfp::model::{Conn, KillSwitchState, ProtectionError, ProtectionStatus};

impl Inner {
    /// A fresh enumeration shows exactly the filters we installed, and nothing is in doubt.
    fn in_sync(&self, c: &Census) -> bool {
        !self.dynamic_dirty
            && same_ids(&c.dynamic, &self.dynamic)
            && self
                .persistent
                .as_ref()
                .is_some_and(|p| same_ids(&c.persistent, p))
    }
}

impl Protection {
    /// Status for the UI: a fresh enumeration of our filters (sub-millisecond) plus the
    /// read-only Windows Firewall and Hyper-V switch checks.
    pub fn status(&self) -> ProtectionStatus {
        let mut status = {
            let mut g = self.inner.lock();
            let census = g.backend.census();
            match &census {
                Ok(c) => {
                    g.bfe_running = Some(true);
                    if g.in_sync(c) {
                        g.last_verified = Some(now_ms());
                    }
                }
                Err(e) if e.is_rpc_failure() => g.bfe_running = Some(false),
                Err(e) => tracing::debug!(error = %e, "status: filters not readable"),
            }
            let level = g.level_in_force();
            let kill_switch = match (level, g.conn) {
                (KillSwitchLevel::Off, _) => KillSwitchState::Off,
                _ if g.last_error.is_some() => KillSwitchState::Failed,
                (KillSwitchLevel::Standard, _) if !g.armed => KillSwitchState::Armed,
                (_, Conn::Up) => KillSwitchState::Engaged,
                _ => KillSwitchState::Blocking,
            };
            let leak_protection_active = level == KillSwitchLevel::Off
                && g.conn.in_session()
                && !g.dynamic.is_empty()
                && !g.dynamic_dirty;
            ProtectionStatus {
                level,
                conn: g.conn,
                kill_switch,
                last_error: g.last_error.clone(),
                leak_protection_active,
                dynamic_filters: census.as_ref().ok().map(|c| c.dynamic.len() as u32),
                persistent_filters: census.as_ref().ok().map(|c| c.persistent.len() as u32),
                sublayer_weight: g.sublayer_weight,
                bfe_running: g.bfe_running,
                last_verified: g.last_verified,
                skipped_exceptions: g.skipped.clone(),
                windows_firewall_outbound_block: None,
                hyperv_switch_present: None,
            }
        };
        status.windows_firewall_outbound_block = fwpolicy::outbound_block_profiles()
            .inspect_err(|e| tracing::debug!(error = %e, "Windows Firewall policy not readable"))
            .ok();
        status.hyperv_switch_present = adapters::hyperv_switch_present()
            .inspect_err(|e| tracing::debug!(error = %e, "interface table not readable"))
            .ok();
        status
    }

    /// One watchdog pass: a fresh enumeration of our filters; a mismatch or a BFE restart (the
    /// only event that drops a dynamic session; sleep does not) re-applies. Does nothing while
    /// no filter exists or is wanted.
    pub fn watchdog_tick(&self) {
        let mut g = self.inner.lock();
        let t = g.target();
        let (d, skipped) = match g.plan(&t) {
            Ok(planned) => planned,
            Err(e) => {
                tracing::warn!(error = %e, "watchdog: protection cannot be planned");
                return;
            }
        };
        let wanted = !d.dynamic.is_empty() || !d.persistent.is_empty();
        let installed = !g.dynamic.is_empty()
            || g.dynamic_dirty
            || g.persistent.as_ref().is_none_or(|p| !p.is_empty());
        if !wanted && !installed {
            return;
        }
        match g.backend.census() {
            Ok(c) => {
                if g.in_sync(&c) {
                    g.last_verified = Some(now_ms());
                }
                g.dynamic_dirty |= !same_ids(&c.dynamic, &g.dynamic);
                if !g
                    .persistent
                    .as_ref()
                    .is_some_and(|p| same_ids(&c.persistent, p))
                {
                    g.persistent = None;
                }
                g.bfe_running = Some(true);
            }
            Err(e) if e.engine_lost() => {
                tracing::warn!(error = %e, "watchdog: BFE session lost, re-applying");
                g.drop_dynamic();
                g.sublayer_weight = None;
            }
            Err(e) => {
                let err = g.wfp_failed(e);
                self.watchdog_failure(&mut g, wanted, &err);
                return;
            }
        }
        let persistent_first = g.persistent_block(g.settings.level);
        match g.sync(&d, persistent_first) {
            Ok(()) => {
                g.watchdog_failed = false;
                self.note_skipped(&mut g, skipped);
            }
            Err(e) => self.watchdog_failure(&mut g, wanted, &e),
        }
    }

    fn watchdog_failure(&self, g: &mut Inner, wanted: bool, e: &ProtectionError) {
        tracing::warn!(error = %e, "watchdog: protection not confirmed");
        if wanted && !g.watchdog_failed {
            self.notify(
                Notice::new(Level::Error, "winnet.wfp.notice.unverifiedTitle")
                    .body("winnet.wfp.notice.unverified"),
            );
        }
        g.watchdog_failed = true;
    }

    /// Runs [`Protection::watchdog_tick`] every [`WATCHDOG_PERIOD`] on the blocking pool until
    /// `cancel` fires.
    pub async fn run_watchdog(self: Arc<Self>, cancel: tokio_util::sync::CancellationToken) {
        let mut tick = tokio::time::interval(WATCHDOG_PERIOD);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                _ = tick.tick() => {}
            }
            let me = self.clone();
            if let Err(e) = tokio::task::spawn_blocking(move || me.watchdog_tick()).await {
                tracing::warn!(error = %e, "watchdog tick failed");
            }
        }
    }
}
