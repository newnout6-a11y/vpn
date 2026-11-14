//! Stopping (spec 3.16, 3.20, 3.28 with B-9, B-18): one slot, every slot, the automatic stop
//! after the failure budget, and the app exit. A slot is released only once its engine's exit
//! is confirmed.
use std::sync::Arc;

use futures_util::future::join_all;
use vpnte_base::types::now_ms;

use super::Inner;
use super::launch::STOP_TIMEOUT;
use super::registry::Live;
use crate::health::{FAILURE_BUDGET, Route};
use crate::model::{ProxyError, StopReason};
use crate::slot::Slot;

impl Inner {
    /// Terminates an engine taken out of `slot`; `false` when its exit was not confirmed.
    pub(super) async fn terminate(&self, slot: Slot, live: &Live, reason: &str) -> bool {
        let confirmed = live.engine.terminate(STOP_TIMEOUT).await;
        if confirmed {
            tracing::info!(slot = %slot, pid = live.pid, reason, "instance process stopped");
        } else {
            tracing::error!(slot = %slot, pid = live.pid, reason, "external proxy engine did not exit");
        }
        confirmed
    }

    /// Stops `slot` (3.20); the caller holds the slot guard. `preserve` keeps the profile and
    /// the health (auto-disable). The slot is released only once the engine's exit is
    /// confirmed (B-18): an engine that does not exit keeps the slot `failed` and its port
    /// reserved; a retry stops it again.
    async fn stop_held(&self, slot: Slot, reason: &str, preserve: bool) -> Result<(), ProxyError> {
        let now = now_ms();
        let engine = {
            let mut reg = self.reg.lock();
            let Some(state) = reg.slots.get_mut(&slot) else {
                return Ok(());
            };
            if !preserve {
                // Not ready from this moment: a status read while the engine stops must not
                // offer the route.
                state.route = Route::stopped(now);
            }
            state.live.as_ref().map(|live| {
                live.cancel.cancel();
                (live.engine.clone(), live.pid)
            })
        };
        if let Some((engine, pid)) = engine
            && !engine.terminate(STOP_TIMEOUT).await
        {
            tracing::error!(slot = %slot, pid, reason, "external proxy engine did not exit");
            let mut reg = self.reg.lock();
            if let Some(state) = reg.slots.get_mut(&slot) {
                state
                    .route
                    .process_failed("engine did not exit".into(), now_ms());
                state.updated_at = Some(now_ms());
            }
            self.publish(&reg);
            return Err(ProxyError::Engine("engine did not exit".into()));
        }
        let mut guard = self.reg.lock();
        let reg = &mut *guard;
        if let Some(state) = reg.slots.get_mut(&slot) {
            state.take_live();
            state.configured = false;
            state.port = None;
            if !preserve {
                state.profile = None;
                state.auto_disabled = false;
                state.country_query = None;
                state.forget_rotations();
            }
            state.updated_at = Some(now_ms());
        }
        self.publish(reg);
        tracing::info!(slot = %slot, reason, "slot stopped");
        Ok(())
    }

    /// `POST /stop`, the UI stop button.
    pub(super) async fn stop_op(&self, slot: Slot, reason: StopReason) -> Result<(), ProxyError> {
        let _guard = self.lock_slot(slot).await;
        self.stop_held(slot, reason.as_str(), false).await
    }

    /// Stops every slot (B-9): UI "stop all", main VPN disconnect.
    pub(super) async fn stop_all_op(&self, reason: StopReason) {
        let slots: Vec<Slot> = {
            let reg = self.reg.lock();
            let listed = reg.slots.iter().filter(|(_, s)| s.is_listed());
            listed.map(|(slot, _)| *slot).collect()
        };
        for slot in slots {
            let _guard = self.lock_slot(slot).await;
            if let Err(err) = self.stop_held(slot, reason.as_str(), false).await {
                tracing::warn!(slot = %slot, error = %err, "external proxy not stopped");
            }
        }
        tracing::info!(
            reason = reason.as_str(),
            "all external proxy instances stopped"
        );
    }

    /// The failure budget of `generation` is spent (3.16): the slot is stopped and marked
    /// auto-disabled, keeping its profile for the UI.
    pub(super) async fn auto_disable(self: Arc<Self>, slot: Slot, generation: u64) {
        let _guard = self.lock_slot(slot).await;
        let now = now_ms();
        {
            let mut guard = self.reg.lock();
            let reg = &mut *guard;
            let Some(state) = reg.slots.get_mut(&slot) else {
                return;
            };
            // A forced probe may have healed the route while this waited for the guard.
            let spent = state.route.consecutive_failures >= FAILURE_BUDGET;
            if !spent || state.live_of(generation).is_none() {
                return;
            }
            state.route.disabled(now);
            state.auto_disabled = true;
            let profile = state
                .profile
                .as_ref()
                .map(|p| p.id.as_str())
                .unwrap_or_default();
            tracing::error!(slot = %slot, profile, failures = state.route.consecutive_failures,
                error = state.route.last_error.as_deref().unwrap_or_default(),
                "disabled after repeated health-check transport failures");
            self.publish(reg);
        }
        let reason = "health failure budget exhausted";
        if let Err(err) = self.stop_held(slot, reason, true).await {
            tracing::warn!(slot = %slot, error = %err, "auto-disabled slot not stopped");
        }
    }

    /// App exit: no new start, every engine stopped.
    pub(super) async fn shutdown(&self) {
        self.closing.cancel();
        let lives: Vec<(Slot, Live)> = {
            let mut guard = self.reg.lock();
            let reg = &mut *guard;
            reg.closed = true;
            let now = now_ms();
            let lives = reg
                .slots
                .iter_mut()
                .filter_map(|(slot, state)| {
                    state.configured = false;
                    state.port = None;
                    state.route = Route::stopped(now);
                    state.take_live().map(|live| (*slot, live))
                })
                .collect();
            self.publish(reg);
            lives
        };
        join_all(
            lives
                .iter()
                .map(|(slot, live)| self.terminate(*slot, live, "shutdown")),
        )
        .await;
    }
}
