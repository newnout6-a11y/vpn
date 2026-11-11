//! The operations (spec 3.20–3.25 with B-3, B-8, B-9, B-10, B-14, B-17, B-18, B-19): start /
//! rotate / connect, stop, stop all, add, batch start, prewarm, auto-disable and shutdown.
//! Every write runs under the slot's guard; the registry lock is only taken for the state
//! changes in between the awaits.
use std::collections::HashSet;
use std::sync::Arc;

use futures_util::future::join_all;
use tokio::sync::{OwnedMutexGuard, oneshot};
use vpnte_base::types::now_ms;

use super::launch::{self, STOP_TIMEOUT};
use super::pick::{Want, matches_country, pick};
use super::registry::{Assigned, Live, Registry};
use super::run::LoopCmd;
use super::{Inner, ProxyProfile};
use crate::health::{Route, ms};
use crate::lease::Guarded;
use crate::model::{
    Action, Aggregate, BatchFailure, BatchSkip, BatchSkipReason, BatchStartResult, PrewarmResult,
    ProxyError, StartRequest, StopReason, StopScope,
};
use crate::slot::Slot;

impl Inner {
    /// Start, rotate or connect `slot` (3.21). The caller holds the slot guard. A start of a
    /// configured running slot returns at once (it does not switch profile or country); a
    /// failed start leaves the slot configured and `failed` until an explicit stop.
    pub(super) async fn start_held(
        self: &Arc<Self>,
        slot: Slot,
        req: &StartRequest,
    ) -> Result<(), ProxyError> {
        let action = req.action;
        let explicit = req
            .profile_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty());
        if action == Action::Connect && explicit.is_none() {
            // B-3: the old answer ("No VPN profiles with outbound config found") misled.
            return Err(ProxyError::BadRequest(
                "profileId is required for connect/trigger".into(),
            ));
        }
        if req.port == Some(0) {
            return Err(ProxyError::BadRequest("invalid port".into()));
        }
        let profiles = self.source.profiles();
        let active_vpn = self.source.active_vpn_profile_id();
        let choice = self.source.engine_choice();
        let now = now_ms();
        let (generation, port, picked, old) = {
            let mut guard = self.reg.lock();
            let reg = &mut *guard;
            if reg.closed {
                return Err(ProxyError::Unavailable(
                    "external proxies are shutting down".into(),
                ));
            }
            let state = reg.slots.get(&slot);
            let configured = state.is_some_and(|s| s.configured);
            let own_port = state.filter(|s| s.configured).and_then(|s| s.port);
            let sticky = state.and_then(|s| s.country_query.clone());
            let current = state.and_then(|s| s.profile.as_ref()).map(|p| p.id.clone());
            if action == Action::Start && configured {
                if state.is_some_and(|s| s.live.is_some()) {
                    return Ok(());
                }
                reg.leases.guard(slot, Guarded::Restart, now)?;
            }
            reg.leases.guard(slot, Guarded::ChangeRoute, now)?;
            let port = req.port.or(own_port).unwrap_or_else(|| slot.default_port());
            self.check_port(reg, slot, port, own_port)?;
            // An explicit (even empty) country replaces the sticky filter.
            let country = req.country.clone().or(sticky);
            let filter = country.as_deref().unwrap_or_default();
            let usable: Vec<&ProxyProfile> = profiles
                .iter()
                .filter(|p| p.usable() && matches_country(p, filter))
                .collect();
            let used = reg.used_profiles(Some(slot));
            let used: HashSet<&str> = used.iter().map(String::as_str).collect();
            let want = Want {
                profile_id: explicit,
                action,
                current: current.as_deref(),
            };
            let picked = pick(&usable, want, &used, active_vpn.as_deref())
                .ok_or_else(|| no_profile(explicit, filter))?;
            let state = reg.slots.entry(slot).or_default();
            state.configured = true;
            state.port = Some(port);
            state.profile = Some(Assigned {
                id: picked.id.clone(),
                name: picked.name.clone(),
                country: picked.country.clone(),
            });
            state.country_query = country;
            state.auto_disabled = false;
            state.generation += 1;
            state.route.begin(action == Action::Rotate);
            if action == Action::Rotate {
                let reason = req
                    .rotate_reason
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or_default();
                let reason = if reason.is_empty() { "manual" } else { reason };
                state.last_rotate_reason = Some(reason.to_owned());
            }
            state.updated_at = Some(now);
            let old = state.take_live();
            let generation = state.generation;
            self.publish(reg);
            (generation, port, picked.clone(), old)
        };
        let reason = match action {
            Action::Start => "start",
            Action::Rotate => "rotate",
            Action::Connect => "connect",
        };
        let prepared = launch::prepare(&picked.profile, port, choice, &self.names).await;
        if let Some(old) = old {
            // Replaced only now that the new config is built and its endpoint resolved.
            self.terminate(slot, &old, "replace").await;
        }
        let started = match prepared {
            Ok(plan) => self.launcher.start(plan, &self.closing).await,
            Err(err) => Err(err),
        };
        let stale = {
            let mut reg = self.reg.lock();
            let current = !reg.closed
                && reg
                    .slots
                    .get(&slot)
                    .is_some_and(|s| s.generation == generation && s.configured);
            match started {
                Ok(engine) if current => {
                    let pid = engine.pid();
                    let live = self.go_live(slot, generation, port, engine);
                    let now = now_ms();
                    let state = reg.slots.entry(slot).or_default();
                    state.live = Some(live);
                    state.started_at = Some(now);
                    state.route.next_check_at = Some(now + ms(self.timing.first(slot)));
                    state.updated_at = Some(now);
                    self.publish(&reg);
                    tracing::info!(slot = %slot, pid, port, profile = %picked.id, reason,
                        "instance started");
                    None
                }
                Ok(engine) => Some(engine),
                Err(err) => {
                    if current && let Some(state) = reg.slots.get_mut(&slot) {
                        state
                            .route
                            .process_failed(err.detail().to_owned(), now_ms());
                        state.updated_at = Some(now_ms());
                        self.publish(&reg);
                    }
                    tracing::warn!(slot = %slot, profile = %picked.id, reason, error = %err,
                        "instance start failed");
                    return Err(err);
                }
            }
        };
        match stale {
            None => Ok(()),
            Some(engine) => {
                engine.terminate(STOP_TIMEOUT).await;
                Err(ProxyError::Conflict(format!(
                    "Slot {slot} was stopped while it started"
                )))
            }
        }
    }

    /// The port rules of a start (2.13): not the control API's, not another slot's, and free
    /// unless this slot's own engine already holds it.
    fn check_port(
        &self,
        reg: &Registry,
        slot: Slot,
        port: u16,
        own: Option<u16>,
    ) -> Result<(), ProxyError> {
        if self.control_port() == Some(port) {
            return Err(ProxyError::Conflict(format!(
                "Port {port} is reserved for the external proxy Control API"
            )));
        }
        if let Some(owner) = reg.port_owner(port, slot) {
            return Err(ProxyError::Conflict(format!(
                "Port {port} is already used by external proxy slot {owner}"
            )));
        }
        if own == Some(port) {
            return Ok(());
        }
        self.launcher
            .check_port(port)
            .map_err(|why| ProxyError::Conflict(format!("Port {port} is unavailable: {why}")))
    }

    /// Terminates an engine taken out of `slot`; `false` when its exit was not confirmed.
    async fn terminate(&self, slot: Slot, live: &Live, reason: &str) -> bool {
        let confirmed = live.engine.terminate(STOP_TIMEOUT).await;
        if confirmed {
            tracing::info!(slot = %slot, pid = live.pid, reason, "instance process stopped");
        } else {
            tracing::error!(slot = %slot, pid = live.pid, reason, "external proxy engine did not exit");
        }
        confirmed
    }

    /// `POST /start` and friends: start / connect under the slot guard, or rotate.
    pub(super) async fn start_op(self: &Arc<Self>, req: StartRequest) -> Result<Slot, ProxyError> {
        let slot = req.slot.unwrap_or(Slot::DEFAULT);
        let _guard = self.lock_slot(slot).await;
        if req.action != Action::Rotate {
            self.start_held(slot, &req).await?;
            return Ok(slot);
        }
        // A retried request with a used key gets the current status, no second rotation.
        let key = req
            .idempotency_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty());
        if let Some(key) = key
            && self
                .reg
                .lock()
                .slots
                .get_mut(&slot)
                .is_some_and(|s| s.rotated_with(key))
        {
            return Ok(slot);
        }
        self.start_held(slot, &req).await?;
        // The status reflects the first probe; a caller that needs full readiness polls
        // `/instances` (a fresh engine may need a moment before its first probe passes).
        self.probe_now(slot).await;
        if let Some(key) = key
            && let Some(state) = self.reg.lock().slots.get_mut(&slot)
        {
            state.remember_rotation(key.to_owned());
        }
        Ok(slot)
    }

    /// Probes `slot` now, or joins the probe in flight, and waits for it.
    pub(super) async fn probe_now(&self, slot: Slot) {
        let (tx, rx) = oneshot::channel();
        let sent = {
            let reg = self.reg.lock();
            let live = reg.slots.get(&slot).and_then(|s| s.live.as_ref());
            live.is_some_and(|l| l.probes.send(LoopCmd::Probe(Some(tx))).is_ok())
        };
        if sent {
            let _ = rx.await;
        }
    }

    /// Stops `slot` (3.20); the caller holds the slot guard. `leased_ok` skips the lease check
    /// (the caller decided); `preserve` keeps the profile and the health (auto-disable). The
    /// slot is released only once the engine's exit is confirmed (B-18): an engine that does
    /// not exit keeps the slot `failed` and its port reserved; a retry stops it again.
    async fn stop_held(
        &self,
        slot: Slot,
        reason: &str,
        preserve: bool,
        leased_ok: bool,
    ) -> Result<(), ProxyError> {
        let now = now_ms();
        let engine = {
            let mut reg = self.reg.lock();
            if !leased_ok {
                reg.leases.guard(slot, Guarded::Stop, now)?;
            }
            let Some(state) = reg.slots.get_mut(&slot) else {
                return Ok(());
            };
            if !preserve {
                // Not ready from this moment, so no lease can catch the route while it stops.
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
        reg.leases.forget_slot(slot);
        self.publish(reg);
        tracing::info!(slot = %slot, reason, "slot stopped");
        Ok(())
    }

    /// `POST /stop`, the UI stop button: a leased slot is a 409.
    pub(super) async fn stop_op(&self, slot: Slot, reason: StopReason) -> Result<(), ProxyError> {
        let _guard = self.lock_slot(slot).await;
        self.stop_held(slot, reason.as_str(), false, false).await
    }

    /// Stops every slot in `scope` (B-9): leased slots survive `Unleased`; `All` ends leases.
    pub(super) async fn stop_all_op(&self, scope: StopScope, reason: StopReason) {
        let slots: Vec<Slot> = {
            let reg = self.reg.lock();
            let known = reg.slots.iter();
            known
                .filter(|(_, s)| s.configured || s.auto_disabled || s.live.is_some())
                .map(|(slot, _)| *slot)
                .collect()
        };
        for slot in slots {
            let _guard = self.lock_slot(slot).await;
            let leased_ok = scope == StopScope::All;
            match self
                .stop_held(slot, reason.as_str(), false, leased_ok)
                .await
            {
                Err(ProxyError::Conflict(_)) => {
                    tracing::info!(slot = %slot, "kept leased external proxy slot {slot}");
                }
                Err(err) => {
                    tracing::warn!(slot = %slot, error = %err, "external proxy not stopped")
                }
                Ok(()) => {}
            }
        }
        tracing::info!(
            reason = reason.as_str(),
            "all external proxy instances stopped"
        );
    }

    /// The failure budget of `generation` is spent (3.16). A leased slot is never taken away
    /// from its consumer: it stays degraded and is re-probed every few minutes instead.
    pub(super) async fn auto_disable(self: Arc<Self>, slot: Slot, generation: u64) {
        let _guard = self.lock_slot(slot).await;
        let now = now_ms();
        {
            let mut guard = self.reg.lock();
            let reg = &mut *guard;
            let leased = reg.leases.lease(slot, now).is_some();
            let Some(state) = reg.slots.get_mut(&slot) else {
                return;
            };
            let Some(live) = state
                .live
                .as_ref()
                .filter(|_| state.generation == generation)
            else {
                return;
            };
            if leased {
                state.route.disable_blocked(now);
                let _ = live.probes.send(LoopCmd::Soon(self.timing.leased_recheck));
                self.publish(reg);
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
        if let Err(err) = self.stop_held(slot, reason, true, true).await {
            tracing::warn!(slot = %slot, error = %err, "auto-disabled slot not stopped");
        }
    }

    /// App exit: no new start, every engine stopped, every lease dropped.
    pub(super) async fn shutdown(&self) {
        self.closing.cancel();
        let lives: Vec<(Slot, Live)> = {
            let mut guard = self.reg.lock();
            let reg = &mut *guard;
            reg.closed = true;
            reg.leases.clear();
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

    /// Waits for the guard of the lowest free slot not in `excluded`; `None` when every slot is
    /// taken. Re-checks after the wait: an explicit-slot start may have taken it meanwhile.
    async fn free_slot(&self, excluded: &HashSet<Slot>) -> Option<(Slot, OwnedMutexGuard<()>)> {
        loop {
            let slot = self.reg.lock().first_free(excluded)?;
            let guard = self.lock_slot(slot).await;
            if self.reg.lock().is_free(slot) {
                return Some((slot, guard));
            }
        }
    }

    /// The guard of `slot` if, once it is ours, the slot still holds `profile_id` with a dead
    /// engine (another operation may have changed it while we waited).
    async fn dead_slot(&self, slot: Slot, profile_id: &str) -> Option<(Slot, OwnedMutexGuard<()>)> {
        let guard = self.lock_slot(slot).await;
        let still_dead = self.reg.lock().slots.get(&slot).is_some_and(|s| {
            s.configured && !s.is_active() && s.profile.as_ref().is_some_and(|p| p.id == profile_id)
        });
        still_dead.then_some((slot, guard))
    }

    /// UI "+" (B-19): `profile_id` on the lowest free slot the backend picks (a blank id is a
    /// 400, never an auto-pick).
    pub(super) async fn add_op(self: &Arc<Self>, profile_id: String) -> Result<Slot, ProxyError> {
        let _batch = self.batch.lock().await;
        let (slot, _guard) = self.free_slot(&HashSet::new()).await.ok_or_else(no_ports)?;
        self.start_held(slot, &connect(slot, profile_id, None))
            .await?;
        Ok(slot)
    }

    /// One proxy per named profile (3.24), never the main VPN's own. A profile whose slot runs
    /// (or starts) is reported as already running; a slot of it whose engine died is restarted
    /// instead of opening a second slot (B-8). Failures do not abort the batch; a slot whose
    /// start failed is not tried again in it.
    pub(super) async fn start_profiles_op(
        self: &Arc<Self>,
        profile_ids: Vec<String>,
    ) -> BatchStartResult {
        let mut ids: Vec<String> = Vec::new();
        for id in profile_ids
            .iter()
            .map(|id| id.trim())
            .filter(|id| !id.is_empty())
        {
            if !ids.iter().any(|seen| seen == id) {
                ids.push(id.to_owned());
            }
        }
        let mut result = BatchStartResult {
            requested: u32::try_from(ids.len()).unwrap_or(u32::MAX),
            ..BatchStartResult::default()
        };
        let _batch = self.batch.lock().await;
        let profiles = self.source.profiles();
        let active_vpn = self.source.active_vpn_profile_id();
        let mut rejected: HashSet<Slot> = HashSet::new();
        let mut started: Vec<Slot> = Vec::new();
        for id in ids {
            let skip = |reason| BatchSkip {
                profile_id: id.clone(),
                reason,
            };
            if active_vpn.as_deref() == Some(id.as_str()) {
                result.skipped.push(skip(BatchSkipReason::ActiveVpn));
                continue;
            }
            let (alive, dead) = self.reg.lock().slots_of_profile(&id);
            if alive {
                result.already_running_profile_ids.push(id);
                continue;
            }
            if !profiles.iter().any(|p| p.id == id && p.usable()) {
                result.skipped.push(skip(BatchSkipReason::Unavailable));
                continue;
            }
            let target = match dead.filter(|slot| !rejected.contains(slot)) {
                Some(slot) => self.dead_slot(slot, &id).await,
                None => None,
            };
            let target = match target {
                Some(target) => Some(target),
                None => self.free_slot(&rejected).await,
            };
            let Some((slot, _guard)) = target else {
                result.failed.push(failure(&id, &no_ports()));
                continue;
            };
            match self
                .start_held(slot, &connect(slot, id.clone(), None))
                .await
            {
                Ok(()) => started.push(slot),
                Err(err) => {
                    tracing::warn!(profile = %id, slot = %slot, error = %err,
                        "batch start failed for profile");
                    rejected.insert(slot);
                    result.failed.push(failure(&id, &err));
                }
            }
        }
        started.sort();
        result.started = started
            .into_iter()
            .map(|slot| self.instance(slot))
            .collect();
        result
    }

    /// Tops up to `count` instances in total (3.25: failed and auto-disabled leftovers count
    /// too), then probes every running one. Profiles in list order, skipping the main VPN's and
    /// those other slots use; each start gets `country` as its sticky filter. A failed start
    /// aborts.
    pub(super) async fn prewarm_op(
        self: &Arc<Self>,
        count: u16,
        country: Option<String>,
    ) -> Result<PrewarmResult, ProxyError> {
        let _batch = self.batch.lock().await;
        let filter = country.as_deref().unwrap_or_default();
        let profiles = self.source.profiles();
        let active_vpn = self.source.active_vpn_profile_id();
        let mut used = self.reg.lock().used_profiles(None);
        let mut started: Vec<Slot> = Vec::new();
        for p in profiles
            .iter()
            .filter(|p| p.usable() && matches_country(p, filter))
        {
            if self.reg.lock().instances(now_ms()).len() >= usize::from(count) {
                break;
            }
            if active_vpn.as_deref() == Some(p.id.as_str()) || used.contains(&p.id) {
                continue;
            }
            let (slot, _guard) = self.free_slot(&HashSet::new()).await.ok_or_else(no_ports)?;
            self.start_held(slot, &connect(slot, p.id.clone(), country.clone()))
                .await?;
            used.insert(p.id.clone());
            started.push(slot);
        }
        let running: Vec<Slot> = {
            let reg = self.reg.lock();
            let live = reg.slots.iter().filter(|(_, s)| s.live.is_some());
            live.map(|(slot, _)| *slot).collect()
        };
        join_all(running.into_iter().map(|slot| self.probe_now(slot))).await;
        let now = now_ms();
        let reg = self.reg.lock();
        let instances = reg.instances(now);
        let aggregate = Aggregate::of(&instances, now);
        Ok(PrewarmResult {
            requested: u32::from(count),
            started: started
                .iter()
                .map(|s| reg.instance(*s, &instances))
                .collect(),
            ready: aggregate.covers(u32::from(count)),
            instances,
            aggregate,
        })
    }
}

/// A `connect` of `profile_id` on `slot`.
fn connect(slot: Slot, profile_id: String, country: Option<String>) -> StartRequest {
    StartRequest {
        slot: Some(slot),
        country,
        profile_id: Some(profile_id),
        action: Action::Connect,
        ..StartRequest::default()
    }
}

fn no_ports() -> ProxyError {
    ProxyError::Engine("No TCP ports are available for another external proxy".into())
}

fn failure(profile_id: &str, err: &ProxyError) -> BatchFailure {
    BatchFailure {
        profile_id: profile_id.to_owned(),
        error: err.detail().to_owned(),
    }
}

fn no_profile(explicit: Option<&str>, country: &str) -> ProxyError {
    ProxyError::Engine(match (explicit, country.trim()) {
        (Some(id), _) => format!("VPN profile not found or unusable: {id}"),
        (None, "") => "No VPN profiles with outbound config found".into(),
        (None, country) => format!("No VPN profiles found for country: {country}"),
    })
}
