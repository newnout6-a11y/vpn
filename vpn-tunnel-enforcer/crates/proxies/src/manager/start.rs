//! Start, rotate and connect (spec 3.21 with B-3, B-10, B-14, B-17): picking the profile,
//! the port rules, the engine start outside the registry lock and the forced probe of a rotate.
//! Every write runs under the slot's guard; the registry lock is only taken for the state
//! changes in between the awaits.
use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::oneshot;
use vpnte_base::types::{Engine as EngineKind, now_ms};

use super::launch::{self, STOP_TIMEOUT};
use super::pick::{Want, matches_country, pick};
use super::registry::{Assigned, Registry};
use super::run::LoopCmd;
use super::{Inner, ProxyProfile};
use crate::health::ms;
use crate::lease::Guarded;
use crate::model::{Action, ProxyError, StartRequest};
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
        let choice = choice.for_profile(&picked);
        let prepared = launch::prepare(&picked.profile, port, choice, &self.names).await;
        if let Some(old) = old {
            // Replaced only now that the new config is built and its endpoint resolved.
            self.terminate(slot, &old, "replace").await;
        }
        let started = match prepared {
            Ok(plan) => {
                // An Xray child carries the server; sing-box then only bridges to it.
                let kind = if plan.xray.is_some() {
                    EngineKind::Xray
                } else {
                    EngineKind::SingBox
                };
                let notice = plan.notice.clone();
                let started = self.launcher.start(plan, &self.closing).await;
                started.map(|engine| (engine, kind, notice))
            }
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
                Ok((engine, kind, notice)) if current => {
                    let pid = engine.pid();
                    let live = self.go_live(slot, generation, port, engine, kind, notice);
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
                Ok((engine, ..)) => Some(engine),
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
}

fn no_profile(explicit: Option<&str>, country: &str) -> ProxyError {
    ProxyError::Engine(match (explicit, country.trim()) {
        (Some(id), _) => format!("VPN profile not found or unusable: {id}"),
        (None, "") => "No VPN profiles with outbound config found".into(),
        (None, country) => format!("No VPN profiles found for country: {country}"),
    })
}
