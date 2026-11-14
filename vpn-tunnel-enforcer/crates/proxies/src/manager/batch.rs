//! The allocating operations (spec 3.23–3.25 with B-8, B-19): the UI's "+", the batch start of
//! the Servers page and prewarm. They are serialised among themselves (`Inner::batch`) and take
//! the lowest free slot under its guard.
use std::collections::HashSet;
use std::sync::Arc;

use futures_util::future::join_all;
use tokio::sync::OwnedMutexGuard;
use vpnte_base::types::now_ms;

use super::Inner;
use super::pick::matches_country;
use crate::model::{
    Action, Aggregate, BatchFailure, BatchSkip, BatchSkipReason, BatchStartResult, PrewarmResult,
    ProxyError, StartRequest,
};
use crate::slot::Slot;

impl Inner {
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
            .await
            .map(|()| slot)
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
