//! [`ProxyOps`] over the manager: what the control API and the UI call.
use vpnte_base::types::now_ms;

use super::pick::matches_country;
use super::run::LoopCmd;
use super::{ProxyManager, ProxyProfile};
use crate::model::{
    Aggregate, BatchStartResult, FRESH_WINDOW_MS, GroupHealth, InstanceStatus, Instances,
    InstancesBatch, PrewarmResult, ProfileRow, ProxyError, ProxyOps, ProxyStatus, StartRequest,
    StopReason, Unlimited, prewarm_count,
};
use crate::slot::Slot;

#[async_trait::async_trait]
impl ProxyOps for ProxyManager {
    fn set_control_port(&self, port: u16) {
        let inner = &self.inner;
        inner
            .control_port
            .store(port, std::sync::atomic::Ordering::Relaxed);
        inner.publish(&inner.reg.lock());
    }

    async fn status(&self, slot: Slot) -> ProxyStatus {
        self.inner.proxy_status(slot)
    }

    async fn instances(&self) -> Instances {
        let inner = &self.inner;
        let now = now_ms();
        let instances = {
            let reg = inner.reg.lock();
            // Kept from the old API: reading the list re-probes running slots not checked for
            // a minute (it is also what heals a parked slot whose exit came back).
            for state in reg.slots.values() {
                let stale = state
                    .route
                    .last_checked_at
                    .is_none_or(|at| now - at >= FRESH_WINDOW_MS);
                if let Some(live) = state.live.as_ref().filter(|_| stale) {
                    let _ = live.probes.send(LoopCmd::Probe(None));
                }
            }
            reg.instances(now)
        };
        Instances {
            max_instances: Unlimited,
            aggregate: Aggregate::of(&instances, now),
            instances,
            control_url: inner.control_url(),
        }
    }

    async fn status_batch(&self, slots: Option<Vec<Slot>>) -> InstancesBatch {
        let now = now_ms();
        let reg = self.inner.reg.lock();
        let all = reg.instances(now);
        let instances = match slots {
            Some(slots) => slots.iter().map(|s| reg.instance(*s, &all)).collect(),
            None => all,
        };
        InstancesBatch {
            aggregate: Aggregate::of(&instances, now),
            instances,
        }
    }

    async fn check_health(&self, slot: Slot) -> InstanceStatus {
        self.inner.probe_now(slot).await;
        self.inner.instance(slot)
    }

    async fn list(&self, country: Option<String>) -> Vec<ProfileRow> {
        let filter = country.unwrap_or_default();
        let profiles = self.inner.source.profiles();
        let active_vpn = self.inner.source.active_vpn_profile_id();
        let reg = self.inner.reg.lock();
        profiles
            .iter()
            .filter(|p| p.usable() && matches_country(p, &filter))
            .map(|p| {
                let active_slots: Vec<Slot> = reg
                    .slots
                    .iter()
                    .filter(|(_, s)| s.configured && s.is_active())
                    .filter(|(_, s)| s.profile.as_ref().is_some_and(|a| a.id == p.id))
                    .map(|(slot, _)| *slot)
                    .collect();
                row(
                    p,
                    active_vpn.as_deref() == Some(p.id.as_str()),
                    active_slots,
                )
            })
            .collect()
    }

    async fn check_group_health(&self, group_id: String) -> Result<GroupHealth, ProxyError> {
        let checked = self.inner.source.check_group_health(&group_id).await;
        checked.map_err(|err| {
            tracing::warn!(error = %err, "group health check failed");
            ProxyError::group_health(err.kind)
        })
    }

    async fn start(&self, req: StartRequest) -> Result<ProxyStatus, ProxyError> {
        let slot = self.inner.start_op(req).await?;
        Ok(self.inner.proxy_status(slot))
    }

    async fn add(&self, profile_id: String) -> Result<ProxyStatus, ProxyError> {
        let slot = self.inner.add_op(profile_id).await?;
        Ok(self.inner.proxy_status(slot))
    }

    async fn start_profiles(&self, profile_ids: Vec<String>) -> BatchStartResult {
        self.inner.start_profiles_op(profile_ids).await
    }

    async fn prewarm(
        &self,
        count: u64,
        country: Option<String>,
    ) -> Result<PrewarmResult, ProxyError> {
        let count = prewarm_count(count)?;
        self.inner.prewarm_op(count, country).await
    }

    async fn stop(&self, slot: Slot, reason: StopReason) -> Result<ProxyStatus, ProxyError> {
        self.inner.stop_op(slot, reason).await?;
        Ok(self.inner.proxy_status(slot))
    }

    async fn stop_all(&self, reason: StopReason) -> ProxyStatus {
        self.inner.stop_all_op(reason).await;
        self.inner.proxy_status(Slot::DEFAULT)
    }
}

fn row(p: &ProxyProfile, selected_for_vpn: bool, active_slots: Vec<Slot>) -> ProfileRow {
    ProfileRow {
        id: p.id.clone(),
        name: p.name.clone(),
        country: p.country.clone(),
        protocol: p.profile.kind.label().to_owned(),
        server: p.profile.server.to_string(),
        port: p.profile.port,
        group_id: p.group_id.clone(),
        status: p.status,
        ping_ms: p.ping_ms,
        health_latency_ms: p.health_latency_ms,
        health_reason: p.health_reason.clone(),
        last_checked_at: p.last_checked_at,
        selected_for_vpn,
        active: !active_slots.is_empty(),
        active_slots,
    }
}
