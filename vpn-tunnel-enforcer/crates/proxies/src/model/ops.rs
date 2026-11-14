//! [`ProxyOps`]: the operations on external proxies. The manager implements it; the control API
//! is written against `Arc<dyn ProxyOps>` and the app adapts it for the UI.
use super::{
    Action, BatchStartResult, GroupHealth, InstanceStatus, Instances, InstancesBatch,
    PrewarmResult, ProfileRow, ProxyError, ProxyStatus, StartRequest, StopReason,
};
use crate::slot::Slot;

/// Operations on external proxy slots, one per control API endpoint (and the UI's "+").
/// Statuses are derived at call time (readiness depends on the clock).
#[async_trait::async_trait]
pub trait ProxyOps: Send + Sync {
    /// Records the port the control API actually bound (it may be an ephemeral fallback);
    /// statuses report it as `controlPort` / `controlUrl`. The control server calls it once,
    /// right after binding and before serving.
    fn set_control_port(&self, port: u16);

    /// One slot plus every instance and the aggregate (`GET /status`, `GET /`).
    async fn status(&self, slot: Slot) -> ProxyStatus;

    /// Every configured or auto-disabled slot, in slot order (`GET /instances`). Side effect
    /// kept from the old API: queues a probe for each running slot not checked for 60 s.
    async fn instances(&self) -> Instances;

    /// The named slots (unknown ones as stopped records), or every instance for `None`
    /// (`POST /instances/status-batch`).
    async fn status_batch(&self, slots: Option<Vec<Slot>>) -> InstancesBatch;

    /// Probes the slot now, or joins a probe already in flight, and returns the result
    /// (`POST /healthcheck`).
    async fn check_health(&self, slot: Slot) -> InstanceStatus;

    /// Profiles that can run as a proxy, optionally filtered by country (`GET /list`).
    async fn list(&self, country: Option<String>) -> Vec<ProfileRow>;

    /// Key health check of a server group (`POST /profiles/healthcheck`); failures map through
    /// [`ProxyError::group_health`].
    async fn check_group_health(&self, group_id: String) -> Result<GroupHealth, ProxyError>;

    /// Starts, rotates or connects a slot (`POST /start`, `/rotate`, `/connect`, `/trigger`).
    /// `connect` without a profile is a 400.
    async fn start(&self, req: StartRequest) -> Result<ProxyStatus, ProxyError>;

    /// Moves a slot to the next usable profile (UI rotate button).
    async fn rotate(&self, slot: Slot, reason: Option<String>) -> Result<ProxyStatus, ProxyError> {
        self.start(StartRequest {
            slot: Some(slot),
            action: Action::Rotate,
            rotate_reason: reason,
            ..StartRequest::default()
        })
        .await
    }

    /// Starts `profile_id` on the lowest free slot the backend allocates (UI "+", a
    /// subscription fetch's spare route).
    async fn add(&self, profile_id: String) -> Result<ProxyStatus, ProxyError>;

    /// One proxy per named profile, never the main VPN's own (`POST /connect-profiles`, the
    /// Servers page). Per-profile failures are reported in the result, not as an error.
    async fn start_profiles(&self, profile_ids: Vec<String>) -> BatchStartResult;

    /// Tops up to `count` instances in total, then probes them (`POST /instances/prewarm`).
    /// `count` is validated with [`super::prewarm_count`].
    async fn prewarm(
        &self,
        count: u64,
        country: Option<String>,
    ) -> Result<PrewarmResult, ProxyError>;

    /// Stops one slot (`POST /stop`, UI stop button).
    async fn stop(&self, slot: Slot, reason: StopReason) -> Result<ProxyStatus, ProxyError>;

    /// Stops every slot (UI "stop all", main VPN disconnect); returns slot 1's status.
    async fn stop_all(&self, reason: StopReason) -> ProxyStatus;
}

#[cfg(test)]
mod tests {
    use super::ProxyOps;

    /// The control API holds `Arc<dyn ProxyOps>` across tokio tasks.
    #[test]
    fn proxy_ops_is_object_safe_and_shareable() {
        fn shareable<T: Send + Sync + 'static>() {}
        shareable::<std::sync::Arc<dyn ProxyOps>>();
    }
}
