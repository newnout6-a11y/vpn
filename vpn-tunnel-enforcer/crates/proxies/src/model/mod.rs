//! What the external-proxy feature talks in: route states, wire DTOs (field names and time
//! encodings of the old control API, kept for its CLI and automation clients), requests, the
//! error type and [`ProxyOps`], the operations the control API and the UI call.
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::slot::Slot;

mod error;
mod ops;
mod ready;
mod wire;

pub use error::ProxyError;
pub use ops::ProxyOps;
pub use ready::{FRESH_WINDOW_MS, derive_readiness};
pub use wire::{
    Aggregate, BatchFailure, BatchSkip, BatchSkipReason, BatchStartResult, ControlError,
    GroupHealth, InstanceStatus, Instances, InstancesBatch, KeyHealth, PrewarmResult, ProfileList,
    ProfileRow, ProxyStatus, Released, Reservation, ServerStatus, Unlimited, iso_ms,
};

/// Route health as the data-plane probe sees it (not a child-process flag). A consumer may use
/// a route only when it is `Healthy` and additionally fresh, unique and ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Health {
    #[default]
    Stopped,
    Starting,
    Healthy,
    Degraded,
    Rotating,
    Quarantined,
    Failed,
}

/// Lifecycle of a slot. (The old type also listed `healthy`, but never set it.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    #[default]
    Stopped,
    Starting,
    Ready,
    Degraded,
    Rotating,
    Quarantined,
    Failed,
}

/// Why a slot is not (or no longer) a usable route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Degradation {
    ProcessFailed,
    LeasedRouteRecoveryBlocked,
    HealthFailureBudgetExhausted,
    EgressIpChangedWithoutRotation,
    RotationDidNotChangeEgressIp,
    DuplicateEgressIp,
    EgressProbeFailed,
}

/// What a start request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Action {
    /// Start the slot; a configured running slot is returned as it is.
    #[default]
    Start,
    /// Move the slot to the next usable profile.
    Rotate,
    /// Start with the named profile; never picks one (old `connect` and `trigger`).
    Connect,
}

impl Action {
    /// Parses the action name of the old API (`trigger` means `connect`).
    pub fn parse(name: &str) -> Option<Action> {
        let name = name.trim();
        [
            ("start", Action::Start),
            ("rotate", Action::Rotate),
            ("connect", Action::Connect),
            ("trigger", Action::Connect),
        ]
        .into_iter()
        .find_map(|(n, action)| n.eq_ignore_ascii_case(name).then_some(action))
    }
}

/// Start, rotate or connect one slot. `slot: None` means [`Slot::DEFAULT`]; `port: None` keeps
/// the slot's current port, else its default port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartRequest {
    pub slot: Option<Slot>,
    /// Country filter (ISO code, alias or free text); sticky for the slot until an explicit stop.
    pub country: Option<String>,
    pub profile_id: Option<String>,
    pub port: Option<u16>,
    pub action: Action,
    /// Retried rotate requests with the same key do not rotate twice.
    pub idempotency_key: Option<String>,
    pub rotate_reason: Option<String>,
}

/// Reserve a ready route for an automation client.
#[derive(Debug, Clone, PartialEq)]
pub struct ReserveRequest {
    /// Who holds the lease (trimmed; required). An owner holds at most one lease.
    pub owner: String,
    /// Lease length as the client sent it; `None` = 120 s. Validated by the lease book.
    pub ttl_secs: Option<f64>,
    /// Prefer the route exiting through this IP. (The old API compared any text; a non-IP
    /// value is now a 400 from the request parser.)
    pub preferred_egress_ip: Option<IpAddr>,
    pub preferred_slot: Option<Slot>,
    /// Exactly this slot. A leased one is always 409; a not-ready one is 409 only without fallback.
    pub slot: Option<Slot>,
    /// Default `true`: may hand out another ready route.
    pub allow_fallback: bool,
}

impl ReserveRequest {
    /// A request with the defaults of the old API (fallback allowed, default TTL).
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            ttl_secs: None,
            preferred_egress_ip: None,
            preferred_slot: None,
            slot: None,
            allow_fallback: true,
        }
    }
}

/// Which slots "stop all" stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StopScope {
    /// Every slot without a lease (UI "stop all", main VPN disconnect); leased ones keep running.
    Unleased,
    /// Every slot, leases notwithstanding.
    All,
}

/// Who stopped a slot (for logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StopReason {
    Api,
    Ui,
    VpnStop,
    Shutdown,
}

impl StopReason {
    /// Log label (`api`, `ui`, `vpn-stop`, `shutdown`).
    pub fn as_str(self) -> &'static str {
        match self {
            StopReason::Api => "api",
            StopReason::Ui => "ui",
            StopReason::VpnStop => "vpn-stop",
            StopReason::Shutdown => "shutdown",
        }
    }
}

/// Validates the instance count of a prewarm request (`1..=MAX_SLOT`).
pub fn prewarm_count(count: u64) -> Result<u16, ProxyError> {
    u16::try_from(count)
        .ok()
        .filter(|n| (1..=crate::slot::MAX_SLOT).contains(n))
        .ok_or_else(|| {
            ProxyError::BadRequest(format!(
                "count must be between 1 and {}",
                crate::slot::MAX_SLOT
            ))
        })
}

/// A running, freshly probed, healthy slot exiting through `ip` (test fixture).
#[cfg(test)]
pub(crate) fn healthy_instance(
    slot: u64,
    ip: &str,
    now: vpnte_base::types::UnixMs,
) -> InstanceStatus {
    let slot = Slot::new(slot).unwrap();
    let port = slot.default_port();
    InstanceStatus {
        process_running: true,
        health: Health::Healthy,
        state: Lifecycle::Ready,
        generation: 1,
        egress_ip: Some(ip.parse().unwrap()),
        latency_ms: Some(123),
        last_checked_at: Some(now - 1_000),
        last_success_at: Some(now - 1_000),
        egress_checked_at: Some(now - 1_000),
        port: Some(port),
        proxy_url: Some(crate::slot::proxy_url(port)),
        profile_id: Some(format!("profile-{slot}")),
        pid: Some(1000 + u32::from(slot.get())),
        ..InstanceStatus::stopped(slot)
    }
}
