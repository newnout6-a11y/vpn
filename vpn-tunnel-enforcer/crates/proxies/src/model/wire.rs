//! Wire DTOs of the control API, field-for-field the old JSON (camelCase). Time encodings are
//! mixed on purpose: `lastCheckedAt` / `lastSuccessAt` are epoch milliseconds, every other
//! timestamp is an ISO string (`2026-11-11T05:19:00.123Z`); old clients parse both.
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use vpnte_base::Msg;
use vpnte_base::types::{Engine, UnixMs};

use super::{Degradation, Health, Lifecycle};
use crate::slot::{CONTROL_HOST, Slot};

/// `Option<UnixMs>` as an ISO-8601 UTC string with milliseconds (JavaScript `toISOString()`).
pub mod iso_ms {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _, ser::Error as _};
    use vpnte_base::types::UnixMs;

    /// Formats one timestamp; `None` when it is outside the calendar range.
    pub fn format(ms: UnixMs) -> Option<String> {
        let ts = jiff::Timestamp::from_millisecond(ms).ok()?;
        Some(ts.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
    }

    /// Writes `Some` as an ISO string and `None` as `null`.
    pub fn serialize<S: Serializer>(value: &Option<UnixMs>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(ms) => {
                let text = format(*ms).ok_or_else(|| S::Error::custom("timestamp out of range"))?;
                s.serialize_some(&text)
            }
            None => s.serialize_none(),
        }
    }

    /// Reads an ISO string (any RFC 3339 offset) or `null`.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<UnixMs>, D::Error> {
        let Some(text) = Option::<String>::deserialize(d)? else {
            return Ok(None);
        };
        let ts: jiff::Timestamp = text.parse().map_err(D::Error::custom)?;
        Ok(Some(ts.as_millisecond()))
    }
}

/// The old `maxInstances` field: always `null` (no product limit). Serialized as `null`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unlimited;

/// Status of one slot (old `ExternalProxyInstanceStatus`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceStatus {
    pub slot: Slot,
    /// True only after a complete, fresh data-plane probe: `process_running && ready`.
    pub running: bool,
    /// The engine child is alive (diagnostics and controls).
    pub process_running: bool,
    /// Consumer readiness: healthy, fresh egress, no duplicate egress (see `derive_readiness`).
    pub ready: bool,
    pub health: Health,
    pub state: Lifecycle,
    pub generation: u64,
    pub egress_ip: Option<IpAddr>,
    pub latency_ms: Option<u32>,
    pub last_checked_at: Option<UnixMs>,
    pub last_success_at: Option<UnixMs>,
    /// Same instant as `last_success_at`, ISO on the wire.
    #[serde(with = "iso_ms")]
    pub egress_checked_at: Option<UnixMs>,
    #[serde(with = "iso_ms")]
    pub updated_at: Option<UnixMs>,
    pub last_error: Option<String>,
    #[serde(with = "iso_ms")]
    pub last_error_at: Option<UnixMs>,
    pub degradation_reason: Option<Degradation>,
    pub consecutive_failures: u32,
    #[serde(with = "iso_ms")]
    pub next_check_at: Option<UnixMs>,
    pub last_rotate_reason: Option<String>,
    pub auto_disabled: bool,
    /// Always `127.0.0.1`.
    pub host: String,
    pub port: Option<u16>,
    pub proxy_url: Option<String>,
    pub profile_id: Option<String>,
    pub profile_name: Option<String>,
    pub country: Option<String>,
    pub pid: Option<u32>,
    #[serde(with = "iso_ms")]
    pub started_at: Option<UnixMs>,
    /// The engine that carries the server while the slot runs: Xray when the slot has an Xray
    /// child (sing-box only bridges to it), else sing-box; `None` while nothing runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<Engine>,
    /// What the running engine goes without, for the slot's row (`proxies.slot.spoofDropped`).
    /// UI state only: the control API's JSON stays field-for-field the old one.
    #[serde(skip)]
    pub notice: Option<Msg>,
}

impl InstanceStatus {
    /// The record of a slot that was never started (or is fully stopped): no 404 for unknown slots.
    pub fn stopped(slot: Slot) -> Self {
        Self {
            slot,
            running: false,
            process_running: false,
            ready: false,
            health: Health::Stopped,
            state: Lifecycle::Stopped,
            generation: 0,
            egress_ip: None,
            latency_ms: None,
            last_checked_at: None,
            last_success_at: None,
            egress_checked_at: None,
            updated_at: None,
            last_error: None,
            last_error_at: None,
            degradation_reason: None,
            consecutive_failures: 0,
            next_check_at: None,
            last_rotate_reason: None,
            auto_disabled: false,
            host: CONTROL_HOST.into(),
            port: None,
            proxy_url: None,
            profile_id: None,
            profile_name: None,
            country: None,
            pid: None,
            started_at: None,
            engine: None,
            notice: None,
        }
    }
}

/// Counters over a list of instances (old `ExternalProxyAggregate`); see `Aggregate::of`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Aggregate {
    pub total: u32,
    /// Instances whose engine child is alive.
    pub running: u32,
    pub ready: u32,
    pub healthy: u32,
    pub unique_egress: u32,
    /// Fresh egress collisions among running instances ("an IP collision exists").
    pub duplicate_egress: u32,
    pub starting: u32,
    pub degraded: u32,
    pub quarantined: u32,
}

/// `GET /status` and the result of start / stop: one slot, every instance and the aggregate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    #[serde(flatten)]
    pub instance: InstanceStatus,
    /// Always `127.0.0.1`.
    pub control_host: String,
    /// The port the control API actually bound (it may have fallen back to an ephemeral one).
    pub control_port: Option<u16>,
    pub control_url: Option<String>,
    pub max_instances: Unlimited,
    pub instances: Vec<InstanceStatus>,
    pub aggregate: Aggregate,
}

/// `GET /instances`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Instances {
    pub max_instances: Unlimited,
    pub instances: Vec<InstanceStatus>,
    pub aggregate: Aggregate,
    pub control_url: Option<String>,
}

/// `POST /instances/status-batch`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstancesBatch {
    pub instances: Vec<InstanceStatus>,
    pub aggregate: Aggregate,
}

/// Persisted key health of a server, as the servers crate reports it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerStatus {
    Online,
    Offline,
    #[default]
    Unknown,
}

/// One profile usable as a proxy (`GET /list`, the card's picker).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileRow {
    pub id: String,
    pub name: String,
    pub country: Option<String>,
    /// Protocol label (`vless`, `hysteria2`, …).
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub group_id: Option<String>,
    /// Key health (`healthStatus` of the server, else its ping status).
    pub status: ServerStatus,
    pub ping_ms: Option<u32>,
    pub health_latency_ms: Option<u32>,
    pub health_reason: Option<String>,
    pub last_checked_at: Option<UnixMs>,
    /// The main VPN uses this profile.
    pub selected_for_vpn: bool,
    /// Some slot runs (or starts) this profile.
    pub active: bool,
    pub active_slots: Vec<Slot>,
}

/// `GET /list`: `{ "profiles": [...] }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileList {
    pub profiles: Vec<ProfileRow>,
}

/// Why a batch start did not start a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BatchSkipReason {
    /// The main VPN uses it: a proxy would exit through the same IP.
    ActiveVpn,
    /// Unknown, removed from its subscription, disabled or not runnable.
    Unavailable,
}

/// A profile a batch start skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSkip {
    pub profile_id: String,
    pub reason: BatchSkipReason,
}

/// A profile a batch start tried and failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchFailure {
    pub profile_id: String,
    /// The error detail.
    pub error: String,
}

/// `POST /connect-profiles` (Servers page "start as proxy").
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchStartResult {
    pub requested: u32,
    /// Started slots, in slot order.
    pub started: Vec<InstanceStatus>,
    pub already_running_profile_ids: Vec<String>,
    pub skipped: Vec<BatchSkip>,
    pub failed: Vec<BatchFailure>,
}

/// `POST /instances/prewarm`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrewarmResult {
    pub requested: u32,
    pub started: Vec<InstanceStatus>,
    pub instances: Vec<InstanceStatus>,
    pub aggregate: Aggregate,
    /// `aggregate.covers(requested)`.
    pub ready: bool,
}

/// Result of one key in a server-group health check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyHealth {
    pub profile_id: String,
    pub online: bool,
    pub latency_ms: Option<u32>,
    /// Short English failure tag (`auth-failed`, `timeout`, `tls-failed`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Verified public exit IP of the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_ip: Option<IpAddr>,
    /// Verified ISO country code of the exit node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// `POST /profiles/healthcheck`: health of every key in a server group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupHealth {
    /// Always `true`.
    pub ok: bool,
    pub results: Vec<KeyHealth>,
}

impl GroupHealth {
    /// Keys that answered (text mode prints `<alive>/<total>`).
    pub fn alive(&self) -> usize {
        self.results.iter().filter(|r| r.online).count()
    }
}

/// JSON error body of the control API: `{ "ok": false, "error": <code>, "detail": <text> }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlError {
    /// Always `false`.
    pub ok: bool,
    pub error: String,
    pub detail: String,
}

impl ControlError {
    /// An error body with its code and detail.
    pub fn new(error: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: error.into(),
            detail: detail.into(),
        }
    }
}

impl From<&super::ProxyError> for ControlError {
    fn from(err: &super::ProxyError) -> Self {
        ControlError::new(err.code(), err.detail())
    }
}

#[cfg(test)]
mod tests;
