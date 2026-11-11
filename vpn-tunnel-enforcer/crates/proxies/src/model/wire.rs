//! Wire DTOs of the control API, field-for-field the old JSON (camelCase). Time encodings are
//! mixed on purpose: `lastCheckedAt` / `lastSuccessAt` are epoch milliseconds, every other
//! timestamp is an ISO string (`2026-11-11T05:19:00.123Z`); old clients parse both.
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use vpnte_base::types::UnixMs;

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

    /// The same encoding for a timestamp that is always present.
    pub mod required {
        use serde::{Deserializer, Serializer, de::Error as _};
        use vpnte_base::types::UnixMs;

        /// Writes the timestamp as an ISO string.
        pub fn serialize<S: Serializer>(value: &UnixMs, s: S) -> Result<S::Ok, S::Error> {
            super::serialize(&Some(*value), s)
        }

        /// Reads an ISO string; `null` is an error.
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<UnixMs, D::Error> {
            super::deserialize(d)?.ok_or_else(|| D::Error::custom("missing timestamp"))
        }
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

/// A granted lease (`/instances/reserve` and `/instances/renew`).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reservation {
    /// Bearer secret of the lease (64 hex chars); never logged.
    pub lease_token: String,
    pub owner: String,
    #[serde(with = "iso_ms::required")]
    pub expires_at: UnixMs,
    pub slot: Slot,
    pub proxy_url: Option<String>,
    pub egress_ip: Option<IpAddr>,
    pub generation: u64,
    pub instance: InstanceStatus,
}

impl std::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reservation")
            .field("owner", &self.owner)
            .field("slot", &self.slot)
            .field("expires_at", &self.expires_at)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// `POST /instances/release`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Released {
    /// Always `true`.
    pub released: bool,
    pub slot: Slot,
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
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::model::{
        Action, ProxyError, ReserveRequest, StopReason, healthy_instance, prewarm_count,
    };

    const NOW: UnixMs = 1_762_800_000_123;

    /// Spec external-proxy §2.2: field names and the mixed time encodings are the wire contract.
    #[test]
    fn instance_status_wire_shape() {
        let mut i = healthy_instance(3, "198.51.100.42", NOW);
        i.updated_at = Some(NOW);
        i.degradation_reason = Some(Degradation::RotationDidNotChangeEgressIp);
        let v = serde_json::to_value(&i).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "slot",
                "running",
                "processRunning",
                "ready",
                "health",
                "state",
                "generation",
                "egressIp",
                "latencyMs",
                "lastCheckedAt",
                "lastSuccessAt",
                "egressCheckedAt",
                "updatedAt",
                "lastError",
                "lastErrorAt",
                "degradationReason",
                "consecutiveFailures",
                "nextCheckAt",
                "lastRotateReason",
                "autoDisabled",
                "host",
                "port",
                "proxyUrl",
                "profileId",
                "profileName",
                "country",
                "pid",
                "startedAt",
            ]
        );
        assert_eq!(v["slot"], 3);
        assert_eq!(
            (v["health"].as_str(), v["state"].as_str()),
            (Some("healthy"), Some("ready"))
        );
        assert_eq!(v["egressIp"], "198.51.100.42");
        assert_eq!(v["lastCheckedAt"], json!(NOW - 1_000));
        assert_eq!(v["egressCheckedAt"], "2025-11-10T18:39:59.123Z");
        assert_eq!(v["updatedAt"], "2025-11-10T18:40:00.123Z");
        assert_eq!(
            (v["lastErrorAt"].clone(), v["startedAt"].clone()),
            (Value::Null, Value::Null)
        );
        assert_eq!(v["degradationReason"], "rotation-did-not-change-egress-ip");
        assert_eq!(
            (v["host"].as_str(), v["proxyUrl"].as_str()),
            (Some("127.0.0.1"), Some("http://127.0.0.1:17992"))
        );
        let back: InstanceStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, i);
        assert_eq!(
            iso_ms::format(0).as_deref(),
            Some("1970-01-01T00:00:00.000Z")
        );
    }

    /// `ProxyStatus` flattens the instance and adds the control fields; `maxInstances` is null.
    #[test]
    fn proxy_status_flattens_the_instance() {
        let instance = InstanceStatus::stopped(crate::slot::Slot::DEFAULT);
        let status = ProxyStatus {
            instance: instance.clone(),
            control_host: CONTROL_HOST.into(),
            control_port: Some(17873),
            control_url: Some("http://127.0.0.1:17873".into()),
            max_instances: Unlimited,
            instances: Vec::new(),
            aggregate: Aggregate::default(),
        };
        let v = serde_json::to_value(&status).unwrap();
        assert_eq!(
            (v["slot"].clone(), v["health"].clone()),
            (json!(1), json!("stopped"))
        );
        assert_eq!(v["maxInstances"], Value::Null);
        assert_eq!(v["controlPort"], 17873);
        assert_eq!(v["instances"], json!([]));
        assert_eq!(v["aggregate"]["uniqueEgress"], 0);
        assert_eq!(serde_json::from_value::<ProxyStatus>(v).unwrap(), status);
    }

    #[test]
    fn reservation_errors_and_small_shapes() {
        let instance = healthy_instance(1, "198.51.100.1", NOW);
        let r = Reservation {
            lease_token: "ab".repeat(32),
            owner: "buyer-worker-1".into(),
            expires_at: NOW,
            slot: instance.slot,
            proxy_url: instance.proxy_url.clone(),
            egress_ip: instance.egress_ip,
            generation: 1,
            instance,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["expiresAt"], "2025-11-10T18:40:00.123Z");
        assert_eq!(v["leaseToken"], "ab".repeat(32));
        assert!(!format!("{r:?}").contains(&"ab".repeat(32)));
        let err = ControlError::from(&ProxyError::Conflict("Slot 2 is already leased".into()));
        assert_eq!(
            serde_json::to_value(err).unwrap(),
            json!({ "ok": false, "error": "conflict", "detail": "Slot 2 is already leased" })
        );
        let skip = BatchSkip {
            profile_id: "profile-1".into(),
            reason: BatchSkipReason::ActiveVpn,
        };
        assert_eq!(
            serde_json::to_value(skip).unwrap(),
            json!({ "profileId": "profile-1", "reason": "active-vpn" })
        );
        assert_eq!(
            serde_json::to_value(ServerStatus::Offline).unwrap(),
            "offline"
        );
        let released = Released {
            released: true,
            slot: crate::slot::Slot::DEFAULT,
        };
        assert_eq!(
            serde_json::to_value(released).unwrap(),
            json!({ "released": true, "slot": 1 })
        );
        let health = GroupHealth {
            ok: true,
            results: vec![KeyHealth {
                profile_id: "p".into(),
                online: true,
                latency_ms: Some(80),
                reason: None,
                egress_ip: None,
                country: None,
            }],
        };
        assert_eq!(
            serde_json::to_value(&health).unwrap()["results"][0],
            json!({ "profileId": "p", "online": true, "latencyMs": 80 })
        );
        assert_eq!(health.alive(), 1);
    }

    #[test]
    fn request_helpers() {
        assert_eq!(Action::parse("start"), Some(Action::Start));
        assert_eq!(Action::parse("rotate"), Some(Action::Rotate));
        assert_eq!(Action::parse("connect"), Some(Action::Connect));
        assert_eq!(Action::parse(" TRIGGER "), Some(Action::Connect));
        assert_eq!(Action::parse("stop"), None);
        assert!(ReserveRequest::new("o").allow_fallback);
        assert_eq!(StopReason::VpnStop.as_str(), "vpn-stop");
        assert_eq!(prewarm_count(30).unwrap(), 30);
        for bad in [0, 47547] {
            assert_eq!(
                prewarm_count(bad).unwrap_err().detail(),
                "count must be between 1 and 47546"
            );
        }
        let names =
            [Lifecycle::Quarantined, Lifecycle::Rotating].map(|l| serde_json::to_value(l).unwrap());
        assert_eq!(names, [json!("quarantined"), json!("rotating")]);
        assert_eq!(serde_json::to_value(Health::Degraded).unwrap(), "degraded");
    }
}
