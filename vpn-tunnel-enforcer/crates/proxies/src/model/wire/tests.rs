use serde_json::{Value, json};

use super::*;
use crate::model::{Action, ProxyError, StopReason, prewarm_count};
use crate::test_support::healthy_instance;

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
fn errors_and_small_shapes() {
    let err = ControlError::from(&ProxyError::Conflict("Slot 2 is busy".into()));
    assert_eq!(
        serde_json::to_value(err).unwrap(),
        json!({ "ok": false, "error": "conflict", "detail": "Slot 2 is busy" })
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
