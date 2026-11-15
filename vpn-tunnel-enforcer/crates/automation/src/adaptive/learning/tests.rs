use serde_json::json;
use vpnte_base::types::{ClientDevice, Engine};

use super::*;
use crate::adaptive::identity::{IdentityRow, NetworkSnapshot};
use crate::test_support::TempDir;

fn view(outbound: Value) -> ProfileView {
    ProfileView {
        id: "p1".into(),
        outbound,
        client_device: None,
        client_fingerprint: None,
        engine: Engine::SingBox,
        tls_compat_applies: true,
    }
}

fn vless() -> Value {
    json!({
        "type": "vless", "tag": "proxy-out", "server": "vpn.example.test", "server_port": 443,
        "uuid": "00000000-0000-4000-8000-000000000000",
        "tls": { "enabled": true, "server_name": "front.example.test",
                 "reality": { "enabled": true, "public_key": "PUBLIC_KEY_PLACEHOLDER_A" } },
        "transport": { "type": "grpc", "service_name": "svc" }
    })
}

fn net(gateway: &str) -> NetworkSnapshot {
    NetworkSnapshot::from_rows(vec![IdentityRow {
        guid: "0".repeat(32),
        mac: "102030405060".into(),
        prefixes: vec!["192.168.1.0/24".into()],
        gateways: vec![gateway.into()],
    }])
    .unwrap()
}

fn open(dir: &TempDir) -> (Arc<Store<AdaptiveDoc>>, Learning) {
    let store = Arc::new(Store::<AdaptiveDoc>::open(dir.path()));
    let learning = Learning::open(store.clone());
    (store, learning)
}

#[test]
fn canonical_json_sorts_keys_recursively() {
    let mut out = String::new();
    canonical_json(&json!({"b": [{"z": 1, "a": null}], "a": "x\"y"}), &mut out);
    assert_eq!(out, r#"{"a":"x\"y","b":[{"a":null,"z":1}]}"#);
}

/// AT-10-007 / F-126: the profile fingerprint ignores key order and routing-only keys, and
/// changes with everything that changes the handshake.
#[test]
fn profile_fingerprint_vectors() {
    let base = profile_material(&view(vless()));
    let mut reordered = serde_json::Map::new();
    let original = vless();
    for (k, v) in original.as_object().unwrap().iter().rev() {
        reordered.insert(k.clone(), v.clone());
    }
    assert_eq!(profile_material(&view(Value::Object(reordered))), base);
    let mut routing = vless();
    routing["tag"] = json!("other-tag");
    routing["bind_interface"] = json!("Wi-Fi");
    routing["detour"] = json!("direct");
    routing["domain_strategy"] = json!("prefer_ipv4");
    routing["domain_resolver"] = json!("dns-bootstrap");
    assert_eq!(profile_material(&view(routing)), base);
    let mut renamed = view(vless());
    renamed.id = "another-id".into();
    assert_eq!(profile_material(&renamed), base);

    let changed = |edit: &dyn Fn(&mut ProfileView)| {
        let mut p = view(vless());
        edit(&mut p);
        profile_material(&p)
    };
    let variants = [
        changed(&|p| p.outbound["transport"]["type"] = json!("ws")),
        changed(&|p| {
            p.outbound["tls"]["reality"]["public_key"] = json!("PUBLIC_KEY_PLACEHOLDER_B")
        }),
        changed(&|p| {
            p.outbound["obfs"] = json!({"type": "salamander", "password": "OBFS_PLACEHOLDER"})
        }),
        changed(&|p| p.client_device = Some(ClientDevice::Android)),
        changed(&|p| p.client_fingerprint = Some("firefox".into())),
        changed(&|p| p.outbound["vpnte_xray"] = json!({"outbounds": [{"protocol": "vless"}]})),
        changed(&|p| p.outbound["uuid"] = json!("00000000-0000-4000-8000-000000000001")),
    ];
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(v, &base, "variant {i}");
    }
}

#[test]
fn compact_drops_old_versions_expired_and_keeps_the_newest_24() {
    let rec = |used: i64, expires: i64| LearnedRecord {
        mode: AdaptiveMode::MtuCompatibility,
        learned_at: used,
        last_used_at: used,
        expires_at: expires,
    };
    let mut learning = BTreeMap::new();
    learning.insert("v2:old:format".to_owned(), rec(5, 1_000));
    learning.insert("v3:expired:x".to_owned(), rec(5, 99));
    for i in 0..30 {
        learning.insert(format!("v3:n{i:02}:p"), rec(i, 1_000));
    }
    compact(&mut learning, 100);
    assert_eq!(learning.len(), MAX_RECORDS);
    assert!(learning.keys().all(|k| k.starts_with("v3:n")));
    assert!(!learning.contains_key("v3:n05:p") && learning.contains_key("v3:n29:p"));
}

/// AT-01-001: a persisted secret gives the same keys after a restart; learned modes survive.
#[test]
fn persisted_secret_keeps_keys_across_restarts() {
    let dir = TempDir::new("adaptive-secret");
    let (_, first) = open(&dir);
    assert!(first.enabled());
    let key = first.key(&net("192.168.1.1"), &view(vless())).unwrap();
    assert!(key.starts_with("v3:"));
    first.learn(&key, AdaptiveMode::MtuCompatibility, 1_000);
    drop(first);
    let (_, second) = open(&dir);
    assert_eq!(
        second.key(&net("192.168.1.1"), &view(vless())).as_ref(),
        Some(&key)
    );
    assert_eq!(
        second.lookup(&key, |_| true, 2_000),
        Some(AdaptiveMode::MtuCompatibility)
    );
    assert_ne!(
        second.key(&net("192.168.1.254"), &view(vless())).unwrap(),
        key
    );
}

/// AT-01-010: the file holds only HMACs and a sealed secret, never SSID, gateway, server,
/// key or credential text.
#[test]
fn store_contains_only_hmacs() {
    let dir = TempDir::new("adaptive-hmac");
    let (store, learning) = open(&dir);
    let key = learning
        .key(&net("192.168.1.1@aabbccddeeff"), &view(vless()))
        .unwrap();
    learning.learn(&key, AdaptiveMode::TlsCompatibility, 1_000);
    let text = std::fs::read_to_string(store.path()).unwrap();
    for secret in [
        "192.168",
        "aabbcc",
        "vpn.example",
        "front.example",
        "PUBLIC_KEY",
        "00000000-",
    ] {
        assert!(!text.contains(secret), "{secret} leaked");
    }
    assert!(text.contains("\"secret\": \"dpapi:"));
}

/// AT-01-010: a stored secret that cannot be opened stays byte-for-byte; learning is off.
#[test]
fn unreadable_secret_is_left_untouched() {
    let dir = TempDir::new("adaptive-locked");
    let path = dir.path().join(AdaptiveDoc::FILE);
    let original = "{
  \"schemaVersion\": 1,
  \"secret\": \"dpapi:v1:AAAA\",
  \"learning\": {}
}
";
    std::fs::write(&path, original).unwrap();
    let (_, learning) = open(&dir);
    assert!(!learning.enabled());
    assert_eq!(learning.key(&net("192.168.1.1"), &view(vless())), None);
    learning.learn("v3:a:b", AdaptiveMode::MtuCompatibility, 1);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
}

/// A store that cannot be written (here: a newer schema) persists nothing and keeps
/// learning off, the same path a refused DPAPI seal takes.
#[test]
fn unwritable_store_persists_nothing() {
    let dir = TempDir::new("adaptive-readonly");
    let path = dir.path().join(AdaptiveDoc::FILE);
    let original = "{\"schemaVersion\": 99, \"learning\": {}}";
    std::fs::write(&path, original).unwrap();
    let (_, learning) = open(&dir);
    assert!(!learning.enabled());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
}

#[test]
fn baseline_is_never_learned_and_forget_removes() {
    let dir = TempDir::new("adaptive-forget");
    let (store, learning) = open(&dir);
    learning.learn("v3:a:b", AdaptiveMode::Baseline, 1_000);
    assert!(store.read(|d| d.learning.is_empty()));
    learning.learn("v3:a:b", AdaptiveMode::TlsCompatibility, 1_000);
    assert_eq!(
        learning.lookup("v3:a:b", |m| m == AdaptiveMode::MtuCompatibility, 1_001),
        None
    );
    learning.forget("v3:a:b");
    assert!(store.read(|d| d.learning.is_empty()));
}
