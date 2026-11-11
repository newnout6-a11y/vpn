//! Snapshots (systemSnapshot.test.ts, systemSnapshotLifetime.test.ts; AT-00-003/005, AT-08-001).
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::diagnostics::snapshot::{self, Collector, SnapshotReason, Snapshotter};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vpnte-probes-{tag}-{}", fastrand::u64(..)));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The name format the diagnostics export parses.
#[test]
fn file_name_format() {
    let ts: jiff::Timestamp = "2026-11-11T02:35:07.123Z".parse().unwrap();
    let name = snapshot::file_name(ts, SnapshotReason::Manual);
    assert_eq!(name, "snapshot-2026-11-11T02-35-07-123Z-manual.json");
    let export =
        regex::Regex::new(r"^snapshot-(\d{4}-\d{2}-\d{2}T\d{2})-(\d{2})-(\d{2})-(\d{3}Z)-")
            .unwrap();
    assert!(export.is_match(&name));
    let ts: jiff::Timestamp = "2026-01-02T03:04:05Z".parse().unwrap();
    assert_eq!(
        snapshot::file_name(ts, SnapshotReason::TunStartFailed),
        "snapshot-2026-01-02T03-04-05-000Z-tun-start-failed.json"
    );
}

/// Public addresses become pseudonyms; private / LAN ones stay (B-SN-1).
#[test]
fn public_ips_are_redacted() {
    let mut doc = json!({ "a": "10.0.0.2", "b": ["8.8.8.8 via 192.168.1.1"], "c": { "d": "fe80::1" }, "n": 5 });
    snapshot::redact_ips(&mut doc);
    assert_eq!(doc["a"], "10.0.0.2");
    let b = doc["b"][0].as_str().unwrap();
    assert!(!b.contains("8.8.8.8") && b.contains("192.168.1.1"), "{b}");
    assert_eq!(doc["c"]["d"], "fe80::1");
    assert_eq!(doc["n"], 5);
}

#[test]
fn retention_keeps_the_newest() {
    let dir = temp_dir("prune");
    let base = SystemTime::now() - Duration::from_secs(10_000);
    for i in 0..65u64 {
        let path = dir.join(format!("f{i:02}.json"));
        std::fs::write(&path, "{}").unwrap();
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(base + Duration::from_secs(i * 10))
            .unwrap();
    }
    snapshot::prune(&dir, snapshot::MAX_RETAINED);
    let mut left: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(left.len(), 60);
    assert_eq!(left[0], "f05.json");
}

/// A collector that records calls and waits for a permit per call (or panics for `fail`).
fn gated(
    fail: Option<SnapshotReason>,
) -> (
    Collector,
    Arc<Mutex<Vec<SnapshotReason>>>,
    std::sync::mpsc::Sender<()>,
) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let rx = Arc::new(Mutex::new(rx));
    let log = calls.clone();
    let collector: Collector = Arc::new(move |reason, _ts| {
        log.lock().push(reason);
        rx.lock().recv().unwrap();
        if Some(reason) == fail {
            panic!("collector failed (test)");
        }
        json!({ "reason": reason.as_str(), "appVersion": "2.0.0" })
    });
    (collector, calls, tx)
}

async fn wait_calls(calls: &Mutex<Vec<SnapshotReason>>, n: usize) {
    for _ in 0..500 {
        if calls.lock().len() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("collector not called {n} times");
}

/// Captures are serialized; a periodic one while busy is skipped (no backlog); afterwards a
/// periodic capture runs again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captures_are_serialized_and_periodic_is_skipped_when_busy() {
    let dir = temp_dir("snap");
    let (collector, calls, permits) = gated(None);
    let s = Snapshotter::with_collector(dir.clone(), collector);
    let manual = tokio::spawn({
        let s = s.clone();
        async move { s.capture(SnapshotReason::Manual).await }
    });
    wait_calls(&calls, 1).await;
    let post = tokio::spawn({
        let s = s.clone();
        async move { s.capture(SnapshotReason::TunPostStart).await }
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        *calls.lock(),
        vec![SnapshotReason::Manual],
        "the second capture waits its turn"
    );
    assert_eq!(s.capture(SnapshotReason::Periodic).await, None);
    permits.send(()).unwrap();
    permits.send(()).unwrap();
    let first = manual.await.unwrap().unwrap();
    let second = post.await.unwrap().unwrap();
    assert!(first.to_string_lossy().ends_with("-manual.json"));
    assert!(second.to_string_lossy().ends_with("-tun-post-start.json"));
    permits.send(()).unwrap();
    assert!(s.capture(SnapshotReason::Periodic).await.is_some());
    assert_eq!(
        *calls.lock(),
        vec![
            SnapshotReason::Manual,
            SnapshotReason::TunPostStart,
            SnapshotReason::Periodic
        ]
    );
    let doc: Value = serde_json::from_slice(&std::fs::read(&first).unwrap()).unwrap();
    assert_eq!(
        (doc["reason"].as_str(), doc["appVersion"].as_str()),
        (Some("manual"), Some("2.0.0"))
    );
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(names.iter().all(|n| n.ends_with(".json")), "{names:?}");
    assert_eq!(names.len(), 3);
}

/// A failed capture returns nothing but releases the queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_capture_releases_the_queue() {
    let dir = temp_dir("snapfail");
    let (collector, _calls, permits) = gated(Some(SnapshotReason::TunStartFailed));
    let s = Snapshotter::with_collector(dir.clone(), collector);
    for _ in 0..3 {
        permits.send(()).unwrap();
    }
    assert_eq!(s.capture(SnapshotReason::TunStartFailed).await, None);
    assert!(s.capture(SnapshotReason::TunPostStop).await.is_some());
    assert!(s.capture(SnapshotReason::Periodic).await.is_some());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The real collector: every section present, each one independently a value or an error.
#[test]
fn real_collector_sections() {
    let mut app = serde_json::Map::new();
    app.insert("engines".into(), json!({ "singBox": { "running": false } }));
    let doc = snapshot::collect(SnapshotReason::Manual, jiff::Timestamp::now(), "2.0.0", app);
    for key in [
        "reason",
        "ts",
        "os",
        "appVersion",
        "elevated",
        "memMb",
        "adapters",
        "routesV4",
        "routesV6",
        "nrptRules",
        "winhttpProxy",
        "wininetProxy",
        "listeners",
        "engines",
    ] {
        assert!(doc.get(key).is_some(), "missing {key}");
    }
    assert_eq!(doc["reason"], "manual");
    for port in ["10808", "10809"] {
        let l = &doc["listeners"][port];
        assert!(l.get("pid").is_some() || l.get("empty").is_some() || l.get("error").is_some());
    }
}
