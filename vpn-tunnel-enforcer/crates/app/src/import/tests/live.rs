//! The old live-check history (`live-server-checks.json`, else its rolling `.bak` when the main
//! file is damaged), imported once into `history/live-checks.json`.
use serde_json::{Map, Value, json};
use vpnte_base::types::now_ms;

use super::fixture::Fixture;
use super::{host, note, rows};
use crate::import::run::run;

const FILE: &str = "history/live-checks.json";

/// A v1 history with one finished check of `target` from yesterday.
fn old_history(target: &str) -> Value {
    let at = now_ms() - 86_400_000;
    let row = json!({
        "id": "lc_0000000000000000000000000000000a", "host": target, "port": 443,
        "startedAt": at, "finishedAt": at + 900,
        "dns": {"status": "ok", "durationMs": 5, "a": ["203.0.113.20"]},
        "reachability": {"status": "ok", "durationMs": 7, "tcpReachable": true, "port": 443},
    });
    let mut old = Map::new();
    old.insert("schemaVersion".into(), json!(1));
    old.insert(format!("host:{target}"), json!([row]));
    Value::Object(old)
}

#[test]
fn the_live_history_is_imported() {
    let fx = Fixture::new("live");
    fx.store("live-server-checks", &old_history("example.org"));
    let report = run(&fx.dirs(), &host(false)).unwrap();
    assert_eq!(rows(&report, FILE), Some(1), "{report:?}");
    let doc = fx.doc(FILE);
    assert_eq!(doc["targets"]["host:example.org"][0]["port"], 443);
}

/// The old loader's rule: an undecodable main file falls back to its `.bak` (said in a note).
#[test]
fn a_damaged_live_history_falls_back_to_its_backup() {
    let fx = Fixture::new("live-bak");
    fx.write_file("live-server-checks.json", b"{ damaged");
    let backup = old_history("backup.example").to_string();
    fx.write_file("live-server-checks.json.bak", backup.as_bytes());
    let report = run(&fx.dirs(), &host(false)).unwrap();
    assert!(
        note(&report, "app.import.fileInvalid").is_some(),
        "{report:?}"
    );
    assert_eq!(rows(&report, FILE), Some(1), "{report:?}");
    assert!(fx.doc(FILE)["targets"]["host:backup.example"].is_array());
}
