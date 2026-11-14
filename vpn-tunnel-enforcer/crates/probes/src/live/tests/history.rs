//! History document and store (live-probe §7.9, §7.10 with B-20 / B-22; storage spec §6.1).
use std::collections::HashSet;
use std::path::Path;

use serde_json::json;
use vpnte_base::ErrorKind;
use vpnte_base::types::now_ms;

use super::{Root, row, row_json};
use crate::live::{HistoryStore, LiveHistory};

fn open(root: &Path) -> HistoryStore {
    HistoryStore::open(root)
}

/// liveServerHistory.test.ts:112-125: 20 per target, newest first; a fresh store is empty.
#[test]
fn twenty_per_target_newest_first() {
    let root = Root::new();
    let store = open(&root.0);
    assert!(store.list(None, None).is_empty());
    for i in 1..=25 {
        store
            .add(row(&format!("check-{i}"), Some("p-1"), 100_000 - i * 10))
            .unwrap();
    }
    let rows = store.list(Some("p-1"), None);
    assert_eq!(rows.len(), 20);
    assert_eq!(rows[0].id, "check-25");
    let reopened = open(&root.0);
    assert_eq!(
        reopened.list(Some("p-1"), None)[0].id,
        "check-25",
        "survives a restart"
    );
}

/// liveServerHistory.test.ts:127-142 + B-18: the baseline skips a check where only DNS worked.
#[test]
fn baseline_is_the_last_answering_check() {
    let root = Root::new();
    let store = open(&root.0);
    store.add(row("c-1", Some("p-1"), 2000)).unwrap();
    let mut failed = row("c-2", Some("p-1"), 1000);
    failed.reachability.timed.status = crate::live_stages::TimedStatus::Error;
    store.add(failed).unwrap();
    let base = store.baseline(Some("p-1"), "vpn.example.com", 443).unwrap();
    assert_eq!(base.id, "c-1");
    assert!(
        store
            .baseline(Some("p-1"), "vpn.example.com", 8443)
            .is_none()
    );
}

/// Review fix: the pipeline stores exactly the row it returns. Sanitising is not idempotent (an
/// escaped `%` in a redirect path would be decoded twice), so it runs once and `insert` keeps
/// the sanitised row as it is.
#[test]
fn sanitised_row_is_stored_as_returned() {
    let root = Root::new();
    let store = open(&root.0);
    let mut check = row("c-1", Some("p-1"), 1000);
    check.http = Some(crate::live_stages::http::HttpInfo {
        location_header: Some("https://redirect.example/a%2541".into()),
        ..Default::default()
    });
    crate::live::sanitize(&mut check);
    assert_eq!(
        check
            .http
            .as_ref()
            .and_then(|h| h.location_header.as_deref()),
        Some("https://redirect.example/a%41")
    );
    store.insert(check.clone()).unwrap();
    assert_eq!(store.list(Some("p-1"), None)[0], check);
}

/// B-20 (AT-05-005): an undecodable file is moved aside with its bytes, the history starts
/// empty and the next add works and survives a restart.
#[test]
fn corrupt_file_is_set_aside() {
    let root = Root::new();
    root.write("{\"targets\": {\"profile:p1\": [");
    let store = open(&root.0);
    assert!(store.list(None, None).is_empty());
    let aside: Vec<_> = std::fs::read_dir(root.0.join("history"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("live-checks.corrupt-"))
        .collect();
    assert_eq!(aside.len(), 1, "{aside:?}");
    store.add(row("new", Some("p1"), 0)).unwrap();
    assert_eq!(open(&root.0).list(Some("p1"), None)[0].id, "new");
}

/// liveServerHistory.integrity.test.ts:57-76: bad rows are dropped one by one, valid siblings
/// and other targets stay; reading does not rewrite the file.
#[test]
fn invalid_rows_are_dropped_per_row() {
    let root = Root::new();
    let mut bad_port = row_json("bad-port", Some("p1"));
    bad_port["port"] = json!(70000);
    let mut bad_time = row_json("bad-time", Some("p1"));
    bad_time["finishedAt"] = json!("yesterday");
    let mut bad_dns = row_json("bad-dns", Some("p1"));
    bad_dns["dns"]["a"] = json!(false);
    let mut good = row_json("good", Some("p1"));
    good["finishedAt"] = json!(now_ms());
    let text = serde_json::to_string(&json!({"schemaVersion": 1, "targets": {
        "profile:p1": [null, bad_port, bad_time, bad_dns, good],
        "profile:other": [row_json("misplaced", Some("p1"))],
        "profile:bad": false
    }}))
    .unwrap();
    root.write(&text);
    let store = open(&root.0);
    let rows = store.list(None, None);
    assert_eq!(
        rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["good"]
    );
    assert_eq!(
        std::fs::read_to_string(root.file()).unwrap(),
        text,
        "read only"
    );
}

/// liveServerHistory.integrity.test.ts:105-113 + 148-153: a newer version's file is never
/// written over.
#[test]
fn newer_version_is_read_only() {
    let root = Root::new();
    let text = r#"{"schemaVersion": 7, "targets": {}}"#;
    root.write(text);
    let store = open(&root.0);
    assert_eq!(
        store.add(row("x", Some("p1"), 0)).unwrap_err().kind,
        ErrorKind::Conflict
    );
    assert!(store.clear().is_err());
    assert_eq!(std::fs::read_to_string(root.file()).unwrap(), text);
}

/// AT-05-008 / B-21: clear empties the history for good; export is the sanitised document.
#[test]
fn clear_and_export() {
    let root = Root::new();
    let store = open(&root.0);
    store.add(row("c-1", Some("p-1"), 0)).unwrap();
    let export: serde_json::Value = serde_json::from_str(&store.export_json()).unwrap();
    assert_eq!(export["targets"]["profile:p-1"][0]["id"], "c-1");
    store.clear().unwrap();
    assert!(store.list(None, None).is_empty());
    assert!(
        open(&root.0).list(None, None).is_empty(),
        "nothing comes back after a restart"
    );
}

/// B-22: deleted profiles' targets and rows older than 180 days go.
#[test]
fn prune_and_age_cap() {
    let root = Root::new();
    let store = open(&root.0);
    store.add(row("keep", Some("live"), 0)).unwrap();
    store.add(row("gone", Some("deleted"), 0)).unwrap();
    store.add(row("host-row", None, 0)).unwrap();
    let live: HashSet<String> = ["live".to_owned()].into();
    assert_eq!(store.prune(&live).unwrap(), 1);
    assert!(store.list(Some("deleted"), None).is_empty());
    assert_eq!(
        store.list(None, Some("vpn.example.com")).len(),
        1,
        "host targets stay"
    );
    store
        .add(row("ancient", Some("live"), 181 * 24 * 3600 * 1000))
        .unwrap();
    let ids: Vec<String> = store
        .list(Some("live"), None)
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(ids, ["keep"]);
}

/// liveServerHistory.integrity.test.ts:159-163 + 203-209: an invalid row is refused before any
/// I/O; ids that look like UUIDs survive while a UUID in free text does not.
#[test]
fn add_validates_and_keeps_ids() {
    let root = Root::new();
    let store = open(&root.0);
    let mut empty_host = row("x", Some("p-1"), 0);
    empty_host.host = " ".into();
    assert_eq!(
        store.add(empty_host).unwrap_err().kind,
        ErrorKind::Validation
    );
    assert!(!root.file().exists());
    let id = "11111111-1111-4111-8111-111111111111";
    let profile = "22222222-2222-4222-8222-222222222222";
    let mut c = row(id, Some(profile), 0);
    c.reachability.timed.error = Some(format!("rejected {id}"));
    store.add(c).unwrap();
    let stored = &store.list(Some(profile), None)[0];
    assert_eq!(
        (stored.id.as_str(), stored.profile_id.as_deref()),
        (id, Some(profile))
    );
    assert!(
        !stored
            .reachability
            .timed
            .error
            .as_deref()
            .unwrap()
            .contains(id)
    );
}

/// Storage §6.6 import: v0 / v1 rows kept when valid, `global` rows re-keyed, hop lines
/// cleaned, cancelled rows dropped; a newer Electron file is not imported.
#[test]
fn legacy_import() {
    let fresh = |id: &str, profile: Option<&str>| {
        let mut v = row_json(id, profile);
        v["finishedAt"] = json!(jiff::Timestamp::now().to_string());
        v
    };
    let mut global = fresh("g-1", None);
    global["host"] = json!("Other.Example");
    global["route"] = json!({"status": "ok", "durationMs": 9,
        "hopDetails": ["  2    14 мс    18 мс    12 мс  10.0.0.1"]});
    let mut cancelled = fresh("c-x", Some("p1"));
    cancelled["cancelled"] = json!(true);
    let old = json!({
        "schemaVersion": 1,
        "migration": {"id": "live-history-provenance-v1", "from": 0, "to": 1, "checksum": "00"},
        "profile:p1": [fresh("a", Some("p1")), fresh("b", Some("p1")), cancelled, {"id": "broken"}],
        "global": [global]
    });
    let doc = LiveHistory::from_legacy(&old);
    assert_eq!(doc.targets["profile:p1"].len(), 2);
    let other = &doc.targets["host:other.example"][0];
    assert_eq!(
        other.route.as_ref().unwrap().hop_details,
        ["2 14 ms 18 ms 12 ms 10.0.0.1"]
    );
    let newer = json!({"schemaVersion": 2, "profile:p1": [fresh("a", Some("p1"))]});
    assert!(LiveHistory::from_legacy(&newer).targets.is_empty());
}
