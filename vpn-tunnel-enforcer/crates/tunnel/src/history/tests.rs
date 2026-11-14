use serde_json::json;

use super::export::cell;
use super::*;
use crate::outcome::tests::text;
use crate::outcome::{Evidence, OutcomeKind, verbatim};
use crate::test_support::TempDir;

use DisconnectReason as R;
use SessionMode as M;

#[allow(clippy::too_many_arguments)]
fn row(
    id: &str,
    started: UnixMs,
    ended: Option<UnixMs>,
    name: &str,
    profile: &str,
    mode: SessionMode,
    down: u64,
    up: u64,
    reason: DisconnectReason,
) -> Entry {
    Entry {
        id: id.into(),
        correlation_id: None,
        provenance: None,
        started_at: started,
        ended_at: ended,
        duration_ms: None,
        profile_name: name.into(),
        profile_id: profile.into(),
        mode,
        bytes_down: down,
        bytes_up: up,
        disconnect_reason: reason,
        error_message: None,
        outcome: None,
    }
}

/// connectionHistory.test.ts fixture (no secrets).
fn fixture() -> Vec<Entry> {
    vec![
        row(
            "entry-1",
            1_700_000_000_000,
            Some(1_700_003_600_000),
            "US Server",
            "profile-1",
            M::Hard,
            1_024_000,
            512_000,
            R::User,
        ),
        row(
            "entry-2",
            1_700_010_000_000,
            Some(1_700_017_200_000),
            "EU Server",
            "profile-2",
            M::Soft,
            2_048_000,
            1_024_000,
            R::Error,
        ),
        row(
            "entry-3",
            1_700_020_000_000,
            None,
            "JP Server",
            "profile-3",
            M::Direct,
            500_000,
            250_000,
            R::Rotation,
        ),
        row(
            "entry-4",
            1_700_030_000_000,
            Some(1_700_031_800_000),
            "US Server",
            "profile-1",
            M::Hard,
            768_000,
            384_000,
            R::Schedule,
        ),
    ]
}

fn ids(rows: &[Entry]) -> Vec<&str> {
    rows.iter().map(|e| e.id.as_str()).collect()
}

fn run(f: Filter) -> Vec<String> {
    ids(&filter(&fixture(), &f, Lang::Ru))
        .into_iter()
        .map(String::from)
        .collect()
}

fn text_filter(t: &str) -> Filter {
    Filter {
        text: Some(t.into()),
        ..Filter::default()
    }
}

/// AT-00-005 (connectionHistory.test.ts): levels, inclusive dates, text, AND of all.
#[test]
fn filter_vectors() {
    assert_eq!(
        run(Filter::default()),
        ["entry-1", "entry-2", "entry-3", "entry-4"]
    );
    let levels = |l: Vec<R>| Filter {
        levels: l,
        ..Filter::default()
    };
    assert_eq!(run(levels(vec![R::User])), ["entry-1"]);
    assert_eq!(run(levels(vec![R::User, R::Error])), ["entry-1", "entry-2"]);
    assert_eq!(run(levels(vec![])).len(), 4);
    let from = Filter {
        date_from: Some(1_700_015_000_000),
        ..Filter::default()
    };
    assert_eq!(run(from), ["entry-3", "entry-4"]);
    let to = Filter {
        date_to: Some(1_700_015_000_000),
        ..Filter::default()
    };
    assert_eq!(run(to), ["entry-1", "entry-2"]);
    let range = Filter {
        date_from: Some(1_700_005_000_000),
        date_to: Some(1_700_025_000_000),
        ..Filter::default()
    };
    assert_eq!(run(range), ["entry-2", "entry-3"]);
    let inclusive = Filter {
        date_from: Some(1_700_010_000_000),
        date_to: Some(1_700_010_000_000),
        ..Filter::default()
    };
    assert_eq!(run(inclusive), ["entry-2"]);
    assert_eq!(run(text_filter("us server")), ["entry-1", "entry-4"]);
    assert_eq!(run(text_filter("soft")), ["entry-2"]);
    assert_eq!(run(text_filter("rotation")), ["entry-3"]);
    assert!(run(text_filter("nonexistent")).is_empty());
    assert_eq!(run(text_filter("")).len(), 4);
    let all = Filter {
        levels: vec![R::User, R::Schedule],
        text: Some("us server".into()),
        date_from: Some(1_700_025_000_000),
        date_to: None,
    };
    assert_eq!(run(all), ["entry-4"]);
    assert!(filter(&Vec::new(), &Filter::default(), Lang::Ru).is_empty());
}

/// The text search also covers the kind and the headline as the user reads them.
#[test]
fn filter_searches_outcomes() {
    let mut rows = fixture();
    rows[2].outcome = Some(SessionOutcome::with_headline(
        OutcomeKind::SystemSleep,
        Evidence::default(),
        verbatim("Компьютер уходил в сон"),
    ));
    rows[3].error_message = Some(verbatim("Сервер НЕ отвечает"));
    let found = |t: &str| ids(&filter(&rows, &text_filter(t), Lang::Ru)).join(",");
    assert_eq!(found("system-sleep"), "entry-3");
    assert_eq!(found("УХОДИЛ в сон"), "entry-3");
    assert_eq!(found("не отвечает"), "entry-4");
}

/// AT-00-005: aggregate, monotonic duration wins, windows, active-only rows.
#[test]
fn stats_vectors() {
    let now = 1_700_040_000_000;
    let day = stats(&fixture(), Period::Day, now);
    assert_eq!(
        day,
        Stats {
            total_time_ms: 3_600_000 + 7_200_000 + 1_800_000,
            total_bytes_down: 4_340_000,
            total_bytes_up: 2_170_000,
            entry_count: 4,
        }
    );
    let mut e1 = fixture().swap_remove(0);
    e1.ended_at = Some(e1.started_at - 3_600_000);
    e1.duration_ms = Some(65_000);
    assert_eq!(stats([&e1], Period::Day, now).total_time_ms, 65_000);
    assert_eq!(
        stats(&fixture(), Period::Day, 1_700_200_000_000),
        Stats::default()
    );
    assert_eq!(stats(&fixture(), Period::Week, now).entry_count, 4);
    assert_eq!(stats(&fixture(), Period::Month, now).entry_count, 4);
    let active = row("a", now - 1000, None, "X", "x", M::Hard, 100, 50, R::User);
    assert_eq!(
        stats([&active], Period::Day, now),
        Stats {
            total_time_ms: 0,
            total_bytes_down: 100,
            total_bytes_up: 50,
            entry_count: 1,
        }
    );
}

/// Starts that never came up are not connections (start-failed, and tun-setup-failed since L-14).
#[test]
fn stats_skip_failed_starts() {
    let now = 1_700_040_000_000;
    let mut rows = fixture();
    rows[0].outcome = Some(SessionOutcome::start_failure(
        false,
        None,
        Evidence::default(),
    ));
    rows[1].outcome = Some(SessionOutcome::start_failure(
        true,
        None,
        Evidence::default(),
    ));
    rows[3].outcome = Some(SessionOutcome::new(
        OutcomeKind::UserStop,
        Evidence::default(),
    ));
    let s = stats(&rows, Period::Day, now);
    assert_eq!(s.entry_count, 2);
    assert_eq!(s.total_time_ms, 1_800_000);
}

/// AT-00-005 (connection-history.test.ts): the duration rule.
#[test]
fn duration_rule() {
    let d = |started, ended, duration| {
        let mut e = row("d", started, ended, "X", "x", M::Hard, 0, 0, R::User);
        e.duration_ms = duration;
        e.connection_ms()
    };
    assert_eq!(d(10_000, Some(100), Some(2_500)), 2_500);
    assert_eq!(d(100, Some(10_000), Some(0)), 0);
    assert_eq!(d(100, Some(2_100), None), 2_000);
    assert_eq!(d(2_100, Some(100), None), 0);
    assert_eq!(d(100, None, Some(2_500)), 0);
}

/// AT-00-005: CSV header, a legacy row, an outcome row and RFC 4180 quoting.
#[test]
fn csv_vectors() {
    assert_eq!(to_csv(&Vec::new(), Lang::Ru), CSV_HEADER);
    assert_eq!(CSV_HEADER.split(',').count(), 18);
    let csv = to_csv(&fixture()[..1], Lang::Ru);
    let lines: Vec<&str> = csv.split('\n').collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(
        lines[1],
        "entry-1,1700000000000,1700003600000,US Server,profile-1,hard,1024000,512000,user,,,,,,,,,"
    );
    let mut crash = fixture().swap_remove(0);
    crash.outcome = Some(SessionOutcome::with_headline(
        OutcomeKind::SingboxCrash,
        Evidence::default(),
        verbatim("Ядро VPN завершилось, код 1"),
    ));
    let csv = to_csv([&crash], Lang::En);
    assert!(
        csv.contains(",singbox-crash,\"Ядро VPN завершилось, код 1\""),
        "{csv}"
    );
    let mut quoted = fixture().swap_remove(0);
    quoted.profile_name = "Server, US".into();
    quoted.profile_id = "Server \"Best\"".into();
    quoted.error_message = Some(verbatim("Wintun failed, timeout reached"));
    let csv = to_csv([&quoted], Lang::Ru);
    assert!(
        csv.contains(",\"Server, US\",\"Server \"\"Best\"\"\",hard,"),
        "{csv}"
    );
    assert!(
        csv.contains(",\"Wintun failed, timeout reached\","),
        "{csv}"
    );
    assert!(!csv.ends_with('\n'));
}

/// L-19: spreadsheet formula guard on text cells only; CR forces quoting.
#[test]
fn csv_formula_guard() {
    assert_eq!(cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
    assert_eq!(cell("-ERR"), "'-ERR");
    assert_eq!(cell("+1"), "'+1");
    assert_eq!(cell("@SUM(A1)"), "'@SUM(A1)");
    assert_eq!(cell("\tx"), "'\tx");
    assert_eq!(cell("a\rb"), "\"a\rb\"");
    assert_eq!(cell("\rb"), "\"'\rb\"");
    assert_eq!(cell("plain"), "plain");
    let mut e = fixture().swap_remove(0);
    e.bytes_down = 1024;
    e.profile_name = "=cmd".into();
    let csv = to_csv([&e], Lang::Ru);
    assert!(csv.contains(",'=cmd,profile-1,hard,1024,512000,"), "{csv}");
}

/// Provenance and duration columns of a new row.
#[test]
fn csv_provenance_columns() {
    let entry = Entry::from_new(new_entry(OutcomeKind::UserStop)).unwrap();
    let csv = to_csv([&entry], Lang::Ru);
    let line = csv.split('\n').nth(1).unwrap();
    let cells: Vec<&str> = line.split(',').collect();
    assert_eq!(cells.len(), 18);
    assert_eq!(cells[10], "user-stop");
    assert_eq!(cells[12], entry.correlation_id.as_ref().unwrap().as_str());
    assert_eq!(&cells[13..], ["tray", "manual", "tun", "observed", "1000"]);
}

/// AT-00-005: JSON export reads back through the same reader; messages become text in `lang`.
#[test]
fn json_round_trip() {
    let mut rows = fixture();
    rows[0].outcome = Some(SessionOutcome::start_failure(
        false,
        Some(verbatim("порт занят")),
        Evidence::default(),
    ));
    rows[0].error_message = rows[0].outcome.as_ref().map(|o| o.headline.clone());
    rows.push(Entry::from_new(new_entry(OutcomeKind::Killswitch)).unwrap());
    let json = to_json(&rows, Lang::Ru).unwrap();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    // Translated messages go through the process-wide catalogs (loaded by the app, not here).
    let headline = rows[0].outcome.as_ref().map(|o| &o.headline).unwrap();
    assert_eq!(
        parsed[0]["outcome"]["headline"],
        outcome::render(headline, Lang::Ru)
    );
    assert_eq!(parsed[0]["outcome"]["evidence"]["hint"], "порт занят");
    assert_eq!(parsed[0]["endedAt"], 1_700_003_600_000_i64);
    assert_eq!(parsed[2]["endedAt"], Value::Null);
    let Value::Array(items) = parsed else {
        panic!("array expected")
    };
    let (back, skipped) = read_rows(items);
    assert_eq!(skipped, 0);
    // Equal once every message is replaced by its rendered text.
    let as_text = |e: &Entry| {
        let mut e = e.clone();
        let flat = |m: &mut Msg| *m = verbatim(outcome::render(m, Lang::Ru));
        if let Some(m) = e.error_message.as_mut() {
            flat(m);
        }
        if let Some(o) = e.outcome.as_mut() {
            flat(&mut o.headline);
            if let Some(hint) = o.evidence.hint.as_mut() {
                flat(hint);
            }
        }
        e
    };
    assert_eq!(back, rows.iter().map(as_text).collect::<Vec<_>>());
}

fn new_entry(kind: OutcomeKind) -> NewEntry {
    NewEntry {
        correlation_id: Some(CorrelationId::new()),
        source: Source::Tray,
        owner: Some(Owner::Manual),
        route: Route::Tun,
        started_at: 1_700_000_000_000,
        ended_at: 1_700_000_001_000,
        duration_ms: 1_000,
        profile_name: "Test".into(),
        profile_id: "profile-1".into(),
        mode: M::Hard,
        bytes_down: 10,
        bytes_up: 20,
        outcome: SessionOutcome::new(kind, Evidence::default()),
    }
}

/// §7.11 base input as stored JSON.
fn base_row() -> Value {
    json!({
        "id": "row-1",
        "startedAt": 1_700_000_000_000_i64, "endedAt": 1_700_000_001_000_i64, "durationMs": 1000,
        "profileId": "profile-1", "profileName": "Test", "mode": "hard",
        "bytesDown": 10, "bytesUp": 20, "disconnectReason": "user",
        "provenance": {"source": "unknown", "owner": "unknown", "route": "unconfirmed",
                       "confidence": "indeterminate"}
    })
}

fn with(pointer: &str, value: Value) -> Value {
    let mut row = base_row();
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    let slot = if parent.is_empty() {
        Some(&mut row)
    } else {
        row.pointer_mut(parent)
    };
    slot.and_then(Value::as_object_mut)
        .unwrap()
        .insert(key.into(), value);
    row
}

fn without(key: &str) -> Value {
    let mut row = base_row();
    row.as_object_mut().unwrap().remove(key);
    row
}

fn accepted(row: Value) -> bool {
    read_row(row).is_some()
}

/// AT-00-010 / §7.13: exact null / absent rules of the reader contract.
#[test]
fn null_and_absent_rules() {
    assert!(accepted(base_row()));
    assert!(!accepted(without("endedAt")));
    assert!(accepted(with("/endedAt", Value::Null)));
    for key in ["durationMs", "correlationId", "provenance"] {
        assert!(
            !accepted(with(&format!("/{key}"), Value::Null)),
            "{key}: null"
        );
    }
    for key in ["durationMs", "provenance", "errorMessage", "outcome"] {
        assert!(accepted(without(key)), "{key}: absent");
    }
    assert!(accepted(with("/errorMessage", Value::Null)));
    assert!(accepted(with("/outcome", Value::Null)));
    let outcome =
        json!({"kind": "unknown", "headline": "", "evidence": {"egressIp": null, "hint": null}});
    assert!(accepted(with("/outcome", outcome)));
    let null_evidence = json!({"kind": "unknown", "headline": "x", "evidence": null});
    assert!(!accepted(with("/outcome", null_evidence)));
    assert!(accepted(with("/foo", json!(1))));
    assert!(accepted(with(
        "/outcome",
        json!({"kind": "user-stop", "headline": "x", "evidence": {"foo": 1}})
    )));
}

/// AT-00-010 (connectionHistoryStorage.test.ts): malformed field values are rejected on read.
#[test]
fn malformed_values_rejected() {
    let bad = [
        ("/durationMs", json!(-1)),
        ("/durationMs", json!("raw-secret")),
        ("/provenance", json!({})),
        (
            "/provenance",
            json!({"source": "ipc", "owner": "manual", "route": "tun"}),
        ),
        ("/provenance/source", json!("raw-secret")),
        ("/provenance/owner", json!("raw-secret")),
        ("/provenance/extra", json!("x")),
        ("/provenance/route", json!("soft-env")),
        ("/correlationId", json!("raw-secret")),
        (
            "/correlationId",
            json!("123e4567-e89b-42d3-a456-426614174000"),
        ),
        ("/correlationId", json!(format!("ipc_{}", "0".repeat(32)))),
        (
            "/correlationId",
            json!("op_0123456789ab4def8123456789abcdef\n"),
        ),
        ("/correlationId", json!({})),
        ("/mode", json!(["hard"])),
        ("/disconnectReason", json!(["user"])),
        ("/bytesUp", json!("20")),
        ("/bytesDown", json!(-1)),
        ("/endedAt", json!({})),
        ("/startedAt", json!(-5)),
        ("/errorMessage", json!([])),
        ("/profileName", json!({"token": "x"})),
        ("/outcome", json!({"kind": "future-kind", "headline": "x"})),
        ("/outcome", json!({"kind": "unknown", "headline": {}})),
        (
            "/outcome",
            json!({"kind": "unknown", "headline": "x", "evidence": {"egressIp": {}}}),
        ),
        (
            "/outcome",
            json!({"kind": "unknown", "headline": "x", "evidence": {"adaptiveAttempts": -1}}),
        ),
        (
            "/outcome",
            json!({"kind": "unknown", "headline": "x", "evidence": {"killSwitchEngaged": "true"}}),
        ),
        (
            "/outcome",
            json!({"kind": "unknown", "headline": "x", "evidence": {"outboundFault": []}}),
        ),
    ];
    for (pointer, value) in bad {
        let shown = value.to_string();
        assert!(!accepted(with(pointer, value)), "{pointer} = {shown}");
    }
    // Route must fit the mode: soft-env only with soft, tun never with soft.
    let mut soft = with("/provenance/route", json!("soft-env"));
    soft["mode"] = json!("soft");
    assert!(accepted(soft.clone()));
    soft["provenance"]["route"] = json!("tun");
    assert!(!accepted(soft));
    for row in [Value::Null, json!([]), json!("secret-value"), json!(42)] {
        assert!(!accepted(row));
    }
}

/// §7.13 C-02: generated correlation ids pass the history reader.
#[test]
fn generated_correlation_ids_are_accepted() {
    for _ in 0..10_000 {
        let id = CorrelationId::new();
        assert!(accepted(with("/correlationId", json!(id.as_str()))), "{id}");
    }
    assert!(accepted(with(
        "/correlationId",
        json!("ipc_0123456789AB4DEF8123456789ABCDEF")
    )));
    assert!(!accepted(with(
        "/correlationId",
        json!("OP_0123456789ab4def8123456789abcdef")
    )));
}

/// The history document of a data root.
fn history_file(root: &TempDir) -> std::path::PathBuf {
    root.0.join("history").join("connections.json")
}

/// Writes `body` as the history document of `root`.
fn write_history(root: &TempDir, body: &str) {
    std::fs::create_dir_all(root.0.join("history")).unwrap();
    std::fs::write(history_file(root), body).unwrap();
}

/// AT-00-010: a new row derives id, bucket, confidence and message; it survives a restart.
#[test]
fn add_persists_and_clear_empties() {
    let root = TempDir::new("history");
    let history = History::open(&root.0);
    let added = history.add(new_entry(OutcomeKind::ServerDown)).unwrap();
    let id = uuid::Uuid::parse_str(&added.id).unwrap();
    assert_eq!(id.get_version_num(), 4);
    assert_eq!(added.disconnect_reason, R::Error);
    assert_eq!(added.provenance.unwrap().confidence, Confidence::Inferred);
    assert_eq!(
        added.error_message,
        added.outcome.as_ref().map(|o| o.headline.clone())
    );
    assert_eq!(added.duration_ms, Some(1_000));
    let reopened = History::open(&root.0);
    assert_eq!(reopened.list(), [added]);
    let on_disk: Value =
        serde_json::from_slice(&std::fs::read(history_file(&root)).unwrap()).unwrap();
    assert_eq!(on_disk["schemaVersion"], 1);
    assert_eq!(on_disk["entries"][0]["provenance"]["source"], "tray");
    reopened.clear().unwrap();
    assert!(History::open(&root.0).list().is_empty());
}

/// Soft only sets the system proxy: its rows carry no byte counts (index.ts:283-284).
#[test]
fn soft_rows_record_no_bytes() {
    let mut soft = new_entry(OutcomeKind::UserStop);
    soft.mode = M::Soft;
    soft.route = Route::SoftEnv;
    let entry = Entry::from_new(soft).unwrap();
    assert_eq!((entry.bytes_down, entry.bytes_up), (0, 0));
}

/// AT-00-010: an invalid row is refused before the write and leaves the file byte-identical.
#[test]
fn invalid_new_row_leaves_file_unchanged() {
    let root = TempDir::new("history");
    let history = History::open(&root.0);
    history.add(new_entry(OutcomeKind::UserStop)).unwrap();
    let before = std::fs::read(history_file(&root)).unwrap();
    let mut tun_on_soft = new_entry(OutcomeKind::UserStop);
    tun_on_soft.mode = M::Soft;
    let err = history.add(tun_on_soft).unwrap_err();
    assert_eq!(err.kind, vpnte_base::ErrorKind::Validation);
    assert_eq!(err.user_msg().key, "tunnel.history.invalidEntry");
    let mut soft_env_on_hard = new_entry(OutcomeKind::UserStop);
    soft_env_on_hard.route = Route::SoftEnv;
    assert!(history.add(soft_env_on_hard).is_err());
    let mut negative = new_entry(OutcomeKind::UserStop);
    negative.started_at = -1;
    assert!(history.add(negative).is_err());
    assert_eq!(std::fs::read(history_file(&root)).unwrap(), before);
    assert_eq!(history.list().len(), 1);
}

/// storage §7.10: 1001 appends keep the newest 1000.
#[test]
fn ring_keeps_the_newest_rows() {
    let mut doc = ConnectionHistory::default();
    for n in 0..=MAX_ENTRIES {
        let mut e = fixture().swap_remove(0);
        e.id = format!("row-{n}");
        doc.push(e);
    }
    assert_eq!(doc.entries.len(), MAX_ENTRIES);
    assert_eq!(doc.entries.front().map(|e| e.id.as_str()), Some("row-1"));
    assert_eq!(doc.entries.back().map(|e| e.id.as_str()), Some("row-1000"));
}

/// AT-00-010: every outcome kind round-trips through the file.
#[test]
fn every_kind_round_trips() {
    let root = TempDir::new("history");
    let history = History::open(&root.0);
    let added: Vec<Entry> = OutcomeKind::ALL
        .into_iter()
        .map(|kind| history.add(new_entry(kind)).unwrap())
        .collect();
    assert_eq!(History::open(&root.0).list(), added);
}

/// AT-00-010: the full evidence object round-trips (old wire values included).
#[test]
fn all_evidence_fields_round_trip() {
    let stored = json!({
        "singboxExitCode": 1, "singboxStderrTail": "stderr",
        "outboundFault": "upstream-unreachable", "adaptiveMode": "external-managed",
        "adaptiveAttempts": 2, "autoRestartAttempts": 1,
        "killSwitchEngaged": true, "leakDetectedDuringSession": false,
        "networkTransition": "changed", "egressCountry": "US", "egressIp": "203.0.113.9",
        "proxyEngine": "xray", "hint": "retry"
    });
    let evidence: Evidence = serde_json::from_value(stored.clone()).unwrap();
    assert_eq!(evidence.hint, Some(verbatim("retry")));
    assert_eq!(
        evidence.network_transition,
        Some(crate::outcome::NetworkTransition::Text("changed".into()))
    );
    let mut written = serde_json::to_value(&evidence).unwrap();
    // A message is stored as {key, args}; the old text form reads back as the same message.
    assert_eq!(written["hint"]["key"], crate::outcome::VERBATIM);
    written["hint"] = json!("retry");
    assert_eq!(written, stored);
}

/// AT-00-010: a legacy row without the optional fields reads back unchanged; 100 rows → 101 CSV lines.
#[test]
fn legacy_optional_fields_read_back() {
    let legacy = json!({
        "id": "legacy-1", "startedAt": 1_600_000_000_000_i64, "endedAt": null,
        "profileName": "Old", "profileId": "p-old", "mode": "direct",
        "bytesDown": 1, "bytesUp": 2, "disconnectReason": "crash"
    });
    let entry = read_row(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(&entry).unwrap(), legacy);
    let mut rows: Vec<Entry> = (0..99)
        .map(|_| Entry::from_new(new_entry(OutcomeKind::Rotation)).unwrap())
        .collect();
    rows.push(entry);
    assert_eq!(to_csv(&rows, Lang::En).split('\n').count(), 101);
}

/// AT-00-010: truncated JSON → the file is set aside, the history starts empty and stays writable.
#[test]
fn corrupt_file_is_set_aside() {
    let root = TempDir::new("history");
    write_history(&root, "{\"schemaVersion\":1,\"entries\":[{\"id\":\"x\"");
    let history = History::open(&root.0);
    assert!(history.list().is_empty());
    assert_eq!(history.store().mode(), vpnte_core::store::Mode::Writable);
    assert!(history.store().notice().is_some());
    history.add(new_entry(OutcomeKind::UserStop)).unwrap();
    assert_eq!(History::open(&root.0).list().len(), 1);
}

/// AT-00-010: damaged rows are skipped on load; the repaired list is what the next write keeps.
#[test]
fn damaged_rows_are_skipped_on_load() {
    let root = TempDir::new("history");
    let good = base_row();
    let body = json!({
        "schemaVersion": 1,
        "entries": [good, null, with("/profileName", json!({"token": "x"})),
                    with("/bytesDown", json!(-1)),
                    with("/outcome", json!({"kind": "future-outcome", "headline": "x"}))]
    });
    write_history(&root, &body.to_string());
    let history = History::open(&root.0);
    assert_eq!(ids(&history.list()), ["row-1"]);
    history.add(new_entry(OutcomeKind::UserStop)).unwrap();
    let on_disk: Value =
        serde_json::from_slice(&std::fs::read(history_file(&root)).unwrap()).unwrap();
    assert_eq!(on_disk["entries"].as_array().map(Vec::len), Some(2));
}

/// AT-00-010: a read failure is not JSON damage — nothing is moved aside and writes are refused.
#[test]
fn unreadable_file_is_not_treated_as_damage() {
    let root = TempDir::new("history");
    std::fs::create_dir_all(history_file(&root)).unwrap();
    let history = History::open(&root.0);
    assert!(matches!(
        history.store().mode(),
        vpnte_core::store::Mode::ReadOnly(vpnte_core::store::ReadOnlyReason::Unreadable)
    ));
    let err = history.add(new_entry(OutcomeKind::UserStop)).unwrap_err();
    assert_eq!(err.kind, vpnte_base::ErrorKind::Conflict);
    assert!(history_file(&root).is_dir());
}

fn legacy_store() -> Value {
    let mut old = with("/id", json!("old-1"));
    old["provenance"]["source"] = json!("ipc");
    old["outcome"] = json!({
        "kind": "network-lost", "headline": "Сеть изменилась под туннелем: адаптер отключился",
        "evidence": {"networkTransition": "адаптер отключился", "egressIp": null}
    });
    old["errorMessage"] = json!("Сеть изменилась под туннелем: адаптер отключился");
    let mut soft_env_on_hard = with("/id", json!("bad-1"));
    soft_env_on_hard["provenance"]["route"] = json!("soft-env");
    json!({
        "connectionHistory": [old, with("/id", json!("old-2")), soft_env_on_hard,
                              with("/outcome", json!({"kind": "unknown-kind", "headline": "x"}))],
        "rejectedConnectionHistory": [{"secret": "x"}, null]
    })
}

/// storage B21 / §6.6: valid old rows are imported before the current ones; damaged rows and the
/// old app's rejected rows are counted, not carried over; a re-run adds nothing.
#[test]
fn legacy_import() {
    let root = TempDir::new("history");
    let history = History::open(&root.0);
    let current = history.add(new_entry(OutcomeKind::UserStop)).unwrap();
    let report = history.import_legacy(&legacy_store()).unwrap();
    assert_eq!(
        report,
        LegacyImport {
            imported: 2,
            dropped: 4
        }
    );
    let warning = report.warning().unwrap();
    assert_eq!(
        text(&warning, Lang::Ru),
        "4 записи истории подключений из старой версии повреждены и не перенесены"
    );
    let rows = history.list();
    assert_eq!(ids(&rows), ["old-1", "old-2", current.id.as_str()]);
    let old = &rows[0];
    assert_eq!(old.provenance.map(|p| p.source), Some(Source::Ui));
    let outcome = old.outcome.as_ref().unwrap();
    assert_eq!(
        text(&outcome.headline, Lang::En),
        "Сеть изменилась под туннелем: адаптер отключился"
    );
    assert_eq!(
        outcome.evidence.network_transition,
        Some(crate::outcome::NetworkTransition::AdapterRemoved)
    );
    let again = history.import_legacy(&legacy_store()).unwrap();
    assert_eq!(
        again,
        LegacyImport {
            imported: 0,
            dropped: 4
        }
    );
    assert_eq!(history.list().len(), 3);
    assert_eq!(LegacyImport::default().warning(), None);
}

/// AT-00-010: unusable legacy roots import nothing.
#[test]
fn legacy_invalid_roots() {
    for root in [
        Value::Null,
        json!([]),
        json!("secret-value"),
        json!({"connectionHistory": {}}),
        json!({}),
    ] {
        let (doc, dropped) = ConnectionHistory::from_legacy(&root);
        assert!(doc.entries.is_empty(), "{root}");
        assert_eq!(dropped, 0, "{root}");
    }
}

/// The ring applies to imports: the newest rows win and only surviving old rows are counted.
#[test]
fn legacy_import_respects_the_ring() {
    let rows: Vec<Value> = (0..MAX_ENTRIES + 5)
        .map(|n| with("/id", json!(format!("old-{n}"))))
        .collect();
    let legacy = json!({ "connectionHistory": rows });
    let (doc, dropped) = ConnectionHistory::from_legacy(&legacy);
    assert_eq!((doc.entries.len(), dropped), (MAX_ENTRIES, 0));
    assert_eq!(doc.entries.front().map(|e| e.id.as_str()), Some("old-5"));
    let root = TempDir::new("history");
    let history = History::open(&root.0);
    for _ in 0..10 {
        history.add(new_entry(OutcomeKind::UserStop)).unwrap();
    }
    let report = history.import_legacy(&legacy).unwrap();
    assert_eq!(report.imported, MAX_ENTRIES - 10);
    let list = history.list();
    assert_eq!(list.len(), MAX_ENTRIES);
    assert_eq!(list[0].id, "old-15");
}

/// Every message this package produces has a template in both languages, fully interpolated.
#[test]
fn every_message_has_both_translations() {
    use crate::outcome::{NetworkTransition as T, headline};
    use vpnte_base::types::OutboundFault as F;
    let mut variants = vec![Evidence::default()];
    for fault in [
        F::RealityKeyMismatch,
        F::TlsHandshakeFailed,
        F::UpstreamUnreachable,
    ] {
        variants.push(Evidence {
            outbound_fault: Some(fault),
            ..Evidence::default()
        });
    }
    for (code, restarts) in [
        (Some(-1), None),
        (None, Some(1)),
        (Some(3), Some(2)),
        (Some(0), Some(5)),
    ] {
        variants.push(Evidence {
            singbox_exit_code: code,
            auto_restart_attempts: restarts,
            ..Evidence::default()
        });
    }
    for transition in [
        T::AdapterRemoved,
        T::AdapterAdded,
        T::AddressChanged,
        T::Text("x".into()),
    ] {
        variants.push(Evidence {
            network_transition: Some(transition),
            ..Evidence::default()
        });
    }
    variants.push(Evidence {
        hint: Some(verbatim("порт занят")),
        ..Evidence::default()
    });
    let mut messages: Vec<Msg> = OutcomeKind::ALL
        .iter()
        .flat_map(|&kind| variants.iter().map(move |ev| headline(kind, ev)))
        .collect();
    messages.push(Msg::new("tunnel.history.invalidEntry"));
    for dropped in [1, 2, 5, 21] {
        messages.extend(
            LegacyImport {
                imported: 0,
                dropped,
            }
            .warning(),
        );
    }
    for msg in &messages {
        for lang in [Lang::Ru, Lang::En] {
            let line = text(msg, lang);
            assert!(
                !line.contains("{{") && line.len() > 5,
                "{msg:?} {lang:?}: {line}"
            );
        }
    }
    assert_eq!(
        text(
            &LegacyImport {
                imported: 0,
                dropped: 1
            }
            .warning()
            .unwrap(),
            Lang::En
        ),
        "1 connection history record from the previous version was damaged and not carried over"
    );
}

/// Engine output is stored in plain JSON: share links, UUIDs and keys in it are masked, on new
/// rows and on imported ones (fake values only).
#[test]
fn engine_output_is_masked() {
    use crate::outcome::{EndSignals, EngineExit, unexpected_end};
    let tail = "ERROR outbound vless://00000000-0000-4000-8000-000000000000@203.0.113.1:443 \
                user 123e4567-e89b-42d3-a456-426614174000 rejected";
    let signals = EndSignals {
        engine_exit: Some(EngineExit {
            stderr_tail: Some(tail.into()),
            ..EngineExit::default()
        }),
        ..EndSignals::default()
    };
    let o = unexpected_end(&signals, Evidence::default());
    let stored = o.evidence.singbox_stderr_tail.unwrap();
    assert!(
        !stored.contains("00000000-0000-4000") && !stored.contains("123e4567"),
        "{stored}"
    );
    assert!(
        stored.contains("<redacted-vpn-uri>") && stored.contains("<redacted-uuid>"),
        "{stored}"
    );
    let mut old = base_row();
    old["outcome"] = json!({"kind": "singbox-crash", "headline": "x",
                            "evidence": {"singboxStderrTail": tail, "egressCountry": ""}});
    let (doc, dropped) = ConnectionHistory::from_legacy(&json!({ "connectionHistory": [old] }));
    assert_eq!(dropped, 0);
    let evidence = &doc.entries[0].outcome.as_ref().unwrap().evidence;
    assert!(
        evidence
            .singbox_stderr_tail
            .as_deref()
            .is_some_and(|t| !t.contains("123e4567"))
    );
    assert_eq!(evidence.egress_country, None);
}

/// AT-00-005 (§7.11): provenance is kept per source × owner, in the file and in the CSV columns.
#[test]
fn provenance_per_source_and_owner() {
    let owners = [
        None,
        Some(Owner::AdaptiveRetry),
        Some(Owner::Autopilot),
        Some(Owner::Rotation),
        Some(Owner::Schedule),
        Some(Owner::Manual),
        Some(Owner::Recovery),
    ];
    let sources = [
        Source::Ui,
        Source::Tray,
        Source::Lifecycle,
        Source::Runtime,
        Source::Unknown,
    ];
    for source in sources {
        for owner in owners {
            let mut new = new_entry(OutcomeKind::UserStop);
            new.source = source;
            new.owner = owner;
            let entry = Entry::from_new(new).unwrap();
            let back = read_row(serde_json::to_value(&entry).unwrap()).unwrap();
            assert_eq!(back, entry);
            let csv = to_csv([&entry], Lang::En);
            let line = csv.split('\n').nth(1).unwrap();
            let cells: Vec<&str> = line.split(',').collect();
            assert_eq!(cells[13], source_str(source));
            assert_eq!(cells[14], owner_str(owner));
        }
    }
    // The Electron app called the window "ipc": read as Ui, written back as "ui".
    let entry = read_row(with("/provenance/source", json!("ipc"))).unwrap();
    let written = serde_json::to_value(&entry).unwrap();
    assert_eq!(written["provenance"]["source"], "ui");
    assert_eq!(written["provenance"]["owner"], "unknown");
}
