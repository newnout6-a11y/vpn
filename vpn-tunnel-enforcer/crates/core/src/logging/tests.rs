//! Logging tests: storage spec §7.8 vectors (rotation, topology, numbers, metadata, subscription
//! error, truncation) plus the §3.13 behaviours kept (blocked rotation, separator, clear, tail).
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tracing_subscriber::layer::SubscriberExt as _;

use super::lane::Lane;
use super::layer::{JsonLayer, Shared};
use super::*;
use crate::test_support::TempDir;

/// The app log's lines, parsed.
fn lines(tmp: &TempDir) -> Vec<LogLine> {
    tmp.read("app.log")
        .lines()
        .map(|l| serde_json::from_str(l).expect("a JSON line"))
        .collect()
}

/// The app log pipeline (layer → lane → rotating file) on a scoped dispatcher.
struct Harness {
    shared: Arc<Shared>,
    lane: Arc<Lane>,
    dispatch: tracing::Dispatch,
}

impl Harness {
    fn new(dir: &Path, max_bytes: u64) -> Self {
        let sink = RotatingFile::open(dir, APP_STEM, max_bytes, 0).expect("sink");
        let lane = Arc::new(Lane::start(sink).expect("lane"));
        let shared = Arc::new(Shared::new(false));
        let layer = JsonLayer::new(Arc::clone(&shared), Arc::clone(&lane), false);
        let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(layer));
        Self {
            shared,
            lane,
            dispatch,
        }
    }

    /// Runs `f` with this pipeline as the thread's subscriber, then waits for the disk.
    fn run(&self, f: impl FnOnce()) {
        tracing::dispatcher::with_default(&self.dispatch, f);
        assert!(self.lane.flush(Duration::from_secs(30)), "lane flushed");
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.lane.stop();
    }
}

/// AT-01-011 (§7.8 rotation): 2,500 events with a 3,500-char detail rotate once into `app.1.log`.
#[test]
fn rotates_into_one_previous_generation() {
    let tmp = TempDir::new("rotate");
    let h = Harness::new(tmp.path(), APP_LOG_MAX_BYTES);
    let detail = "word ".repeat(700);
    h.run(|| {
        for i in 0..2500 {
            tracing::info!(detail = %detail, i, "rotation event");
        }
    });
    let current = fs::metadata(tmp.path().join("app.log")).map_or(0, |m| m.len());
    let previous = fs::metadata(tmp.path().join("app.1.log")).map_or(0, |m| m.len());
    assert!(current > 0 && current < APP_LOG_MAX_BYTES, "{current}");
    assert!(previous > 0 && previous <= 6 * 1024 * 1024, "{previous}");
    assert!(
        previous <= APP_LOG_MAX_BYTES,
        "a generation never exceeds the cap"
    );

    let small = TempDir::new("no-rotate");
    let h = Harness::new(small.path(), APP_LOG_MAX_BYTES);
    h.run(|| (0..20).for_each(|i| tracing::info!(i, "small event")));
    assert_eq!(lines(&small).len(), 20);
    assert!(!small.path().join("app.1.log").exists());
}

/// §3.13: a rotation blocked by a directory at the target is retried by the next write.
#[test]
fn blocked_rotation_is_retried() {
    let tmp = TempDir::new("blocked");
    let file = RotatingFile::open(tmp.path(), "app", 1024, 0).expect("open");
    let obstacle = tmp.path().join("app.1.log");
    fs::create_dir(&obstacle).expect("obstacle");
    for i in 0..30 {
        file.write_line(&format!("line {i:03} {}", "x".repeat(80)))
            .expect("write despite the blocked rotation");
    }
    assert!(
        tmp.read("app.log").len() > 1024,
        "kept writing past the cap"
    );
    fs::remove_dir(&obstacle).expect("remove obstacle");
    file.write_line("after the obstacle").expect("write");
    assert!(obstacle.is_file(), "rotated on the next single write");
    assert_eq!(tmp.read("app.log"), "after the obstacle\n");
}

/// AT-01-002 (§7.8 topology): public IPs become pseudonyms; numbers and adapter aliases stay.
#[test]
fn pseudonymizes_topology_and_keeps_numbers() {
    let tmp = TempDir::new("topology");
    let h = Harness::new(tmp.path(), APP_LOG_MAX_BYTES);
    h.run(|| {
        tracing::info!(
            publicIpViaProxy = "203.0.113.10",
            adapterAlias = "Ethernet 7",
            routeCount = 2,
            keptCounter = 3,
            "adapter 192.0.2.44 saw mac aa:bb:cc:dd:ee:ff"
        );
        tracing::info!(
            port = 10808,
            interfaceMetric = 5,
            routeCount = 14,
            timeoutMs = 5000,
            ifindex = 42,
            "metrics report"
        );
    });
    let raw = tmp.read("app.log");
    assert!(
        !raw.contains("192.0.2.44") && !raw.contains("203.0.113.10"),
        "{raw}"
    );
    assert!(
        raw.contains("ip_") && raw.contains("<redacted-mac>"),
        "{raw}"
    );
    // Deliberately not ported: the old topology key rule that blanked adapter aliases (§5).
    assert!(raw.contains(r#""adapterAlias":"Ethernet 7""#), "{raw}");
    for kept in [
        r#""routeCount":2"#,
        r#""keptCounter":3"#,
        r#""port":10808"#,
        r#""interfaceMetric":5"#,
        r#""routeCount":14"#,
        r#""timeoutMs":5000"#,
        r#""ifindex":42"#,
    ] {
        assert!(raw.contains(kept), "{kept} missing in {raw}");
    }
}

/// AT-08-001: safe failure stage/code metadata stays readable.
#[test]
fn keeps_safe_failure_metadata() {
    let tmp = TempDir::new("metadata");
    let h = Harness::new(tmp.path(), APP_LOG_MAX_BYTES);
    h.run(|| {
        tracing::warn!(
            schemaVersion = 1,
            assessment = "UPSTREAM_TCP_OK_ENGINE_EGRESS_UNCONFIRMED",
            stage = "tls",
            code = "ETIMEDOUT",
            elapsedMs = 3000,
            target = "cloudflare-ip-trace",
            "tunnel failure path diagnostics"
        );
    });
    let raw = tmp.read("app.log");
    for kept in [
        r#""stage":"tls""#,
        r#""code":"ETIMEDOUT""#,
        r#""target":"cloudflare-ip-trace""#,
        "UPSTREAM_TCP_OK_ENGINE_EGRESS_UNCONFIRMED",
    ] {
        assert!(raw.contains(kept), "{kept} missing in {raw}");
    }
}

/// AT-00-004/005: a subscription failure keeps its cause and location, loses its secrets.
#[test]
fn error_chain_keeps_cause_and_location() {
    let tmp = TempDir::new("subscription");
    let h = Harness::new(tmp.path(), APP_LOG_MAX_BYTES);
    let err = std::io::Error::other(concat!(
        "HTTP 403; TLS verification failed; Could not resolve host: private.example.test ",
        "token=PRIVATE-TOKEN https://sub.example.test/PRIVATE-URL\n",
        "    at refreshGroupUnlocked (serverGroups.ts:463:5)\n",
        "    at C:/Users/PrivateUser/vpn/main.js:20:4",
    ));
    h.run(|| {
        tracing::warn!(error = &err as &dyn std::error::Error, "refresh diagnostic");
    });
    let raw = tmp.read("app.log");
    for kept in [
        "HTTP 403",
        "TLS verification failed",
        "Could not resolve host:",
        "serverGroups.ts:463:5",
    ] {
        assert!(raw.contains(kept), "{kept} missing in {raw}");
    }
    for gone in [
        "PRIVATE-TOKEN",
        "PRIVATE-URL",
        "private.example.test",
        "PrivateUser",
    ] {
        assert!(!raw.contains(gone), "{gone} leaked in {raw}");
    }
}

/// §7.8: an 8,000-char message and field are cut to exactly 4000 chars + `...<truncated>`.
#[test]
fn cuts_long_values() {
    let tmp = TempDir::new("truncate");
    let h = Harness::new(tmp.path(), APP_LOG_MAX_BYTES);
    let long = "e".repeat(8000);
    h.run(|| tracing::error!(detail = %long, "{long}"));
    let line = lines(&tmp).pop().expect("one line");
    let detail = line.fields["detail"].as_str().unwrap_or_default();
    for value in [detail, line.msg.as_str()] {
        assert_eq!(value.chars().count(), 4000 + "...<truncated>".len());
        assert!(value.ends_with("e...<truncated>"));
    }
}

/// §6.5: secret field names are masked whole, id fields stay verbatim, `corr` is top-level.
#[test]
fn masks_secret_fields_and_keeps_ids() {
    let tmp = TempDir::new("fields");
    let h = Harness::new(tmp.path(), APP_LOG_MAX_BYTES);
    let uuid = "0190f1d2-3c4b-7a8e-9f00-0123456789ab";
    h.run(|| {
        tracing::info!(
            password = "hunter2-FAKE",
            api_key = 5,
            ok = true,
            profile = uuid,
            corr = "op_0123456789abcdef0123456789abcdef",
            note = format!("user {uuid}"),
            "profile saved"
        );
    });
    let raw = tmp.read("app.log");
    assert!(!raw.contains("hunter2"), "{raw}");
    let line = lines(&tmp).pop().expect("one line");
    assert_eq!(line.level, "INFO");
    assert!(line.target.starts_with("vpnte_core::logging"));
    assert_eq!(line.msg, "profile saved");
    assert_eq!(line.fields["password"], "<redacted>");
    assert_eq!(line.fields["api_key"], "<redacted>");
    assert_eq!(line.fields["ok"], true);
    assert_eq!(line.fields["profile"], uuid);
    assert_eq!(line.fields["note"], "user <redacted-uuid>");
    assert_eq!(
        line.corr.as_deref(),
        Some("op_0123456789abcdef0123456789abcdef")
    );
    assert!(!line.fields.contains_key("corr"));
    assert!(line.ts.ends_with('Z') && line.ts.len() == "2026-11-11T08:00:00.000Z".len());
}

/// Span fields (and a late `record`) reach the events inside; the event's own fields win.
#[test]
fn events_inherit_span_fields() {
    let tmp = TempDir::new("spans");
    let h = Harness::new(tmp.path(), APP_LOG_MAX_BYTES);
    h.run(|| {
        let span = tracing::info_span!(
            "connect",
            corr = "op_00000000000000000000000000000001",
            profile = "p-1",
            stage = tracing::field::Empty
        );
        span.record("stage", "tls");
        span.in_scope(|| {
            tracing::info!("inside");
            tracing::info!(stage = "dial", "own field wins");
        });
    });
    let lines = lines(&tmp);
    assert_eq!(lines.len(), 2);
    for line in &lines {
        assert_eq!(
            line.corr.as_deref(),
            Some("op_00000000000000000000000000000001")
        );
        assert_eq!(line.fields["profile"], "p-1");
    }
    assert_eq!(lines[0].fields["stage"], "tls");
    assert_eq!(lines[1].fields["stage"], "dial");
}

fn emit_debug() {
    tracing::debug!("debug detail");
}

/// §6.5: info by default, debug at runtime; libraries only from warn.
#[test]
fn debug_toggle_and_library_filter() {
    let tmp = TempDir::new("levels");
    let h = Harness::new(tmp.path(), APP_LOG_MAX_BYTES);
    h.run(|| {
        emit_debug();
        tracing::trace!("never written");
        tracing::info!(target: "hyper::client::pool", "library chatter");
        tracing::warn!(target: "hyper::client::pool", "library warning");
    });
    h.shared.set_debug(true);
    h.run(emit_debug);
    h.shared.set_debug(false);
    h.run(emit_debug);
    let msgs: Vec<String> = lines(&tmp).into_iter().map(|l| l.msg).collect();
    assert_eq!(msgs, ["library warning", "debug detail"]);
}

/// The last warnings and errors stay in memory for the diagnostics report.
#[test]
fn remembers_recent_problems() {
    let tmp = TempDir::new("problems");
    let h = Harness::new(tmp.path(), APP_LOG_MAX_BYTES);
    h.run(|| {
        tracing::info!("fine");
        tracing::warn!("slow handshake to 203.0.113.9");
        for i in 0..250 {
            tracing::error!(i, "failure {i}");
        }
    });
    let recent = h.shared.recent();
    assert_eq!(recent.len(), 200);
    assert_eq!(recent[0].msg, "failure 50");
    assert_eq!(recent[199].level, tracing::Level::ERROR);
    assert!(
        recent
            .iter()
            .all(|p| p.at > 0 && p.target.starts_with("vpnte_core"))
    );
}

/// §2.9 log viewer: a tail starts at a whole line; a missing file is reported, not an error.
#[test]
fn tail_returns_whole_lines() {
    let tmp = TempDir::new("tail");
    let file = RotatingFile::engine(tmp.path(), "xray").expect("open");
    for i in 0..100 {
        file.write_line(&format!("line {i:03}")).expect("write");
    }
    let snap = tail(tmp.path(), &LogFile::engine("xray"), 50).expect("tail");
    assert!(snap.exists && snap.truncated);
    assert_eq!(snap.size, 900);
    assert_eq!(
        snap.content,
        "line 095\nline 096\nline 097\nline 098\nline 099\n"
    );
    let whole = tail(tmp.path(), &LogFile::engine("xray"), TAIL_MAX_BYTES).expect("tail");
    assert!(!whole.truncated && whole.content.starts_with("line 000\n"));
    let missing = tail(tmp.path(), &LogFile::engine("sing-box").previous(), 10).expect("tail");
    assert_eq!(missing.name, "sing-box.1.log");
    assert!(!missing.exists && missing.content.is_empty());
    let bad = tail(tmp.path(), &LogFile::engine("../app"), 10);
    assert!(bad.is_err_and(|e| e.kind() == io::ErrorKind::InvalidInput));
}

/// §2.9/§3.13 clear: current logs truncated (live writers keep working), previous ones deleted.
#[test]
fn clear_truncates_and_deletes() {
    let tmp = TempDir::new("clear");
    fs::write(tmp.path().join("app.log"), "old app\n").expect("seed");
    fs::write(tmp.path().join("app.1.log"), "older app\n").expect("seed");
    fs::write(tmp.path().join("xray.log"), "old xray\n").expect("seed");
    fs::write(tmp.path().join("notes.txt"), "not a log").expect("seed");
    let singbox = RotatingFile::engine(tmp.path(), "sing-box").expect("open");
    singbox.write_line("before clear").expect("write");
    fs::write(tmp.path().join("sing-box.1.log"), "previous run\n").expect("seed");

    let report = clear(tmp.path());
    assert!(report.errors.is_empty(), "{report:?}");
    assert_eq!(
        report.cleared,
        [
            "app-log",
            "app-previous-log",
            "sing-box-log",
            "sing-box-previous-log",
            "xray-log"
        ]
    );
    assert_eq!(report.absent, ["xray-previous-log"]);
    assert_eq!(tmp.read("app.log"), "");
    assert!(!tmp.path().join("app.1.log").exists() && !tmp.path().join("sing-box.1.log").exists());
    assert_eq!(tmp.read("notes.txt"), "not a log");

    singbox.write_line("after clear").expect("write");
    assert_eq!(tmp.read("sing-box.log"), "after clear\n");
    assert_eq!(singbox.tail(), ["before clear", "after clear"]);
    let names: Vec<String> = list(tmp.path())
        .expect("list")
        .iter()
        .map(LogFile::file_name)
        .collect();
    assert_eq!(names, ["app.log", "sing-box.log", "xray.log"]);

    let empty = TempDir::new("clear-empty");
    let report = clear(&empty.path().join("missing"));
    assert_eq!(report.absent, ["app-log", "app-previous-log"]);
}

/// §6.5 engine pipes: lines are redacted on the way to the file and the in-memory tail.
#[test]
fn engine_log_redacts_and_keeps_a_tail() {
    let tmp = TempDir::new("engine");
    let log = RotatingFile::engine(tmp.path(), "sing-box").expect("open");
    log.write_line("inbound connection to 142.250.74.46:443\r\n")
        .expect("write");
    log.write_line("router: vless://0190f1d2-3c4b-7a8e-9f00-0123456789ab@node.test:443 ok")
        .expect("write");
    let raw = tmp.read("sing-box.log");
    assert!(
        !raw.contains("142.250.74.46") && !raw.contains("0190f1d2"),
        "{raw}"
    );
    assert!(raw.contains("inbound connection to ip_") && raw.contains("<redacted-vpn-uri> ok"));
    assert!(!raw.contains('\r'));
    for i in 0..70 {
        log.write_line(&format!("event {i}")).expect("write");
    }
    let tail = log.tail();
    assert_eq!(tail.len(), ENGINE_TAIL_LINES);
    assert_eq!(tail.first().map(String::as_str), Some("event 6"));
    assert_eq!(tail.last().map(String::as_str), Some("event 69"));

    let again = RotatingFile::engine(tmp.path(), "sing-box").expect("reopen");
    again.write_line("same writer").expect("write");
    assert_eq!(log.tail().last().map(String::as_str), Some("same writer"));
    assert_eq!(again.path(), log.path());
    assert!(
        RotatingFile::engine(tmp.path(), "Sing Box").is_err(),
        "stem is [a-z0-9-]+"
    );
}

/// §3.13: an old record without a trailing newline does not merge with the next one.
#[test]
fn separates_from_a_cut_record() {
    let tmp = TempDir::new("separator");
    fs::write(tmp.path().join("xray.log"), "cut short").expect("seed");
    let log = RotatingFile::engine(tmp.path(), "xray").expect("open");
    log.write_line("next").expect("write");
    assert_eq!(tmp.read("xray.log"), "cut short\nnext\n");
}

/// Opening a live writer again follows a file moved away meanwhile (engine session start).
#[test]
fn reopening_a_live_writer_follows_a_moved_file() {
    let tmp = TempDir::new("moved");
    let first = RotatingFile::engine(tmp.path(), "sing-box").expect("open");
    first.write_line("last session").expect("write");
    fs::rename(
        tmp.path().join("sing-box.log"),
        tmp.path().join("sing-box.1.log"),
    )
    .expect("the engine moves the last session's log");
    let next = RotatingFile::engine(tmp.path(), "sing-box").expect("reopen");
    next.write_line("new session").expect("write");
    assert_eq!(tmp.read("sing-box.log"), "new session\n");
    assert_eq!(tmp.read("sing-box.1.log"), "last session\n");
}

/// §3.13: a deleted logs directory is recreated within a second.
#[test]
fn recreates_a_deleted_directory() {
    let tmp = TempDir::new("recreate");
    let dir = tmp.path().join("logs");
    let log = RotatingFile::engine(&dir, "xray").expect("open");
    log.write_line("first").expect("write");
    fs::remove_dir_all(&dir).expect("user deletes the folder");
    std::thread::sleep(Duration::from_millis(1100));
    log.write_line("second").expect("write");
    assert_eq!(
        fs::read_to_string(dir.join("xray.log")).unwrap_or_default(),
        "second\n"
    );
}

/// The global setup: one subscriber per process, runtime debug toggle, logged panics.
#[test]
fn init_installs_the_global_log() {
    let tmp = TempDir::new("init");
    let guard = init(tmp.path(), false).expect("first init");
    tracing::info!(note = "token=abc", "global hello");
    tracing::debug!("global debug off");
    set_debug(true);
    tracing::debug!("global debug on");
    set_debug(false);
    let panicked = std::thread::spawn(|| panic!("boom with password=hunter2-FAKE")).join();
    assert!(panicked.is_err());
    let raw = tmp.read("app.log");
    assert!(
        raw.contains(r#""msg":"panic""#) && raw.contains("boom with"),
        "the hook waits for the disk: {raw}"
    );
    tracing::warn!("global warning");
    flush();
    let raw = tmp.read("app.log");
    assert!(raw.contains("global hello") && raw.contains("token=<redacted-credential>"));
    assert!(raw.contains("global debug on") && !raw.contains("global debug off"));
    assert!(!raw.contains("hunter2"), "{raw}");
    assert!(recent_problems().iter().any(|p| p.msg == "global warning"));
    let again = init(tmp.path(), true);
    assert!(again.is_err_and(|e| e.kind == ErrorKind::Conflict));
    drop(guard);
    let snap = tail(tmp.path(), &LogFile::app(), TAIL_MAX_BYTES).expect("tail");
    assert!(
        snap.content
            .lines()
            .all(|l| serde_json::from_str::<LogLine>(l).is_ok())
    );
}

/// The `core-log` fragment holds exactly the file label keys.
#[test]
fn locale_fragment_holds_the_label_keys() {
    let labels: std::collections::BTreeSet<String> = [
        LogFile::app(),
        LogFile::app().previous(),
        LogFile::engine("xray"),
        LogFile::engine("x").previous(),
    ]
    .iter()
    .map(|file| file.label().key.into_owned())
    .collect();
    assert_eq!(crate::test_support::package_keys("core-log"), labels);
}

/// A full queue is reported in the file instead of vanishing silently; a stopped lane is inert.
#[test]
fn overflow_record_and_stopped_lane() {
    let line: LogLine = serde_json::from_slice(&super::layer::overflow_line(3)).expect("JSON");
    assert_eq!(
        (line.level.as_str(), line.fields["dropped"].as_u64()),
        ("WARN", Some(3))
    );
    let tmp = TempDir::new("stop");
    let h = Harness::new(tmp.path(), APP_LOG_MAX_BYTES);
    h.run(|| tracing::info!("before stop"));
    h.lane.stop();
    h.lane.stop();
    tracing::dispatcher::with_default(&h.dispatch, || tracing::info!("after stop"));
    assert!(!h.lane.flush(Duration::from_millis(100)));
    assert_eq!(lines(&tmp).len(), 1);
}
