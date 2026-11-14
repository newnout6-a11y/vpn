//! p-tails-a: the page's script errors as the app log writes them. `ScriptErrors` (the root's
//! `use_script_errors` per page) emits the event; `vpnte_core::logging::event_line` is the app
//! log's own line builder, so these lines are what app.log gets: redacted, a few a minute.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};
use vpnte_core::logging::{LogLine, event_line};
use vpnte_ui::webview_errors::{PER_MINUTE, ScriptErrors};

/// Every event, as its app.log line.
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<LogLine>>>);

impl Subscriber for Lines {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        self.0.lock().expect("lines").push(event_line(event));
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

/// The lines the page's `reports` leave in the app log, each taken at its offset in seconds.
fn logged(reports: &[(u64, Value)]) -> Vec<LogLine> {
    let lines = Lines::default();
    let start = Instant::now();
    tracing::subscriber::with_default(lines.clone(), || {
        let mut errors = ScriptErrors::default();
        for (second, report) in reports {
            errors.take(report.clone(), start + Duration::from_secs(*second));
        }
    });
    lines.0.lock().expect("lines").clone()
}

/// A share link, a subscription address with its token and the user's profile path in the page's
/// text do not reach app.log; the app's own script address keeps its line and column.
#[test]
fn a_page_script_error_reaches_the_app_log_redacted() {
    let link = "vless://11111111-2222-3333-4444-555555555555@nl.example.com:443?security=reality";
    let report = json!({
        "kind": "rejection",
        "message": format!("TypeError: bad link {link} from https://sub.example.com/s/feedcafe"),
        "source": "http://app.localhost/assets/js/servers.js",
        "line": 12,
        "col": 7,
        "stack": "at parse (http://app.localhost/assets/js/servers.js:12:7)\n\
                  at go (token=deadbeef0123)\n\
                  at load (C:\\Users\\Ivan\\AppData\\Local\\x.js:1:1)",
    });
    let lines = logged(&[(0, report)]);
    let [line] = lines.as_slice() else {
        panic!("one line expected: {lines:?}")
    };
    // INFO: a page error is no problem the user could act on (review tailsa-b2).
    assert_eq!(line.level, "INFO");
    assert_eq!(line.msg, "page script error");
    let all = serde_json::to_string(&line.fields).expect("fields");
    for secret in [
        "11111111-2222",
        "nl.example.com",
        "feedcafe",
        "Ivan",
        "deadbeef0123",
    ] {
        assert!(!all.contains(secret), "{secret} in {all}");
    }
    let text = |name: &str| line.fields[name].as_str().unwrap_or_default().to_owned();
    assert!(text("error").starts_with("TypeError: bad link <redacted-vpn-uri>"));
    assert_eq!(text("kind"), "rejection");
    assert_eq!(text("source"), "app:/assets/js/servers.js");
    assert!(text("stack").starts_with("at parse (app:/assets/js/servers.js:12:7) | at go"));
    assert_eq!(
        (&line.fields["line"], &line.fields["col"]),
        (&json!(12), &json!(7))
    );
    assert_eq!(line.fields["suppressed"], json!(0));
}

/// A page stuck in an error loop: five lines a minute; the next line says how many it left out.
#[test]
fn an_error_loop_costs_five_lines_a_minute() {
    let report = json!({"kind": "error", "message": "ReferenceError: x is not defined"});
    let mut reports: Vec<(u64, Value)> = (0..20).map(|n| (n, report.clone())).collect();
    reports.push((61, json!("not a report")));
    reports.push((61, report.clone()));
    let lines = logged(&reports);
    assert_eq!(lines.len(), PER_MINUTE + 1);
    let suppressed: Vec<&Value> = lines.iter().map(|l| &l.fields["suppressed"]).collect();
    assert!(suppressed[..PER_MINUTE].iter().all(|n| **n == json!(0)));
    assert_eq!(suppressed[PER_MINUTE], &json!(20 - PER_MINUTE));
}
