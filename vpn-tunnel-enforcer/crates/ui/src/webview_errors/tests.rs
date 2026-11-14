use super::*;

/// p-tails-a: five reports a minute reach the log, counted over a sliding minute; the ones
/// turned away are counted into the next logged line, which then starts a new count.
#[test]
fn five_a_minute_reach_the_log_and_the_rest_are_counted() {
    let start = Instant::now();
    let at = |secs: u64| start + Duration::from_secs(secs);
    let mut limit = Limit::default();
    for second in 0..5 {
        assert_eq!(limit.admit(at(second)), Some(0), "second {second}");
    }
    assert_eq!(limit.admit(at(10)), None);
    assert_eq!(limit.admit(at(59)), None);
    // the first one is a minute old: one place frees, the two turned away are reported with it
    assert_eq!(limit.admit(at(60)), Some(2));
    assert_eq!(limit.admit(at(60)), None);
    assert_eq!(limit.admit(at(61)), Some(1));
    assert_eq!(limit.admit(at(200)), Some(0));
}

/// p-tails-a: page text is untrusted: every field becomes one line (no forged log lines, no
/// control characters), cut to a few hundred characters; the stack keeps its top frames; an
/// unknown kind is an `error`; fields the page did not send stay empty and others are ignored;
/// the page's own script addresses are written short (not URLs the app log would redact).
#[test]
fn a_report_is_cleaned_to_bounded_lines() {
    let long = "x".repeat(5000);
    let stack = (0..20)
        .map(|n| format!("    at f{n} (http://dioxus.index.html/assets/js/a.js:{n}:1)"))
        .collect::<Vec<_>>()
        .join("\n");
    let value = serde_json::json!({
        "kind": "anything",
        "message": format!("TypeError:\n\tbad\u{1b}[31m value\r\n{long}"),
        "source": "http://app.localhost/assets/js/a.js",
        "line": 12,
        "col": 7,
        "stack": stack,
        "data": {"password": "fake-secret"},
    });
    let report = serde_json::from_value::<Report>(value)
        .expect("report")
        .clean();
    assert_eq!(report.kind, "error");
    assert!(report.message.starts_with("TypeError: bad [31m value xxx"));
    assert_eq!(report.message.chars().count(), TEXT_MAX + 1);
    assert!(report.message.ends_with('…'));
    assert_eq!((report.line, report.col), (12, 7));
    let frames: Vec<&str> = report.stack.split(" | ").collect();
    assert_eq!(frames.len(), FRAMES_MAX);
    // the page's own script addresses are written short, so the app log keeps line and column
    assert_eq!(frames[0], "at f0 (page:/assets/js/a.js:0:1)");
    assert_eq!(report.source, "app:/assets/js/a.js");
    for field in [&report.kind, &report.message, &report.source, &report.stack] {
        assert!(!field.chars().any(char::is_control), "{field:?}");
        assert!(!field.contains("fake-secret"));
    }
    let rejection = serde_json::from_value::<Report>(serde_json::json!({
        "kind": "rejection",
        "message": "[object Object]",
    }))
    .expect("rejection")
    .clean();
    assert_eq!(rejection.kind, "rejection");
    assert_eq!(
        (rejection.source.as_str(), rejection.stack.as_str()),
        ("", "")
    );
    assert!(serde_json::from_value::<Report>(serde_json::json!("text")).is_err());
}

/// p-tails-a: the page script reports only an `Error`'s message and stack, or a rejected
/// value's type name: page data (a server, a typed link) never leaves the page as JSON.
#[test]
fn the_page_script_never_serialises_a_rejected_value() {
    assert!(!SCRIPT.contains("JSON.stringify"));
    assert!(SCRIPT.contains("Object.prototype.toString.call(r)"));
    assert!(SCRIPT.contains("'unhandledrejection'"));
    assert!(SCRIPT.contains("addEventListener('error'"));
}
