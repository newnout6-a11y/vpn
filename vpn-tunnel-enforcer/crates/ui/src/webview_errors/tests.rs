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
/// control characters), cut to a few hundred characters between words (a longer word goes
/// whole); the stack keeps its top frames; an unknown kind is an `error`; fields the page did not
/// send stay empty and others are ignored; the page's own script addresses are written short
/// (not URLs the app log would redact).
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
    assert_eq!(report.message, "TypeError: bad [31m value…");
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

/// p-tails-a, tailsa-a3: the page script reports only an `Error`'s message and stack, or a
/// rejected value's type name, a string included: page data (a server, a typed link, a host
/// name) never leaves the page, as JSON or as the string itself. Its own cut drops the word it
/// would split (tailsa-a1), and Chromium's "ResizeObserver loop" notice stays out (tailsa-b2).
#[test]
fn the_page_script_never_serialises_a_rejected_value() {
    assert!(!SCRIPT.contains("JSON.stringify"));
    assert!(!SCRIPT.contains("typeof r"), "a string reason is page data");
    let message = "const message = error ? r.message : Object.prototype.toString.call(r);";
    assert!(SCRIPT.contains(message));
    assert!(SCRIPT.contains(r"s.slice(0, n).replace(/\S*$/, '')"));
    assert!(SCRIPT.contains("if (/^ResizeObserver loop/.test(String(e.message))) return;"));
    assert!(SCRIPT.contains("'unhandledrejection'"));
    assert!(SCRIPT.contains("addEventListener('error'"));
}

/// tailsa-a1: a secret that the cut would split is never half logged: the word it falls in goes
/// whole, so the log's redaction sees every secret whole or not at all. A cut that falls between
/// two words keeps the last one.
#[test]
fn a_word_the_cut_would_split_goes_whole() {
    let key = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg";
    assert_eq!(key.len(), 43, "a base64 key");
    for start in [258, 280, 299] {
        // Single spaces only: the line keeps every position.
        let gap = start - "TypeError: ".len();
        let filler = match gap % 2 {
            0 => "x ".repeat(gap / 2),
            _ => format!("xx {}", "x ".repeat((gap - 3) / 2)),
        };
        let text = format!("TypeError: {filler}{key} tail");
        assert_eq!(text.find(key), Some(start), "the key starts at {start}");
        let line = one_line(&text);
        assert!(line.ends_with('…'), "{line}");
        assert!(line.chars().count() <= TEXT_MAX + 1);
        assert!(!line.contains(&key[..8]), "start {start}: {line}");
    }
    let words = "word ".repeat(80);
    let line = one_line(&words);
    assert_eq!(line.chars().count(), TEXT_MAX, "{line}");
    assert!(line.ends_with("word…"));
    let one_word = "y".repeat(400);
    assert_eq!(one_line(&one_word), "…");
}
