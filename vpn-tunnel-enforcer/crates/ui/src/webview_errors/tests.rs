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

/// p-tails-a, tailsa-a3, fixr3-b1: the page script's text, for where Node is missing (the next
/// test runs it): only an `Error`'s message and stack, or the type name of any other thrown or
/// rejected value, a string included; never JSON of a value.
#[test]
fn the_page_script_never_serialises_a_value() {
    assert!(!SCRIPT.contains("JSON.stringify"));
    assert!(!SCRIPT.contains("typeof"), "a string is page data");
    for sent in [
        "message: error ? cut(e.message, 1000) : typeName(e.error),",
        "stack: cut(error ? e.error.stack : '', 4000)",
        "message: error ? cut(r.message, 1000) : typeName(r),",
        "stack: cut(error ? r.stack : '', 4000)",
    ] {
        assert!(SCRIPT.contains(sent), "{sent}");
    }
}

/// The page script with a stand-in window and dioxus channel: listeners kept by event type,
/// reports collected.
const PRELUDE: &str = r#"
const sent = [], on = {};
globalThis.window = { addEventListener: (type, f) => { on[type] = f; } };
globalThis.dioxus = { send: r => sent.push(r) };
(async () => {
"#;

/// What a page may throw or reject, as Chromium hands it to the listeners.
const EVENTS: &str = r#"
})();
const page = 'bad host nl.example.com';
on.error({ message: 'Uncaught ' + page, error: page, filename: 'http://dioxus.index.html/a.js', lineno: 3, colno: 4 });
on.error({ message: 'Uncaught [object Object]', error: { host: page } });
const thrown = new TypeError('x is not a function');
on.error({ message: 'Uncaught TypeError: x is not a function', error: thrown });
on.error({ message: 'ResizeObserver loop completed with undelivered notifications.', error: null });
on.unhandledrejection({ reason: page });
on.unhandledrejection({ reason: new Error('w'.repeat(995) + ' split' + 'y'.repeat(10)) });
process.stdout.write(JSON.stringify({ sent, stack: thrown.stack }));
"#;

/// Runs `script` in Node and returns what it wrote; `None` (said on stderr) where Node is not
/// installed.
fn node(script: &str) -> Option<String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let child = Command::new("node")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("node not found: the page script's run is skipped");
            return None;
        }
        started => started.expect("node started"),
    };
    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(script.as_bytes()).expect("script");
    drop(stdin);
    let out = child.wait_with_output().expect("node ran");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8(out.stdout).expect("utf-8"))
}

/// fixr3-b1, tailsa-a3, tailsa-a1, tailsa-b2: what the page script actually sends. A thrown or
/// rejected value that is not an `Error` (V8 writes a thrown string into the event's message)
/// leaves the page as its type name only, without a stack; an `Error` with its message and
/// stack, cut between words; Chromium's "ResizeObserver loop" notice is not sent.
#[test]
fn the_page_script_sends_no_page_data() {
    let Some(out) = node(&[PRELUDE, SCRIPT, EVENTS].concat()) else {
        return;
    };
    let out: serde_json::Value = serde_json::from_str(&out).expect("json");
    let sent = out["sent"].as_array().expect("reports");
    let all = serde_json::to_string(sent).expect("text");
    assert!(!all.contains("example.com"), "{all}");
    let fields = |n: usize| (sent[n]["kind"].clone(), sent[n]["message"].clone());
    let string = serde_json::json!("[object String]");
    assert_eq!(fields(0), ("error".into(), string.clone()));
    assert_eq!(
        (&sent[0]["stack"], &sent[0]["line"]),
        (&"".into(), &3.into())
    );
    assert_eq!(fields(1).1, "[object Object]");
    let error = "Uncaught TypeError: x is not a function";
    assert_eq!(fields(2).1, error);
    assert_eq!(sent[2]["stack"], out["stack"]);
    assert_eq!(fields(3), ("rejection".into(), string));
    assert_eq!(
        fields(4).1,
        format!("{} ", "w".repeat(995)),
        "the split word dropped"
    );
    assert_eq!(sent.len(), 5, "no ResizeObserver notice: {all}");
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

/// fixr3-a4: the log's redaction knows a quoted secret by its closing quote, so a quoted string
/// the line leaves open (our cut between its words, or the page's or V8's cut before) goes from
/// its opening quote: wherever the cut falls, a word of the value is logged only inside the
/// whole, closed value. Closed strings and an apostrophe inside a word stay.
#[test]
fn a_quoted_string_left_open_goes_whole() {
    let words = ["correct", "horse", "battery", "staple"];
    let value = words.join(" ");
    let mut opened = 0;
    for (open, close) in [("\"", "\""), ("'", "'"), ("\\\"", "\\\"")] {
        let whole = format!("{open}{value}{close}");
        for filler in 230..300 {
            let x = "x".repeat(filler);
            let text = format!("SyntaxError: {x} {open}password{close}:{whole} tail");
            let line = one_line(&text);
            assert!(line.chars().count() <= TEXT_MAX + 1, "{line}");
            let kept = words.iter().any(|w| line.contains(w));
            assert!(!kept || line.contains(&whole), "{line}");
            opened += usize::from(line.contains("password") && line.ends_with(":…"));
        }
    }
    assert!(opened > 0, "some cut fell inside the value");
    let left_open = "TypeError: \"password\":\"correct horse";
    assert_eq!(one_line(left_open), "TypeError: \"password\":…");
    assert_eq!(one_line("bad password='correct horse"), "bad password=…");
    for kept in [
        "TypeError: \"password\":\"correct horse\" at x",
        "TypeError: can't read 'x' of {\\\"a\\\":\\\"b c\\\"}",
    ] {
        assert_eq!(one_line(kept), kept);
    }
}
