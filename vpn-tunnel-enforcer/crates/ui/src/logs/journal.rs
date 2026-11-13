//! The technical tab's line model: app.log and service JSON lines and the engines' own text
//! output parsed into time / level / short scope / text (JSON fields apart, shown on expand),
//! filtered by level and search, newest first (formats: core logging, sing-box
//! `log/format.go`, Xray's `[Level]` prefix).
use jiff::Timestamp;
use jiff::tz::TimeZone;
use serde_json::Value;

use super::format::local_time;
use super::model::{LogSource, LogTail};

/// Lines rendered at most (the newest that match).
pub const TAIL_LINES: usize = 2000;
/// Longer lines are cut (a stray binary or a giant JSON field must not flood the pane).
pub const MAX_LINE_CHARS: usize = 1000;

/// Severity of a journal line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LineLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LineLevel {
    /// Parses a level word of any of the three writers (`INFO`, `warn`, `Warning`, `FATAL`).
    pub fn parse(word: &str) -> Option<Self> {
        match word.to_ascii_lowercase().as_str() {
            "trace" => Some(LineLevel::Trace),
            "debug" => Some(LineLevel::Debug),
            "info" => Some(LineLevel::Info),
            "warn" | "warning" => Some(LineLevel::Warn),
            "error" | "fatal" | "panic" => Some(LineLevel::Error),
            _ => None,
        }
    }

    /// The level word shown in the pane (lower-case, as the old panel).
    pub fn name(self) -> &'static str {
        match self {
            LineLevel::Trace => "trace",
            LineLevel::Debug => "debug",
            LineLevel::Info => "info",
            LineLevel::Warn => "warn",
            LineLevel::Error => "error",
        }
    }
}

/// Which lines the level filter keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LevelFilter {
    /// Everything the logger wrote (debug lines only exist while debug logging is on).
    #[default]
    All,
    Warnings,
    Errors,
}

impl LevelFilter {
    pub const ALL: [LevelFilter; 3] =
        [LevelFilter::All, LevelFilter::Warnings, LevelFilter::Errors];

    pub fn keeps(self, level: LineLevel) -> bool {
        match self {
            LevelFilter::All => true,
            LevelFilter::Warnings => level >= LineLevel::Warn,
            LevelFilter::Errors => level == LineLevel::Error,
        }
    }
}

/// One line as shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalLine {
    /// The line's byte offset in its file (row key; 0 from [`parse_line`]).
    pub key: u64,
    /// Local `HH:MM:SS`, when the line carries a time.
    pub time: Option<String>,
    pub level: LineLevel,
    /// Short module or engine component (`tunnel/lifecycle`, `inbound/tun[tun-in]`).
    pub scope: Option<String>,
    pub text: String,
    /// `key=value` facts of a JSON line (shown on expand), the full module path first.
    pub fields: Vec<(String, String)>,
}

impl JournalLine {
    /// The line as copied: time, level, scope, text and its fields.
    pub fn copy_text(&self) -> String {
        let mut out = String::new();
        if let Some(time) = &self.time {
            out.push_str(time);
            out.push(' ');
        }
        out.push_str(self.level.name());
        if let Some(scope) = &self.scope {
            out.push_str(&format!(" [{scope}]"));
        }
        out.push(' ');
        out.push_str(&self.text);
        for (key, value) in &self.fields {
            out.push_str(&format!(" {key}={value}"));
        }
        out
    }

    /// The search (case-insensitive, already lower-cased `needle`) finds it anywhere shown.
    fn contains(&self, needle: &str) -> bool {
        needle.is_empty() || self.copy_text().to_lowercase().contains(needle)
    }
}

/// The shown lines of a tail: parsed, kept by `level` and the search `text`, newest first, at
/// most [`TAIL_LINES`].
pub fn journal(
    source: LogSource,
    tail: &LogTail,
    level: LevelFilter,
    text: &str,
    tz: &TimeZone,
) -> Vec<JournalLine> {
    let needle = text.trim().to_lowercase();
    tail.lines
        .iter()
        .rev()
        .filter_map(|line| {
            let mut parsed = parse_line(source, &line.text, tz)?;
            parsed.key = line.offset;
            Some(parsed)
        })
        .filter(|line| level.keeps(line.level) && line.contains(&needle))
        .take(TAIL_LINES)
        .collect()
}

/// Parses one raw line of `source`; `None` for a blank line.
pub fn parse_line(source: LogSource, line: &str, tz: &TimeZone) -> Option<JournalLine> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.trim().is_empty() {
        return None;
    }
    let parsed = match source {
        LogSource::App | LogSource::Service => parse_app(line, tz),
        LogSource::SingBox => parse_singbox(line),
        LogSource::Xray => parse_xray(line),
    };
    Some(parsed.unwrap_or_else(|| plain(line)))
}

/// A line in no known format: info, cut.
fn plain(line: &str) -> JournalLine {
    JournalLine {
        key: 0,
        time: None,
        level: LineLevel::Info,
        scope: None,
        text: cut(line.trim()),
        fields: Vec::new(),
    }
}

fn cut(text: &str) -> String {
    match text.char_indices().nth(MAX_LINE_CHARS) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_owned(),
    }
}

/// app.log and the service log: `{"ts":"…Z","level":"INFO","target":"vpnte_x::y","msg":"…",
/// "fields":{…},"corr":"…"}`. The message is the text; the module path and the fields (the
/// logger already redacted them) are kept apart for the expanded line.
fn parse_app(line: &str, tz: &TimeZone) -> Option<JournalLine> {
    let Value::Object(obj) = serde_json::from_str::<Value>(line).ok()? else {
        return None;
    };
    let message = obj
        .get("msg")
        .or_else(|| obj.get("message"))
        .and_then(Value::as_str)?;
    let level = obj
        .get("level")
        .and_then(Value::as_str)
        .and_then(LineLevel::parse)
        .unwrap_or(LineLevel::Info);
    let time = obj
        .get("ts")
        .and_then(Value::as_str)
        .and_then(|ts| ts.parse::<Timestamp>().ok())
        .and_then(|ts| local_time(ts.as_millisecond(), tz));
    let target = obj
        .get("target")
        .or_else(|| obj.get("scope"))
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty());
    let mut fields = Vec::new();
    if let Some(target) = target {
        fields.push(("target".to_owned(), target.to_owned()));
    }
    if let Some(Value::Object(values)) = obj.get("fields") {
        for (key, value) in values {
            let value = match value {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            fields.push((key.clone(), cut(&value)));
        }
    }
    if let Some(corr) = obj.get("corr").and_then(Value::as_str) {
        fields.push(("corr".to_owned(), corr.to_owned()));
    }
    Some(JournalLine {
        key: 0,
        time,
        level,
        scope: target.map(short_scope),
        text: cut(message),
        fields,
    })
}

/// `vpnte_tunnel::lifecycle::actor` -> `tunnel/lifecycle`: the crate and its first module.
fn short_scope(target: &str) -> String {
    let target = target.strip_prefix("vpnte_").unwrap_or(target);
    let mut parts = target.split("::");
    match (parts.next(), parts.next()) {
        (Some(first), Some(second)) => format!("{first}/{second}"),
        (Some(first), None) => first.to_owned(),
        _ => target.to_owned(),
    }
}

/// sing-box with `--disable-color`: `+0300 2026-11-11 12:34:56 INFO [id 0ms] tag: message`
/// (full timestamp), `INFO[0012] message` (seconds since start) or `INFO message`.
fn parse_singbox(line: &str) -> Option<JournalLine> {
    let (time, rest) = match singbox_timestamp(line) {
        Some((time, rest)) => (Some(time.to_owned()), rest),
        None => (None, line),
    };
    let (word, rest) = rest.split_once(' ').unwrap_or((rest, ""));
    let word = word.split_once('[').map_or(word, |(w, _)| w);
    let level = LineLevel::parse(word)?;
    let (scope, text) = split_scope(rest);
    Some(JournalLine {
        key: 0,
        time,
        level,
        scope,
        text: cut(&text),
        fields: Vec::new(),
    })
}

/// `-0700 2006-01-02 15:04:05 ` → (`15:04:05`, rest).
fn singbox_timestamp(line: &str) -> Option<(&str, &str)> {
    let b = line.as_bytes();
    let shape = b.len() > 26
        && matches!(b[0], b'+' | b'-')
        && b[1..5].iter().all(u8::is_ascii_digit)
        && b[5] == b' '
        && b[10] == b'-'
        && b[13] == b'-'
        && b[16] == b' '
        && is_hms(&b[17..25])
        && b[25] == b' ';
    shape.then(|| (&line[17..25], &line[26..]))
}

/// Xray: `2026/11/11 12:34:56.123456 [Warning] [id] proxy/vless/outbound: message`; access lines
/// carry no level and count as info.
fn parse_xray(line: &str) -> Option<JournalLine> {
    let b = line.as_bytes();
    let shape = b.len() > 20
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'/'
        && b[7] == b'/'
        && b[10] == b' '
        && is_hms(&b[11..19]);
    if !shape {
        return None;
    }
    let time = line[11..19].to_owned();
    let mut rest = &line[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        rest = fraction.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let rest = rest.strip_prefix(' ')?;
    let (level, rest) = match rest.strip_prefix('[').and_then(|r| r.split_once("] ")) {
        Some((word, body)) => match LineLevel::parse(word) {
            Some(level) => (level, body),
            None => (LineLevel::Info, rest),
        },
        None => (LineLevel::Info, rest),
    };
    let (scope, text) = split_scope(rest);
    Some(JournalLine {
        key: 0,
        time: Some(time),
        level,
        scope,
        text: cut(&text),
        fields: Vec::new(),
    })
}

fn is_hms(b: &[u8]) -> bool {
    b.len() == 8
        && b[2] == b':'
        && b[5] == b':'
        && [0, 1, 3, 4, 6, 7].iter().all(|&i| b[i].is_ascii_digit())
}

/// Splits `[id …] tag: message` into the tag (a component name without spaces) and the text;
/// the connection id stays in the text (it ties the lines of one connection together).
fn split_scope(rest: &str) -> (Option<String>, String) {
    let (id, body) = match rest.strip_prefix('[').and_then(|r| r.split_once("] ")) {
        Some((id, body)) => (Some(id), body),
        None => (None, rest),
    };
    let (scope, message) = match body.split_once(": ") {
        Some((tag, message))
            if !tag.is_empty() && tag.len() <= 48 && !tag.contains(char::is_whitespace) =>
        {
            (Some(tag.to_owned()), message)
        }
        _ => (None, body),
    };
    let text = match id {
        Some(id) => format!("[{id}] {message}"),
        None => message.to_owned(),
    };
    (scope, text)
}
