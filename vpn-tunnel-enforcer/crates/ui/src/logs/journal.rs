//! The journal viewer's line model: app.log JSON lines and the engines' own text output parsed
//! into time / level / scope / text, filtered by level, newest first (ui-pages §3.9 live log,
//! U-19; formats: core logging, sing-box `log/format.go`, Xray's `[Level]` prefix).
use jiff::Timestamp;
use jiff::tz::TimeZone;
use serde_json::Value;

use super::format::local_time;
use super::model::{LogSource, LogTail};

/// Lines kept on screen (the old panel kept the last 300 app.log lines).
pub const TAIL_LINES: usize = 300;
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
    /// Local `HH:MM:SS`, when the line carries a time.
    pub time: Option<String>,
    pub level: LineLevel,
    /// Module or engine component (`tunnel::lifecycle`, `inbound/tun[tun-in]`).
    pub scope: Option<String>,
    pub text: String,
}

/// The shown lines of a tail: parsed, filtered, newest first, at most [`TAIL_LINES`].
pub fn journal(
    source: LogSource,
    tail: &LogTail,
    filter: LevelFilter,
    tz: &TimeZone,
) -> Vec<JournalLine> {
    tail.lines
        .iter()
        .rev()
        .filter_map(|line| parse_line(source, line, tz))
        .filter(|line| filter.keeps(line.level))
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
        LogSource::App => parse_app(line, tz),
        LogSource::SingBox => parse_singbox(line),
        LogSource::Xray => parse_xray(line),
    };
    Some(parsed.unwrap_or_else(|| plain(line)))
}

/// A line in no known format: info, cut.
fn plain(line: &str) -> JournalLine {
    JournalLine {
        time: None,
        level: LineLevel::Info,
        scope: None,
        text: cut(line.trim()),
    }
}

fn cut(text: &str) -> String {
    match text.char_indices().nth(MAX_LINE_CHARS) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_owned(),
    }
}

/// app.log: `{"ts":"…Z","level":"INFO","target":"vpnte_x::y","msg":"…","fields":{…},"corr":"…"}`.
/// Fields follow the message as `key=value` (the logger already redacted them).
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
    let scope = obj
        .get("target")
        .or_else(|| obj.get("scope"))
        .and_then(Value::as_str)
        .map(|t| t.strip_prefix("vpnte_").unwrap_or(t).to_owned())
        .filter(|t| !t.is_empty());
    let mut text = message.to_owned();
    if let Some(Value::Object(fields)) = obj.get("fields") {
        for (key, value) in fields {
            text.push(' ');
            text.push_str(key);
            text.push('=');
            match value {
                Value::String(s) => text.push_str(s),
                other => text.push_str(&other.to_string()),
            }
        }
    }
    Some(JournalLine {
        time,
        level,
        scope,
        text: cut(&text),
    })
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
        time,
        level,
        scope,
        text: cut(&text),
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
        time: Some(time),
        level,
        scope,
        text: cut(&text),
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
