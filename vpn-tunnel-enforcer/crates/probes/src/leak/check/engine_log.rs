//! The engine-log item: real errors of the current session (benign noise removed) and counts.
use std::sync::LazyLock;

use vpnte_base::Msg;

use super::{CheckItem, CheckStatus};

/// Counts and real errors of the current session's engine log (sing-box INFO level).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorSummary {
    pub proxy_out: u32,
    pub direct_out: u32,
    pub dns_events: u32,
    /// The last 5 real errors (benign noise removed).
    pub errors: Vec<String>,
}

fn rx(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).expect("static pattern")
}

static PROXY_OUT: LazyLock<regex::Regex> =
    LazyLock::new(|| rx(r"(?i)outbound/[a-z0-9]+\[proxy-out\]"));
static DIRECT_OUT: LazyLock<regex::Regex> =
    LazyLock::new(|| rx(r"(?i)outbound/direct\[direct-out\]"));
static DNS_EVENT: LazyLock<regex::Regex> = LazyLock::new(|| rx(r"(?i)hijack|dns"));
static ERROR_LEVEL: LazyLock<regex::Regex> = LazyLock::new(|| rx(r"\b(?:FATAL|ERROR|PANIC)\b"));
static ERROR_TEXT: LazyLock<regex::Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)\b(?:connection|dns|router|inbound|outbound)[:/].*",
        r"\b(?:failed|timeout|refused|reset by peer|no such host|network is unreachable)\b"
    ))
});
/// Field-proven noise: the core refusing UDP for traffic deliberately sent to block-out (QUIC
/// on a TCP-only outbound); process lookup denied for SYSTEM / elevated processes (routing
/// continues by the other matchers); peers closing connections.
static BENIGN: LazyLock<[regex::Regex; 5]> = LazyLock::new(|| {
    [
        rx(r"(?i)outbound/block\[block-out\]"),
        rx(r"(?i)listen packet connection using .*block-out: operation not permitted"),
        rx(r"(?i)router: failed to search process: Access is denied"),
        rx(r"(?i)\bconnection upload closed\b"),
        rx(r"(?i)\bforcibly closed by the remote host\b"),
    ]
});

/// Whether `line` is a real error (not field-proven noise).
pub fn is_real_error(line: &str) -> bool {
    (ERROR_LEVEL.is_match(line) || ERROR_TEXT.is_match(line))
        && !BENIGN.iter().any(|b| b.is_match(line))
}

/// Summarises engine log lines (any protocol counts as `proxy-out`).
pub fn summarize_engine_log<'a>(lines: impl IntoIterator<Item = &'a str>) -> ErrorSummary {
    let mut s = ErrorSummary::default();
    let mut errors: Vec<&str> = Vec::new();
    for line in lines {
        s.proxy_out += u32::from(PROXY_OUT.is_match(line));
        s.direct_out += u32::from(DIRECT_OUT.is_match(line));
        s.dns_events += u32::from(DNS_EVENT.is_match(line));
        if is_real_error(line) {
            errors.push(line);
        }
    }
    let skip = errors.len().saturating_sub(5);
    s.errors = errors[skip..].iter().map(|e| e.trim().to_owned()).collect();
    s
}

/// `engine-log`: the current session's engine lines (`None` = unavailable). Missing or empty
/// evidence is `NotChecked` (D-49), never "no errors".
pub fn engine_log_item(lines: Option<&[String]>, tunnel_up: bool) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.engineLog.{k}"));
    if !tunnel_up {
        return CheckItem::new("engine-log", CheckStatus::Info, key("tunnelOff"));
    }
    let lines = match lines {
        None => return CheckItem::new("engine-log", CheckStatus::NotChecked, key("missing")),
        Some([]) => return CheckItem::new("engine-log", CheckStatus::NotChecked, key("empty")),
        Some(lines) => lines,
    };
    let s = summarize_engine_log(lines.iter().map(String::as_str));
    let counts = key("counts")
        .arg("proxy", s.proxy_out)
        .arg("direct", s.direct_out)
        .arg("dns", s.dns_events);
    if s.errors.is_empty() {
        return CheckItem::new("engine-log", CheckStatus::Ok, key("clean")).detail(counts);
    }
    let value = key("errors").arg("count", s.errors.len());
    let mut item = CheckItem::new("engine-log", CheckStatus::Warn, value).detail(counts);
    for error in &s.errors {
        let text = vpnte_core::redact::text(error).into_owned();
        item = item.detail(Msg::new("probes.leak.check.value.text").arg("text", text));
    }
    item
}
