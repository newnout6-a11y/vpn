//! The engine-log item: real errors of the current session (routine noise removed). One
//! definition of "real" for the leak check and the diagnostics' `tun-log` item.
use std::sync::LazyLock;

use vpnte_base::Msg;

use super::{CheckItem, CheckStatus};

/// The real errors of the current session's engine lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorSummary {
    /// The last 5 real errors (routine noise removed).
    pub errors: Vec<String>,
}

fn rx(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).expect("static pattern")
}

static ERROR_LEVEL: LazyLock<regex::Regex> = LazyLock::new(|| rx(r"\b(?:FATAL|ERROR|PANIC)\b"));
static ERROR_TEXT: LazyLock<regex::Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)\b(?:connection|dns|router|inbound|outbound)[:/].*",
        r"\b(?:failed|timeout|refused|reset by peer|no such host|network is unreachable)\b"
    ))
});
/// Field-proven routine lines that read like errors: the core refusing UDP sent to block-out
/// (QUIC on a TCP-only outbound); a process lookup that cannot see the process (SYSTEM,
/// elevated, gone); one connection ending because its peer or the local app closed it; and
/// (owner logs O-3, 15.11) a site that does not answer on the direct path, one XHTTP upload
/// request, HTTP/2 stream chatter, a client leaving the slot before its request (the readiness
/// probe). None of them is a leak or a broken route.
static BENIGN: LazyLock<[regex::Regex; 10]> = LazyLock::new(|| {
    [
        rx(r"(?i)outbound/block\[block-out\]"),
        rx(r"(?i)listen packet connection using .*block-out: operation not permitted"),
        rx(r"(?i)router: failed to search process"),
        rx(r"(?i)\bconnection (?:upload|download) closed\b"),
        rx(r"(?i)\bforcibly closed by the remote host\b|\baborted by the software in your host\b"),
        rx(r"(?i)failed to transfer (?:request|response) payload"),
        rx(r"(?i)using outbound/direct\[direct-out\]: .*\b(?:i/o timeout|refused|reset by peer)\b"),
        rx(r"(?i)splithttp: failed to send upload"),
        rx(r"(?i)received DATA after END_STREAM"),
        rx(r"(?i)proxy/socks: failed to read request\b.*\bEOF\b"),
    ]
});

/// Whether `line` is a real error (not routine noise).
pub fn is_real_error(line: &str) -> bool {
    (ERROR_LEVEL.is_match(line) || ERROR_TEXT.is_match(line))
        && !BENIGN.iter().any(|b| b.is_match(line))
}

/// The real errors among engine log lines.
pub fn summarize_engine_log<'a>(lines: impl IntoIterator<Item = &'a str>) -> ErrorSummary {
    let errors: Vec<&str> = lines.into_iter().filter(|l| is_real_error(l)).collect();
    let skip = errors.len().saturating_sub(5);
    ErrorSummary {
        errors: errors[skip..].iter().map(|e| e.trim().to_owned()).collect(),
    }
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
    if s.errors.is_empty() {
        return CheckItem::new("engine-log", CheckStatus::Ok, key("clean"));
    }
    let value = key("errors").arg("count", s.errors.len());
    let mut item = CheckItem::new("engine-log", CheckStatus::Warn, value);
    for error in &s.errors {
        let text = vpnte_core::redact::text(error).into_owned();
        item = item.detail(Msg::new("probes.leak.check.value.text").arg("text", text));
    }
    item
}
