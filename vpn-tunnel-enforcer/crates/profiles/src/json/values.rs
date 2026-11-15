//! Lenient readers for hand-written provider JSON: numbers may be quoted, booleans may be words,
//! lists may be one comma-joined string.
use serde_json::{Map, Value};

use crate::common::fields::go_duration_ms;

/// First non-empty string among `keys` (values are not trimmed: credentials are taken verbatim).
pub(crate) fn text<'a>(o: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .filter_map(|k| o.get(*k)?.as_str())
        .find(|s| !s.trim().is_empty())
}

/// Like [`text`], but also accepts numbers (ids and passwords written without quotes).
pub(crate) fn text_or_number(o: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| match o.get(*k)? {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

/// A number, or a string holding one.
pub(crate) fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
    .filter(|n| n.is_finite())
}

/// A non-negative whole number (decimal digits only when quoted).
pub(crate) fn whole(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => {
            let s = s.trim();
            (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .then(|| s.parse().ok())
                .flatten()
        }
        _ => None,
    }
}

/// A positive whole number that fits `u32`.
pub(crate) fn positive_u32(v: &Value) -> Option<u32> {
    whole(v)
        .filter(|n| *n > 0)
        .and_then(|n| u32::try_from(n).ok())
}

/// A positive number rounded to an integer (old imports stored floats where sing-box wants ints).
pub(crate) fn rounded_positive(v: &Value) -> Option<u32> {
    let n = number(v)?.round();
    (n >= 1.0 && n <= f64::from(u32::MAX)).then_some(n as u32)
}

/// TCP/UDP port 1..=65535.
pub(crate) fn port(v: &Value) -> Option<u16> {
    whole(v)
        .and_then(|n| u16::try_from(n).ok())
        .filter(|p| *p > 0)
}

/// `true`/`false`, a non-zero number, or `1|0|true|false|yes|no|on|off` in any case.
pub(crate) fn boolean(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => n.as_f64().map(|f| f != 0.0),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Whether `key` is present and truthy.
pub(crate) fn flag(o: &Map<String, Value>, key: &str) -> bool {
    o.get(key).and_then(boolean).unwrap_or(false)
}

/// A list of non-empty trimmed strings from an array or a comma-joined string.
pub(crate) fn list(v: &Value) -> Vec<String> {
    let items: Vec<&str> = match v {
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        Value::String(s) => s.split(',').collect(),
        _ => Vec::new(),
    };
    items
        .into_iter()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Seconds from a Go duration (`30s`, `1m30s`, `500ms`) or a bare number of seconds (mihomo style).
/// A positive value below one second becomes 1 so it is never lost.
pub(crate) fn duration_secs(v: &Value) -> Option<u32> {
    let millis = match v {
        Value::Number(_) => number(v)? * 1000.0,
        Value::String(s) => go_duration_millis(s.trim())?,
        _ => return None,
    };
    if millis.is_nan() || millis <= 0.0 {
        return None;
    }
    let secs = (millis / 1000.0).round().max(1.0);
    (secs <= f64::from(u32::MAX)).then_some(secs as u32)
}

/// Milliseconds of a Go duration string; a bare number counts as seconds.
fn go_duration_millis(s: &str) -> Option<f64> {
    if let Ok(secs) = s.parse::<f64>() {
        return Some(secs * 1000.0);
    }
    go_duration_ms(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Go durations and bare seconds; sub-second values are never lost.
    #[test]
    fn durations() {
        let secs = |v: serde_json::Value| duration_secs(&v);
        assert_eq!(secs(json!("30s")), Some(30));
        assert_eq!(secs(json!("1m30s")), Some(90));
        assert_eq!(secs(json!("1h")), Some(3600));
        assert_eq!(secs(json!("500ms")), Some(1));
        assert_eq!(secs(json!(30)), Some(30));
        assert_eq!(secs(json!("30")), Some(30));
        assert_eq!(secs(json!("0s")), None);
        assert_eq!(secs(json!("soon")), None);
        assert_eq!(secs(json!("10x")), None);
    }

    /// Lenient scalars: quoted numbers, word booleans, decimal-only ports.
    #[test]
    fn scalars() {
        assert_eq!(port(&json!("443")), Some(443));
        assert_eq!(port(&json!(65536)), None);
        assert_eq!(port(&json!("0x1BB")), None);
        assert_eq!(port(&json!(443.5)), None);
        assert_eq!(boolean(&json!("On")), Some(true));
        assert_eq!(boolean(&json!(0)), Some(false));
        assert_eq!(rounded_positive(&json!(80.4)), Some(80));
        assert_eq!(rounded_positive(&json!(0.2)), None);
        assert_eq!(list(&json!("h2, http/1.1,")), ["h2", "http/1.1"]);
    }
}
