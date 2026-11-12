//! The user's extra request headers of a subscription (v2rayN 7.25 offers the same): `Name: value`
//! lines, checked when saved and sealed like the URL. Typical uses: a client name a panel insists
//! on (`User-Agent`), an access token header, a panel-specific switch.
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use vpnte_base::{AppError, AppResult, Msg};

/// Headers one subscription may carry.
pub const MAX_HEADERS: usize = 16;
/// Longest header name / value accepted.
const MAX_NAME: usize = 64;
const MAX_VALUE: usize = 1024;
/// Names the transport owns (framing, hop-by-hop, proxy): a user value would break the request
/// or leak to a proxy.
const RESERVED: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
    "expect",
    "proxy-authorization",
    "proxy-connection",
];

/// The lines of `text` as checked `(name, value)` pairs; blank lines are skipped. Errors name the
/// line (1-based) or the header.
pub fn parse_headers(text: &str) -> AppResult<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let invalid =
            || AppError::validation(Msg::new("servers.headers.invalid").arg("line", index + 1));
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        let (name, value) = (name.trim(), value.trim());
        let usable = !name.is_empty()
            && name.len() <= MAX_NAME
            && value.len() <= MAX_VALUE
            && HeaderName::from_bytes(name.as_bytes()).is_ok()
            && HeaderValue::from_str(value).is_ok();
        if !usable {
            return Err(invalid());
        }
        if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(name)) {
            return Err(AppError::validation(
                Msg::new("servers.headers.reserved").arg("name", name),
            ));
        }
        out.push((name.to_owned(), value.to_owned()));
        if out.len() > MAX_HEADERS {
            return Err(AppError::validation(
                Msg::new("servers.headers.tooMany").arg("max", MAX_HEADERS),
            ));
        }
    }
    Ok(out)
}

/// The stored form of checked headers: one `Name: value` per line; `None` when there are none.
pub fn stored_headers(headers: &[(String, String)]) -> Option<String> {
    let lines: Vec<String> = headers.iter().map(|(n, v)| format!("{n}: {v}")).collect();
    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// The names of stored headers, in order (values are never shown: they may be tokens).
pub fn header_names(stored: &str) -> Vec<String> {
    parse_headers(stored)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// Stored headers as a map; a value that no longer parses is skipped (it was checked when saved).
pub(super) fn header_map(headers: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            map.insert(name, value);
        }
    }
    map
}
