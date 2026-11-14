//! Subscription metadata from Happ-style `#key: value` body lines and from response headers.
//! A malformed field is dropped; it never invalidates the body (P-20).
use std::sync::LazyLock;

use percent_encoding::percent_decode_str;
use regex::Regex;

use super::layers::decode_base64_layer;
use crate::model::SubscriptionMeta;

/// Longest title kept (Happ shows 25 chars; the group name is cut later by the servers crate).
const MAX_TITLE_CHARS: usize = 256;
/// Longest announcement kept (Happ shows at most 200 chars).
const MAX_ANNOUNCE_CHARS: usize = 200;

/// Metadata from the `#key: value` lines at the top of a body (Happ reads them only before the
/// configs; Hiddify also reads `//key: value`), and the rest of the body after the leading
/// comment block. Comment lines that are not metadata are skipped with it; parse the rest (it may
/// be a base64 blob).
pub fn body_meta(text: &str) -> (SubscriptionMeta, &str) {
    let mut meta = SubscriptionMeta::default();
    let rest = comment_block(text, |key, value| apply_meta(&mut meta, key, value));
    (meta, rest)
}

/// Walks the comment block at the top of `text`, hands every `key: value` line to `apply` and
/// returns what follows the block.
pub(super) fn comment_block(text: &str, mut apply: impl FnMut(&str, &str)) -> &str {
    let mut rest = text;
    while !rest.is_empty() {
        let (line, next) = rest.split_once('\n').unwrap_or((rest, ""));
        let line = line.trim();
        if !line.is_empty() {
            let Some(comment) = comment_text(line) else {
                break;
            };
            if let Some((key, value)) = comment.split_once(':') {
                apply(key, value);
            }
        }
        rest = next;
    }
    rest
}

/// The text of a comment line: `#…`, or `//…` unless the line is a bare base64 run (`/` is a
/// base64 character, so a blob may well start with `//`).
fn comment_text(line: &str) -> Option<&str> {
    if let Some(comment) = line.strip_prefix('#') {
        return Some(comment);
    }
    let comment = line.strip_prefix("//")?;
    let blob = line
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'));
    (!blob).then_some(comment)
}

/// Applies one metadata field to `meta`: `subscription-userinfo`, `profile-update-interval`
/// (hours, as Happ documents it; the old app read seconds, P-21), `profile-title`,
/// `profile-web-page-url`, `support-url`, `announce`. Keys in any case; anything else is ignored.
pub fn apply_meta(meta: &mut SubscriptionMeta, key: &str, value: &str) {
    let value = value.trim();
    match key.trim().to_ascii_lowercase().as_str() {
        "subscription-userinfo" => userinfo(meta, value),
        "profile-update-interval" => {
            if let Some(hours) = digits::<u32>(value).filter(|h| *h > 0) {
                meta.refresh_hours = Some(hours);
            }
        }
        "profile-title" => {
            if let Some(title) = title(value) {
                meta.title = Some(title);
            }
        }
        "profile-web-page-url" => {
            if let Some(url) = web_url(value) {
                meta.web_page_url = Some(url);
            }
        }
        "support-url" => {
            if let Some(url) = web_url(value) {
                meta.support_url = Some(url);
            }
        }
        "announce" => {
            if let Some(text) = announce(value) {
                meta.announce = Some(text);
            }
        }
        _ => {}
    }
}

/// Metadata from response headers (names in any case; a repeated header: the last one wins), each
/// missing field filled from `body` (see [`body_meta`]). A `Content-Disposition` filename names
/// the subscription only when neither gives a title.
pub fn header_meta<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    body: SubscriptionMeta,
) -> SubscriptionMeta {
    let mut meta = SubscriptionMeta::default();
    let mut filename = None;
    for (name, value) in headers {
        if name.trim().eq_ignore_ascii_case("content-disposition") {
            filename = disposition_title(value).or(filename);
        } else {
            apply_meta(&mut meta, name, value);
        }
    }
    SubscriptionMeta {
        upload: meta.upload.or(body.upload),
        download: meta.download.or(body.download),
        total: meta.total.or(body.total),
        expires_at: meta.expires_at.or(body.expires_at),
        refresh_hours: meta.refresh_hours.or(body.refresh_hours),
        title: meta.title.or(body.title).or(filename),
        web_page_url: meta.web_page_url.or(body.web_page_url),
        support_url: meta.support_url.or(body.support_url),
        announce: meta.announce.or(body.announce),
    }
}

/// `upload=1; download=2; total=3; expire=<unix seconds>`; `expire=0` means no expiry.
fn userinfo(meta: &mut SubscriptionMeta, value: &str) {
    for part in value.split(';') {
        let Some((key, amount)) = part.split_once('=') else {
            continue;
        };
        let Some(n) = non_negative(amount.trim()) else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "upload" => meta.upload = Some(n),
            "download" => meta.download = Some(n),
            "total" => meta.total = Some(n),
            "expire" if n > 0 => {
                meta.expires_at = i64::try_from(n).ok().and_then(|s| s.checked_mul(1000))
            }
            _ => {}
        }
    }
}

/// Panels send integers; a few send floats (`1.5e10`). Negative or non-finite values are dropped.
fn non_negative(s: &str) -> Option<u64> {
    digits(s).or_else(|| {
        s.parse::<f64>()
            .ok()
            .filter(|f| f.is_finite() && *f >= 0.0)
            .map(|f| f as u64)
    })
}

/// Decimal digits only (Rust's integer parse would also take a leading `+`).
fn digits<T: std::str::FromStr>(s: &str) -> Option<T> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

fn web_url(value: &str) -> Option<String> {
    let url = url::Url::parse(unquote(value)).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.into())
}

/// `profile-title`: plain, `base64:<b64>`, `UTF-8''<percent-encoded>` or percent-encoded, each
/// optionally quoted; a value that fails to decode is kept as it came.
fn title(value: &str) -> Option<String> {
    let raw = unquote(value);
    let decoded = if let Some(b64) = strip_prefix_ci(raw, "base64:") {
        decode_base64_layer(unquote(b64))
    } else if let Some(encoded) = strip_prefix_ci(raw, "utf-8''") {
        percent_decode_strict(encoded)
    } else if has_percent_escape(raw) {
        percent_decode_strict(raw)
    } else {
        None
    };
    let text = decoded
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| raw.to_owned());
    clean(unquote(&text), MAX_TITLE_CHARS)
}

/// `announce`: plain text or `base64:<b64>`.
fn announce(value: &str) -> Option<String> {
    let raw = unquote(value);
    let decoded = strip_prefix_ci(raw, "base64:").and_then(|b64| decode_base64_layer(unquote(b64)));
    clean(decoded.as_deref().unwrap_or(raw), MAX_ANNOUNCE_CHARS)
}

static FILENAME: LazyLock<Regex> = LazyLock::new(|| {
    // Constant pattern; the tests compile it. Group 1 marks the RFC 5987 `filename*` form.
    Regex::new(r#"(?i)filename(\*)?=(?:utf-8'[^']*')?["']?([^"';\r\n]+)["']?"#)
        .expect("filename pattern compiles")
});

/// Subscription name from `Content-Disposition: attachment; filename="My VPN.txt"`. A stray `%`
/// (`100%.txt`) keeps the raw name; the old unguarded decode failed the whole download (P-20).
/// `filename*` wins over `filename` in any order (RFC 6266 §4.3: the plain one is the fallback
/// for old clients, often an ASCII transliteration).
fn disposition_title(value: &str) -> Option<String> {
    let names: Vec<(bool, &str)> = FILENAME
        .captures_iter(value)
        .filter_map(|c| Some((c.get(1).is_some(), c.get(2)?.as_str())))
        .collect();
    let (_, raw) = names
        .iter()
        .find(|(extended, _)| *extended)
        .or(names.first())?;
    let name = percent_decode_strict(raw).unwrap_or_else(|| (*raw).to_owned());
    let name = name.trim();
    let stem = [".yaml", ".yml", ".txt", ".json"]
        .iter()
        .find_map(|ext| {
            let cut = name.len().checked_sub(ext.len())?;
            (name.is_char_boundary(cut) && name[cut..].eq_ignore_ascii_case(ext))
                .then(|| &name[..cut])
        })
        .unwrap_or(name);
    clean(stem, MAX_TITLE_CHARS)
}

/// `s` without one pair of surrounding quotes (either kind) and surrounding whitespace.
pub(super) fn unquote(s: &str) -> &str {
    let s = s.trim();
    let quote = |b: &u8| matches!(b, b'"' | b'\'');
    let quoted = s.len() >= 2
        && s.as_bytes().first().is_some_and(quote)
        && s.as_bytes().last().is_some_and(quote);
    if quoted { s[1..s.len() - 1].trim() } else { s }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

fn has_percent_escape(s: &str) -> bool {
    s.as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
}

/// Like JS `decodeURIComponent`: every `%` must start an escape and the result must be UTF-8.
fn percent_decode_strict(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let well_formed = bytes.iter().enumerate().all(|(i, &b)| {
        b != b'%'
            || bytes
                .get(i + 1..i + 3)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit))
    });
    well_formed
        .then(|| percent_decode_str(s).decode_utf8().ok().map(String::from))
        .flatten()
}

/// Control characters become spaces, the ends are trimmed, the length is capped; blank is `None`.
fn clean(s: &str, max_chars: usize) -> Option<String> {
    let text: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max_chars)
        .collect();
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

#[cfg(test)]
mod tests;
