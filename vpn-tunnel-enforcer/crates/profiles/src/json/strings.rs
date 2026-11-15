//! JSON string values that carry more content, read like a pasted text (profiles spec §3.4): JSON
//! documents anywhere in the string, then Clash YAML and share links in what they leave over, each
//! format adding its entries; up to two base64 layers.
use std::borrow::Cow;

use serde_json::Value;

use super::{Out, walk};
use crate::common::b64::base64_text;
use crate::text::{MAX_JSON_SPANS, blank_spans, json_spans};

/// Base64 layers unwrapped inside a JSON string (profiles spec §2.4: 2 for strings in JSON).
const BASE64_LAYERS: usize = 2;

/// Imports what the string `s` carries; true when anything came out of it.
pub(super) fn import(s: &str, depth: usize, out: &mut Out) -> bool {
    let mut layer = Cow::Borrowed(s);
    for level in 0..=BASE64_LAYERS {
        if layer_import(&layer, depth, out) {
            return true;
        }
        if level == BASE64_LAYERS {
            break;
        }
        match base64_text(&layer) {
            Some(next) => layer = Cow::Owned(next),
            None => break,
        }
    }
    false
}

fn layer_import(text: &str, depth: usize, out: &mut Out) -> bool {
    let before = out.len();
    let mut taken = Vec::new();
    for span in json_spans(text, MAX_JSON_SPANS) {
        if let Some(Ok(value)) = text.get(span.clone()).map(serde_json::from_str::<Value>)
            && walk(&value, depth + 1, None, out)
        {
            taken.push(span);
        }
    }
    let rest = match taken.is_empty() {
        true => Cow::Borrowed(text),
        false => Cow::Owned(blank_spans(text, &taken)),
    };
    other_formats(&rest, out);
    out.len() > before
}

/// Clash YAML and share links (embedded in prose too), through their own importers.
fn other_formats(text: &str, out: &mut Out) {
    if text.lines().any(|l| l.trim_start().starts_with("proxies:"))
        && let Some(report) = crate::clash::parse_clash(text)
    {
        out.extend(report);
    }
    // Share-link schemes only: `http(s)://` in JSON are web pages, feed URLs or local proxy
    // settings far more often than keys.
    for link in crate::text::uri_candidates(text) {
        out.push(crate::uri::parse_uri(link), || crate::uri::excerpt(link));
    }
}
