//! The page-head scanner: what a site says about itself (`og:*`, `<title>`, description,
//! canonical and icon links), cleaned into the stored result.
use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;
use url::Url;
use vpnte_base::types::UnixMs;

use super::{DomainEnrichment, EnrichStatus, allowed_url, allowed_url_str};

/// Metadata found in a page head, raw (entities decoded, URLs resolved).
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct PageMeta {
    pub(super) site_name: Option<String>,
    pub(super) title: Option<String>,
    pub(super) description: Option<String>,
    pub(super) canonical: Option<String>,
    pub(super) icon: Option<String>,
}

static TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<(meta|link)\b([^>]*)>").expect("valid regex"));
static ATTR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"#)
        .expect("valid regex")
});
static TITLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<title\b[^>]*>(.*?)</title\s*>").expect("valid regex"));

/// Attributes of one tag: lowercase name → decoded value (first occurrence wins).
fn attributes(tag: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for caps in ATTR.captures_iter(tag) {
        let value = caps.get(2).or(caps.get(3)).or(caps.get(4));
        out.entry(caps[1].to_ascii_lowercase())
            .or_insert_with(|| decode_entities(value.map_or("", |m| m.as_str())));
    }
    out
}

/// Reads what the old in-browser script read: `og:site_name`, `og:title` or `<title>`,
/// `og:description` or `meta[name=description]`, `link[rel=canonical]`, `link[rel~=icon]`.
/// Relative links resolve against `base` (the final URL).
pub(super) fn scan_head(html: &str, base: &Url) -> PageMeta {
    let end = html
        .to_ascii_lowercase()
        .find("</head")
        .unwrap_or(html.len());
    let head = &html[..end];
    let (mut og_title, mut og_desc, mut meta_desc) = (None, None, None);
    let mut meta = PageMeta::default();
    let first = |slot: &mut Option<String>, value: Option<&String>| {
        if slot.is_none() {
            *slot = value.filter(|v| !v.trim().is_empty()).cloned();
        }
    };
    for tag in TAG.captures_iter(head) {
        let attrs = attributes(&tag[2]);
        if tag[1].eq_ignore_ascii_case("meta") {
            let key = attrs.get("property").or(attrs.get("name"));
            let content = attrs.get("content");
            match key.map(|k| k.to_ascii_lowercase()).as_deref() {
                Some("og:site_name") => first(&mut meta.site_name, content),
                Some("og:title") => first(&mut og_title, content),
                Some("og:description") => first(&mut og_desc, content),
                Some("description") => first(&mut meta_desc, content),
                _ => {}
            }
        } else {
            let rel = attrs
                .get("rel")
                .map(|r| r.to_ascii_lowercase())
                .unwrap_or_default();
            let href = attrs
                .get("href")
                .and_then(|h| base.join(h.trim()).ok())
                .map(String::from);
            let has = |token: &str| rel.split_ascii_whitespace().any(|t| t == token);
            if has("canonical") {
                first(&mut meta.canonical, href.as_ref());
            } else if has("icon") {
                first(&mut meta.icon, href.as_ref());
            }
        }
    }
    let title = TITLE.captures(head).map(|c| decode_entities(&c[1]));
    meta.title = og_title.or(title.filter(|t| !t.trim().is_empty()));
    meta.description = og_desc.or(meta_desc);
    meta
}

/// Decodes the HTML character references titles and attributes use in practice.
pub(super) fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let decoded = rest.find(';').filter(|&semi| semi <= 10).and_then(|semi| {
            let name = &rest[1..semi];
            let ch = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some('\u{a0}'),
                _ => name
                    .strip_prefix("#x")
                    .or_else(|| name.strip_prefix("#X"))
                    .map(|hex| u32::from_str_radix(hex, 16))
                    .or_else(|| name.strip_prefix('#').map(str::parse::<u32>))
                    .and_then(Result::ok)
                    .and_then(char::from_u32),
            };
            ch.map(|c| (c, semi))
        });
        match decoded {
            Some((c, semi)) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Collapses whitespace (control characters count as such) and cuts to `max` characters. Text
/// with replacement characters (a page in a legacy encoding read as UTF-8) is dropped rather than
/// shown garbled.
pub(super) fn clean_text(value: Option<String>, max: usize) -> Option<String> {
    let value = value?;
    let clean = value
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if clean.is_empty() || clean.contains('\u{FFFD}') {
        return None;
    }
    Some(clean.chars().take(max).collect())
}

/// The stored result: texts cleaned and cut (120 / 180 / 360), URLs re-checked, the site name
/// falls back to the title and the canonical URL to the final one; `ready` iff any text.
pub(super) fn sanitize(meta: PageMeta, final_url: &Url, now: UnixMs) -> DomainEnrichment {
    let site_name = clean_text(meta.site_name, 120);
    let title = clean_text(meta.title, 180);
    let description = clean_text(meta.description, 360);
    if site_name.is_none() && title.is_none() && description.is_none() {
        return DomainEnrichment::empty(EnrichStatus::Unavailable, now);
    }
    let checked = |url: Option<String>| url.filter(|u| allowed_url_str(u));
    let final_url = allowed_url(final_url).then(|| final_url.to_string());
    DomainEnrichment {
        status: EnrichStatus::Ready,
        site_name: site_name.or_else(|| title.clone()),
        title,
        description,
        canonical_url: checked(meta.canonical).or(final_url),
        favicon_url: checked(meta.icon),
        fetched_at: now,
    }
}
