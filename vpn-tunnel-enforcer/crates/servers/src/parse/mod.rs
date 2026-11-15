//! Pasted text and subscription bodies -> profiles (profiles spec §3.2): app deep links, body
//! metadata, nested base64 layers, then every format of a layer (JSON documents, Clash, WireGuard
//! `.conf`, share links), never "first format wins". Results are de-duplicated by
//! `Profile::identity()` and bounded (§6.5 #12). Pure and synchronous: fetching is
//! `subscription`'s job, and nothing here logs a key.
use std::borrow::Cow;
use std::collections::HashSet;

use serde_json::Value;
use vpnte_base::{AppError, Msg};
use vpnte_profiles::model::{
    ParseReport, Profile, SkipReason, Skipped, Source, SubscriptionMeta, TooLarge,
};
use vpnte_profiles::text::ProviderKeys;
use vpnte_profiles::{clash, deeplink, json, text, uri, wg_ini};

use crate::common::is_http_url;

#[cfg(test)]
mod tests;

/// Most profiles taken from one text (profiles §6.5 #12). Reaching it ends the import with a
/// skipped entry, so a cut list never passes for a complete one.
pub const MAX_PROFILES: usize = 5000;
/// Most skipped entries listed: a body of a million broken lines must not grow the report
/// without bound. Problems past it still leave one entry saying how many were not listed.
pub const MAX_SKIPPED: usize = 5000;

/// Pasted text (at most [`text::MAX_INPUT_BYTES`]) -> profiles, skipped entries and the body
/// metadata. A deep link carrying keys is unwrapped and parsed; one that carries a subscription
/// URL, or cannot be unwrapped, comes back as a single skipped entry: route URLs and deep links to
/// the fetcher before calling this (only it can fetch, and `DeepLinkError::msg` explains better).
pub fn parse_text(input: &str) -> Result<ParseReport, TooLarge> {
    text::prepare(input, text::MAX_INPUT_BYTES).map(|t| parse_prepared(t).0)
}

/// Subscription body bytes (at most [`text::MAX_BODY_BYTES`], also after decompression) ->
/// the same report as [`parse_text`]. gzip / zlib / UTF-16 / brotli bodies are decoded first;
/// response headers are merged afterwards with `text::header_meta(headers, report.meta)`.
pub fn parse_body(raw: &[u8]) -> Result<ParseReport, TooLarge> {
    parse_body_full(raw).map(|parsed| parsed.report)
}

/// A subscription body as the fetcher reads it: the report, the provider controls and relocation
/// hints of its comment blocks (outer layers win), and the decoded text.
pub(crate) struct Parsed {
    pub report: ParseReport,
    pub keys: ProviderKeys,
    pub text: String,
}

/// [`parse_body`] with the provider keys and the decoded text kept.
pub(crate) fn parse_body_full(raw: &[u8]) -> Result<Parsed, TooLarge> {
    let body = text::decode_body(raw, text::MAX_BODY_BYTES)?;
    let (report, keys) = parse_prepared(text::prepare(&body, text::MAX_BODY_BYTES)?);
    Ok(Parsed {
        report,
        keys,
        text: body,
    })
}

/// The validation error for a [`TooLarge`] input; `limit` is the byte limit that was exceeded.
pub fn too_large(limit: usize) -> AppError {
    let mib = limit.div_ceil(1 << 20);
    AppError::validation(Msg::new("servers.parse.tooLarge").arg("mib", mib))
}

/// The validation error for a source that yielded no profile: the reason of a lone skipped entry
/// (a single broken key explains itself), else how many entries were skipped, else "nothing found".
pub fn no_profiles(report: &ParseReport) -> AppError {
    let msg = match report.skipped.as_slice() {
        [] => Msg::new("servers.parse.nothingFound"),
        [only] => match &only.reason {
            // Its detail is English, and a cut paste is common enough to deserve a sentence.
            SkipReason::Invalid { scheme, .. } if scheme == DAMAGED_BASE64 => {
                Msg::new("servers.parse.damagedBase64")
            }
            reason => vpnte_profiles::caps::skip_msg(reason),
        },
        many => Msg::new("servers.parse.allSkipped").arg("count", many.len()),
    };
    AppError::validation(msg)
}

/// Scheme of the one entry reporting a text that looks like base64 but does not decode.
const DAMAGED_BASE64: &str = "base64";

/// Prepared text (trimmed, within its size limit) -> report and provider keys.
fn parse_prepared(text: &str) -> (ParseReport, ProviderKeys) {
    let skipped = |detail: String| (link_skipped(text, detail), ProviderKeys::default());
    match deeplink::unwrap_deeplink(text) {
        Ok(None) => parse_document(text),
        Ok(Some(inner)) if is_http_url(&inner) => {
            skipped("carries a subscription URL, which has to be fetched".to_owned())
        }
        Ok(Some(inner)) => parse_document(&inner),
        Err(err) => skipped(err.to_string()),
    }
}

/// Metadata lines, then the first base64 layer that yields anything (`base64(base64(list))`
/// works, AT-04-003). Metadata lines at the top of a decoded layer count too; outer ones win.
fn parse_document(text: &str) -> (ParseReport, ProviderKeys) {
    let (mut meta, body) = text::body_meta(text);
    let mut keys = text::body_keys(text);
    let layers = text::layers(body);
    for (index, layer) in layers.iter().enumerate() {
        let (inner_meta, rest) = text::body_meta(layer);
        fill_gaps(&mut meta, inner_meta);
        // Layer 0 is `body`, which `text` covered already.
        if index > 0 {
            keys = keys.or(text::body_keys(layer));
        }
        let mut found = Collector::default();
        found.layer(rest);
        if !found.is_empty() {
            return (found.finish(meta), keys);
        }
    }
    let mut report = ParseReport {
        meta,
        ..ParseReport::default()
    };
    // AT-04-003: a blob that stopped decoding is damaged (or ciphertext), not "no keys here".
    if layers
        .last()
        .is_some_and(|last| looks_like_base64(text::body_meta(last).1))
    {
        let detail = "does not decode to text (damaged, truncated or encrypted)".to_owned();
        report
            .skipped
            .push(invalid(DAMAGED_BASE64.to_owned(), DAMAGED_BASE64, detail));
    }
    (report, keys)
}

/// What one layer yielded, in import order: JSON documents, then Clash, WireGuard `.conf` and
/// share links in what the JSON importer did not take.
#[derive(Default)]
struct Collector {
    profiles: Vec<Profile>,
    skipped: Vec<Skipped>,
    seen: HashSet<[u8; 16]>,
    /// Problems past [`MAX_SKIPPED`] (duplicates are not counted: they lose nothing).
    unlisted: usize,
    /// [`MAX_PROFILES`] was passed: nothing after that point is read.
    full: bool,
}

impl Collector {
    fn layer(&mut self, layer: &str) {
        // One span more than the limit tells whether a document was left unread.
        let mut documents: Vec<_> = text::json_spans(layer, text::MAX_JSON_SPANS + 1)
            .into_iter()
            .enumerate()
            .filter_map(|(index, span)| {
                let value = serde_json::from_str::<Value>(&layer[span.clone()]).ok()?;
                let report = json::parse_json(&value);
                let any = !(report.profiles.is_empty() && report.skipped.is_empty());
                any.then_some((index, span, report))
            })
            .collect();
        // Sub-Store writes Clash entries in JSON syntax (`  - {"name":…}`), which the JSON
        // importer misreads as sing-box outbounds: in a Clash document a span behind other text on
        // its line is a YAML value and stays with the Clash reader.
        let alone: Vec<_> = documents
            .iter()
            .filter(|(_, span, _)| starts_line(layer, span.start))
            .map(|(_, span, _)| span.clone())
            .collect();
        let blanked = text::blank_spans(layer, &alone);
        let clash = clash::parse_clash(&without_link_lines(&blanked));
        if clash.is_some() {
            documents.retain(|(_, span, _)| starts_line(layer, span.start));
        }
        let mut taken = Vec::with_capacity(documents.len());
        for (index, span, report) in documents {
            if index == text::MAX_JSON_SPANS {
                let detail = format!(
                    "more than {} JSON documents: the rest were not read",
                    text::MAX_JSON_SPANS
                );
                self.skip(invalid("{…}".to_owned(), "json", detail));
                break;
            }
            taken.push(span);
            self.merge(report);
        }
        if let Some(report) = clash {
            self.merge(report);
        }
        let rest = if taken == alone {
            blanked
        } else {
            text::blank_spans(layer, &taken)
        };
        if let Some(result) = wg_ini::parse_wg_ini(&without_link_lines(&rest)) {
            self.push(result, || "[Interface]".to_owned());
        }
        for line in text::uri_candidates(&rest) {
            if self.full {
                break;
            }
            self.push(uri::parse_uri(line), || link_excerpt(line));
        }
    }

    /// Takes over an importer's report (its profiles, then its skipped entries).
    fn merge(&mut self, report: ParseReport) {
        for profile in report.profiles {
            self.push(Ok(profile), String::new);
        }
        for skipped in report.skipped {
            self.skip(skipped);
        }
    }

    /// One import result. `excerpt` names a skipped entry; a profile's own excerpt is derived
    /// from it when it turns out to be a duplicate or over the limit.
    fn push(&mut self, result: Result<Profile, SkipReason>, excerpt: impl FnOnce() -> String) {
        if self.full {
            return;
        }
        let profile = match result {
            Ok(profile) => profile,
            Err(reason) => {
                return self.skip(Skipped {
                    excerpt: excerpt(),
                    reason,
                });
            }
        };
        if !self.seen.insert(profile.identity()) {
            return self.skip(Skipped {
                excerpt: profile_excerpt(&profile),
                reason: SkipReason::Duplicate,
            });
        }
        if self.profiles.len() == MAX_PROFILES {
            self.full = true;
            // Past every cap on purpose: this entry is what marks the list as cut.
            self.skipped.push(cut_marker(&profile));
            return;
        }
        self.profiles.push(profile);
    }

    fn skip(&mut self, skipped: Skipped) {
        if self.full {
            return;
        }
        if self.skipped.len() < MAX_SKIPPED {
            self.skipped.push(skipped);
        } else if skipped.reason != SkipReason::Duplicate {
            self.unlisted += 1;
        }
    }

    fn is_empty(&self) -> bool {
        self.profiles.is_empty() && self.skipped.is_empty()
    }

    fn finish(mut self, meta: SubscriptionMeta) -> ParseReport {
        if self.unlisted > 0 {
            let detail = format!("{} more entries could not be imported", self.unlisted);
            self.skipped.push(invalid("…".to_owned(), "text", detail));
        }
        ParseReport {
            profiles: self.profiles,
            skipped: self.skipped,
            meta,
        }
    }
}

/// `text` with every share-link line emptied (line breaks kept). Those lines go to the share-link
/// importer; left in a Clash document that a paste mixes with links, they end the YAML reader
/// with a syntax error before the entry above them is taken.
fn without_link_lines(text: &str) -> Cow<'_, str> {
    if !text.lines().any(text::is_uri_line) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if !text::is_uri_line(line) {
            out.push_str(line);
        } else if line.ends_with('\n') {
            out.push('\n');
        }
    }
    Cow::Owned(out)
}

/// Only whitespace precedes byte `at` on its line (looks back over that whitespace only, so a
/// 16 MiB single-line body costs nothing).
fn starts_line(text: &str, at: usize) -> bool {
    text[..at]
        .chars()
        .rev()
        .find(|&c| matches!(c, '\n' | '\r') || !c.is_whitespace())
        .is_none_or(|c| matches!(c, '\n' | '\r'))
}

/// Base64 alphabet (either variant) and line breaks only, longer than a plain word. Spaces rule it
/// out, so prose never reads as a damaged blob.
fn looks_like_base64(text: &str) -> bool {
    let mut len = 0usize;
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' | b'-' | b'_' => len += 1,
            b'\r' | b'\n' => {}
            _ => return false,
        }
    }
    len >= 16
}

fn invalid(excerpt: String, scheme: &str, detail: String) -> Skipped {
    Skipped {
        excerpt,
        reason: SkipReason::Invalid {
            scheme: scheme.to_owned(),
            detail,
        },
    }
}

/// The entry that marks a list as cut at [`MAX_PROFILES`] (`profile` is the first one not
/// taken): a refresh must not take the unread keys as removed by the provider.
pub(crate) fn cut_marker(profile: &Profile) -> Skipped {
    let detail = format!("more than {MAX_PROFILES} keys: the rest were not read");
    invalid(profile_excerpt(profile), profile.kind.label(), detail)
}

/// Excerpt of a profile for a duplicate / over-limit entry: the redacted link it came from, else
/// its name and protocol (never a credential).
fn profile_excerpt(profile: &Profile) -> String {
    let text = match &profile.source {
        Source::Uri(line) => link_excerpt(line),
        _ => format!("{} ({})", profile.name, profile.kind.label()),
    };
    text.chars().take(80).collect()
}

/// `uri::excerpt` cut to `scheme://host:port`: a path can be the provider's access token, and a
/// broken line keeps whatever follows a stray `@` (fuzzing put a password or a JSON object there),
/// so only characters an authority can hold are shown.
fn link_excerpt(line: &str) -> String {
    let excerpt = uri::excerpt(line);
    let start = excerpt.find("://").map_or(0, |i| i + 3);
    match excerpt[start..].find(|c: char| !(c.is_alphanumeric() || ".-_:[]%".contains(c))) {
        Some(end) if !excerpt[start + end..].starts_with('…') => {
            format!("{}…", &excerpt[..start + end])
        }
        _ => excerpt,
    }
}

/// A deep link that cannot be parsed here, as the report's only entry. The excerpt shows the
/// scheme and a host that is a plain word (`happ://crypt4/…`), never the payload: encrypted links
/// exist to hide the subscription address.
fn link_skipped(link: &str, detail: String) -> ParseReport {
    let (scheme, rest) = link.split_once("://").unwrap_or_default();
    let scheme: String = scheme
        .chars()
        .take(16)
        .collect::<String>()
        .to_ascii_lowercase();
    let host = rest.split('/').next().unwrap_or_default();
    let plain = (1..=24).contains(&host.len())
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    let excerpt = if plain {
        format!("{scheme}://{host}/…")
    } else {
        format!("{scheme}://…")
    };
    ParseReport {
        skipped: vec![invalid(excerpt, &scheme, detail)],
        ..ParseReport::default()
    }
}

/// Fields of `from` that `meta` does not have yet.
fn fill_gaps(meta: &mut SubscriptionMeta, from: SubscriptionMeta) {
    let SubscriptionMeta {
        upload,
        download,
        total,
        expires_at,
        refresh_hours,
        title,
        web_page_url,
        support_url,
        announce,
    } = from;
    meta.upload = meta.upload.or(upload);
    meta.download = meta.download.or(download);
    meta.total = meta.total.or(total);
    meta.expires_at = meta.expires_at.or(expires_at);
    meta.refresh_hours = meta.refresh_hours.or(refresh_hours);
    meta.title = meta.title.take().or(title);
    meta.web_page_url = meta.web_page_url.take().or(web_page_url);
    meta.support_url = meta.support_url.take().or(support_url);
    meta.announce = meta.announce.take().or(announce);
}
