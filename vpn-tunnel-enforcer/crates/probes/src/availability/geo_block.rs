//! Geo-block scoring (old `geoBlockDetect.ts`, ported verbatim): an HTTP 200 is not "usable"
//! when the page says "not available in your country". Signals, strongest first: the
//! differential between the protected and the direct render, hard HTTP statuses, the final URL
//! shape, and marker text (trusted only on interstitial-sized pages).
use std::sync::LazyLock;

use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use vpnte_base::Msg;

/// What one page fetch looked like (HTTP GET, B-UA-10: no hidden browser).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PageSignal {
    pub requested_url: String,
    pub final_url: Option<String>,
    pub title: Option<String>,
    /// Lowercased visible text, at most [`TEXT_SAMPLE_CHARS`] chars.
    pub text_sample: String,
    /// Length of the whole visible text, in chars.
    pub text_length: usize,
    pub http_status: Option<u16>,
}

/// Outcome of a scoring.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GeoVerdict {
    pub blocked: bool,
    /// 0..=1; `blocked` from 0.6.
    pub confidence: f32,
    pub reasons: Vec<GeoReason>,
}

/// Why a page was judged geo-blocked (`probes.availability.geo.*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GeoReason {
    /// HTTP 451 (Unavailable For Legal Reasons).
    Http451,
    /// HTTP 403 on a short page.
    Http403Short,
    /// Redirected to a stub page.
    StubRedirect,
    /// Block marker in the title.
    TitleMarker,
    /// Block text on a short page.
    ShortPageMarker,
    /// Mention on a long page (weak signal).
    LongPageMarker,
    /// The protected path did not get a normal page either (differential inconclusive).
    ForeignAlsoBlocked,
    /// Only the direct path was redirected to a stub.
    LocalOnlyStubRedirect,
    /// Full page through the protected path, almost empty directly.
    LocalNearlyEmpty,
    /// A block marker directly but not through the protected path.
    LocalOnlyMarker,
}

impl GeoReason {
    /// User text of the reason.
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            GeoReason::Http451 => "probes.availability.geo.http451",
            GeoReason::Http403Short => "probes.availability.geo.http403Short",
            GeoReason::StubRedirect => "probes.availability.geo.stubRedirect",
            GeoReason::TitleMarker => "probes.availability.geo.titleMarker",
            GeoReason::ShortPageMarker => "probes.availability.geo.shortPageMarker",
            GeoReason::LongPageMarker => "probes.availability.geo.longPageMarker",
            GeoReason::ForeignAlsoBlocked => "probes.availability.geo.foreignAlsoBlocked",
            GeoReason::LocalOnlyStubRedirect => "probes.availability.geo.localOnlyStubRedirect",
            GeoReason::LocalNearlyEmpty => "probes.availability.geo.localNearlyEmpty",
            GeoReason::LocalOnlyMarker => "probes.availability.geo.localOnlyMarker",
        })
    }
}

/// Below this text length a page is an interstitial (block / error page), not content.
pub const INTERSTITIAL_TEXT_MAX: usize = 2200;
/// Visible text kept for marker matching.
pub const TEXT_SAMPLE_CHARS: usize = 8000;

const BLOCK_URL_PATTERNS: [&str; 13] = [
    r"/sorry(?:/|\b)",
    r"/unavailable(?:/|\b)",
    r"/not-?available(?:/|\b)",
    r"/unsupported[-_]?country",
    r"/geo[-_]?block",
    r"/geoblock",
    r"/region[-_]?block",
    r"/blocked(?:/|\b)",
    r"/restricted(?:/|\b)",
    r"[?&]error=country",
    r"[?&]reason=geo",
    r"country[_-]?unsupported",
    r"not[_-]?in[_-]?region",
];

static BLOCK_URLS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new(BLOCK_URL_PATTERNS.iter().map(|p| format!("(?i){p}"))).expect("static regex")
});

/// Lowercase block phrases (en, ru, es, pt, de, fr).
const BLOCK_MARKERS: [&str; 41] = [
    "not available in your country",
    "isn't available in your country",
    "is not available in your country",
    "not available in your region",
    "not supported in your country",
    "not supported in your region",
    "isn't supported in your country",
    "not supported in your location",
    "not available in your location",
    "services are not available in your country",
    "this content is not available",
    "content is not available in your",
    "unavailable for legal reasons",
    "not available in the country",
    "access from your country",
    "access from your region",
    "restricted in your region",
    "restricted in your country",
    "blocked in your country",
    "available in your country or region",
    "geographic restriction",
    "geo-restricted",
    "due to your geographic",
    "in your country",
    "in your region",
    "in your location",
    "недоступно в вашей стране",
    "недоступен в вашей стране",
    "недоступна в вашей стране",
    "недоступно в вашем регионе",
    "недоступен в вашем регионе",
    "не доступно в вашей стране",
    "в вашей стране недоступ",
    "в вашем регионе недоступ",
    "сервис недоступен в вашей",
    "недоступно в вашем местоположении",
    "ограничен доступ из вашей страны",
    "no disponible en tu país",
    "não está disponível no seu país",
    "nicht in deinem land verfügbar",
    "n'est pas disponible dans votre pays",
];

fn block_url(url: Option<&str>) -> bool {
    url.is_some_and(|u| !u.is_empty() && BLOCK_URLS.is_match(&u.to_lowercase()))
}

fn has_marker(text: &str) -> bool {
    BLOCK_MARKERS.iter().any(|m| text.contains(m))
}

fn verdict(score: f32, reasons: Vec<GeoReason>) -> GeoVerdict {
    let confidence = score.min(1.0);
    GeoVerdict {
        blocked: confidence >= 0.6,
        confidence,
        reasons,
    }
}

/// Scores one page (the only signal when just one path reached the origin). Conservative on
/// long pages.
pub fn score_single_page(sig: &PageSignal) -> GeoVerdict {
    let mut reasons = Vec::new();
    let mut score = 0.0;
    if sig.http_status == Some(451) {
        reasons.push(GeoReason::Http451);
        score += 0.9;
    } else if sig.http_status == Some(403) && sig.text_length < INTERSTITIAL_TEXT_MAX {
        reasons.push(GeoReason::Http403Short);
        score += 0.5;
    }
    if block_url(sig.final_url.as_deref()) {
        reasons.push(GeoReason::StubRedirect);
        score += 0.6;
    }
    let title = sig.title.as_deref().unwrap_or_default().to_lowercase();
    if !title.is_empty() && has_marker(&title) {
        reasons.push(GeoReason::TitleMarker);
        score += 0.6;
    }
    if has_marker(&sig.text_sample) {
        if sig.text_length <= INTERSTITIAL_TEXT_MAX {
            reasons.push(GeoReason::ShortPageMarker);
            score += 0.6;
        } else {
            reasons.push(GeoReason::LongPageMarker);
            score += 0.2;
        }
    }
    verdict(score, reasons)
}

/// Decides whether the LOCAL (direct) render is geo-blocked, given a FOREIGN (protected) render
/// that is assumed to work. Language-independent: redirects, size gaps and marker divergence.
pub fn compare_renders(foreign: &PageSignal, local: &PageSignal) -> GeoVerdict {
    if score_single_page(foreign).blocked {
        return GeoVerdict {
            blocked: false,
            confidence: 0.0,
            reasons: vec![GeoReason::ForeignAlsoBlocked],
        };
    }
    let mut reasons = Vec::new();
    let mut score = 0.0;
    let single = score_single_page(local);
    if single.blocked {
        reasons.extend(single.reasons);
        score += single.confidence;
    }
    if block_url(local.final_url.as_deref()) && !block_url(foreign.final_url.as_deref()) {
        reasons.push(GeoReason::LocalOnlyStubRedirect);
        score += 0.7;
    }
    if local.text_length < INTERSTITIAL_TEXT_MAX
        && foreign.text_length > local.text_length * 3
        && foreign.text_length > 3000
    {
        reasons.push(GeoReason::LocalNearlyEmpty);
        score += 0.5;
    }
    let text = |s: &PageSignal| {
        format!(
            "{}\n{}",
            s.title.as_deref().unwrap_or_default(),
            s.text_sample
        )
        .to_lowercase()
    };
    let (local_text, foreign_text) = (text(local), text(foreign));
    if BLOCK_MARKERS
        .iter()
        .any(|m| local_text.contains(m) && !foreign_text.contains(m))
    {
        reasons.push(GeoReason::LocalOnlyMarker);
        score += 0.6;
    }
    verdict(score, reasons)
}

static HIDDEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?is)<!--.*?-->|<head\b.*?</head\s*>|<script\b.*?</script\s*>|<style\b.*?</style\s*>|<noscript\b.*?</noscript\s*>|<template\b.*?</template\s*>",
    )
    .expect("static regex")
});
static TITLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<title\b[^>]*>(.*?)</title\s*>").expect("static regex"));
static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<[^>]*>").expect("static regex"));
static ENTITY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"&(#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[a-zA-Z]{2,8});").expect("static regex")
});

/// Builds the page signal from a fetched HTML body (what a browser's `innerText` roughly
/// shows): head, scripts, styles and comments removed, tags stripped, entities decoded,
/// whitespace collapsed, lowercased. JS-only notices of single-page apps are not seen.
pub fn html_to_signal(
    requested_url: &str,
    final_url: Option<&str>,
    http_status: Option<u16>,
    html: &str,
) -> PageSignal {
    let title = TITLE
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| collapse(&decode_entities(&TAG.replace_all(m.as_str(), " "))))
        .filter(|t| !t.is_empty());
    let visible = HIDDEN.replace_all(html, " ");
    let visible = TAG.replace_all(&visible, " ");
    let text = collapse(&decode_entities(&visible)).to_lowercase();
    let text_length = text.chars().count();
    let text_sample = text.chars().take(TEXT_SAMPLE_CHARS).collect();
    PageSignal {
        requested_url: requested_url.to_owned(),
        final_url: final_url.map(str::to_owned),
        title,
        text_sample,
        text_length,
        http_status,
    }
}

fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn decode_entities(text: &str) -> String {
    ENTITY
        .replace_all(text, |caps: &regex::Captures<'_>| {
            let name = &caps[1];
            let code = if let Some(hex) = name.strip_prefix("#x").or(name.strip_prefix("#X")) {
                u32::from_str_radix(hex, 16).ok()
            } else if let Some(dec) = name.strip_prefix('#') {
                dec.parse().ok()
            } else {
                named_entity(name)
            };
            code.and_then(char::from_u32)
                .map_or_else(|| caps[0].to_owned(), String::from)
        })
        .into_owned()
}

fn named_entity(name: &str) -> Option<u32> {
    Some(match name {
        "amp" => '&' as u32,
        "lt" => '<' as u32,
        "gt" => '>' as u32,
        "quot" => '"' as u32,
        "apos" => '\'' as u32,
        "nbsp" => ' ' as u32,
        "laquo" => 0xAB,
        "raquo" => 0xBB,
        "lsquo" => 0x2018,
        "rsquo" => 0x2019,
        "ldquo" => 0x201C,
        "rdquo" => 0x201D,
        "ndash" => 0x2013,
        "mdash" => 0x2014,
        "hellip" => 0x2026,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PageSignal {
        PageSignal {
            requested_url: "https://example.com".into(),
            final_url: Some("https://example.com".into()),
            title: Some("Example".into()),
            text_sample: "welcome to example, this is a normal page with content".into(),
            text_length: 54,
            http_status: Some(200),
        }
    }

    fn with(text: &str, len: usize) -> PageSignal {
        PageSignal {
            text_sample: text.into(),
            text_length: len,
            ..base()
        }
    }

    /// geoBlockDetect.test.ts: single-page scoring.
    #[test]
    fn single_page_scores() {
        assert!(!score_single_page(&base()).blocked);
        let v = score_single_page(&PageSignal {
            http_status: Some(451),
            ..base()
        });
        assert!(v.blocked && v.confidence >= 0.9);
        let short_403 = PageSignal {
            http_status: Some(403),
            text_length: 120,
            ..base()
        };
        assert!(!score_single_page(&short_403).blocked, "0.5 < 0.6");
        let marked = PageSignal {
            text_sample: "access denied in your country".into(),
            ..short_403
        };
        assert!(score_single_page(&marked).blocked);
    }

    /// geoBlockDetect.test.ts: URL shape, markers on short pages, long articles, titles.
    #[test]
    fn urls_markers_and_titles() {
        let redirected = PageSignal {
            final_url: Some("https://site.com/sorry/?error=country_unsupported".into()),
            ..base()
        };
        assert!(score_single_page(&redirected).blocked);
        assert!(score_single_page(&with("gemini isn't available in your country yet", 41)).blocked);
        assert!(score_single_page(&with("сервис недоступен в вашей стране", 33)).blocked);
        let article = with("long article ... not available in your country ...", 50_000);
        assert!(!score_single_page(&article).blocked);
        let titled = PageSignal {
            title: Some("Not available in your region".into()),
            ..base()
        };
        assert!(score_single_page(&titled).blocked);
    }

    fn gemini() -> PageSignal {
        PageSignal {
            requested_url: "https://gemini.google.com/app".into(),
            final_url: Some("https://gemini.google.com/app".into()),
            title: Some("Gemini".into()),
            text_sample: "a".repeat(8000),
            text_length: 40_000,
            http_status: Some(200),
        }
    }

    /// geoBlockDetect.test.ts: differential comparison of the two renders.
    #[test]
    fn differential_renders() {
        let foreign = gemini();
        let notice = PageSignal {
            title: Some("Gemini".into()),
            ..with("gemini isn't available in your country", 42)
        };
        assert!(compare_renders(&foreign, &notice).blocked);

        let local_stub = PageSignal {
            final_url: Some("https://site.com/unavailable".into()),
            ..with("short page", 200)
        };
        let foreign_home = PageSignal {
            final_url: Some("https://site.com/home".into()),
            ..with("home", 9000)
        };
        assert!(compare_renders(&foreign_home, &local_stub).blocked);

        assert!(!compare_renders(&foreign, &foreign.clone()).blocked);

        let foreign_451 = PageSignal {
            http_status: Some(451),
            ..gemini()
        };
        let v = compare_renders(&foreign_451, &notice);
        assert!(!v.blocked);
        assert_eq!(v.confidence, 0.0);
        assert_eq!(v.reasons, vec![GeoReason::ForeignAlsoBlocked]);

        let similar_foreign = with("a normal app page with the same layout", 1500);
        let similar_local = with("this content is not available in your region", 1400);
        assert!(compare_renders(&similar_foreign, &similar_local).blocked);
    }

    #[test]
    fn html_becomes_visible_text() {
        let html = "<html><head><title> Not&nbsp;available &amp; more </title>\
            <style>.x{}</style></head><body><script>var t='in your country'</script>\
            <!-- in your region --><h1>Hello&#33;</h1><p>Isn&#x27;t   here</p></body></html>";
        let s = html_to_signal("https://a.b/", Some("https://a.b/x"), Some(200), html);
        assert_eq!(s.title.as_deref(), Some("Not available & more"));
        assert_eq!(s.text_sample, "hello! isn't here");
        assert_eq!(s.text_length, 17);
        assert_eq!(s.final_url.as_deref(), Some("https://a.b/x"));
        let long = format!("<p>{}</p>", "x".repeat(9000));
        let s = html_to_signal("https://a.b/", None, None, &long);
        assert_eq!(s.text_length, 9000);
        assert_eq!(s.text_sample.len(), TEXT_SAMPLE_CHARS);
    }
}
