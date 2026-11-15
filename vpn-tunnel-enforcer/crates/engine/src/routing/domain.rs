//! User domain rules: the validated pattern, host matching that mirrors the emitted sing-box
//! matchers, and text-list import.
use std::collections::HashSet;
use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vpnte_base::{AppError, AppResult, Msg};

/// Longest pattern sing-box can ever see (a DNS name).
pub const MAX_PATTERN_LEN: usize = 253;
/// Most rules one document keeps: a 4 MiB list must not become a 300 000-rule config.
pub const MAX_RULES: usize = 10_000;
/// Largest list file accepted for import.
pub const MAX_LIST_BYTES: u64 = 4 * 1024 * 1024;

/// What a matching connection does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainAction {
    Vpn,
    Direct,
    Block,
}

/// A validated domain pattern; the persisted form is its `Display` (`x.com`, `*.x.com`, `~kw`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DomainPattern {
    /// `x.com`: the apex and every subdomain (owner decision 10.4 «B»).
    Exact(String),
    /// `*.x.com`: subdomains only.
    Subdomains(String),
    /// `~kw`: any host containing `kw`. Explicit, because a bare `ru` silently matched
    /// `crunchyroll.com` in the old app.
    Keyword(String),
}

/// Why a pattern was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    #[error("empty domain pattern")]
    Empty,
    #[error("domain pattern longer than 253 characters")]
    TooLong,
    #[error("IP literal instead of a domain")]
    IpLiteral,
    #[error("dotless name without the ~ keyword prefix")]
    NeedsDot,
    #[error("invalid characters or labels in a domain pattern")]
    Invalid,
}

impl PatternError {
    /// User-facing explanation.
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            PatternError::Empty => "engine.routing.domain.empty",
            PatternError::TooLong => "engine.routing.domain.tooLong",
            PatternError::IpLiteral => "engine.routing.domain.ipLiteral",
            PatternError::NeedsDot => "engine.routing.domain.needsDot",
            PatternError::Invalid => "engine.routing.domain.invalid",
        })
    }
}

impl From<PatternError> for AppError {
    fn from(err: PatternError) -> Self {
        AppError::validation(err.msg()).with_source(err)
    }
}

impl DomainPattern {
    /// Parses user input: trims, lower-cases, takes the host of a pasted URL, strips a path and
    /// trailing dots, converts IDN to punycode (what sing-box sees in SNI) and checks the labels.
    pub fn parse(raw: &str) -> Result<Self, PatternError> {
        let t = raw.trim().to_lowercase();
        if let Some(kw) = t.strip_prefix('~') {
            return keyword(kw.trim());
        }
        let t = normalize(&t);
        if t.is_empty() {
            return Err(PatternError::Empty);
        }
        if let Some(base) = t.strip_prefix("*.") {
            return name(base, true).map(DomainPattern::Subdomains);
        }
        name(&t, false).map(DomainPattern::Exact)
    }

    /// The old app's dotless patterns were keywords: keep that meaning, visibly (`~word`).
    pub fn parse_legacy(raw: &str) -> Result<Self, PatternError> {
        match Self::parse(raw) {
            Err(PatternError::NeedsDot) => {
                Self::parse(&format!("~{}", normalize(&raw.trim().to_lowercase())))
            }
            other => other,
        }
    }

    /// True when `host` matches, exactly as the sing-box matcher emitted for this pattern.
    pub fn matches(&self, host: &str) -> bool {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.is_empty() {
            return false;
        }
        match self {
            DomainPattern::Exact(p) => h == *p || is_subdomain(&h, p),
            DomainPattern::Subdomains(b) => is_subdomain(&h, b),
            DomainPattern::Keyword(k) => h.contains(k.as_str()),
        }
    }
}

fn is_subdomain(host: &str, base: &str) -> bool {
    host.len() > base.len() + 1
        && host.ends_with(base)
        && host.as_bytes()[host.len() - base.len() - 1] == b'.'
}

/// The old normalisation (`domainRouting.ts:58-72`): URL → host, else cut at `/?#`; trailing
/// dots removed. Input is already trimmed and lower-cased; the text before a cut is trimmed
/// again, so a list line `x.com # note` is `x.com` (the old app re-trimmed it on every use).
fn normalize(t: &str) -> String {
    let cut = |s: &str| -> String {
        let end = s.find(['/', '?', '#']).unwrap_or(s.len());
        s[..end].trim_end().trim_end_matches('.').to_owned()
    };
    if t.starts_with("*.") {
        return cut(t);
    }
    if t.contains("://")
        && let Some(host) = url::Url::parse(t)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
    {
        return host.trim_end_matches('.').to_owned();
    }
    cut(t)
}

/// A keyword: non-empty ASCII `[a-z0-9._-]` with at least one letter or digit, so an empty or
/// all-punctuation keyword (which sing-box would match against every host) cannot exist.
fn keyword(kw: &str) -> Result<DomainPattern, PatternError> {
    if kw.is_empty() {
        return Err(PatternError::Empty);
    }
    if kw.len() > MAX_PATTERN_LEN {
        return Err(PatternError::TooLong);
    }
    let allowed = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c);
    if !kw.chars().all(allowed) || !kw.chars().any(|c| c.is_ascii_alphanumeric()) {
        return Err(PatternError::Invalid);
    }
    Ok(DomainPattern::Keyword(kw.to_owned()))
}

/// A host name after IDNA: labels of `[a-z0-9_-]{1,63}` joined by single dots, ≤ 253 chars.
/// `single_label` allows `*.ru`-style bases; a bare dotless name needs the `~` prefix.
fn name(s: &str, single_label: bool) -> Result<String, PatternError> {
    if s.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        return Err(PatternError::IpLiteral);
    }
    let ascii = match url::Host::parse(s) {
        Ok(url::Host::Domain(d)) => d,
        Ok(url::Host::Ipv4(_) | url::Host::Ipv6(_)) => return Err(PatternError::IpLiteral),
        Err(_) => return Err(PatternError::Invalid),
    };
    if ascii.len() > MAX_PATTERN_LEN {
        return Err(PatternError::TooLong);
    }
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    };
    if !ascii.split('.').all(label_ok) {
        return Err(PatternError::Invalid);
    }
    if !single_label && !ascii.contains('.') {
        return Err(PatternError::NeedsDot);
    }
    Ok(ascii)
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainPattern::Exact(p) => f.write_str(p),
            DomainPattern::Subdomains(b) => write!(f, "*.{b}"),
            DomainPattern::Keyword(k) => write!(f, "~{k}"),
        }
    }
}

impl FromStr for DomainPattern {
    type Err = PatternError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for DomainPattern {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DomainPattern {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// One user rule; its position in the list is its priority (first match wins).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRule {
    pub id: Uuid,
    pub pattern: DomainPattern,
    pub action: DomainAction,
}

impl DomainRule {
    /// A rule with a fresh id.
    pub fn new(pattern: DomainPattern, action: DomainAction) -> Self {
        Self {
            id: Uuid::new_v4(),
            pattern,
            action,
        }
    }
}

/// The rule that decides `host` among the user rules, in the generated order: block rules
/// first (`plan` hoists them above everything), then the others in list order.
pub fn first_match<'a>(rules: &'a [DomainRule], host: &str) -> Option<&'a DomainRule> {
    let block = |r: &&DomainRule| r.action == DomainAction::Block;
    let hit = |r: &&DomainRule| r.pattern.matches(host);
    (rules.iter().filter(block).find(hit)).or_else(|| rules.iter().filter(|r| !block(r)).find(hit))
}

/// Result of reading a text list of patterns (one per line).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListImport {
    /// Valid patterns in file order, first occurrence only.
    pub patterns: Vec<DomainPattern>,
    /// Lines that were not valid patterns.
    pub invalid: usize,
    /// Lines repeating an earlier pattern.
    pub duplicates: usize,
}

/// Reads a list file the user picked: a regular file of at most [`MAX_LIST_BYTES`], read
/// once, decoded as UTF-8 (invalid bytes become U+FFFD and fail as patterns). Blocking.
pub fn read_list_file(path: &Path) -> AppResult<String> {
    let refused = || AppError::validation(Msg::new("engine.routing.domain.importFile"));
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() || meta.len() > MAX_LIST_BYTES {
        return Err(refused());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_LIST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    // The file may have grown after the size check.
    if bytes.len() as u64 > MAX_LIST_BYTES {
        return Err(refused());
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Parses a list file's text: a leading BOM is dropped (Rust's `trim` keeps U+FEFF), blank
/// lines and `#` comment lines are skipped, every other line must be a valid pattern.
pub fn parse_list(text: &str) -> ListImport {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = ListImport::default();
    // A 4 MiB list holds ~300 000 lines: deduplicate by hash, not by scanning the output.
    let mut seen = HashSet::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match DomainPattern::parse(line) {
            Ok(p) if seen.insert(p.clone()) => out.patterns.push(p),
            Ok(_) => out.duplicates += 1,
            Err(_) => out.invalid += 1,
        }
    }
    out
}

#[cfg(test)]
#[path = "domain_tests.rs"]
mod tests;
