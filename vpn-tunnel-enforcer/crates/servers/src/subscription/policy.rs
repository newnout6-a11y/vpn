//! Pure rules of a fetch: where a redirect points, whether a redirect may be followed, and what an
//! unusable body looked like.
use std::net::IpAddr;

use url::Url;
use vpnte_core::net::is_public_ip;
use vpnte_profiles::text;

use crate::common::has_scheme;
use crate::model::{BodyKind, FetchOutcome};

/// Schemes a redirect target may name as is (old `normalizeSubscriptionRedirectLocation`).
fn is_known_target(text: &str) -> bool {
    ["http", "https", "happ", "mantaray"]
        .iter()
        .any(|s| has_scheme(text, s))
}

/// The target of a `Location` header, made absolute against `base` (old
/// `normalizeSubscriptionRedirectLocation`): panels send `<url>`, quoted URLs, `URL: https://…`,
/// percent-encoded URLs and app deep links. `None` for an empty header.
pub fn normalize_redirect(location: &str, base: &Url) -> Option<String> {
    let mut value = location.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(inner) = value.strip_prefix('<').and_then(|v| v.strip_suffix('>')) {
        value = inner.trim();
    }
    if value.len() >= 3 && value.starts_with(['"', '\'']) && value.ends_with(['"', '\'']) {
        value = value[1..value.len() - 1].trim();
    }
    value = strip_url_label(value);
    let decoded = percent_decode(value).map(|d| strip_url_label(d.trim()).to_owned());
    let value = match decoded {
        Some(d) if is_known_target(&d) => d,
        _ => value.to_owned(),
    };
    if value.starts_with("//") {
        return Some(format!("{}:{value}", base.scheme()));
    }
    if is_known_target(&value) {
        return Some(value);
    }
    Some(base.join(&value).map_or(value, String::from))
}

/// Strips a leading `url:` / `url=` label (any case, spaces around the separator).
fn strip_url_label(value: &str) -> &str {
    let Some(head) = value.get(..3) else {
        return value;
    };
    if !head.eq_ignore_ascii_case("url") {
        return value;
    }
    let rest = value[3..].trim_start();
    match rest.strip_prefix([':', '=']) {
        Some(rest) => rest.trim_start(),
        None => value,
    }
}

/// Strict percent-decoding (JavaScript `decodeURIComponent`): `None` on a broken escape or bytes
/// that are not UTF-8.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Why a redirect is not followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// `https` → `http`: the device headers would travel in clear text.
    Downgrade,
    /// A public origin pointing into a non-public address (S-29: the HWID must not reach the LAN
    /// or a cloud metadata service).
    PrivateTarget,
}

/// Whether the hop `from` → `to` must be refused. `origin_public`: the URL the user gave is
/// public (a subscription the user typed may itself live in the LAN, and then so may its
/// redirects); `to_addrs`: the target's addresses when known (IP literal or resolver answer).
pub(crate) fn refuse_hop(
    from: &Url,
    to: &Url,
    origin_public: bool,
    to_addrs: &[IpAddr],
) -> Option<Refusal> {
    if from.scheme() == "https" && to.scheme() == "http" {
        return Some(Refusal::Downgrade);
    }
    if origin_public && (is_local_name(to) || to_addrs.iter().any(|ip| !is_public_ip(*ip))) {
        return Some(Refusal::PrivateTarget);
    }
    None
}

/// `localhost` and `*.localhost`: local whatever DNS says.
pub(crate) fn is_local_name(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(name)) => {
            let name = name.to_ascii_lowercase();
            name == "localhost" || name.ends_with(".localhost")
        }
        _ => false,
    }
}

/// The address of an IP-literal host.
pub(crate) fn literal_ip(url: &Url) -> Option<IpAddr> {
    match url.host()? {
        url::Host::Ipv4(ip) => Some(ip.into()),
        url::Host::Ipv6(ip) => Some(ip.into()),
        url::Host::Domain(_) => None,
    }
}

/// What a body that gave no profile was (old `describeSubscriptionBody`). Nothing but whitespace,
/// metadata lines or an empty base64 layer is the provider's empty list (the classic "trial over"
/// answer of Marzban / 3X-UI panels); anything else is an unusable body of some kind.
pub fn classify_body(body: &str) -> FetchOutcome {
    let (_, rest) = text::body_meta(body.trim_start_matches('\u{feff}'));
    let rest = rest.trim();
    if rest.is_empty()
        || text::layers(rest)
            .iter()
            .skip(1)
            .any(|l| l.trim().is_empty())
    {
        return FetchOutcome::EmptyList;
    }
    let mut end = rest.len().min(64 * 1024);
    while !rest.is_char_boundary(end) {
        end -= 1;
    }
    let head = &rest[..end];
    let kind = match head.as_bytes().first() {
        _ if is_encrypted(head) => BodyKind::Encrypted,
        Some(b'<') => BodyKind::Html,
        Some(b'{' | b'[') => BodyKind::Json,
        _ if names_a_config_key(head) => BodyKind::Json,
        _ if is_base64_blob(rest) => BodyKind::Base64,
        _ if head.contains("://") => BodyKind::Uris,
        _ => BodyKind::Other,
    };
    FetchOutcome::Unparseable(kind)
}

/// A list encrypted for the provider's own app: an app link to an encrypted payload
/// (`happ://crypt5/…`, `v2raytun://crypt/…`, `incy://crypt1/…`) or an age file (Remnawave's
/// response rules encrypt with age1 / age1pq1). Never decrypted (owner decision 12.11.2026).
fn is_encrypted(head: &str) -> bool {
    let first = head
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let crypt_link = first.split_once("://").is_some_and(|(scheme, rest)| {
        !scheme.is_empty()
            && scheme.bytes().all(|b| b.is_ascii_alphanumeric())
            && rest.starts_with("crypt")
    });
    crypt_link
        || first.starts_with("age-encryption.org/")
        || first.starts_with("-----begin age encrypted file-----")
}

/// `"outbounds":` / `'proxies':`-style keys anywhere in `text` (any case).
fn names_a_config_key(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["outbounds", "xrayfullconfig", "config", "proxies"]
        .iter()
        .any(|key| {
            ['"', '\''].iter().any(|q| {
                let quoted = format!("{q}{key}{q}");
                lower
                    .match_indices(&quoted)
                    .any(|(at, m)| lower[at + m.len()..].trim_start().starts_with(':'))
            })
        })
}

/// At least 64 base64 / base64url characters and nothing else but whitespace.
fn is_base64_blob(text: &str) -> bool {
    let mut count = 0usize;
    for b in text.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')) {
            return false;
        }
        count += 1;
    }
    count >= 64
}
