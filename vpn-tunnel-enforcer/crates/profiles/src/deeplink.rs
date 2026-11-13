//! App deep links (`happ://`, `mantaray://`, …) unwrapped to the text or URL they carry, the
//! remote-profile links of sing-box, Clash and Hiddify unwrapped to their subscription URL, and
//! AmneziaVPN keys (`vpn://`) unwrapped to the server description they encode.
use std::borrow::Cow;

use percent_encoding::percent_decode_str;
use serde_json::Value;
use vpnte_base::msg::Msg;

use crate::amnezia::{self, Payload};
use crate::common::b64::base64_text;
use crate::text::uri_candidates;

mod remote;
mod target;
#[cfg(test)]
mod tests;

/// Why a deep link could not be unwrapped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeepLinkError {
    #[error("encrypted {app} link ({variant})")]
    Encrypted { app: &'static str, variant: String },
    /// A Happ routing profile (`happ://routing/…`), not a subscription: the Apps page reads it
    /// ([`crate::text::parse_routing`]) and adds it to the user's own rules on the user's click.
    #[error("routing profile link")]
    RoutingProfile,
    #[error("unrecognised add payload")]
    AddPayloadUnrecognised,
    #[error("unknown deep link host {0}")]
    UnknownHost(String),
    /// A `vpn://` key that does not decode (damaged or truncated).
    #[error("damaged AmneziaVPN key")]
    AmneziaDamaged,
    /// A `vpn://` key carrying a protocol no engine of this app runs (`OpenVPN`).
    #[error("AmneziaVPN key with {0}")]
    AmneziaUnsupported(String),
    /// A link carrying a subscription in the local network (loopback, LAN, link-local): a web
    /// page or a chat must not make the app request it.
    #[error("deep link into a local network")]
    LocalTarget,
}

impl DeepLinkError {
    /// User-facing message (`profiles.deeplink.*`); it never carries the link's payload.
    pub fn msg(&self) -> Msg {
        match self {
            DeepLinkError::Encrypted { app, variant } => {
                let key = match *app {
                    HAPP => "profiles.deeplink.encryptedHapp",
                    MANTARAY => "profiles.deeplink.encryptedMantaray",
                    _ => "profiles.deeplink.encrypted",
                };
                Msg::new(key).arg("app", app).arg("variant", variant)
            }
            DeepLinkError::RoutingProfile => Msg::new("profiles.deeplink.routingProfile"),
            DeepLinkError::AddPayloadUnrecognised => {
                Msg::new("profiles.deeplink.addPayloadUnrecognised")
            }
            DeepLinkError::UnknownHost(link) => {
                Msg::new("profiles.deeplink.unknownHost").arg("link", link)
            }
            DeepLinkError::AmneziaDamaged => Msg::new("profiles.deeplink.amneziaDamaged"),
            DeepLinkError::AmneziaUnsupported(protocol) => {
                Msg::new("profiles.deeplink.amneziaUnsupported").arg("protocol", protocol)
            }
            DeepLinkError::LocalTarget => Msg::new("profiles.deeplink.localTarget"),
        }
    }
}

const HAPP: &str = "Happ";
const MANTARAY: &str = "MantaRay";

/// A client app whose links wrap a subscription URL or a key.
struct LinkApp {
    scheme: &'static str,
    name: &'static str,
    /// Hosts whose path is the wrapped payload.
    add_hosts: &'static [&'static str],
}

/// `happ://add` comes from providers' share buttons (Happ documents no such syntax);
/// `v2raytun://import` is documented by v2RayTun; `incy://` is the same plain wrapper.
const APPS: [LinkApp; 4] = [
    LinkApp {
        scheme: "happ",
        name: HAPP,
        add_hosts: &["add"],
    },
    LinkApp {
        scheme: "mantaray",
        name: MANTARAY,
        add_hosts: &["add", "import", "sub", "subscription"],
    },
    LinkApp {
        scheme: "v2raytun",
        name: "v2RayTun",
        add_hosts: &["import"],
    },
    LinkApp {
        scheme: "incy",
        name: "INCY",
        add_hosts: &["add", "import"],
    },
];

// Signature fixed by the lead.
/// `Ok(None)` when the input is not a deep link. Only a single line is a link; errors never
/// echo the payload (encrypted links exist to hide the subscription address).
pub fn unwrap_deeplink(input: &str) -> Result<Option<String>, DeepLinkError> {
    unwrap_with(input, Hosts::Internet)
}

/// [`unwrap_deeplink`] for a redirect's `Location`: the carried URL is not judged here. The
/// subscription fetcher judges every hop by the redirect's origin and the resolved addresses,
/// so a subscription the user runs in the LAN may redirect inside it and an internet one may not.
pub fn unwrap_redirect(input: &str) -> Result<Option<String>, DeepLinkError> {
    unwrap_with(input, Hosts::Any)
}

/// Which hosts a carried subscription URL may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hosts {
    /// Internet hosts only: the link came from a page, a chat or the clipboard.
    Internet,
    /// Any host: the caller judges the target itself.
    Any,
}

fn unwrap_with(input: &str, hosts: Hosts) -> Result<Option<String>, DeepLinkError> {
    let input = input.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if input.contains(['\n', '\r']) {
        return Ok(None);
    }
    let Some((scheme, after)) = input.split_once("://") else {
        return Ok(None);
    };
    if scheme.eq_ignore_ascii_case(amnezia::SCHEME) {
        return match amnezia::decode_key(input) {
            Some(Payload::Text(text)) => Ok(Some(text)),
            Some(Payload::Unsupported(protocol)) => {
                Err(DeepLinkError::AmneziaUnsupported(protocol.to_owned()))
            }
            None => Err(DeepLinkError::AmneziaDamaged),
        };
    }
    if let Some(carried) = remote::unwrap(scheme, after, hosts) {
        return carried.map(Some);
    }
    let Some(app) = APPS.iter().find(|a| scheme.eq_ignore_ascii_case(a.scheme)) else {
        return Ok(None);
    };
    let (host, rest) = after.split_once('/').unwrap_or((after, ""));
    if host.is_empty() {
        return Ok(None);
    }
    let host = host.to_ascii_lowercase();
    // `crypt`, `crypt2`…`crypt5`, `crypto`: RSA-encrypted subscription URLs whose key lives
    // inside the client app; Happ asks tools not to decrypt them. Refuse with guidance.
    if host == "crypto"
        || host
            .strip_prefix("crypt")
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(DeepLinkError::Encrypted {
            app: app.name,
            variant: host,
        });
    }
    // Routing profiles are offered on the Apps page, never added as a subscription: the
    // message says where.
    if app.name == HAPP && host == "routing" {
        return Err(DeepLinkError::RoutingProfile);
    }
    if app.add_hosts.contains(&host.as_str()) {
        return add_payload(rest, hosts).map(Some);
    }
    Err(DeepLinkError::UnknownHost(format!(
        "{}://{}",
        app.scheme,
        shown_host(&host)
    )))
}

/// The host as shown in an error: a short word, or `…` when it may be a payload without `/`.
fn shown_host(host: &str) -> &str {
    let plain = host.len() <= 24
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if plain { host } else { "…" }
}

/// Payload of an add/import link: a subscription URL or a key, as text, percent-encoded or
/// base64, or a JSON object `{"url": …}` (fallback `link`). Candidates are tried in order and
/// each one completely, so a key inside an earlier candidate wins over a URL in a later one.
fn add_payload(rest: &str, hosts: Hosts) -> Result<String, DeepLinkError> {
    let decoded = pct_decode(rest);
    let mut candidates: Vec<Cow<'_, str>> = Vec::with_capacity(3);
    if !decoded.trim().is_empty() {
        candidates.push(Cow::Borrowed(decoded.trim()));
    }
    if starts_http(rest) {
        candidates.push(Cow::Borrowed(rest));
    }
    // Base64 of the decoded form: senders percent-encode the padding (`%3D`) as often as not.
    if let Some(text) = base64_text(&decoded) {
        candidates.push(Cow::Owned(text.trim().to_owned()));
    }
    for candidate in &candidates {
        if starts_http(candidate) {
            return target::carried_url(candidate, hosts);
        }
        if let Some(target) = json_target(candidate) {
            return match starts_http(&target) {
                true => target::carried_url(&target, hosts),
                false => Ok(target),
            };
        }
        if let Some(uri) = first_link(candidate) {
            return Ok(uri.to_owned());
        }
    }
    Err(DeepLinkError::AddPayloadUnrecognised)
}

/// `{"url": …}` / `{"link": …}` payloads (provider share buttons), when the value is a
/// subscription URL or a key.
fn json_target(candidate: &str) -> Option<String> {
    if !candidate.starts_with('{') {
        return None;
    }
    let value: Value = serde_json::from_str(candidate).ok()?;
    let target = ["url", "link"].iter().find_map(|key| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    })?;
    if starts_http(target) {
        return Some(first_token(target).to_owned());
    }
    first_link(target).map(str::to_owned)
}

/// The first share link in `text` ([`uri_candidates`]: a line that starts with a known scheme
/// is taken whole, names may contain spaces; otherwise the first link inside a line).
fn first_link(text: &str) -> Option<&str> {
    uri_candidates(text).into_iter().next()
}

fn starts_http(text: &str) -> bool {
    let head = text.get(..8).unwrap_or(text).to_ascii_lowercase();
    head.starts_with("http://") || head.starts_with("https://")
}

/// A URL never contains raw whitespace; anything after it is not part of the link.
fn first_token(text: &str) -> &str {
    text.split_whitespace().next().unwrap_or(text)
}

/// `decodeURIComponent` semantics: a malformed escape or invalid UTF-8 leaves the text as is.
fn pct_decode(value: &str) -> Cow<'_, str> {
    let escapes_ok = value.match_indices('%').all(|(i, _)| {
        value
            .get(i + 1..i + 3)
            .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
    });
    if !escapes_ok {
        return Cow::Borrowed(value);
    }
    percent_decode_str(value)
        .decode_utf8()
        .unwrap_or(Cow::Borrowed(value))
}
