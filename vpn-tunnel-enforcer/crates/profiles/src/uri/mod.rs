//! Share-link importer: one `scheme://…` line -> [`Profile`].
//!
//! Every value is percent-decoded exactly once and `+` stays `+` (base64 keys and passwords
//! contain it). Provider values are stored as given: uTLS, ALPN and other defaults belong to the
//! emitter, so a re-export stays faithful to the source. Skip reasons carry no credentials: the
//! details are fixed English phrases, and only scheme, transport and plugin names (short
//! identifier-like tokens) are echoed.
use crate::common::fields::{display_name, reality_conflict};
use crate::model::{Host, Kind, Profile, SkipReason, Source};

mod parts;
mod proxy;
mod quic;
mod ss;
mod stream;
mod v2ray;
mod wg;

#[cfg(test)]
mod tests;

/// Why a link was not imported, before the scheme is attached.
enum Fail {
    /// Malformed link: an English diagnostic that never quotes a value from the link.
    Invalid(String),
    Skip(SkipReason),
}

type Res<T> = Result<T, Fail>;

fn bad<T>(detail: impl Into<String>) -> Res<T> {
    Err(Fail::Invalid(detail.into()))
}

fn skip<T>(reason: SkipReason) -> Res<T> {
    Err(Fail::Skip(reason))
}

/// Excerpt of a link for a skipped entry ([`Skipped::excerpt`](crate::model::Skipped)):
/// `scheme://host:port` at most 80 chars, `…` marking a cut; a body without `@` (VMess / SS
/// base64, a credential) becomes `scheme://…`.
pub fn excerpt(line: &str) -> String {
    let head = line.trim().split(['?', '#']).next().unwrap_or_default();
    let excerpt = match head.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.rsplit_once('@').map_or("", |(_, host)| host);
            // A path can be an access token, and in a broken line whatever follows a stray `@`
            // can be a password: only characters an authority holds are shown.
            let end = host
                .find(|c: char| !(c.is_alphanumeric() || ".-_:[]%".contains(c)))
                .unwrap_or(host.len());
            let cut = if end < host.len() || host.is_empty() {
                "…"
            } else {
                ""
            };
            format!("{scheme}://{}{cut}", &host[..end])
        }
        None => "…".to_owned(),
    };
    excerpt.chars().take(80).collect()
}

/// Parses one share link (`scheme://…`) into a typed profile.
pub fn parse_uri(line: &str) -> Result<Profile, SkipReason> {
    let line = line.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    let Some((scheme, rest)) = split_scheme(line) else {
        return Err(SkipReason::UnknownScheme(String::new()));
    };
    let (body, fragment) = parts::split_once(rest, '#');
    let meta = Meta::new(fragment, line);
    let parsed = match scheme.as_str() {
        "vless" => v2ray::vless(body, meta),
        "vmess" => v2ray::vmess(body, meta),
        "trojan" => v2ray::trojan(body, meta),
        "ss" => ss::shadowsocks(body, meta),
        "hysteria2" | "hy2" => quic::hysteria2(body, meta),
        "tuic" => quic::tuic(body, meta),
        "naive" | "naive+https" => proxy::naive(body, meta, false),
        "naive+quic" => proxy::naive(body, meta, true),
        "anytls" => proxy::anytls(body, meta),
        "wireguard" | "wg" => wg::wireguard(body, meta),
        "socks" | "socks5" | "socks5h" => proxy::socks(body, meta),
        "http" => proxy::http(body, meta, false),
        "https" => proxy::http(body, meta, true),
        // A ShadowTLS outbound only dials for an inner Shadowsocks; chains come from JSON / Clash.
        "shadowtls" => skip(SkipReason::ShadowTlsNeedsInner),
        _ => skip(SkipReason::UnknownScheme(scheme.clone())),
    };
    let parsed = parsed.and_then(|p| match reality_conflict(&p) {
        Some(detail) => Err(Fail::Invalid(detail.to_owned())),
        None => Ok(p),
    });
    parsed.map_err(|fail| match fail {
        Fail::Invalid(detail) => SkipReason::Invalid { scheme, detail },
        Fail::Skip(reason) => reason,
    })
}

/// `scheme://rest` with the scheme lower-cased; `None` when the line has no such prefix.
fn split_scheme(line: &str) -> Option<(String, &str)> {
    let (scheme, rest) = line.split_once("://")?;
    let valid = (1..=32).contains(&scheme.len())
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
    valid.then(|| (scheme.to_ascii_lowercase(), rest))
}

/// Name, description and source line shared by every scheme.
struct Meta {
    name: Option<String>,
    description: Option<String>,
    source: String,
}

impl Meta {
    fn new(fragment: Option<&str>, line: &str) -> Self {
        let (name, description) = parts::name_and_description(fragment);
        Self {
            name,
            description,
            source: line.to_owned(),
        }
    }

    /// A profile without TLS, transport, mux or notes; the scheme fills those in.
    fn profile(self, server: Host, port: u16, kind: Kind) -> Profile {
        Profile {
            name: self
                .name
                .unwrap_or_else(|| display_name(kind.label()).to_owned()),
            description: self.description,
            server,
            port,
            kind,
            tls: None,
            transport: None,
            mux: None,
            dial: Default::default(),
            native_xray: None,
            singbox_extra: Default::default(),
            source: Source::Uri(self.source),
            notes: Vec::new(),
        }
    }
}
