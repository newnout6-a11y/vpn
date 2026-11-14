//! Lexical pieces of a share link: name and description, query parameters, authority, decoding.
use std::net::{IpAddr, Ipv6Addr};

use percent_encoding::percent_decode_str;

use super::{Res, bad};
use crate::common::b64::base64_text;
use crate::common::fields::{NAME_MAX_CHARS, clean_text, go_duration_ms, parse_host, parse_port};
use crate::model::Host;

const DESCRIPTION_MAX_CHARS: usize = 1024;

/// Splits at the first `sep`: `(before, Some(after))`, or `(s, None)` when absent.
pub(super) fn split_once(s: &str, sep: char) -> (&str, Option<&str>) {
    match s.split_once(sep) {
        Some((before, after)) => (before, Some(after)),
        None => (s, None),
    }
}

/// Percent-decodes once (`+` stays `+`); text that does not decode to UTF-8 is kept raw.
pub(super) fn pct(s: &str) -> String {
    match percent_decode_str(s).decode_utf8() {
        Ok(text) => text.into_owned(),
        Err(_) => s.to_owned(),
    }
}

/// Display name and Happ `serverDescription` from the raw fragment.
pub(super) fn name_and_description(fragment: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(fragment) = fragment else {
        return (None, None);
    };
    let decoded = pct(fragment);
    // Happ appends `?serverDescription=<base64>` to the title inside the fragment.
    const MARKER: &str = "?serverdescription=";
    match decoded.to_ascii_lowercase().find(MARKER) {
        Some(at) => (
            name(&decoded[..at]),
            description(&decoded[at + MARKER.len()..]),
        ),
        None => (name(&decoded), None),
    }
}

/// Display name ([`clean_text`], at most 256 chars); empty -> `None`.
pub(super) fn name(text: &str) -> Option<String> {
    non_empty(clean_text(text, NAME_MAX_CHARS))
}

/// Happ server description: base64 text when it decodes strictly, else the raw value.
pub(super) fn description(value: &str) -> Option<String> {
    // Plain words must not be mistaken for base64 that happens to decode.
    let decoded = (!value.contains(char::is_whitespace))
        .then(|| base64_text(value))
        .flatten()
        .filter(|text| {
            !text
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        });
    non_empty(clean_text(
        decoded.as_deref().unwrap_or(value),
        DESCRIPTION_MAX_CHARS,
    ))
}

/// `None` for an empty string.
pub(super) fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

/// `1|true|yes|on`, any case.
pub(super) fn truthy(value: &str) -> bool {
    ["1", "true", "yes", "on"]
        .iter()
        .any(|t| value.trim().eq_ignore_ascii_case(t))
}

/// `0|false|no|off`, any case.
pub(super) fn falsy(value: &str) -> bool {
    ["0", "false", "no", "off"]
        .iter()
        .any(|t| value.trim().eq_ignore_ascii_case(t))
}

/// Query parameters, each decoded once; names compare ASCII-case-insensitively. No `Debug`:
/// values are credentials.
#[derive(Default)]
pub(super) struct Params(Vec<(String, String)>);

impl Params {
    pub(super) fn parse(query: &str) -> Self {
        let pairs = query
            .split('&')
            .filter(|piece| !piece.is_empty())
            .map(|piece| {
                let (key, value) = split_once(piece, '=');
                (pct(key), pct(value.unwrap_or_default()))
            })
            .collect();
        Self(pairs)
    }

    pub(super) fn push(&mut self, key: &str, value: impl Into<String>) {
        self.0.push((key.to_owned(), value.into()));
    }

    /// Value of the first alias (in the given order) that is present and non-empty.
    pub(super) fn get(&self, aliases: &[&str]) -> Option<&str> {
        aliases.iter().find_map(|alias| {
            self.0
                .iter()
                .find(|(key, value)| key.eq_ignore_ascii_case(alias) && !value.is_empty())
                .map(|(_, value)| value.as_str())
        })
    }

    /// True when the first non-empty alias is `1|true|yes|on`.
    pub(super) fn flag(&self, aliases: &[&str]) -> bool {
        self.get(aliases).is_some_and(truthy)
    }

    /// Comma-separated list: items trimmed, empty items dropped.
    pub(super) fn csv(&self, aliases: &[&str]) -> Vec<String> {
        self.get(aliases).map(csv).unwrap_or_default()
    }

    /// Every parameter as (name, value), in link order.
    pub(super) fn pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}

/// Comma-separated list: items trimmed, empty items dropped.
pub(super) fn csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A share link body (after `scheme://`, fragment removed) cut into raw parts.
pub(super) struct Link<'a> {
    /// Raw userinfo: everything before the last `@` of the part before the query.
    pub userinfo: Option<&'a str>,
    /// Raw `host[:port]`.
    pub hostport: &'a str,
    /// Raw path: empty or starting with `/`.
    pub path: &'a str,
    pub params: Params,
}

impl<'a> Link<'a> {
    pub(super) fn parse(body: &'a str) -> Self {
        let (before_query, query) = split_once(body, '?');
        let (userinfo, authority_and_path) = match before_query.rfind('@') {
            Some(at) => (Some(&before_query[..at]), &before_query[at + 1..]),
            None => (None, before_query),
        };
        let (hostport, path) = match authority_and_path.find('/') {
            Some(slash) => authority_and_path.split_at(slash),
            None => (authority_and_path, ""),
        };
        Self {
            userinfo,
            hostport,
            path,
            params: Params::parse(query.unwrap_or_default()),
        }
    }

    /// Userinfo split at its first `:` into (user, password), each decoded once.
    pub(super) fn user_password(&self) -> (String, Option<String>) {
        let raw = self.userinfo.unwrap_or_default();
        let (user, password) = split_once(raw, ':');
        (pct(user), password.map(pct))
    }

    /// The whole userinfo decoded once (a `:` inside stays part of the value).
    pub(super) fn userinfo_whole(&self) -> String {
        pct(self.userinfo.unwrap_or_default())
    }

    /// True when the path is empty or `/` (a SIP002-style trailing slash).
    pub(super) fn root_path(&self) -> bool {
        self.path.is_empty() || self.path == "/"
    }

    /// Server and port; `default` applies when the link has no port (`None`: port required).
    pub(super) fn endpoint(&self, default: Option<u16>) -> Res<(Host, u16)> {
        let (host, raw) = host_port(self.hostport)?;
        Ok((host, port_or(raw, default)?))
    }
}

/// `host[:port]` or `[v6][:port]`: the host (IPv6 unbracketed) and the raw port text.
pub(super) fn host_port(s: &str) -> Res<(Host, Option<&str>)> {
    if let Some(inner) = s.strip_prefix('[') {
        let Some((v6, after)) = inner.split_once(']') else {
            return bad("unclosed IPv6 bracket");
        };
        let Ok(ip) = v6.parse::<Ipv6Addr>() else {
            return bad("invalid IPv6 address");
        };
        let port = match after {
            "" => None,
            _ => match after.strip_prefix(':') {
                Some(port) => Some(port),
                None => return bad("unexpected text after the IPv6 address"),
            },
        };
        return Ok((Host::Ip(IpAddr::V6(ip)), port.filter(|p| !p.is_empty())));
    }
    if s.matches(':').count() > 1 {
        return match s.parse::<Ipv6Addr>() {
            Ok(ip) => Ok((Host::Ip(IpAddr::V6(ip)), None)),
            Err(_) => bad("an IPv6 address with a port must be in brackets"),
        };
    }
    let (host, port) = split_once(s, ':');
    Ok((host_name(host)?, port.filter(|p| !p.is_empty())))
}

/// An IP address or a domain name kept as given ([`parse_host`]).
pub(super) fn host_name(host: &str) -> Res<Host> {
    match parse_host(host) {
        Some(host) => Ok(host),
        None if host.is_empty() => bad("missing server address"),
        None => bad("invalid server address"),
    }
}

/// Decimal port 1..=65535: digits only (no sign, hex, exponent or fraction).
pub(super) fn port(raw: &str) -> Res<u16> {
    parse_port(raw).map_or_else(|| bad("invalid port"), Ok)
}

/// The raw port, or `default` when the link has none (`None` = the scheme requires a port).
pub(super) fn port_or(raw: Option<&str>, default: Option<u16>) -> Res<u16> {
    match (raw, default) {
        (Some(raw), _) => port(raw),
        (None, Some(default)) => Ok(default),
        (None, None) => bad("missing port"),
    }
}

/// Go-style duration (`30s`, `1m30s`, `1.5s`, `500ms`) in milliseconds; a bare integer counts
/// in units of `bare_unit_ms` (providers write seconds or milliseconds without a unit).
pub(super) fn duration_ms(raw: &str, bare_unit_ms: u64) -> Option<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.bytes().all(|b| b.is_ascii_digit()) {
        return raw.parse::<u64>().ok()?.checked_mul(bare_unit_ms);
    }
    let total = go_duration_ms(raw)?;
    // The range check keeps the rounded value inside u64.
    (total.is_finite() && total < 1e15).then(|| total.round() as u64)
}

/// Milliseconds rounded to whole seconds; less than half a second is not a usable interval.
pub(super) fn secs(ms: u64) -> Option<u32> {
    u32::try_from(ms.saturating_add(500) / 1000)
        .ok()
        .filter(|s| *s > 0)
}
