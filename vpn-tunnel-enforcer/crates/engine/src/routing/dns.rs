//! DNS resolver addresses and profiles, and how the active profile becomes the tunnelled
//! `dns-remote` server.
//!
//! Every query is captured by `hijack-dns` and answered by sing-box; `dns-remote` always
//! detours through `proxy-out`, so DNS never leaks to the ISP resolver. Plain resolvers are
//! sent as TCP/53: in the field TCP over VLESS/Reality kept working while its UDP timed out.
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use vpnte_base::{AppError, Msg};

use crate::tags::{DNS_REMOTE, PROXY_OUT};

/// Longest address the UI accepts.
pub const MAX_ADDR_LEN: usize = 2048;

/// Host of a DoH / DoT resolver.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsHost {
    Ip(IpAddr),
    /// Lower-case host name with at least two labels.
    Name(String),
}

/// A validated resolver address; `Display` is the persisted form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsAddr {
    /// `1.1.1.1`, `2001:db8::1` (sent as TCP/53 through the tunnel).
    Plain(IpAddr),
    /// `https://host[:port][/path]`; `path: None` = `/dns-query`.
    Doh {
        host: DnsHost,
        port: Option<u16>,
        path: Option<String>,
    },
    /// `tls://host[:port]`.
    Dot { host: DnsHost, port: Option<u16> },
}

/// Why an address was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DnsAddrError {
    #[error("address is required")]
    Required,
    #[error("address is too long")]
    TooLong,
    #[error("only https:// (DoH) and tls:// (DoT) schemes are supported")]
    Scheme,
    #[error("not a valid IPv4 or IPv6 address")]
    Invalid,
    #[error("invalid DoH host")]
    DohHost,
    #[error("invalid DoT host")]
    DotHost,
    #[error("invalid port")]
    Port,
    #[error("invalid path")]
    Path,
    #[error("address cannot be used as a resolver through the tunnel")]
    UnusableIp,
}

impl DnsAddrError {
    /// User-facing explanation.
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            DnsAddrError::Required => "engine.routing.dns.required",
            DnsAddrError::TooLong => "engine.routing.dns.tooLong",
            DnsAddrError::Scheme => "engine.routing.dns.scheme",
            DnsAddrError::Invalid => "engine.routing.dns.invalid",
            DnsAddrError::DohHost => "engine.routing.dns.dohHost",
            DnsAddrError::DotHost => "engine.routing.dns.dotHost",
            DnsAddrError::Port => "engine.routing.dns.port",
            DnsAddrError::Path => "engine.routing.dns.path",
            DnsAddrError::UnusableIp => "engine.routing.dns.unusableIp",
        })
    }
}

impl From<DnsAddrError> for AppError {
    fn from(err: DnsAddrError) -> Self {
        AppError::validation(err.msg()).with_source(err)
    }
}

impl FromStr for DnsAddr {
    type Err = DnsAddrError;

    /// Parses a resolver address. Unlike the old validator, the scheme is case-insensitive,
    /// port and path are checked at save time (a saved profile always maps at connect),
    /// bracketed IPv6 hosts are accepted, and addresses that cannot work through the tunnel
    /// (unspecified, broadcast, multicast, loopback, link-local, zone ids) are refused.
    /// Private and CGNAT resolvers stay valid: WireGuard providers use in-tunnel resolvers.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if t.is_empty() {
            return Err(DnsAddrError::Required);
        }
        if t.len() > MAX_ADDR_LEN {
            return Err(DnsAddrError::TooLong);
        }
        if let Some(rest) = strip_scheme(t, "https://") {
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, ""),
            };
            let (host, port) = authority_of(authority, DnsAddrError::DohHost)?;
            let path = match path {
                "" | "/" => None,
                p if path_ok(p) => Some(p.to_owned()),
                _ => return Err(DnsAddrError::Path),
            };
            return Ok(DnsAddr::Doh { host, port, path });
        }
        if let Some(rest) = strip_scheme(t, "tls://") {
            let authority = rest.strip_suffix('/').unwrap_or(rest);
            if authority.contains('/') {
                return Err(DnsAddrError::Path);
            }
            let (host, port) = authority_of(authority, DnsAddrError::DotHost)?;
            return Ok(DnsAddr::Dot { host, port });
        }
        if t.contains("://") {
            return Err(DnsAddrError::Scheme);
        }
        let ip: IpAddr = t.parse().map_err(|_| DnsAddrError::Invalid)?;
        usable(ip).map(DnsAddr::Plain)
    }
}

fn strip_scheme<'a>(t: &'a str, scheme: &str) -> Option<&'a str> {
    let head = t.get(..scheme.len())?;
    head.eq_ignore_ascii_case(scheme)
        .then(|| &t[scheme.len()..])
}

/// `host[:port]`, `[v6][:port]`; an unbracketed IPv6 is refused (its colons are ambiguous).
fn authority_of(a: &str, bad_host: DnsAddrError) -> Result<(DnsHost, Option<u16>), DnsAddrError> {
    let (host, port) = if let Some(rest) = a.strip_prefix('[') {
        let (v6, after) = rest.split_once(']').ok_or(bad_host)?;
        let ip: Ipv6Addr = v6.parse().map_err(|_| bad_host)?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or(bad_host)?),
        };
        (DnsHost::Ip(usable(IpAddr::V6(ip))?), port)
    } else {
        let (h, port) = match a.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (a, None),
        };
        (host_of(h, bad_host)?, port)
    };
    let port = match port {
        None => None,
        Some(p) => Some(port_of(p)?),
    };
    Ok((host, port))
}

/// An RFC 3986 path (`/`, pchar, valid `%XX`) without query or fragment. sing-box 1.14 sets
/// `path` through Go's `url.setPath` (`dns/transport/https.go`): a `?query` would be sent as
/// `%3F…` (the query is lost) and a bad escape fails the engine start.
fn path_ok(p: &str) -> bool {
    let b = p.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'%' {
            if !b
                .get(i + 1..i + 3)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit))
            {
                return false;
            }
            i += 3;
            continue;
        }
        if !(c.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&c)) {
            return false;
        }
        i += 1;
    }
    true
}

fn port_of(p: &str) -> Result<u16, DnsAddrError> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(DnsAddrError::Port);
    }
    match p.parse::<u16>() {
        Ok(port) if port > 0 => Ok(port),
        _ => Err(DnsAddrError::Port),
    }
}

/// An IPv4 literal (range-checked: `999.1.1.1` is refused) or a host name of at least two
/// labels of `[A-Za-z0-9-]`, 1..=63 chars, not starting or ending with `-` (so `localhost`
/// is refused, as before).
fn host_of(h: &str, bad_host: DnsAddrError) -> Result<DnsHost, DnsAddrError> {
    if h.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let ip: Ipv4Addr = h.parse().map_err(|_| bad_host)?;
        return usable(IpAddr::V4(ip)).map(DnsHost::Ip);
    }
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    let labels: Vec<&str> = h.split('.').collect();
    let last_numeric = labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if h.len() > 253 || labels.len() < 2 || last_numeric || !labels.iter().all(|l| label_ok(l)) {
        return Err(bad_host);
    }
    Ok(DnsHost::Name(h.to_ascii_lowercase()))
}

/// Refuses addresses that cannot answer through `proxy-out`.
fn usable(ip: IpAddr) -> Result<IpAddr, DnsAddrError> {
    let v4_bad = |v4: Ipv4Addr| {
        v4.is_unspecified()
            || v4.is_broadcast()
            || v4.is_multicast()
            || v4.is_loopback()
            || v4.is_link_local()
    };
    let bad = match ip {
        IpAddr::V4(v4) => v4_bad(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4_bad(v4),
            None => {
                v6.is_unspecified()
                    || v6.is_multicast()
                    || v6.is_loopback()
                    || v6.is_unicast_link_local()
            }
        },
    };
    if bad {
        Err(DnsAddrError::UnusableIp)
    } else {
        Ok(ip)
    }
}

impl fmt::Display for DnsHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsHost::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]"),
            DnsHost::Ip(ip) => ip.fmt(f),
            DnsHost::Name(n) => f.write_str(n),
        }
    }
}

impl fmt::Display for DnsAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let port = |p: &Option<u16>| p.map(|p| format!(":{p}")).unwrap_or_default();
        match self {
            DnsAddr::Plain(ip) => ip.fmt(f),
            DnsAddr::Doh {
                host,
                port: p,
                path,
            } => {
                write!(
                    f,
                    "https://{host}{}{}",
                    port(p),
                    path.as_deref().unwrap_or("")
                )
            }
            DnsAddr::Dot { host, port: p } => write!(f, "tls://{host}{}", port(p)),
        }
    }
}

impl Serialize for DnsAddr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DnsAddr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Id prefix reserved for the built-in profiles (never stored, never deletable).
pub const BUILTIN_PREFIX: &str = "builtin-";
/// Longest profile name.
pub const MAX_NAME_LEN: usize = 120;

/// A named resolver choice. `secondary` is kept for round-trips only: sing-box routes each
/// query to one server and has no failover, so the old `dns-backup` server was never queried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsProfile {
    pub id: String,
    pub name: String,
    pub primary: DnsAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary: Option<DnsAddr>,
}

impl DnsProfile {
    /// True for the four profiles shipped in code.
    pub fn is_builtin(&self) -> bool {
        self.id.starts_with(BUILTIN_PREFIX)
    }
}

/// The built-in plain resolvers, verbatim from the old app (`dnsProfiles.ts:24-57`).
pub fn builtin_profiles() -> [DnsProfile; 4] {
    let p = |id: &str, name: &str, a: [u8; 4], b: [u8; 4]| DnsProfile {
        id: format!("{BUILTIN_PREFIX}{id}"),
        name: name.to_owned(),
        primary: DnsAddr::Plain(IpAddr::from(a)),
        secondary: Some(DnsAddr::Plain(IpAddr::from(b))),
    };
    [
        p("cloudflare", "Cloudflare", [1, 1, 1, 1], [1, 0, 0, 1]),
        p("google", "Google", [8, 8, 8, 8], [8, 8, 4, 4]),
        p("quad9", "Quad9", [9, 9, 9, 9], [149, 112, 112, 112]),
        p("adguard", "AdGuard", [94, 140, 14, 14], [94, 140, 15, 15]),
    ]
}

/// A profile by id: built-ins first, then `custom`.
pub fn find_profile(custom: &[DnsProfile], id: &str) -> Option<DnsProfile> {
    builtin_profiles()
        .into_iter()
        .chain(custom.iter().cloned())
        .find(|p| p.id == id)
}

/// Well-known DoH host names replaced by an address literal + SNI (saves the remote lookup of
/// the resolver's own name). DoH only, as before.
const KNOWN_DOH: [(&str, [u8; 4], &str); 4] = [
    ("cloudflare-dns.com", [1, 1, 1, 1], "cloudflare-dns.com"),
    ("one.one.one.one", [1, 1, 1, 1], "cloudflare-dns.com"),
    ("dns.google", [8, 8, 8, 8], "dns.google"),
    ("dns.quad9.net", [9, 9, 9, 9], "dns.quad9.net"),
];

/// The tunnelled `dns-remote` server for the active address (`None` = automatic: Cloudflare
/// DoH by address literal). A host name stays a name: with `detour` set, sing-box hands it to
/// the proxy outbound, so it is resolved at the VPN server (no loop, no leak).
pub(crate) fn remote_server(addr: Option<&DnsAddr>) -> Value {
    let mut s = Map::new();
    let mut put = |k: &str, v: Value| {
        s.insert(k.to_owned(), v);
    };
    let host_str = |h: &DnsHost| match h {
        DnsHost::Ip(ip) => ip.to_string(),
        DnsHost::Name(n) => n.clone(),
    };
    let sni = |h: &DnsHost| match h {
        DnsHost::Name(n) => Some(n.clone()),
        DnsHost::Ip(_) => None,
    };
    let auto = DnsAddr::Doh {
        host: DnsHost::Name("cloudflare-dns.com".into()),
        port: None,
        path: None,
    };
    match addr.unwrap_or(&auto) {
        DnsAddr::Plain(ip) => {
            put("type", json!("tcp"));
            put("tag", json!(DNS_REMOTE));
            put("server", json!(ip.to_string()));
        }
        DnsAddr::Doh { host, port, path } => {
            let known = match host {
                DnsHost::Name(n) => KNOWN_DOH.iter().find(|(name, ..)| name == n),
                DnsHost::Ip(_) => None,
            };
            put("type", json!("https"));
            put("tag", json!(DNS_REMOTE));
            match known {
                Some((_, ip, _)) => put("server", json!(Ipv4Addr::from(*ip).to_string())),
                None => put("server", json!(host_str(host))),
            }
            if let Some(p) = port {
                put("server_port", json!(p));
            }
            put("path", json!(path.as_deref().unwrap_or("/dns-query")));
            if let Some(name) = known
                .map(|(_, _, sni)| (*sni).to_owned())
                .or_else(|| sni(host))
            {
                put("tls", json!({ "server_name": name }));
            }
        }
        DnsAddr::Dot { host, port } => {
            put("type", json!("tls"));
            put("tag", json!(DNS_REMOTE));
            put("server", json!(host_str(host)));
            if let Some(p) = port {
                put("server_port", json!(p));
            }
            if let Some(name) = sni(host) {
                put("tls", json!({ "server_name": name }));
            }
        }
    }
    put("detour", json!(PROXY_OUT));
    Value::Object(s)
}

#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;
