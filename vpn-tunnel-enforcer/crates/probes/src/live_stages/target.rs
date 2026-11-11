//! Target handling before any packet is sent: host/port normalisation and the safety filter that
//! keeps a hostile subscription from turning the live check into a local port scan (B-06).
use std::net::IpAddr;

use vpnte_base::{AppError, Msg};
use vpnte_core::net::{is_cgnat, is_link_local, is_loopback, is_private, unmap};

/// Default port when none (or an invalid one) is given.
pub const DEFAULT_PORT: u16 = 443;

/// Ports that imply TLS for an endpoint-only target (no profile to ask, B-30).
pub const TLS_PORTS: [u16; 7] = [443, 8443, 2053, 2083, 2087, 2096, 4433];

/// A host entered by the user or taken from a profile, with the embedded port applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedTarget {
    /// Trimmed host, IPv6 without brackets.
    pub host: String,
    pub port: u16,
    /// Set when the host is an IP literal.
    pub ip: Option<IpAddr>,
}

impl NormalizedTarget {
    /// The host is an IP literal.
    pub fn is_ip(&self) -> bool {
        self.ip.is_some()
    }
    /// The host is an IPv6 literal.
    pub fn is_ipv6(&self) -> bool {
        matches!(self.ip, Some(IpAddr::V6(_)))
    }
}

/// Splits `host[:port]` / `[v6]:port`; an embedded port beats `port`; a missing or zero port is 443.
/// A bare full-form IPv6 (`2001:db8:0:0:0:0:0:1`) stays intact; embedded ports are decimal only.
pub fn normalize_host_port(raw_host: &str, port: Option<u16>) -> NormalizedTarget {
    let mut host = raw_host.trim().to_owned();
    let mut port = port.filter(|p| *p != 0).unwrap_or(DEFAULT_PORT);
    if host.starts_with('[')
        && let Some(close) = host.find(']')
    {
        let rest = &host[close + 1..];
        if let Some(p) = rest.strip_prefix(':').and_then(decimal_port) {
            port = p;
        }
        host = host[1..close].to_owned();
    } else if !host.contains("::")
        && host.matches(':').count() == 1
        && let Some((name, suffix)) = host.split_once(':')
    {
        // A non-numeric suffix is still cut off (old behaviour); the port stays the default.
        if let Some(p) = decimal_port(suffix) {
            port = p;
        }
        host = name.to_owned();
    }
    let ip = host.parse::<IpAddr>().ok();
    NormalizedTarget { host, port, ip }
}

fn decimal_port(s: &str) -> Option<u16> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok().filter(|p| *p != 0)
}

/// An empty or whitespace host is refused before any stage runs (Node used to dial localhost).
pub fn require_host(raw_host: &str) -> Result<(), AppError> {
    if raw_host.trim().is_empty() {
        return Err(AppError::validation(Msg::new(
            "probes.liveStages.target.emptyHost",
        )));
    }
    Ok(())
}

/// What the safety filter says about the address the stages would talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetClass {
    /// Loopback, unspecified, link-local (cloud metadata 169.254.169.254), multicast, broadcast:
    /// nothing is sent.
    Refused,
    /// RFC 1918, CGNAT, ULA: allowed (self-hosted servers) with an info finding.
    Private,
    Public,
}

/// Classifies the first resolved address (IPv4-mapped forms judged by their IPv4).
pub fn classify_target(ip: IpAddr) -> TargetClass {
    let ip = unmap(ip);
    let refused = is_loopback(ip)
        || is_link_local(ip)
        || ip.is_unspecified()
        || ip.is_multicast()
        || match ip {
            IpAddr::V4(v4) => v4.is_broadcast() || v4.octets()[0] == 0,
            IpAddr::V6(_) => false,
        };
    if refused {
        TargetClass::Refused
    } else if is_private(ip) || is_cgnat(ip) {
        TargetClass::Private
    } else {
        TargetClass::Public
    }
}

/// The error of a refused target (`probes.liveStages.target.refused`, arg `ip`).
pub fn refused_error(ip: IpAddr) -> AppError {
    AppError::validation(Msg::new("probes.liveStages.target.refused").arg("ip", ip))
}

/// TLS applies to an endpoint-only target on a TLS port or when an SNI is configured.
pub fn tls_applicable(port: u16, sni_configured: bool) -> bool {
    sni_configured || TLS_PORTS.contains(&port)
}

/// Top-level domains that never resolve publicly (DoH comparison is pointless for them).
const PRIVATE_TLDS: [&str; 11] = [
    "local",
    "lan",
    "internal",
    "home",
    "arpa",
    "invalid",
    "test",
    "example",
    "localhost",
    "onion",
    "corp",
];

/// True for a multi-label DNS name under a public TLD (trailing dots ignored).
pub fn is_public_fqdn(host: &str) -> bool {
    let name = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.parse::<IpAddr>().is_ok() {
        return false;
    }
    match name.rsplit_once('.') {
        Some((_, tld)) => !tld.is_empty() && !PRIVATE_TLDS.contains(&tld),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(host: &str, port: Option<u16>) -> (String, u16, bool, bool) {
        let t = normalize_host_port(host, port);
        (t.host.clone(), t.port, t.is_ip(), t.is_ipv6())
    }

    /// AT-05-001: normalizeHostAndPort vectors (live-probe §7.1).
    #[test]
    fn normalizes_host_and_port() {
        let s = |h: &str| h.to_owned();
        assert_eq!(norm("1.2.3.4", None), (s("1.2.3.4"), 443, true, false));
        assert_eq!(
            norm("1.2.3.4:8443", None),
            (s("1.2.3.4"), 8443, true, false)
        );
        assert_eq!(
            norm("vpn.example.com", None),
            (s("vpn.example.com"), 443, false, false)
        );
        assert_eq!(
            norm("vpn.example.com:2083", None),
            (s("vpn.example.com"), 2083, false, false)
        );
        assert_eq!(
            norm("[2001:db8::1]:9000", None),
            (s("2001:db8::1"), 9000, true, true)
        );
        assert_eq!(
            norm("2001:db8::1", Some(8080)),
            (s("2001:db8::1"), 8080, true, true)
        );
    }

    /// Edges of §3.1: embedded port wins, decimal only, zero falls back, full-form IPv6 intact.
    #[test]
    fn normalization_edges() {
        assert_eq!(norm(" h.example:8443 ", Some(9000)).1, 8443);
        assert_eq!(
            norm("h.example:abc", Some(9000)),
            ("h.example".into(), 9000, false, false)
        );
        assert_eq!(norm("h.example:0x1BB", None).1, 443);
        assert_eq!(norm("h.example", Some(0)).1, 443);
        let full = "2001:db8:0:0:0:0:0:1";
        assert_eq!(norm(full, None), (full.into(), 443, true, true));
        assert_eq!(norm("[::1]", Some(81)), ("::1".into(), 81, true, true));
    }

    /// AT-05-001 / B-06: the private-target filter (§7.14).
    #[test]
    fn classifies_targets() {
        for refused in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "169.254.169.254",
            "fe80::1",
            "224.0.0.1",
            "255.255.255.255",
            "::ffff:127.0.0.1",
            "::",
        ] {
            let ip: IpAddr = refused.parse().unwrap();
            assert_eq!(classify_target(ip), TargetClass::Refused, "{refused}");
        }
        for private in [
            "10.0.0.5",
            "192.168.1.10",
            "100.64.0.1",
            "fd00::1",
            "::ffff:10.1.2.3",
        ] {
            let ip: IpAddr = private.parse().unwrap();
            assert_eq!(classify_target(ip), TargetClass::Private, "{private}");
        }
        for public in ["203.0.113.10", "1.1.1.1", "2606:4700::1111"] {
            let ip: IpAddr = public.parse().unwrap();
            assert_eq!(classify_target(ip), TargetClass::Public, "{public}");
        }
    }

    /// B-06: an empty endpoint host is a validation error before DNS.
    #[test]
    fn empty_host_is_refused() {
        assert!(require_host("").is_err());
        assert!(require_host("   ").is_err());
        assert!(require_host("vpn.example.com").is_ok());
        let e = refused_error("127.0.0.1".parse().unwrap());
        assert_eq!(e.user_msg().key, "probes.liveStages.target.refused");
    }

    /// isPublicFqdn vectors (§7.2, §7.15).
    #[test]
    fn public_fqdn() {
        for yes in [
            "example.com",
            "vpn.sub.service.org",
            "node-12.fra.example.co.uk",
            "example.com.",
        ] {
            assert!(is_public_fqdn(yes), "{yes}");
        }
        for no in [
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "::1",
            "2001:db8::1",
            "fe80::1",
            "localhost",
            "myserver",
            "gateway.local",
            "node.lan",
            "nas.internal",
            "printer.home.arpa",
            "nas.internal.",
            "localhost.",
            "",
        ] {
            assert!(!is_public_fqdn(no), "{no}");
        }
    }

    /// B-30: TLS applicability of an endpoint-only target.
    #[test]
    fn tls_ports() {
        assert!(tls_applicable(4433, false));
        assert!(tls_applicable(2096, false));
        assert!(!tls_applicable(8080, false));
        assert!(tls_applicable(8080, true));
    }
}
