//! The local proxy as the soft-mode targets write it. Parsing is `vpnte_core::net::HostPort` (the
//! one strict parser of the app): only a parsed address ever reaches a writer, so no newline or
//! markup can be injected into a properties or XML file (spec G1 / G3, F-014).
use std::net::IpAddr;

use vpnte_base::types::ProxyKind;
use vpnte_core::net::{Host, HostPort};

/// `socks5h://host:port` (DNS through the proxy: without a TUN, local resolution would leak every
/// name to the ISP) or `http://host:port`; IPv6 in brackets.
pub fn proxy_url(addr: &HostPort, kind: ProxyKind) -> String {
    match kind {
        ProxyKind::Socks5 => format!("socks5h://{addr}"),
        ProxyKind::Http => format!("http://{addr}"),
    }
}

/// The host without IPv6 brackets, for JVM properties and IDE settings.
pub fn host_bare(addr: &HostPort) -> String {
    match addr.host() {
        Host::Ip(IpAddr::V6(ip)) => ip.to_string(),
        host => host.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Option<(String, u16)> {
        HostPort::parse(s).ok().map(|a| (host_bare(&a), a.port()))
    }

    /// Spec §7.5 (`androidStudio.test.ts` "parseProxyAddr"), on the app's single parser.
    #[test]
    fn proxy_addresses_parse_strictly() {
        assert_eq!(parse("127.0.0.1:1080"), Some(("127.0.0.1".into(), 1080)));
        assert_eq!(parse("localhost:8080"), Some(("localhost".into(), 8080)));
        assert_eq!(parse("[::1]:10808"), Some(("::1".into(), 10808)));
        assert_eq!(
            parse("[2001:db8::1]:8080"),
            Some(("2001:db8::1".into(), 8080))
        );
        assert_eq!(parse("localhost:01080"), Some(("localhost".into(), 1080)));
        assert_eq!(
            parse("  127.0.0.1:1080  "),
            Some(("127.0.0.1".into(), 1080))
        );
        for bad in [
            "::1",
            "2001:db8::1",
            "127.0.0.1",
            "127.0.0.1:0",
            "127.0.0.1:70000",
            "127.0.0.1:abc",
            "localhost:1080junk",
            "localhost:1.5",
            "[]:1080",
            "",
            ":1080",
            "a b:1080",
            // The old parser trimmed the host part and accepted this as `host`.
            "host\n:1080",
        ] {
            assert_eq!(parse(bad), None, "{bad:?} must be rejected");
        }
    }

    /// F-014: IPv6 survives into the URL; `socks5h` keeps DNS on the proxy.
    #[test]
    fn urls_follow_the_proxy_kind() {
        let url = |s: &str, k| proxy_url(&HostPort::parse(s).unwrap(), k);
        assert_eq!(
            url("127.0.0.1:10808", ProxyKind::Socks5),
            "socks5h://127.0.0.1:10808"
        );
        assert_eq!(
            url("127.0.0.1:10809", ProxyKind::Http),
            "http://127.0.0.1:10809"
        );
        assert_eq!(
            url("[::1]:10808", ProxyKind::Socks5),
            "socks5h://[::1]:10808"
        );
    }
}
