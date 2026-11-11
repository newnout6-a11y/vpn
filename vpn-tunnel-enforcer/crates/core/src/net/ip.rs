//! IP classification. [`is_public_ip`] is the one predicate for "routable on the internet" used
//! by geo lookups, egress checks, DoH answers and redirect guards (servers §6, R4-23).
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Strips the IPv4-mapped form: `::ffff:a.b.c.d` → `a.b.c.d`; anything else is returned as is.
pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// True when `ip` is a globally routable unicast address. IPv6 forms that carry an IPv4
/// address (mapped `::ffff:0:0/96`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) are judged by it.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match embedded_v4(v6) {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(v6),
        },
    }
}

/// Loopback: `127.0.0.0/8`, `::1` (IPv4-mapped forms included).
pub fn is_loopback(ip: IpAddr) -> bool {
    unmap(ip).is_loopback()
}

/// Private LAN ranges: RFC 1918 and IPv6 unique-local `fc00::/7` (IPv4-mapped forms included).
pub fn is_private(ip: IpAddr) -> bool {
    match unmap(ip) {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

/// Carrier-grade NAT `100.64.0.0/10` (RFC 6598; IPv4-mapped forms included).
pub fn is_cgnat(ip: IpAddr) -> bool {
    matches!(unmap(ip), IpAddr::V4(v4) if in_cgnat(v4))
}

/// Link-local: `169.254.0.0/16`, `fe80::/10` (IPv4-mapped forms included).
pub fn is_link_local(ip: IpAddr) -> bool {
    match unmap(ip) {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    }
}

fn in_cgnat(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (b & 0xc0) == 64
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let special = a == 0                                  // "this network"
        || a == 10
        || in_cgnat(ip)
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && (b & 0xf0) == 16)
        || (a == 192 && b == 0 && (c == 0 || c == 2))     // IETF assignments, TEST-NET-1
        || (a == 192 && b == 88 && c == 99)               // 6to4 relay anycast
        || (a == 192 && b == 168)
        || (a == 198 && (b & 0xfe) == 18)                 // benchmarking 198.18/15
        || (a == 198 && b == 51 && c == 100)              // TEST-NET-2
        || (a == 203 && b == 0 && c == 113)               // TEST-NET-3
        || a >= 224; // multicast, reserved, broadcast
    !special
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // Only 2000::/3 is allocated for global unicast. Everything outside it is local or reserved:
    // `::`, `::1`, `fc00::/7`, `fe80::/10`, `fec0::/10`, `ff00::/8`, `100::/64`, `64:ff9b:1::/48`.
    if s[0] & 0xe000 != 0x2000 {
        return false;
    }
    let special = (s[0] == 0x2001 && s[1] == 0x0db8)      // documentation
        || (s[0] == 0x2001 && s[1] == 0)                  // Teredo 2001::/32 (normative A13)
        || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010)  // ORCHID 2001:10::/28
        || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0020)  // ORCHIDv2 2001:20::/28
        || (s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0) // benchmarking 2001:2::/48
        || (s[0] == 0x3fff && (s[1] & 0xf000) == 0); // documentation 3fff::/20 (RFC 9637)
    !special
}

/// The IPv4 address carried by IPv4-mapped, NAT64 well-known-prefix and 6to4 addresses.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = ip.segments();
    let o = ip.octets();
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// R4-23 (servers §7 netaddr; domainEnrichment.test.ts, residualReview2.test.ts): one
    /// predicate replacing the old five.
    #[test]
    fn public_ip_vectors() {
        let not_public = [
            "127.0.0.1",
            "127.255.255.254",
            "::1",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.254.254",
            "169.254.169.254",
            "169.254.1.1",
            "fe80::1",
            "100.64.0.1",
            "100.100.50.1",
            "100.127.255.254",
            "224.0.0.1",
            "255.255.255.255",
            "ff02::1",
            "fc00::1",
            "fd12:3456:789a::1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.1.10",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "::ffff:100.64.0.1",
            "::ffff:192.0.2.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
            "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
            "198.18.0.1",
            "198.19.255.1",
            "100::1",
            "2001:2::1",
            "192.0.0.8",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
            "fec0::1",
        ];
        for s in not_public {
            assert!(!is_public_ip(ip(s)), "{s} must not be public");
        }
        let public = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "142.250.180.206",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "::ffff:1.1.1.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "64:ff9b::808:808",
        ];
        for s in public {
            assert!(is_public_ip(ip(s)), "{s} must be public");
        }
    }

    /// The rest of the spec table (servers §6), the egress probe's IPv4 list (xray §2.9) and the
    /// server-info DNS answers (servers §7: `::ffff:7f00:1`, `fe90::1`, full-form `::1`).
    #[test]
    fn special_blocks_from_the_table() {
        for s in [
            "0.0.0.0",
            "0.1.2.3",
            "192.88.99.1",
            "240.0.0.1",
            "239.255.255.255",
            "::",
            "2001:10::1",
            "2001:20::1",
            "64:ff9b:1::1",
            "3fff::1",
            "::7f00:1",
            "5f00::1",
            "::ffff:7f00:1",
            "fe90::1",
            "0:0:0:0:0:0:0:1",
        ] {
            assert!(!is_public_ip(ip(s)), "{s} must not be public");
        }
        for s in [
            "2002:808:808::1",
            "223.255.255.255",
            "2001:4:112::1",
            "2a02:6b8::2:242",
        ] {
            assert!(is_public_ip(ip(s)), "{s} must be public");
        }
    }

    /// Normative A13 / §7 and the monitoring quirks: judged on bits, never on spelling; Teredo
    /// `2001::/32` is not public (decided).
    #[test]
    fn normative_vectors() {
        for s in [
            "fd00::1",
            "64:ff9b::a00:1",
            "64:ff9b::10.0.0.1",
            "::ffff:c0a8:101",
            "0::0",
            "::1.2.3.4",
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        ] {
            assert!(!is_public_ip(ip(s)), "{s} must not be public");
        }
        for s in [
            "::ffff:8.8.8.8",
            "2002:0808:0808::1",
            "2606:4700::192.168.1.1",
        ] {
            assert!(is_public_ip(ip(s)), "{s} must be public");
        }
    }

    #[test]
    fn small_classifiers() {
        assert!(is_loopback(ip("127.0.0.53")) && is_loopback(ip("::ffff:127.0.0.1")));
        assert!(is_loopback(ip("::1")) && !is_loopback(ip("10.0.0.1")));
        assert!(is_private(ip("192.168.1.1")) && is_private(ip("fd00::1")));
        assert!(is_private(ip("::ffff:172.16.0.1")) && !is_private(ip("100.64.0.1")));
        assert!(is_cgnat(ip("100.64.0.1")) && is_cgnat(ip("::ffff:100.127.0.1")));
        assert!(!is_cgnat(ip("100.128.0.1")) && !is_cgnat(ip("::1")));
        assert!(is_link_local(ip("169.254.10.1")) && is_link_local(ip("fe80::1")));
        assert!(!is_link_local(ip("fec0::1")));
        assert_eq!(unmap(ip("::ffff:1.2.3.4")), ip("1.2.3.4"));
        assert_eq!(unmap(ip("2001:db8::1")), ip("2001:db8::1"));
    }
}
