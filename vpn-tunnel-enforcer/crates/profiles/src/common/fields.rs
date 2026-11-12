//! Field values every importer reads the same way: display names, server addresses, ports and
//! port ranges, uTLS fingerprint names; and the REALITY combinations no engine runs.
use std::net::IpAddr;

use vpnte_base::types::ClientDevice;

use crate::model::{Host, Kind, Profile, Transport};

/// Why no engine can run the profile's REALITY (`None`: fine or no REALITY). REALITY is a TCP
/// camouflage that sends the cover site's own hello: it cannot run over QUIC (Hysteria2, TUIC,
/// the v2ray QUIC transport) or carry ECH. The emitter refuses both at connect
/// (`RealityOverQuic`, `RealityWithEch`); the importers skip such keys instead of storing them.
pub fn reality_conflict(p: &Profile) -> Option<&'static str> {
    let tls = p.tls.as_ref().filter(|tls| tls.reality.is_some())?;
    let quic = matches!(p.kind, Kind::Hysteria2 { .. } | Kind::Tuic { .. })
        || matches!(p.transport, Some(Transport::Quic));
    if quic {
        Some("REALITY cannot run over QUIC")
    } else if tls.ech.is_some() {
        Some("REALITY cannot be combined with ECH")
    } else {
        None
    }
}

/// Longest display name kept, in characters (`Profile::name`).
pub const NAME_MAX_CHARS: usize = 256;

/// uTLS fingerprint names sing-box 1.14 accepts (`common/tls/utls_client.go`). Any other name,
/// e.g. Xray's `randomizednoalpn`, would stop the engine at start.
pub const UTLS_FINGERPRINTS: [&str; 10] = [
    "chrome",
    "firefox",
    "edge",
    "safari",
    "360",
    "qq",
    "ios",
    "android",
    "random",
    "randomized",
];

/// Hysteria2 obfuscation types sing-box 1.14 runs (`gecko` is new in 1.14).
pub const HY2_OBFS_TYPES: [&str; 2] = ["salamander", "gecko"];

/// XHTTP modes Xray accepts; any other value makes `xray run` reject the whole config.
pub const XHTTP_MODES: [&str; 4] = ["auto", "packet-up", "stream-up", "stream-one"];

/// uTLS fingerprint that matches `device`: the emitter's default when the provider gave none.
/// Safari only for Mac: a Safari ClientHello from Windows is itself an anomaly DPI can flag.
pub fn utls_fingerprint(device: ClientDevice) -> &'static str {
    match device {
        ClientDevice::Pc => "chrome",
        ClientDevice::Android => "android",
        ClientDevice::Ios => "ios",
        ClientDevice::Mac => "safari",
    }
}

/// Control characters become spaces, outer whitespace goes, at most `max_chars` characters.
pub fn clean_text(raw: &str, max_chars: usize) -> String {
    let spaced: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let capped: String = spaced.trim().chars().take(max_chars).collect();
    capped.trim_end().to_owned()
}

/// Display name: [`clean_text`] capped at [`NAME_MAX_CHARS`]; may come back empty.
pub fn clean_name(raw: &str) -> String {
    clean_text(raw, NAME_MAX_CHARS)
}

/// Default display name of a key without one, by protocol label ([`Kind::label`](crate::model::Kind::label),
/// plus `shadowtls`); `VPN` for anything else.
pub fn display_name(label: &str) -> &'static str {
    match label {
        "vless" => "VLESS",
        "vmess" => "VMess",
        "trojan" => "Trojan",
        "shadowsocks" => "Shadowsocks",
        "shadowtls" => "ShadowTLS",
        "hysteria2" => "Hysteria2",
        "tuic" => "TUIC",
        "naive" => "Naive",
        "anytls" => "AnyTLS",
        "wireguard" => "WireGuard",
        "socks" => "SOCKS",
        "http" => "HTTP",
        _ => "VPN",
    }
}

/// Server address as written (not trimmed): an IP literal (IPv6 with or without brackets) or a
/// host name of letters, digits, `-`, `.` and `_` that is not all digits and dots. Zone ids,
/// ports, userinfo and paths are refused.
pub fn parse_host(raw: &str) -> Option<Host> {
    let bare = raw
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(raw);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Some(Host::Ip(ip));
    }
    let name_char = |c: char| c.is_alphanumeric() || matches!(c, '-' | '.' | '_');
    let numeric = raw.chars().all(|c| c.is_ascii_digit() || c == '.');
    (!raw.is_empty() && raw.chars().all(name_char) && !numeric)
        .then(|| Host::Domain(raw.to_owned()))
}

/// Decimal port 1..=65535 as written: digits only (no sign, hex, exponent, fraction or spaces).
pub fn parse_port(raw: &str) -> Option<u16> {
    let digits = (1..=5).contains(&raw.len()) && raw.bytes().all(|b| b.is_ascii_digit());
    digits
        .then(|| raw.parse::<u16>().ok())
        .flatten()
        .filter(|&p| p != 0)
}

/// One port-hopping item: `443`, `20000-30000` or `20000:30000` (spaces around the parts
/// allowed), inclusive and ordered.
pub fn port_range(item: &str) -> Option<(u16, u16)> {
    let item = item.trim();
    let (start, end) = item.split_once(['-', ':']).unwrap_or((item, item));
    let (start, end) = (parse_port(start.trim())?, parse_port(end.trim())?);
    (start <= end).then_some((start, end))
}

/// Whole-certificate SHA-256 pin (Hysteria2 `pinSHA256`, Xray `pinnedPeerCertSha256` / `pcs`):
/// 64 hex digits, `:` separators allowed, lower-cased; of a comma-joined list the first.
pub fn sha256_pin(raw: &str) -> Option<String> {
    let hex: String = raw
        .split(',')
        .next()?
        .trim()
        .chars()
        .filter(|c| *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hex)
}

/// Milliseconds of a Go duration with units (`30s`, `1m30s`, `1.5s`, `500ms`, `2h`); bare numbers
/// are the caller's call (providers mean seconds or milliseconds).
pub fn go_duration_ms(raw: &str) -> Option<f64> {
    let is_number = |c: char| c.is_ascii_digit() || c == '.';
    let mut rest = raw;
    let mut total = 0f64;
    while !rest.is_empty() {
        let number_len = rest.find(|c: char| !is_number(c)).unwrap_or(rest.len());
        let value: f64 = rest[..number_len].parse().ok()?;
        rest = &rest[number_len..];
        let unit_len = rest.find(is_number).unwrap_or(rest.len());
        let unit_ms = match &rest[..unit_len] {
            "ns" => 1e-6,
            "us" | "µs" => 1e-3,
            "ms" => 1.0,
            "s" => 1e3,
            "m" => 6e4,
            "h" => 3.6e6,
            _ => return None,
        };
        total += value * unit_ms;
        rest = &rest[unit_len..];
    }
    (!raw.is_empty()).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned_and_capped() {
        assert_eq!(clean_name("  Germany\t#1\u{7}  "), "Germany #1");
        assert_eq!(clean_name("\n\r"), "");
        let long = "я".repeat(300);
        assert_eq!(clean_name(&long).chars().count(), NAME_MAX_CHARS);
        assert_eq!(clean_text(&format!("{} x", "a".repeat(4)), 5), "aaaa");
    }

    /// AT-04-004: IPv6 loses its brackets; zone ids, ports and unbalanced brackets are refused.
    #[test]
    fn hosts() {
        let ip = |s: &str| Some(Host::Ip(s.parse().unwrap()));
        assert_eq!(parse_host("[2001:db8::1]"), ip("2001:db8::1"));
        assert_eq!(parse_host("2001:db8::1"), ip("2001:db8::1"));
        assert_eq!(parse_host("::ffff:1.2.3.4"), ip("::ffff:1.2.3.4"));
        assert_eq!(parse_host("1.2.3.4"), ip("1.2.3.4"));
        assert_eq!(
            parse_host("xn--e1afmkfd.xn--p1ai"),
            Some(Host::Domain("xn--e1afmkfd.xn--p1ai".into()))
        );
        assert_eq!(
            parse_host("сервер.рф"),
            Some(Host::Domain("сервер.рф".into()))
        );
        for bad in [
            "",
            " vpn.example",
            "[2001:db8::1",
            "fe80::1%eth0",
            "h.example:443",
            "u@h.example",
            "h.example/x",
            "[h.example]",
            "1.2.3",
            "a b",
        ] {
            assert_eq!(parse_host(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn ports_and_ranges() {
        assert_eq!(parse_port("443"), Some(443));
        assert_eq!(parse_port("65535"), Some(65535));
        for bad in ["", "0", "65536", "+443", "0x1BB", "443.0", " 443", "123456"] {
            assert_eq!(parse_port(bad), None, "{bad:?}");
        }
        assert_eq!(port_range("443"), Some((443, 443)));
        assert_eq!(port_range(" 20000 - 30000 "), Some((20000, 30000)));
        assert_eq!(port_range("20000:30000"), Some((20000, 30000)));
        assert_eq!(port_range("30000-20000"), None);
        assert_eq!(port_range("1-"), None);
    }

    #[test]
    fn certificate_pins() {
        let pin = "ab".repeat(32);
        assert_eq!(sha256_pin(&pin.to_uppercase()), Some(pin.clone()));
        let colons = vec!["AB"; 32].join(":");
        assert_eq!(
            sha256_pin(&format!("{colons},{}", "cd".repeat(32))),
            Some(pin)
        );
        for bad in ["", "ab", &"zz".repeat(32), &"ab".repeat(33)] {
            assert_eq!(sha256_pin(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn go_durations() {
        assert_eq!(go_duration_ms("1m30s"), Some(90_000.0));
        assert_eq!(go_duration_ms("1.5s"), Some(1_500.0));
        assert_eq!(go_duration_ms("2h"), Some(7_200_000.0));
        assert_eq!(go_duration_ms("500ms"), Some(500.0));
        for bad in ["", "30", "10x", "s", "1m30"] {
            assert_eq!(go_duration_ms(bad), None, "{bad:?}");
        }
    }
}
