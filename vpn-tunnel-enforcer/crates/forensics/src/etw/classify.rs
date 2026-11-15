//! Pure classification helpers of the ETW callback, ported verbatim from the old sidecar
//! (`native/vpnte-etw-sidecar/src/classify.rs` and the address helpers of its `main.rs`).
//!
//! The substring rules are kept as they were on purpose (`rst` also matches `first` / `burst`,
//! `fin` matches `final`): old sessions and support tooling read rows classified this way.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Maps a provider name to the row `category` (first match wins).
pub fn provider_category(provider: &str) -> &'static str {
    let p = provider.to_ascii_lowercase();
    if p.contains("dns") {
        "dns"
    } else if p.contains("wfp") || p.contains("firewall") {
        "wfp"
    } else if p.contains("tcpip") {
        "tcp"
    } else if p.contains("afd") {
        "afd"
    } else if p.contains("webio") {
        "webio"
    } else {
        "event"
    }
}

/// The canonical Microsoft provider name written in the `provider` field of data rows.
pub fn canonical_provider(provider: &str) -> &'static str {
    match provider_category(provider) {
        "dns" => "Microsoft-Windows-DNS-Client",
        "wfp" => "Microsoft-Windows-WFP",
        "tcp" => "Microsoft-Windows-TCPIP",
        "afd" => "Microsoft-Windows-Winsock-AFD",
        "webio" => "Microsoft-Windows-WebIO",
        _ => "Microsoft-Windows-TCPIP",
    }
}

/// Well-known provider GUID, used when a provider cannot be resolved by name on this machine.
pub fn known_guid(provider: &str) -> Option<u128> {
    Some(match provider_category(provider) {
        "tcp" => 0x2F07E2EE_15DB_40F1_90EF_9D7BA282188A,
        "dns" => 0x1C95126E_7EEA_49A9_A3FE_A378B03DDB4D,
        "wfp" => 0x0C478C5B_0351_41B1_8C58_4A6737DA32E3,
        "afd" => 0xE53C6823_7BB8_44BB_90DC_3F86090D48A6,
        "webio" => 0x50B3E73C_9370_461D_BB9F_26F32D68887D,
        _ => return None,
    })
}

/// Derives the row `event` and optional `reason` from the category and the lowercased
/// `"<provider> <task> <opcode>"` kind string.
pub fn derive_event_and_reason(
    category: &str,
    kind: &str,
    opcode: &str,
) -> (String, Option<&'static str>) {
    match category {
        "dns" => ("query".to_string(), None),
        "wfp" => {
            if contains_any(
                kind,
                &["block", "blocked", "drop", "discard", "5152", "5157"],
            ) {
                ("block".to_string(), Some("wfp-block-observed"))
            } else {
                (default_event(opcode), None)
            }
        }
        "tcp" => {
            if contains_any(kind, &["reset", "rst"]) {
                ("reset".to_string(), Some("reset-observed"))
            } else if kind.contains("taillossprobe") {
                // A Tail Loss Probe is a proactive probe TCP sends on healthy connections while an
                // ACK is outstanding: despite the name it is not a retransmission or loss.
                ("observed".to_string(), None)
            } else if contains_any(kind, &["timeout", "retrans", "retransmit", "loss"]) {
                ("loss".to_string(), Some("timeout-or-retransmit-observed"))
            } else if contains_any(kind, &["mtu", "fragment", "packet too big"]) {
                ("mtu".to_string(), Some("mtu-or-fragmentation-observed"))
            } else {
                (default_event(opcode), None)
            }
        }
        _ => (default_event(opcode), None),
    }
}

/// Whether an event is worth a row, decided on the lowercased task name before any property
/// parsing.
///
/// All-keyword TCPIP / AFD is a firehose: `TcpDataTransfer*`, `AfdSend` / `AfdReceive` and
/// `TcpConnectionRundown` (which enumerates every connection at session start) exhausted the
/// old event cap within seconds, and Tail Loss Probe alone was ~98 % of the rows in the field.
/// Only the task is matched because AFD data-path events carry the opcode `Connected`.
pub fn is_significant(category: &str, task: &str) -> bool {
    if task.contains("rundown") || task.contains("taillossprobe") {
        return false;
    }
    match category {
        "tcp" => contains_any(
            task,
            &[
                "connect",
                "accept",
                "disconnect",
                "close",
                "reset",
                "rst",
                "retrans",
                "timeout",
                "loss",
                "mtu",
                "fragment",
                "establish",
                "abort",
                "shutdown",
                "fin",
                "syn",
                "fail",
            ],
        ),
        "afd" => contains_any(
            task,
            &[
                "connect",
                "accept",
                "disconnect",
                "close",
                "abort",
                "shutdown",
                "bind",
                "listen",
                "fail",
            ],
        ),
        // dns, wfp, webio and unknown providers are low-volume: always kept.
        _ => true,
    }
}

/// The opcode as the event name, or `observed` when it is empty or `info`.
pub fn default_event(opcode: &str) -> String {
    let trimmed = opcode.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("info") {
        "observed".to_string()
    } else {
        trimmed.to_string()
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// Parses a Windows `SOCKADDR_IN` / `SOCKADDR_IN6` blob or a raw `IN_ADDR` / `IN6_ADDR`.
/// Ports inside a sockaddr are network order; port 0 means "none".
pub fn parse_sockaddr(bytes: &[u8]) -> Option<(IpAddr, Option<u16>)> {
    if bytes.len() >= 8 {
        let family = u16::from_le_bytes([bytes[0], bytes[1]]);
        let port = u16::from_be_bytes([bytes[2], bytes[3]]);
        if family == 2 {
            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            return Some((IpAddr::V4(ip), nonzero(port)));
        }
        if family == 23 && bytes.len() >= 24 {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&bytes[8..24]);
            return Some((IpAddr::V6(Ipv6Addr::from(addr)), nonzero(port)));
        }
    }
    match bytes.len() {
        4 => Some((
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
            None,
        )),
        16 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(bytes);
            Some((IpAddr::V6(Ipv6Addr::from(addr)), None))
        }
        _ => None,
    }
}

fn nonzero(port: u16) -> Option<u16> {
    (port != 0).then_some(port)
}

/// First token of `text` that parses as an IP address; tokens are split on every character that
/// is not an ASCII hex digit, `.` or `:` (DNS-Client `QueryResults` look like `1.2.3.4;5.6.7.8;`).
pub fn first_ip(text: &str) -> Option<IpAddr> {
    text.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
        .filter(|t| !t.is_empty())
        .find_map(|t| t.parse::<IpAddr>().ok())
}

/// Unsigned integer from a little-endian TDH value of 2, 4 or 8 bytes (the old `try_u`:
/// u16, then u32, then u64).
pub fn le_uint(bytes: &[u8]) -> Option<u64> {
    match *bytes {
        [a, b] => Some(u64::from(u16::from_le_bytes([a, b]))),
        [a, b, c, d] => Some(u64::from(u32::from_le_bytes([a, b, c, d]))),
        [a, b, c, d, e, f, g, h] => Some(u64::from_le_bytes([a, b, c, d, e, f, g, h])),
        _ => None,
    }
}

/// A port from a separate `*Port` property. TDH `win:Port` values are network order, so the old
/// little-endian read turned 443 into 47873 (B-36); a 16-bit value is therefore read big-endian.
/// Wider values keep the old little-endian read. Port 0 means "none".
pub fn port_value(bytes: &[u8]) -> Option<u64> {
    let port = match *bytes {
        [a, b] => u64::from(u16::from_be_bytes([a, b])),
        _ => le_uint(bytes)?,
    };
    (port != 0).then_some(port)
}

/// The first `max` characters of `text` (never splits a character).
pub fn truncate_chars(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §7.6 provider_category / known_guid (RC unit tests, verbatim).
    #[test]
    fn maps_providers_to_categories_and_guids() {
        assert_eq!(provider_category("Microsoft-Windows-DNS-Client"), "dns");
        assert_eq!(provider_category("Microsoft-Windows-WFP"), "wfp");
        assert_eq!(provider_category("Microsoft-Windows-TCPIP"), "tcp");
        assert_eq!(provider_category("Microsoft-Windows-Winsock-AFD"), "afd");
        assert_eq!(provider_category("Microsoft-Windows-WebIO"), "webio");
        assert_eq!(provider_category("Some-Other-Provider"), "event");
        assert_eq!(
            canonical_provider("Some-Other-Provider"),
            "Microsoft-Windows-TCPIP"
        );
        assert_eq!(
            canonical_provider("microsoft-windows-dns-client"),
            "Microsoft-Windows-DNS-Client"
        );
        for p in [
            "Microsoft-Windows-TCPIP",
            "Microsoft-Windows-DNS-Client",
            "Microsoft-Windows-WFP",
            "Microsoft-Windows-Winsock-AFD",
            "Microsoft-Windows-WebIO",
        ] {
            assert!(known_guid(p).is_some(), "{p}");
        }
        assert_eq!(known_guid("Unknown-Provider"), None);
        assert_eq!(
            known_guid("Microsoft-Windows-TCPIP"),
            Some(0x2F07E2EE_15DB_40F1_90EF_9D7BA282188A)
        );
    }

    /// §7.6 derive_event_and_reason (RC unit tests, verbatim).
    #[test]
    fn derives_events_and_reasons() {
        let d = derive_event_and_reason;
        assert_eq!(
            d("dns", "microsoft-windows-dns-client query", ""),
            ("query".into(), None)
        );
        assert_eq!(
            d("wfp", "microsoft-windows-wfp filter block packet", "Block"),
            ("block".into(), Some("wfp-block-observed"))
        );
        assert_eq!(
            d("tcp", "tcpip connection reset", "").1,
            Some("reset-observed")
        );
        assert_eq!(
            d("tcp", "tcpip retransmit timeout", "").1,
            Some("timeout-or-retransmit-observed")
        );
        assert_eq!(
            d("tcp", "tcpip path mtu changed", "").1,
            Some("mtu-or-fragmentation-observed")
        );
        // Tail Loss Probe is proactive, never loss; genuine loss recovery still is.
        assert_eq!(
            d("tcp", "tcpip tcptaillossprobe", ""),
            ("observed".into(), None)
        );
        assert_eq!(
            d("tcp", "tcpip tcplossrecoverysend", "").1,
            Some("timeout-or-retransmit-observed")
        );
        assert_eq!(
            d("tcp", "tcpip tcpdatatransferretransmitround", "").1,
            Some("timeout-or-retransmit-observed")
        );
        assert_eq!(
            d("tcp", "tcpip connect", "Connect"),
            ("Connect".into(), None)
        );
        assert_eq!(d("tcp", "tcpip", "info"), ("observed".into(), None));
        // Verbatim substring rule: "rst" inside "first" still reads as a reset.
        assert_eq!(d("tcp", "tcpip first packet", "").0, "reset");
    }

    /// §7.6 is_significant: rundown / data path / TLP dropped, lifecycle and faults kept.
    #[test]
    fn drops_noise_keeps_connection_events() {
        for (c, t) in [
            ("tcp", "tcpconnectionrundown"),
            ("tcp", "tcpdatatransferreceive"),
            ("tcp", "tcpdatatransfersend"),
            ("tcp", "tcptaillossprobe"),
            ("afd", "afdsend"),
            ("afd", "afdreceive"),
            ("afd", "afddataindication"),
        ] {
            assert!(!is_significant(c, t), "{c} {t}");
        }
        for (c, t) in [
            ("tcp", "tcprequestconnect"),
            ("tcp", "tcpclosetcbrequest"),
            ("tcp", "tcpconnectionterminatedrcvdrst"),
            ("tcp", "tcplossrecoverysend"),
            ("tcp", "tcpdatatransferretransmitround"),
            ("tcp", "tcprecentconnectionfailure"),
            ("afd", "afdconnect"),
            ("afd", "afdclose"),
            ("afd", "afdbindwithaddress"),
            ("dns", "dnsqueryresolution"),
            ("wfp", "filterevent"),
            ("webio", "request"),
        ] {
            assert!(is_significant(c, t), "{c} {t}");
        }
        // An empty task (schema lookup failed) drops tcp/afd, keeps the rest (RS:190-215).
        assert!(!is_significant("tcp", ""));
        assert!(is_significant("dns", ""));
    }

    /// §7.6 parse_sockaddr / first_ip (RS unit tests, verbatim).
    #[test]
    fn parses_addresses() {
        let v4 = [2u8, 0, 0x01, 0xBB, 142, 250, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_sockaddr(&v4),
            Some(("142.250.1.2".parse().unwrap(), Some(443)))
        );
        let mut v6 = vec![23u8, 0, 0x01, 0xBB, 0, 0, 0, 0];
        v6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            parse_sockaddr(&v6),
            Some(("2001:db8::1".parse().unwrap(), Some(443)))
        );
        assert_eq!(
            parse_sockaddr(&[8, 8, 4, 4]),
            Some(("8.8.4.4".parse().unwrap(), None))
        );
        assert_eq!(parse_sockaddr(&[1, 2, 3]), None);
        assert_eq!(
            first_ip("172.16.2.2;10.0.0.1;"),
            Some("172.16.2.2".parse().unwrap())
        );
        assert_eq!(first_ip("no-ip-here"), None);
    }

    /// B-36: a 16-bit port property is network order; other integers stay little-endian.
    #[test]
    fn reads_integers_and_ports() {
        assert_eq!(le_uint(&443u16.to_le_bytes()), Some(443));
        assert_eq!(le_uint(&9_000_000u32.to_le_bytes()), Some(9_000_000));
        assert_eq!(le_uint(&[1, 2, 3]), None);
        assert_eq!(port_value(&443u16.to_be_bytes()), Some(443));
        assert_eq!(port_value(&[0, 0]), None);
        assert_eq!(truncate_chars("пример", 3), "при");
    }
}
