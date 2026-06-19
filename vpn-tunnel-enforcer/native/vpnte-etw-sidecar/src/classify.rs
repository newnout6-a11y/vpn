//! Pure, unit-testable classification helpers shared by the ETW callback.
//!
//! These mirror the category / event / reason mapping used by the previous
//! PowerShell sidecar (`resources/vpnte-etw-sidecar.ps1` `Convert-Event`) so the
//! downstream summary parser (`src/main/trafficForensicsSummary.ts`) keeps
//! behaving consistently.

/// Map a provider name to a normalized `category` value.
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

/// Normalize a provider name to the canonical Microsoft provider string used in
/// the `provider` field of emitted rows.
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

/// Fallback GUID table (as `u128`) for providers that cannot be resolved by name
/// on the target machine. Values are the well-known Microsoft provider GUIDs.
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

/// Derive the `event` name and optional `reason` from the event category and a
/// lowercased "kind" string built from provider/task/opcode names.
pub fn derive_event_and_reason(category: &str, kind: &str, opcode: &str) -> (String, Option<String>) {
    match category {
        "dns" => ("query".to_string(), None),
        "wfp" => {
            if contains_any(kind, &["block", "blocked", "drop", "discard", "5152", "5157"]) {
                ("block".to_string(), Some("wfp-block-observed".to_string()))
            } else {
                (default_event(opcode), None)
            }
        }
        "tcp" => {
            if contains_any(kind, &["reset", "rst"]) {
                ("reset".to_string(), Some("reset-observed".to_string()))
            } else if contains_any(kind, &["timeout", "retrans", "retransmit", "loss"]) {
                ("loss".to_string(), Some("timeout-or-retransmit-observed".to_string()))
            } else if contains_any(kind, &["mtu", "fragment", "packet too big"]) {
                ("mtu".to_string(), Some("mtu-or-fragmentation-observed".to_string()))
            } else {
                (default_event(opcode), None)
            }
        }
        _ => (default_event(opcode), None),
    }
}

/// Decide whether an event carries enough signal to be worth emitting, based on
/// its (lowercased) ETW **task name**.
///
/// Enabling the TCPIP/AFD providers with every keyword at max verbosity makes
/// ETW deliver a firehose: per-packet data-transfer rows (`TcpDataTransfer*`,
/// `AfdSend`/`AfdReceive`), and — worst of all — `TcpConnectionRundown`, which
/// enumerates *every* existing connection whenever the session (re)starts. That
/// floods the NDJSON timeline and slams the data-event cap within seconds
/// without adding insight.
///
/// We keep connection-lifecycle and security-relevant events (what a user
/// debugging a tunnel actually cares about) and drop the high-volume data path.
/// DNS / WFP / WebIO are naturally low-volume, so they pass through untouched.
///
/// Matching is on the task name only — NOT the opcode — because AFD data-path
/// events carry the opcode `Connected` (a socket-state qualifier), which would
/// otherwise falsely match a "connect" substring and defeat the filter.
pub fn is_significant(category: &str, task: &str) -> bool {
    // Connection rundown / capture-state enumeration is pure noise for a live
    // timeline regardless of provider.
    if task.contains("rundown") {
        return false;
    }
    match category {
        "dns" | "wfp" | "webio" | "event" => true,
        "tcp" => contains_any(
            task,
            &[
                "connect", "accept", "disconnect", "close", "reset", "rst", "retrans",
                "timeout", "loss", "mtu", "fragment", "establish", "abort", "shutdown",
                "fin", "syn", "fail",
            ],
        ),
        "afd" => contains_any(
            task,
            &[
                "connect", "accept", "disconnect", "close", "abort", "shutdown", "bind",
                "listen", "fail",
            ],
        ),
        _ => true,
    }
}

fn default_event(opcode: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_providers_to_categories() {
        assert_eq!(provider_category("Microsoft-Windows-DNS-Client"), "dns");
        assert_eq!(provider_category("Microsoft-Windows-WFP"), "wfp");
        assert_eq!(provider_category("Microsoft-Windows-TCPIP"), "tcp");
        assert_eq!(provider_category("Microsoft-Windows-Winsock-AFD"), "afd");
        assert_eq!(provider_category("Microsoft-Windows-WebIO"), "webio");
        assert_eq!(provider_category("Some-Other-Provider"), "event");
    }

    #[test]
    fn resolves_known_guids_for_known_providers() {
        assert!(known_guid("Microsoft-Windows-TCPIP").is_some());
        assert!(known_guid("Microsoft-Windows-DNS-Client").is_some());
        assert!(known_guid("Microsoft-Windows-WFP").is_some());
        assert!(known_guid("Microsoft-Windows-Winsock-AFD").is_some());
        assert!(known_guid("Microsoft-Windows-WebIO").is_some());
        assert!(known_guid("Unknown-Provider").is_none());
    }

    #[test]
    fn dns_events_are_queries() {
        let (event, reason) = derive_event_and_reason("dns", "microsoft-windows-dns-client query", "");
        assert_eq!(event, "query");
        assert_eq!(reason, None);
    }

    #[test]
    fn wfp_block_is_detected() {
        let (event, reason) =
            derive_event_and_reason("wfp", "microsoft-windows-wfp filter block packet", "Block");
        assert_eq!(event, "block");
        assert_eq!(reason.as_deref(), Some("wfp-block-observed"));
    }

    #[test]
    fn tcp_reset_loss_mtu_are_detected() {
        assert_eq!(
            derive_event_and_reason("tcp", "tcpip connection reset", "").1.as_deref(),
            Some("reset-observed")
        );
        assert_eq!(
            derive_event_and_reason("tcp", "tcpip retransmit timeout", "").1.as_deref(),
            Some("timeout-or-retransmit-observed")
        );
        assert_eq!(
            derive_event_and_reason("tcp", "tcpip path mtu changed", "").1.as_deref(),
            Some("mtu-or-fragmentation-observed")
        );
    }

    #[test]
    fn drops_rundown_and_data_path_noise_keeps_connection_events() {
        // Matching is on the task name only. The biggest noise sources observed
        // in the field (real ETW task names):
        assert!(!is_significant("tcp", "tcpconnectionrundown"));
        assert!(!is_significant("tcp", "tcpdatatransferreceive"));
        assert!(!is_significant("tcp", "tcpdatatransfersend"));
        assert!(!is_significant("afd", "afdsend"));
        assert!(!is_significant("afd", "afdreceive"));
        assert!(!is_significant("afd", "afddataindication"));

        // Connection-lifecycle and fault events are kept (real task names).
        assert!(is_significant("tcp", "tcprequestconnect"));
        assert!(is_significant("tcp", "tcpclosetcbrequest"));
        assert!(is_significant("tcp", "tcpconnectionterminatedrcvdrst"));
        assert!(is_significant("tcp", "tcptaillossprobe"));
        assert!(is_significant("tcp", "tcprecentconnectionfailure"));
        assert!(is_significant("afd", "afdconnect"));
        assert!(is_significant("afd", "afdclose"));
        assert!(is_significant("afd", "afdbindwithaddress"));

        // Low-volume providers always pass.
        assert!(is_significant("dns", "dnsqueryresolution"));
        assert!(is_significant("wfp", "filterevent"));
        assert!(is_significant("webio", "request"));
    }

    #[test]
    fn tcp_without_keywords_falls_back_to_opcode_or_observed() {
        let (event, reason) = derive_event_and_reason("tcp", "tcpip connect", "Connect");
        assert_eq!(event, "Connect");
        assert_eq!(reason, None);

        let (event, reason) = derive_event_and_reason("tcp", "tcpip", "info");
        assert_eq!(event, "observed");
        assert_eq!(reason, None);
    }
}
