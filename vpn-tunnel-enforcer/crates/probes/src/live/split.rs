//! Split-tunnel snapshot of the extended check (live-probe §3.18): which process rules send
//! traffic around the tunnel and whether one process name sits in several rules.
use vpnte_base::Msg;

use super::env::SplitTunnelRules;
use super::model::{SplitTunnel, SplitTunnelStatus};

/// The outbound everything not matched by a direct rule takes.
const PROXY_OUT: &str = "proxy-out";

/// Summarises the rules. Process names are compared case-insensitively (Windows names are,
/// B-32); duplicates are reported in lower case, in first-seen order.
pub fn summarize_split_tunnel(rules: &SplitTunnelRules) -> SplitTunnel {
    let mut seen: Vec<String> = Vec::new();
    let mut duplicates: Vec<String> = Vec::new();
    for name in rules.direct_names.iter().chain(&rules.vpn_names) {
        let lower = name.trim().to_lowercase();
        if seen.contains(&lower) {
            if !duplicates.contains(&lower) {
                duplicates.push(lower);
            }
        } else {
            seen.push(lower);
        }
    }
    let direct_rule_count =
        u32::from(!rules.direct_names.is_empty()) + u32::from(!rules.direct_paths.is_empty());
    let (status, detail) = if !rules.enabled {
        (
            SplitTunnelStatus::Skipped,
            Msg::new("probes.live.split.disabled"),
        )
    } else if !duplicates.is_empty() {
        (
            SplitTunnelStatus::Warning,
            Msg::new("probes.live.split.duplicates").arg("names", duplicates.join(", ")),
        )
    } else if rules.direct_names.len() + rules.direct_paths.len() > 0 {
        (
            SplitTunnelStatus::Ok,
            Msg::new("probes.live.split.direct")
                .arg("names", rules.direct_names.len())
                .arg("paths", rules.direct_paths.len()),
        )
    } else {
        (SplitTunnelStatus::Ok, Msg::new("probes.live.split.none"))
    };
    SplitTunnel {
        status,
        enabled: rules.enabled,
        direct_process_names: rules.direct_names.clone(),
        vpn_process_names: rules.vpn_names.clone(),
        duplicate_process_names: duplicates,
        direct_rule_count,
        vpn_rule_count: 0,
        default_outbound: PROXY_OUT.into(),
        detail: Some(detail.into()),
        error: None,
    }
}

/// The rules could not be read: the routing state is unknown.
pub(crate) fn split_tunnel_failed(error: String) -> SplitTunnel {
    SplitTunnel {
        status: SplitTunnelStatus::Error,
        default_outbound: "unknown".into(),
        error: Some(error),
        ..SplitTunnel::default()
    }
}
