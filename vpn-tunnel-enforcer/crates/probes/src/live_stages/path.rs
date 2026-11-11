//! Route / interface facts for the server address (`GetBestRoute2`, about 1 ms instead of a
//! PowerShell `Find-NetRoute`) and the physical uplink the direct stages bind to.
use std::net::IpAddr;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use vpnte_base::Msg;
use vpnte_winnet::adapters;

use super::{NotCheckedReason, ProbePath, Text, elapsed_ms};

/// Status of the path stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathStatus {
    Ok,
    Error,
    Skipped,
    #[default]
    NotChecked,
}

/// Where the facts came from (old vocabulary; native lookups are `net-route`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    EtwCorroborated,
    RoutePolicy,
    NetRoute,
    #[default]
    OsUnverified,
}

/// Which interface Windows uses for the server now (`pathDiagnostics` in the row).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathInfo {
    pub status: PathStatus,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub destination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_interface_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_interface_alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_local_ip: Option<String>,
    /// Gateway; absent for an on-link destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_hop: Option<String>,
    #[serde(default)]
    pub is_tun_interface: bool,
    #[serde(default)]
    pub evidence_kind: EvidenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NotCheckedReason>,
    /// Interface LUID, for the PMTU stage only (never stored).
    #[serde(skip)]
    pub luid: Option<u64>,
}

/// Looks up the best route to `dst`. `tun_luid` = our TUN while the tunnel is up: the route is
/// "through the TUN" when it uses that interface or one of our TUN addresses as source.
pub fn path_info(dst: IpAddr, tun_luid: Option<u64>) -> PathInfo {
    let start = Instant::now();
    let base = PathInfo {
        destination: dst.to_string(),
        evidence_kind: EvidenceKind::NetRoute,
        ..PathInfo::default()
    };
    match adapters::best_route(dst) {
        Ok(route) => PathInfo {
            status: PathStatus::Ok,
            active_interface_index: Some(route.if_index),
            active_interface_alias: adapters::alias_of(route.luid).ok(),
            active_local_ip: Some(route.source.to_string()),
            next_hop: route
                .next_hop
                .filter(|h| !h.is_unspecified())
                .map(|h| h.to_string()),
            is_tun_interface: is_tun(route.luid, route.source, tun_luid),
            luid: Some(route.luid),
            duration_ms: elapsed_ms(start),
            ..base
        },
        Err(err) => {
            tracing::debug!(error = %err, "best route lookup failed");
            PathInfo {
                status: PathStatus::Error,
                error: Some(Text::Msg(Msg::new(route_error_key(&err)))),
                duration_ms: elapsed_ms(start),
                ..base
            }
        }
    }
}

fn is_tun(luid: u64, source: IpAddr, tun_luid: Option<u64>) -> bool {
    tun_luid == Some(luid) || adapters::is_own_tun_address(source)
}

/// "No route" (the table has nothing for the address) vs any other failure.
pub(super) fn route_error_key(err: &windows::core::Error) -> &'static str {
    use windows::Win32::Foundation::{
        ERROR_HOST_UNREACHABLE, ERROR_NETWORK_UNREACHABLE, ERROR_NOT_FOUND,
    };
    let no_route = [
        ERROR_NETWORK_UNREACHABLE,
        ERROR_HOST_UNREACHABLE,
        ERROR_NOT_FOUND,
    ]
    .iter()
    .any(|code| err.code() == code.to_hresult());
    if no_route {
        "probes.liveStages.path.noRoute"
    } else {
        "probes.liveStages.path.failed"
    }
}

/// The physical uplink to bind the direct stages to while our tunnel is up, with its alias
/// (blocking: walks the adapter table, 7-20 ms). Prefers an adapter that has a gateway.
pub fn physical_uplink() -> windows::core::Result<(ProbePath, String)> {
    let adapters = adapters::physical_adapters()?;
    let best = adapters
        .iter()
        .filter(|a| a.is_up())
        .min_by_key(|a| (a.gateways.is_empty(), a.source_v4().is_empty()))
        .or(adapters.first());
    let Some(a) = best else {
        return Err(windows::core::Error::new(
            windows::Win32::Foundation::ERROR_NOT_FOUND.to_hresult(),
            "no physical network adapter is up",
        ));
    };
    let path = ProbePath::Physical {
        if_index: a.if_index,
        luid: a.luid,
        src_v4: a.source_v4().first().copied(),
        src_v6: a.global_v6().first().copied(),
    };
    Ok((path, a.alias.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AT-05-001: the loopback route is reported with its interface and source.
    #[test]
    fn loopback_route_facts() {
        let info = path_info(IpAddr::from([127, 0, 0, 1]), None);
        assert_eq!(info.status, PathStatus::Ok, "{info:?}");
        assert_eq!(info.active_local_ip.as_deref(), Some("127.0.0.1"));
        assert!(info.active_interface_alias.unwrap().contains("Loopback"));
        assert!(!info.is_tun_interface);
        assert_eq!(info.evidence_kind, EvidenceKind::NetRoute);
        assert!(info.luid.is_some());
        let json = serde_json::to_value(PathInfo {
            luid: Some(7),
            ..PathInfo::default()
        })
        .unwrap();
        assert!(json.get("luid").is_none());
    }

    #[test]
    fn tun_detection() {
        let lan = IpAddr::from([192, 168, 1, 5]);
        assert!(is_tun(42, lan, Some(42)));
        assert!(!is_tun(41, lan, Some(42)));
        assert!(is_tun(41, IpAddr::from([192, 168, 250, 253]), None));
        assert!(!is_tun(41, lan, None));
    }

    /// The uplink (when this machine has one) carries a source address of its own.
    #[test]
    fn uplink_smoke() {
        if let Ok((
            ProbePath::Physical {
                if_index,
                src_v4,
                src_v6,
                ..
            },
            alias,
        )) = physical_uplink()
        {
            assert!(if_index > 0 && !alias.is_empty());
            assert!(src_v4.is_some() || src_v6.is_some());
        }
    }
}
