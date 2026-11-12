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

/// The uplink of the network-mode check: the adapter that carries the default route once every
/// tunnel is set aside — ours (`own_tun`, or any Wintun / WireGuard / TAP / VPN-named adapter per
/// winnet's one detector) and another client's. A PPPoE or mobile-broadband uplink counts (it
/// owns the default route, though it is no network card); a card without a route (a PPPoE NIC
/// with an APIPA address) does not. Blocking: three table walks, a few ms.
pub fn route_uplink(own_tun: Option<u64>) -> windows::core::Result<(ProbePath, String)> {
    use adapters::{Family, foreign_tun};
    let list = adapters::inventory()?;
    let mut defaults: Vec<(u64, u32)> = Vec::new();
    for family in [Family::V4, Family::V6] {
        let table = adapters::routes(family).unwrap_or_default();
        let zero = table.iter().filter(|r| r.destination.prefix_len() == 0);
        defaults.extend(zero.map(|r| (r.luid, r.metric)));
    }
    let mut tunnels: Vec<u64> = foreign_tun::detect(None, &[])?
        .iter()
        .map(|t| t.luid)
        .collect();
    tunnels.extend(own_tun);
    // Windows' own pick (route + interface metric) wins whenever it is not a tunnel.
    let preferred = adapters::default_route(Family::V4)
        .ok()
        .flatten()
        .map(|d| d.luid);
    let Some(a) = pick_uplink(&list, &defaults, &tunnels, preferred) else {
        return Err(windows::core::Error::new(
            windows::Win32::Foundation::ERROR_NOT_FOUND.to_hresult(),
            "no adapter outside a tunnel carries a default route",
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

/// `defaults` = `(luid, route metric)` of every `/0` route; `preferred` = the stack's own pick.
pub(crate) fn pick_uplink<'a>(
    list: &'a [adapters::Adapter],
    defaults: &[(u64, u32)],
    tunnels: &[u64],
    preferred: Option<u64>,
) -> Option<&'a adapters::Adapter> {
    let metric = |luid: u64| {
        defaults
            .iter()
            .filter(|(l, _)| *l == luid)
            .map(|(_, m)| *m)
            .min()
    };
    let usable = |a: &&adapters::Adapter| {
        a.is_up()
            && !tunnels.contains(&a.luid)
            && metric(a.luid).is_some()
            && !(a.source_v4().is_empty() && a.global_v6().is_empty())
    };
    let candidates: Vec<&adapters::Adapter> = list.iter().filter(usable).collect();
    candidates
        .iter()
        .find(|a| Some(a.luid) == preferred)
        .or_else(|| {
            candidates
                .iter()
                .min_by_key(|a| (metric(a.luid), a.if_index))
        })
        .copied()
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
        // The route uplink (read-only walks) is never a tunnel, ours or another client's.
        if let Ok((ProbePath::Physical { luid, .. }, _)) = route_uplink(None) {
            let tunnels = adapters::foreign_tun::detect(None, &[]).unwrap_or_default();
            assert!(tunnels.iter().all(|t| t.luid != luid));
        }
    }

    fn adapter(luid: u64, ip: &str, up: bool) -> adapters::Adapter {
        use adapters::{AdapterStatus, UnicastAddress};
        adapters::Adapter {
            if_index: u32::try_from(luid).unwrap(),
            luid,
            guid: windows::core::GUID::zeroed(),
            alias: format!("if{luid}"),
            description: String::new(),
            if_type: 6,
            status: if up {
                AdapterStatus::Up
            } else {
                AdapterStatus::Disconnected
            },
            mac: Vec::new(),
            permanent_mac: Vec::new(),
            hardware: true,
            filter: false,
            hidden: false,
            driver: None,
            ipv4_enabled: true,
            ipv6_enabled: true,
            link_speed_bps: 0,
            addresses: vec![UnicastAddress {
                ip: ip.parse().unwrap(),
                prefix_len: 24,
                dad_state: 4,
                temporary: false,
            }],
            gateways: Vec::new(),
            dns: Vec::new(),
            dns_static: false,
            physical: true,
        }
    }

    /// Review b5: the probes take the adapter that carries the default route, never a tunnel.
    /// PPPoE: the card has only an APIPA address and no route; the PPP line owns the default
    /// route. A foreign TUN with a lower metric and our own TUN are set aside.
    #[test]
    fn uplink_is_the_default_route_owner_past_tunnels() {
        let nic = adapter(3, "169.254.10.2", true);
        let ppp = adapter(7, "100.71.4.9", true);
        let happ = adapter(9, "172.19.0.1", true);
        let ours = adapter(11, "192.168.250.253", true);
        let list = [nic, ppp, happ, ours];
        let defaults = [(7, 50), (9, 0), (11, 0)];
        let pick = |tunnels: &[u64], preferred| {
            pick_uplink(&list, &defaults, tunnels, preferred).map(|a| a.luid)
        };
        assert_eq!(
            pick(&[9, 11], Some(9)),
            Some(7),
            "the stack's TUN pick is skipped"
        );
        assert_eq!(pick(&[9, 11], Some(7)), Some(7));
        assert_eq!(pick(&[9, 11], None), Some(7));
        // Without a route outside a tunnel there is no uplink (never a guessed card).
        assert_eq!(pick(&[7, 9, 11], None), None);
        // A disconnected adapter never carries the probes, whatever its route says.
        let down = [adapter(7, "100.71.4.9", false)];
        assert_eq!(pick_uplink(&down, &[(7, 0)], &[], Some(7)), None);
        // Two uplinks: the stack's pick, else the lower metric.
        let two = [
            adapter(4, "192.0.2.10", true),
            adapter(5, "198.51.100.10", true),
        ];
        let defaults = [(4, 25), (5, 35)];
        let luid = |preferred| pick_uplink(&two, &defaults, &[], preferred).map(|a| a.luid);
        assert_eq!(luid(Some(5)), Some(5));
        assert_eq!(luid(None), Some(4));
    }
}
