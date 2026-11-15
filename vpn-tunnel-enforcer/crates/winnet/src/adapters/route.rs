//! Route reads: the table, the stack's choice for a destination, the default-route interface, the
//! interface MTU, and the route proof for our TUN. Lookups only: no packet is ever sent.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use windows::Win32::Foundation::{E_UNEXPECTED, ERROR_NOT_FOUND};
use windows::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6};

use super::Family;
use super::ffi::{self, RawBest};
use super::tun::{self, OwnedTun};

/// Public canaries of the route proof: all must route into the TUN.
const CANARIES_V4: [Ipv4Addr; 3] = [
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(208, 67, 222, 222),
];
/// Added when the TUN is dual-stack (IPv6 egress goes through the tunnel).
const CANARY_V6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
const OPER_UP: i32 = 1;

/// One row of the route table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub if_index: u32,
    pub luid: u64,
    pub destination: IpNet,
    /// `None` for on-link routes (next hop `0.0.0.0` / `::`).
    pub next_hop: Option<IpAddr>,
    pub metric: u32,
    /// `NL_ROUTE_PROTOCOL` (2 local, 3 static / netmgmt, 19 DHCP ...).
    pub protocol: i32,
}

/// The route the stack picks for a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BestRoute {
    pub if_index: u32,
    pub luid: u64,
    /// Prefix of the selected route.
    pub destination: IpNet,
    pub next_hop: Option<IpAddr>,
    /// Source address the stack would use.
    pub source: IpAddr,
}

/// The interface carrying the default route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub if_index: u32,
    pub luid: u64,
    pub alias: String,
    pub next_hop: Option<IpAddr>,
    /// Route metric + interface metric (how Windows ranks default routes).
    pub metric: u32,
}

fn af(family: Family) -> ADDRESS_FAMILY {
    match family {
        Family::V4 => AF_INET,
        Family::V6 => AF_INET6,
    }
}

fn unexpected(what: String) -> windows::core::Error {
    windows::core::Error::new(E_UNEXPECTED, what)
}

/// The route table of one family (`GetIpForwardTable2`). An empty IPv4 table is a failed read
/// (every stack has loopback routes); an empty IPv6 table is possible.
pub fn routes(family: Family) -> windows::core::Result<Vec<Route>> {
    let rows = ffi::forward_table(af(family))?;
    if family == Family::V4 && rows.is_empty() {
        return Err(windows::core::Error::new(
            ERROR_NOT_FOUND.to_hresult(),
            "empty IPv4 route table",
        ));
    }
    Ok(rows)
}

/// The route the stack would use for `dst` (`GetBestRoute2`, any interface, any source).
pub fn best_route(dst: IpAddr) -> windows::core::Result<BestRoute> {
    check_best(dst, ffi::best_route(dst)?)
}

/// A usable answer names an interface and gives a route prefix and a source of `dst`'s family.
fn check_best(dst: IpAddr, raw: RawBest) -> windows::core::Result<BestRoute> {
    let family = Family::of(dst);
    let prefix = raw.prefix.filter(|(ip, _)| Family::of(*ip) == family);
    let source = raw.source.filter(|ip| Family::of(*ip) == family);
    let (Some((prefix, len)), Some(source)) = (prefix, source) else {
        return Err(unexpected(format!(
            "best route for {dst}: wrong address family"
        )));
    };
    if raw.if_index == 0 {
        return Err(unexpected(format!("best route for {dst}: no interface")));
    }
    let destination = IpNet::new(prefix, len)
        .map_err(|_| unexpected(format!("best route for {dst}: bad prefix")))?;
    Ok(BestRoute {
        if_index: raw.if_index,
        luid: raw.luid,
        destination,
        next_hop: raw.next_hop,
        source,
    })
}

/// Connection name of an interface (`ConvertInterfaceLuidToAlias`).
pub fn alias_of(luid: u64) -> windows::core::Result<String> {
    ffi::luid_alias(luid)
}

/// IP MTU of an interface for one family (`GetIpInterfaceEntry.NlMtu`); `None` without a binding.
pub fn interface_mtu(luid: u64, family: Family) -> windows::core::Result<Option<u32>> {
    Ok(ffi::ip_interface(luid, af(family))?.map(|i| i.mtu))
}

/// The interface Windows uses for the default route of `family`: among `0.0.0.0/0` (`::/0`) routes
/// on interfaces that are up, the lowest route + interface metric (ties: lowest index). A TUN that
/// installs its own `/0` (Happ does) is the answer; under a split-default TUN (`0.0.0.0/1` +
/// `128.0.0.0/1`) it is still the uplink. For the physical uplink use [`super::physical_adapters`].
pub fn default_route(family: Family) -> windows::core::Result<Option<DefaultRoute>> {
    let mut best: Option<DefaultRoute> = None;
    for route in routes(family)?
        .into_iter()
        .filter(|r| r.destination.prefix_len() == 0)
    {
        let Some(row) = ffi::if_row(route.luid)? else {
            continue;
        };
        if row.oper_status != OPER_UP {
            continue;
        }
        let Some(ip_if) = ffi::ip_interface(route.luid, af(family))? else {
            continue;
        };
        let metric = route.metric.saturating_add(ip_if.metric);
        if best
            .as_ref()
            .is_none_or(|b| (metric, route.if_index) < (b.metric, b.if_index))
        {
            best = Some(DefaultRoute {
                if_index: route.if_index,
                luid: route.luid,
                alias: row.alias,
                next_hop: route.next_hop,
                metric,
            });
        }
    }
    Ok(best)
}

/// True when our TUN still holds its identity (up, same GUID and alias, own addresses) and the
/// stack routes every public canary into it (`2606:4700:4700::1111` too when the TUN is dual-stack).
/// A competing route is authoritative: no retry until a later observation. `Err` = a read failed,
/// which proves nothing (callers treat it as not proven).
pub fn route_proof(tun: &OwnedTun) -> windows::core::Result<bool> {
    if !tun::identity_holds(tun)? {
        return Ok(false);
    }
    canaries_through(tun, best_route)
}

/// Stops at the first lookup that fails or selects another interface.
fn canaries_through(
    tun: &OwnedTun,
    mut lookup: impl FnMut(IpAddr) -> windows::core::Result<BestRoute>,
) -> windows::core::Result<bool> {
    let v6 = tun.v6.map(|_| IpAddr::V6(CANARY_V6));
    for dst in CANARIES_V4.map(IpAddr::V4).into_iter().chain(v6) {
        if lookup(dst)?.luid != tun.luid {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
