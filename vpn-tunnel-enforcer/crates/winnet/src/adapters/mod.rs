//! Network adapter and route reads through IP Helper (read-only: nothing here changes system state).
//!
//! - [`inventory`] — every interface `GetAdaptersAddresses` reports, joined with its `GetIfTable2`
//!   row and its NDIS class key, with a `physical` classification ([`physical_adapters`]).
//! - Our TUN: [`wait_owned_tun`] (alias + exact address ⇒ LUID / GUID / index), [`wait_released`],
//!   [`adapter_present`], [`route_proof`].
//! - Routes: [`routes`], [`best_route`], [`default_route`], [`interface_mtu`].
//! - [`alias`]: free TUN alias; [`foreign_tun`]: the one foreign / competing TUN detector;
//!   [`watch_network`]: debounced network-change events.
//!
//! Our adapter is identified by LUID once known, never by alias alone: a physical NIC that Windows
//! auto-named `Ethernet 5` must not be mistaken for ours (firewall-recovery B6).
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

pub mod alias;
pub mod foreign_tun;

mod ffi;
mod inventory;
mod reg;
mod route;
mod tun;
mod watch;

pub(crate) use inventory::hyperv_switch_present;
pub use inventory::{
    Adapter, AdapterStatus, UnicastAddress, inventory, physical_adapters, physical_dns_v4,
};
pub use route::{
    BestRoute, DefaultRoute, Route, alias_of, best_route, default_route, interface_mtu,
    route_proof, routes,
};
pub use tun::{OwnedTun, Release, TunAdapterError, adapter_present, wait_owned_tun, wait_released};
pub use watch::{NetChange, NetChangeKind, watch_network};

/// Our TUN's IPv4 (sing-box side, also the gateway) in its /30. Disguised as "another LAN" on
/// purpose: anti-VPN scanners flag unusual subnets such as the old `172.19.0.1/30`.
pub const TUN_V4: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 250, 253), 30);
/// The other usable address of the /30: the resolver sing-box hijacks DNS on.
pub const TUN_RESOLVER_V4: Ipv4Addr = Ipv4Addr::new(192, 168, 250, 254);
/// Our TUN's IPv6, present only when the TUN is dual-stack. A fixed RFC 4193 ULA, deliberately not
/// sing-box's documentation prefix (same anti-detection reasoning as [`TUN_V4`]).
pub const TUN_V6: Ipv6Net =
    Ipv6Net::new_assert(Ipv6Addr::new(0xfd8b, 0x3f2a, 0x91c4, 0, 0, 0, 0, 1), 126);

/// Address family selector for route and interface reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// Family of an address.
    pub fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

/// True for addresses our TUN has used: `192.168.250.x` (current) and `172.19.0.x` (builds before
/// the disguise). A prefix match is a hint for the release wait, never proof of ownership: other
/// clients use the same private ranges (Happ's `happ-xray` sits on `172.19.0.1/30`).
pub fn is_own_tun_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => matches!(v4.octets(), [192, 168, 250, _] | [172, 19, 0, _]),
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AT-02-002: `isOwnTunAddress` vectors (tunnel-core §7.14).
    #[test]
    fn own_tun_address_prefixes() {
        for own in ["192.168.250.253", "192.168.250.1", "172.19.0.1"] {
            assert!(is_own_tun_address(own.parse().unwrap()), "{own}");
        }
        for other in [
            "192.168.43.1",
            "192.168.43.50",
            "172.20.10.1",
            "10.0.0.1",
            "8.8.8.8",
            "::1",
        ] {
            assert!(!is_own_tun_address(other.parse().unwrap()), "{other}");
        }
        // The old vector also had "" → false: an empty string is not an address in Rust at all.
        assert!("".parse::<IpAddr>().is_err());
    }

    #[test]
    fn tun_constants() {
        assert_eq!(TUN_V4.to_string(), "192.168.250.253/30");
        assert_eq!(TUN_V4.network(), Ipv4Addr::new(192, 168, 250, 252));
        assert!(TUN_V4.contains(&TUN_RESOLVER_V4));
        assert_eq!(TUN_V6.to_string(), "fd8b:3f2a:91c4::1/126");
    }
}
