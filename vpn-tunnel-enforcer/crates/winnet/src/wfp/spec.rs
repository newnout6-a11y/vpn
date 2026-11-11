//! The filter catalogue (firewall-recovery §6.3): what each group matches, on which layers and
//! with which weight. Pure data; [`super::engine`] turns a [`FilterSpec`] into `FWPM_FILTER0`.
//!
//! Inside our sublayer the highest-weight matching filter decides. Conditions with the same
//! field are OR'ed, different fields AND'ed (WFP semantics), which the LAN, DNS and NDP groups
//! rely on.
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::{Ipv4Net, Ipv6Net};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_OUTBOUND_IPPACKET_V6,
};
use windows::core::GUID;

/// A WFP layer this module adds filters to (or, for the legacy one, deletes from).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layer {
    Connect4,
    Connect6,
    Accept4,
    Accept6,
    /// Used by the old app's IPv6 helper only; legacy cleanup deletes from it.
    OutboundIpPacket6,
}

impl Layer {
    /// The four ALE layers our protection uses.
    pub const OURS: [Layer; 4] = [
        Layer::Connect4,
        Layer::Connect6,
        Layer::Accept4,
        Layer::Accept6,
    ];

    /// Layer GUID from the `windows` crate.
    pub fn key(self) -> GUID {
        match self {
            Layer::Connect4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Layer::Connect6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            Layer::Accept4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            Layer::Accept6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            Layer::OutboundIpPacket6 => FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        }
    }

    /// The layer with this GUID, if it is one of ours.
    pub fn from_key(key: &GUID) -> Option<Layer> {
        [
            Layer::Connect4,
            Layer::Connect6,
            Layer::Accept4,
            Layer::Accept6,
            Layer::OutboundIpPacket6,
        ]
        .into_iter()
        .find(|l| l.key() == *key)
    }
}

/// What a filter does when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Soft permit (never `CLEAR_ACTION_RIGHT`): foreign blocks and sing-tun's DNS block still apply.
    Permit,
    Block,
}

/// A WFP application ID: the NT device path blob from `FwpmGetAppIdFromFileName0`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AppId(Box<[u8]>);

impl AppId {
    /// Wraps raw app-ID bytes (as returned by WFP).
    pub fn from_bytes(bytes: impl Into<Box<[u8]>>) -> Self {
        Self(bytes.into())
    }
    /// The raw bytes handed to WFP.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for AppId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppId({} bytes)", self.0.len())
    }
}

/// One filter condition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Cond {
    /// `FWPM_CONDITION_ALE_APP_ID` equals the blob.
    AppId(Arc<AppId>),
    /// `FWPM_CONDITION_IP_LOCAL_INTERFACE` equals the interface LUID.
    LocalInterface(u64),
    /// `FWPM_CONDITION_IP_LOCAL_ADDRESS` equals the address.
    LocalAddr(IpAddr),
    /// `FWPM_CONDITION_FLAGS` has `FWP_CONDITION_FLAG_IS_LOOPBACK` set.
    Loopback,
    /// `FWPM_CONDITION_IP_PROTOCOL` (17 = UDP, 58 = ICMPv6).
    Protocol(u8),
    LocalPort(u16),
    RemotePort(u16),
    /// Remote IPv4 network (host bits already masked).
    RemoteV4(Ipv4Net),
    /// Remote IPv6 network (host bits already masked).
    RemoteV6(Ipv6Net),
    /// ICMP type; `fwpmu.h` aliases `FWPM_CONDITION_ICMP_TYPE` to the local-port field.
    IcmpType(u16),
}

/// One WFP filter on one layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FilterSpec {
    /// Group name (`engine`, `dns`, ...); shown as display data `VPNTE <name>`, never parsed.
    pub name: &'static str,
    pub layer: Layer,
    pub action: Action,
    /// `FWP_UINT8` weight inside our sublayer.
    pub weight: u8,
    pub conds: Vec<Cond>,
}

/// Weights (§6.3): programs 15 > loopback 14 > TUN 13 > user exceptions 12 > DNS block 11 >
/// LAN / DHCP / NTP / NDP 10 > blocks 0. Exceptions outrank the DNS block on purpose: an
/// exception for a corporate resolver or an app with its own DNS must keep working.
pub(crate) const W_PROGRAM: u8 = 15;
pub(crate) const W_LOOPBACK: u8 = 14;
pub(crate) const W_TUN: u8 = 13;
pub(crate) const W_EXCEPTION: u8 = 12;
pub(crate) const W_DNS: u8 = 11;
pub(crate) const W_SERVICE: u8 = 10;
pub(crate) const W_BLOCK: u8 = 0;

const V4: [Layer; 2] = [Layer::Connect4, Layer::Accept4];
const V6: [Layer; 2] = [Layer::Connect6, Layer::Accept6];
const CONNECT: [Layer; 2] = [Layer::Connect4, Layer::Connect6];

/// Old `LAN_BYPASS_CIDRS` minus loopback (covered by the flag) plus limited broadcast.
const LAN_V4: [Ipv4Net; 6] = [
    Ipv4Net::new_assert(std::net::Ipv4Addr::new(10, 0, 0, 0), 8),
    Ipv4Net::new_assert(std::net::Ipv4Addr::new(172, 16, 0, 0), 12),
    Ipv4Net::new_assert(std::net::Ipv4Addr::new(192, 168, 0, 0), 16),
    Ipv4Net::new_assert(std::net::Ipv4Addr::new(169, 254, 0, 0), 16),
    Ipv4Net::new_assert(std::net::Ipv4Addr::new(224, 0, 0, 0), 4),
    Ipv4Net::new_assert(std::net::Ipv4Addr::BROADCAST, 32),
];
const LAN_V6: [Ipv6Net; 3] = [
    Ipv6Net::new_assert(std::net::Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    Ipv6Net::new_assert(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    Ipv6Net::new_assert(std::net::Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
];
const UDP: u8 = 17;
const ICMPV6: u8 = 58;
/// Router solicitation / advertisement, neighbour solicitation / advertisement, redirect.
const NDP_TYPES: [u16; 5] = [133, 134, 135, 136, 137];

fn group(
    name: &'static str,
    layers: &[Layer],
    action: Action,
    weight: u8,
    conds: &[Cond],
) -> Vec<FilterSpec> {
    layers
        .iter()
        .map(|&layer| FilterSpec {
            name,
            layer,
            action,
            weight,
            conds: conds.to_vec(),
        })
        .collect()
}

/// Permit for one program (engine, our own exe, per-session program) on all four layers.
pub(crate) fn program(name: &'static str, id: &Arc<AppId>) -> Vec<FilterSpec> {
    group(
        name,
        &Layer::OURS,
        Action::Permit,
        W_PROGRAM,
        &[Cond::AppId(id.clone())],
    )
}

pub(crate) fn loopback() -> Vec<FilterSpec> {
    group(
        "loopback",
        &Layer::OURS,
        Action::Permit,
        W_LOOPBACK,
        &[Cond::Loopback],
    )
}

pub(crate) fn tun(luid: u64) -> Vec<FilterSpec> {
    group(
        "tun",
        &Layer::OURS,
        Action::Permit,
        W_TUN,
        &[Cond::LocalInterface(luid)],
    )
}

/// Provisional TUN permit between `connect_begin` and `tun_up`: sing-box may add its routes
/// before the LUID is reported, and only the TUN owns this fixed local address (review R1).
pub(crate) fn tun_addr(addr: IpAddr) -> Vec<FilterSpec> {
    let layers = if addr.is_ipv4() { V4 } else { V6 };
    let conds = [Cond::LocalAddr(addr)];
    group("tun_addr", &layers, Action::Permit, W_TUN, &conds)
}

pub(crate) fn exception_app(id: &Arc<AppId>) -> Vec<FilterSpec> {
    group(
        "exception_app",
        &Layer::OURS,
        Action::Permit,
        W_EXCEPTION,
        &[Cond::AppId(id.clone())],
    )
}

/// Permit for one user CIDR on the layers of its family; host bits are masked here.
pub(crate) fn exception_ip(net: ipnet::IpNet) -> Vec<FilterSpec> {
    match net.trunc() {
        ipnet::IpNet::V4(n) => group(
            "exception_ip",
            &V4,
            Action::Permit,
            W_EXCEPTION,
            &[Cond::RemoteV4(n)],
        ),
        ipnet::IpNet::V6(n) => group(
            "exception_ip",
            &V6,
            Action::Permit,
            W_EXCEPTION,
            &[Cond::RemoteV6(n)],
        ),
    }
}

/// Block of plain DNS and DoT to anything outranked by nothing but programs, TUN and exceptions.
pub(crate) fn dns() -> Vec<FilterSpec> {
    group(
        "dns",
        &CONNECT,
        Action::Block,
        W_DNS,
        &[Cond::RemotePort(53), Cond::RemotePort(853)],
    )
}

pub(crate) fn lan(v4: bool, v6: bool) -> Vec<FilterSpec> {
    let mut out = Vec::new();
    if v4 {
        let conds: Vec<Cond> = LAN_V4.iter().map(|n| Cond::RemoteV4(*n)).collect();
        out.extend(group("lan", &V4, Action::Permit, W_SERVICE, &conds));
    }
    if v6 {
        let conds: Vec<Cond> = LAN_V6.iter().map(|n| Cond::RemoteV6(*n)).collect();
        out.extend(group("lan", &V6, Action::Permit, W_SERVICE, &conds));
    }
    out
}

/// DHCP lease renewal (client 68 <-> server 67).
pub(crate) fn dhcp() -> Vec<FilterSpec> {
    let conds = [
        Cond::Protocol(UDP),
        Cond::LocalPort(68),
        Cond::RemotePort(67),
    ];
    group("dhcp", &V4, Action::Permit, W_SERVICE, &conds)
}

/// DHCPv6 (client 546 <-> server 547).
pub(crate) fn dhcp6() -> Vec<FilterSpec> {
    let conds = [
        Cond::Protocol(UDP),
        Cond::LocalPort(546),
        Cond::RemotePort(547),
    ];
    group("dhcp6", &V6, Action::Permit, W_SERVICE, &conds)
}

/// NTP keeps the clock right for Reality / TLS.
pub(crate) fn ntp() -> Vec<FilterSpec> {
    group(
        "ntp",
        &CONNECT,
        Action::Permit,
        W_SERVICE,
        &[Cond::Protocol(UDP), Cond::RemotePort(123)],
    )
}

/// Neighbour discovery (port of sing-tun's RS / NS / NA permits).
pub(crate) fn ndp() -> Vec<FilterSpec> {
    let mut conds = vec![Cond::Protocol(ICMPV6)];
    conds.extend(NDP_TYPES.iter().map(|t| Cond::IcmpType(*t)));
    group("ndp", &V6, Action::Permit, W_SERVICE, &conds)
}

pub(crate) fn block4() -> Vec<FilterSpec> {
    group("block4", &V4, Action::Block, W_BLOCK, &[])
}

pub(crate) fn block6() -> Vec<FilterSpec> {
    group("block6", &V6, Action::Block, W_BLOCK, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layers_round_trip_through_their_keys() {
        for l in [
            Layer::Connect4,
            Layer::Connect6,
            Layer::Accept4,
            Layer::Accept6,
            Layer::OutboundIpPacket6,
        ] {
            assert_eq!(Layer::from_key(&l.key()), Some(l));
        }
        assert_eq!(Layer::from_key(&GUID::zeroed()), None);
    }

    /// AT-03-009: `192.0.2.1/24` installs the network `192.0.2.0/24`; an IPv4 CIDR is a C4/A4 pair.
    #[test]
    fn exception_ip_masks_host_bits_on_its_family() {
        let specs = exception_ip("192.0.2.1/24".parse().unwrap());
        assert_eq!(specs.iter().map(|s| s.layer).collect::<Vec<_>>(), V4);
        assert_eq!(
            specs[0].conds,
            [Cond::RemoteV4("192.0.2.0/24".parse().unwrap())]
        );
        let specs = exception_ip("2001:db8::5/128".parse().unwrap());
        assert_eq!(specs.iter().map(|s| s.layer).collect::<Vec<_>>(), V6);
        assert!(
            specs
                .iter()
                .all(|s| s.weight == W_EXCEPTION && s.action == Action::Permit)
        );
    }
}
