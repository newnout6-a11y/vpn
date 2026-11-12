//! The adapter inventory: `GetAdaptersAddresses` rows joined with their `GetIfTable2` row and NDIS
//! class key, plus the one `physical` predicate every consumer shares (DNS sources, leak tests,
//! pings, network identity), so they always agree on what "the user's real NICs" are.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::ERROR_NOT_FOUND;
use windows::core::GUID;

use super::TUN_V4;
use super::ffi::{self, GaaRow, IfRow};
use super::reg::{self, ClassInfo};

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IF_TYPE_TUNNEL: u32 = 131;
const OPER_UP: i32 = 1;
const OPER_DOWN: i32 = 2;
const OPER_NOT_PRESENT: i32 = 6;
const NCF_HIDDEN: u32 = 0x8;
const DAD_INVALID: i32 = 0;
const DAD_DUPLICATE: i32 = 2;

/// Virtual and tunnel adapters by description, case-insensitive (old `ADAPTER_EXCLUSION_PATTERN`).
/// `Hyper-V` is deliberately absent: inside a Hyper-V guest "Microsoft Hyper-V Network Adapter" is
/// the real uplink, while the host's vSwitch vNICs already fail the hardware test.
const VIRTUAL_DESCRIPTIONS: [&str; 10] = [
    "wintun",
    "tap-windows",
    "tailscale",
    "wireguard",
    "loopback",
    "vethernet",
    "vpn",
    "virtualbox",
    "vmware",
    "bluetooth",
];

/// One unicast address of an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnicastAddress {
    pub ip: IpAddr,
    pub prefix_len: u8,
    /// `NL_DAD_STATE`: 0 invalid, 1 tentative, 2 duplicate, 3 deprecated, 4 preferred.
    pub dad_state: i32,
    /// A temporary (privacy) IPv6 address (`SuffixOrigin == NlsoRandom`).
    pub temporary: bool,
}

impl UnicastAddress {
    /// Usable as a source: DAD neither Invalid nor Duplicate (Tentative and Deprecated count).
    pub fn usable(&self) -> bool {
        self.dad_state != DAD_INVALID && self.dad_state != DAD_DUPLICATE
    }
}

/// Adapter state as `Get-NetAdapter` words it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdapterStatus {
    Up,
    Disconnected,
    NotPresent,
    Disabled,
}

impl AdapterStatus {
    fn from_oper(oper_status: i32, media_disconnected: bool) -> Self {
        match oper_status {
            OPER_UP => AdapterStatus::Up,
            OPER_NOT_PRESENT => AdapterStatus::NotPresent,
            OPER_DOWN if media_disconnected => AdapterStatus::Disconnected,
            _ => AdapterStatus::Disabled,
        }
    }
}

/// One network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    pub if_index: u32,
    pub luid: u64,
    pub guid: GUID,
    /// Connection name ("Беспроводная сеть", "Ethernet 5").
    pub alias: String,
    pub description: String,
    /// IANA ifType: 6 Ethernet, 71 Wi-Fi, 24 loopback, 131 tunnel, 53 proprietary virtual.
    pub if_type: u32,
    pub status: AdapterStatus,
    /// Current hardware address (may be randomised on Wi-Fi).
    pub mac: Vec<u8>,
    /// Burned-in hardware address (`GetIfTable2`); empty for virtual adapters.
    pub permanent_mac: Vec<u8>,
    /// Backed by a hardware device (`HardwareInterface`).
    pub hardware: bool,
    /// An NDIS lightweight filter module, not an adapter (`FilterInterface`).
    pub filter: bool,
    /// `NCF_HIDDEN` in the NDIS class key (WAN miniports, Wi-Fi Direct, kernel debugger).
    pub hidden: bool,
    /// Driver `ComponentId` from the class key, lowercase (`wintun`, `tap0901`, `wireguard`).
    pub driver: Option<String>,
    pub ipv4_enabled: bool,
    pub ipv6_enabled: bool,
    /// Transmit link speed in bit/s (`u64::MAX` = unknown).
    pub link_speed_bps: u64,
    pub addresses: Vec<UnicastAddress>,
    pub gateways: Vec<IpAddr>,
    pub dns: Vec<IpAddr>,
    /// `NameServer` is set in the registry (static IPv4 DNS); otherwise DNS comes from DHCP.
    pub dns_static: bool,
    /// The user's real NIC (see [`physical_adapters`]).
    pub physical: bool,
}

impl Adapter {
    /// Operationally up.
    pub fn is_up(&self) -> bool {
        self.status == AdapterStatus::Up
    }

    /// Listed by `Get-NetAdapter` without `-IncludeHidden`: not a filter module, not a loopback or
    /// tunnel pseudo-interface, not `NCF_HIDDEN`.
    pub fn is_visible(&self) -> bool {
        !self.filter
            && self.if_type != IF_TYPE_SOFTWARE_LOOPBACK
            && self.if_type != IF_TYPE_TUNNEL
            && !self.hidden
    }

    /// Usable IPv4 source addresses, link-local `169.254.*` excluded (leak-test / ping sources).
    pub fn source_v4(&self) -> Vec<Ipv4Addr> {
        self.addresses
            .iter()
            .filter(|a| a.usable())
            .filter_map(|a| match a.ip {
                IpAddr::V4(v4) if !v4.is_link_local() => Some(v4),
                _ => None,
            })
            .collect()
    }

    /// Usable global unicast IPv6 addresses (`2000::/3`).
    pub fn global_v6(&self) -> Vec<Ipv6Addr> {
        self.addresses
            .iter()
            .filter(|a| a.usable())
            .filter_map(|a| match a.ip {
                IpAddr::V6(v6) if v6.segments()[0] & 0xe000 == 0x2000 => Some(v6),
                _ => None,
            })
            .collect()
    }

    /// IPv4 DNS servers.
    pub fn dns_v4(&self) -> Vec<Ipv4Addr> {
        self.dns.iter().filter_map(|ip| v4(*ip)).collect()
    }

    /// IPv4 default gateways; an on-link `0.0.0.0` next hop is not a gateway.
    pub fn gateways_v4(&self) -> Vec<Ipv4Addr> {
        self.gateways
            .iter()
            .filter_map(|ip| v4(*ip))
            .filter(|g| !g.is_unspecified())
            .collect()
    }
}

fn v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// The physical-adapter predicate (firewall-recovery §3.7, plus "visible" so a physical adapter is
/// always one `Get-NetAdapter` lists). Our TUN never passes it: Wintun is a software device (no
/// `HardwareInterface`, no permanent MAC), so no alias list is needed (B6).
fn is_physical(a: &Adapter) -> bool {
    let description = a.description.to_lowercase();
    a.is_up()
        && a.is_visible()
        && a.hardware
        // IPv6-only and DHCP-pending NICs count; an unbound SR-IOV VF does not.
        && (a.ipv4_enabled || a.ipv6_enabled)
        && !VIRTUAL_DESCRIPTIONS.iter().any(|v| description.contains(v))
        && a.permanent_mac.iter().any(|&b| b != 0)
}

/// A non-blank `NameServer` value means static DNS; blank or absent means DHCP.
fn is_static_dns(name_server: Option<&str>) -> bool {
    name_server.is_some_and(|s| !s.trim().is_empty())
}

/// Joins the three sources. An adapter whose `GetIfTable2` row vanished in between (it went away
/// during the read) keeps neutral flags and fails the physical test.
fn join(
    gaa: Vec<GaaRow>,
    if_rows: &HashMap<u64, IfRow>,
    classes: &HashMap<GUID, ClassInfo>,
    name_server: impl Fn(&GUID) -> Option<String>,
) -> Vec<Adapter> {
    gaa.into_iter()
        .filter_map(|g| {
            let row = if_rows.get(&g.luid);
            let guid = row.map(|r| r.guid).or(g.guid)?;
            let class = classes.get(&guid);
            let mut adapter = Adapter {
                // GAA leaves `IfIndex` 0 when IPv4 is unbound; the interface table always has it.
                if_index: row.map_or(g.if_index, |r| r.if_index),
                luid: g.luid,
                guid,
                alias: g.alias,
                description: g.description,
                if_type: g.if_type,
                status: AdapterStatus::from_oper(
                    g.oper_status,
                    row.is_some_and(|r| r.media_disconnected),
                ),
                mac: g.mac,
                permanent_mac: row.map(|r| r.permanent_mac.clone()).unwrap_or_default(),
                hardware: row.is_some_and(|r| r.hardware),
                filter: row.is_some_and(|r| r.filter),
                hidden: class.is_some_and(|c| c.characteristics & NCF_HIDDEN != 0),
                driver: class.and_then(|c| c.component_id.clone()),
                ipv4_enabled: g.ipv4_enabled,
                ipv6_enabled: g.ipv6_enabled,
                link_speed_bps: g.link_speed_bps,
                addresses: g.addresses,
                gateways: g.gateways,
                dns: g.dns,
                // `NameServer` is an IPv4 setting: no registry read for unbound interfaces.
                dns_static: g.ipv4_enabled && is_static_dns(name_server(&guid).as_deref()),
                physical: false,
            };
            adapter.physical = is_physical(&adapter);
            Some(adapter)
        })
        .collect()
}

/// Every interface `GetAdaptersAddresses` reports (down, hidden and unbound ones included).
/// An empty or loopback-only enumeration is a failed read, never "this machine has no network".
pub fn inventory() -> windows::core::Result<Vec<Adapter>> {
    let gaa = ffi::adapters()?;
    let if_rows: HashMap<u64, IfRow> = ffi::if_rows()?.into_iter().map(|r| (r.luid, r)).collect();
    // The class key only refines `hidden` / `driver`; losing it must not take the inventory down.
    let classes = reg::class_keys().unwrap_or_else(|err| {
        tracing::warn!("adapter class keys unreadable: {err}");
        HashMap::new()
    });
    let adapters = join(gaa, &if_rows, &classes, |guid| {
        reg::name_server(guid).ok().flatten()
    });
    plausible(adapters)
}

fn plausible(adapters: Vec<Adapter>) -> windows::core::Result<Vec<Adapter>> {
    if !adapters
        .iter()
        .any(|a| a.if_type != IF_TYPE_SOFTWARE_LOOPBACK)
    {
        return Err(windows::core::Error::new(
            ERROR_NOT_FOUND.to_hresult(),
            "adapter enumeration returned no interface besides loopback",
        ));
    }
    Ok(adapters)
}

/// The user's real NICs (firewall-recovery §3.7): up, hardware-backed, not a filter module, an
/// IPv4 or IPv6 binding, not hidden, not a known virtual/tunnel description, a non-zero burned-in
/// MAC. An empty selection is an error (fail closed), never "no adapters".
pub fn physical_adapters() -> windows::core::Result<Vec<Adapter>> {
    select_physical(inventory()?)
}

fn select_physical(adapters: Vec<Adapter>) -> windows::core::Result<Vec<Adapter>> {
    let physical: Vec<Adapter> = adapters.into_iter().filter(|a| a.physical).collect();
    if physical.is_empty() {
        return Err(windows::core::Error::new(
            ERROR_NOT_FOUND.to_hresult(),
            "no physical network adapter is up",
        ));
    }
    Ok(physical)
}

/// IPv4 DNS servers of the physical adapters, deduplicated in adapter order, without our TUN's
/// gateway / resolver (an old build could leave them on a NIC). For the engine's direct resolver
/// only: never evidence for anything security-related.
pub fn physical_dns_v4() -> windows::core::Result<Vec<Ipv4Addr>> {
    Ok(dns_sources(&physical_adapters()?))
}

fn dns_sources(physical: &[Adapter]) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for dns in physical.iter().flat_map(Adapter::dns_v4) {
        if !TUN_V4.contains(&dns) && !dns.is_unspecified() && !out.contains(&dns) {
            out.push(dns);
        }
    }
    out
}

/// A Hyper-V virtual switch exists (a `vEthernet (…)` host vNIC): WSL 2, Windows Sandbox, Docker
/// and Hyper-V guests are NATed below the ALE layers the kill switch filters (WFP review D3).
pub(crate) fn hyperv_switch_present() -> windows::core::Result<bool> {
    Ok(ffi::if_rows()?.iter().any(is_hyperv_vnic))
}

fn is_hyperv_vnic(row: &IfRow) -> bool {
    row.alias.starts_with("vEthernet (")
        || row
            .description
            .starts_with("Hyper-V Virtual Ethernet Adapter")
}

#[cfg(test)]
mod tests;
