//! Unsafe IP Helper calls, each returning owned Rust data. Everything above this file is safe code.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};

use ipnet::IpNet;
use windows::Win32::Foundation::{
    E_UNEXPECTED, ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_NO_DATA, ERROR_NOT_FOUND,
    NO_ERROR, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToAlias, FreeMibTable, GAA_FLAG_INCLUDE_ALL_INTERFACES,
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses, GetBestRoute2, GetIfTable2,
    GetIpForwardTable2, GetIpInterfaceEntry, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_IPV4_ENABLED,
    IP_ADAPTER_IPV6_ENABLED, InitializeIpInterfaceEntry, MIB_IF_ROW2, MIB_IF_TABLE2,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
};
use windows::Win32::NetworkManagement::Ndis::{MediaConnectStateDisconnected, NET_LUID_LH};
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0,
    NlsoRandom, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET, SOCKET_ADDRESS,
};
use windows::core::GUID;

use super::{Route, UnicastAddress};
use crate::win::{from_wide, read_wide};

/// One `GetAdaptersAddresses` node, copied out of the OS buffer.
#[derive(Debug, Clone)]
pub(super) struct GaaRow {
    pub if_index: u32,
    pub luid: u64,
    /// Parsed from `AdapterName` (`{GUID}`); `None` if the OS gave something else.
    pub guid: Option<GUID>,
    pub alias: String,
    pub description: String,
    pub mac: Vec<u8>,
    pub ipv4_enabled: bool,
    pub ipv6_enabled: bool,
    pub if_type: u32,
    pub oper_status: i32,
    pub link_speed_bps: u64,
    pub addresses: Vec<UnicastAddress>,
    pub gateways: Vec<IpAddr>,
    pub dns: Vec<IpAddr>,
}

/// Every interface, including those without an IP binding (`GAA_FLAG_INCLUDE_ALL_INTERFACES`: a NIC
/// whose bindings were switched off still exists), with gateways and DNS servers.
const GAA_FLAGS: GET_ADAPTERS_ADDRESSES_FLAGS = GET_ADAPTERS_ADDRESSES_FLAGS(
    GAA_FLAG_SKIP_ANYCAST.0
        | GAA_FLAG_SKIP_MULTICAST.0
        | GAA_FLAG_INCLUDE_GATEWAYS.0
        | GAA_FLAG_INCLUDE_ALL_INTERFACES.0,
);
/// Buffer size of the next read: the largest size the OS has asked for. A machine with dozens of
/// NDIS filter interfaces needs ~100 KiB, and every overflow costs a whole second call (~7 ms).
static GAA_BYTES: AtomicU32 = AtomicU32::new(32 * 1024);
/// The table can grow between the size query and the read (adapters appearing); retry a few times.
const GAA_ATTEMPTS: usize = 6;

/// The adapter table ([`GAA_FLAGS`]). Blocking: several milliseconds on a busy machine.
pub(super) fn adapters() -> windows::core::Result<Vec<GaaRow>> {
    let mut size = GAA_BYTES.load(Ordering::Relaxed);
    for _ in 0..GAA_ATTEMPTS {
        // `u64` backing: `IP_ADAPTER_ADDRESSES` must be 8-byte aligned.
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let head = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: `buf` is writable, 8-byte aligned and at least `size` bytes long.
        let rc = unsafe {
            GetAdaptersAddresses(AF_UNSPEC.0.into(), GAA_FLAGS, None, Some(head), &mut size)
        };
        match WIN32_ERROR(rc) {
            NO_ERROR => {
                let mut rows = Vec::new();
                let mut node = head.cast_const();
                while !node.is_null() {
                    // SAFETY: the OS filled a linked list inside `buf`, which outlives this loop.
                    let a = unsafe { &*node };
                    rows.push(gaa_row(a));
                    node = a.Next;
                }
                return Ok(rows);
            }
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_BUFFER_OVERFLOW => {
                // `size` now holds what the OS needs.
                GAA_BYTES.fetch_max(size, Ordering::Relaxed);
            }
            err => return Err(err.into()),
        }
    }
    Err(ERROR_BUFFER_OVERFLOW.into())
}

/// [`adapters`] on tokio's blocking pool, for the async waits that poll it.
pub(super) async fn adapters_async() -> windows::core::Result<Vec<GaaRow>> {
    tokio::task::spawn_blocking(adapters)
        .await
        .unwrap_or_else(|join| Err(windows::core::Error::new(E_UNEXPECTED, join.to_string())))
}

fn gaa_row(a: &IP_ADAPTER_ADDRESSES_LH) -> GaaRow {
    // SAFETY: both union views are plain integers; the OS writes `Length` + `IfIndex`.
    let v4_index = unsafe { a.Anonymous1.Anonymous.IfIndex };
    // SAFETY: as above, `Flags` is the documented view of this union.
    let flags = unsafe { a.Anonymous2.Flags };
    // SAFETY: `NET_LUID_LH` is a u64 union.
    let luid = unsafe { a.Luid.Value };
    let mac_len = (a.PhysicalAddressLength as usize).min(a.PhysicalAddress.len());
    GaaRow {
        // `IfIndex` is 0 when IPv4 is not bound; the interface index is the same for both families.
        if_index: if v4_index != 0 {
            v4_index
        } else {
            a.Ipv6IfIndex
        },
        luid,
        guid: adapter_guid(a),
        // SAFETY: the OS sets both to valid NUL-terminated strings (possibly empty).
        alias: unsafe { read_wide(a.FriendlyName.0) },
        // SAFETY: as above.
        description: unsafe { read_wide(a.Description.0) },
        mac: a.PhysicalAddress[..mac_len].to_vec(),
        ipv4_enabled: flags & IP_ADAPTER_IPV4_ENABLED != 0,
        ipv6_enabled: flags & IP_ADAPTER_IPV6_ENABLED != 0,
        if_type: a.IfType,
        oper_status: a.OperStatus.0,
        link_speed_bps: a.TransmitLinkSpeed,
        addresses: unicast_list(a),
        gateways: gateway_list(a),
        dns: dns_list(a),
    }
}

fn adapter_guid(a: &IP_ADAPTER_ADDRESSES_LH) -> Option<GUID> {
    if a.AdapterName.is_null() {
        return None;
    }
    // SAFETY: non-null `AdapterName` is a NUL-terminated ANSI string owned by the GAA buffer.
    let name = unsafe { std::ffi::CStr::from_ptr(a.AdapterName.0.cast()) };
    parse_guid(name.to_str().ok()?)
}

/// `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` (braces optional, any case) to a GUID.
pub(super) fn parse_guid(text: &str) -> Option<GUID> {
    let bare = text.trim().trim_start_matches('{').trim_end_matches('}');
    GUID::try_from(bare).ok()
}

fn unicast_list(a: &IP_ADAPTER_ADDRESSES_LH) -> Vec<UnicastAddress> {
    let mut out = Vec::new();
    let mut node = a.FirstUnicastAddress.cast_const();
    while !node.is_null() {
        // SAFETY: list nodes live in the same GAA buffer as `a`.
        let u = unsafe { &*node };
        if let Some(ip) = socket_ip(&u.Address) {
            out.push(UnicastAddress {
                ip,
                prefix_len: u.OnLinkPrefixLength,
                dad_state: u.DadState.0,
                temporary: u.SuffixOrigin == NlsoRandom,
            });
        }
        node = u.Next;
    }
    out
}

fn gateway_list(a: &IP_ADAPTER_ADDRESSES_LH) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut node = a.FirstGatewayAddress.cast_const();
    while !node.is_null() {
        // SAFETY: list nodes live in the same GAA buffer as `a`.
        let g = unsafe { &*node };
        out.extend(socket_ip(&g.Address));
        node = g.Next;
    }
    out
}

fn dns_list(a: &IP_ADAPTER_ADDRESSES_LH) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut node = a.FirstDnsServerAddress.cast_const();
    while !node.is_null() {
        // SAFETY: list nodes live in the same GAA buffer as `a`.
        let d = unsafe { &*node };
        out.extend(socket_ip(&d.Address));
        node = d.Next;
    }
    out
}

fn socket_ip(sa: &SOCKET_ADDRESS) -> Option<IpAddr> {
    let len = usize::try_from(sa.iSockaddrLength).ok()?;
    if sa.lpSockaddr.is_null() || len < size_of::<SOCKADDR>() {
        return None;
    }
    // SAFETY: non-null and at least a `SOCKADDR` long, as the OS reported.
    let family = unsafe { (*sa.lpSockaddr).sa_family };
    if family == AF_INET && len >= size_of::<SOCKADDR_IN>() {
        // SAFETY: the family and length say this is a `SOCKADDR_IN`.
        let sin = unsafe { &*sa.lpSockaddr.cast::<SOCKADDR_IN>() };
        // SAFETY: `S_addr` is the plain u32 view of `IN_ADDR`, stored in network order.
        Some(IpAddr::V4(Ipv4Addr::from(
            unsafe { sin.sin_addr.S_un.S_addr }.to_ne_bytes(),
        )))
    } else if family == AF_INET6 && len >= size_of::<SOCKADDR_IN6>() {
        // SAFETY: the family and length say this is a `SOCKADDR_IN6`.
        let sin6 = unsafe { &*sa.lpSockaddr.cast::<SOCKADDR_IN6>() };
        // SAFETY: `Byte` is the plain byte view of `IN6_ADDR`.
        Some(IpAddr::V6(Ipv6Addr::from(unsafe { sin6.sin6_addr.u.Byte })))
    } else {
        None
    }
}

/// `SOCKADDR_INET` (route rows, best-route results) to an address; `None` for other families.
pub(super) fn inet_ip(s: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: every view of the union starts with the family field.
    let family = unsafe { s.si_family };
    if family == AF_INET {
        // SAFETY: the family selects the IPv4 view; `S_addr` is in network order.
        Some(IpAddr::V4(Ipv4Addr::from(
            unsafe { s.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
        )))
    } else if family == AF_INET6 {
        // SAFETY: the family selects the IPv6 view.
        Some(IpAddr::V6(Ipv6Addr::from(unsafe {
            s.Ipv6.sin6_addr.u.Byte
        })))
    } else {
        None
    }
}

/// An address as `SOCKADDR_INET` with port, flow info, scope and padding zero (GetBestRoute2
/// input).
pub(super) fn inet_from(ip: IpAddr) -> SOCKADDR_INET {
    let mut s = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(v4) => {
            s.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(v4.octets()),
                    },
                },
                sin_zero: [0; 8],
            };
        }
        IpAddr::V6(v6) => {
            s.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            };
        }
    }
    s
}

/// Frees a table returned by a `Get*Table2` call on every path.
struct MibTable<T>(*mut T);

impl<T> Drop for MibTable<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a successful `Get*Table2` call and is freed once.
            unsafe { FreeMibTable(self.0.cast_const().cast()) };
        }
    }
}

/// The parts of a `MIB_IF_ROW2` this module uses.
#[derive(Debug, Clone)]
pub(super) struct IfRow {
    pub luid: u64,
    pub if_index: u32,
    pub guid: GUID,
    pub alias: String,
    pub description: String,
    pub oper_status: i32,
    pub media_disconnected: bool,
    pub permanent_mac: Vec<u8>,
    /// `InterfaceAndOperStatusFlags.HardwareInterface`: backed by a hardware device (a Hyper-V
    /// guest uplink is; a vSwitch host vNIC, Wintun, TAP and the WAN miniports are not).
    pub hardware: bool,
    /// `InterfaceAndOperStatusFlags.FilterInterface`: an NDIS lightweight filter module.
    pub filter: bool,
}

fn if_row_from(r: &MIB_IF_ROW2) -> IfRow {
    let len = (r.PhysicalAddressLength as usize).min(r.PermanentPhysicalAddress.len());
    let bits = r.InterfaceAndOperStatusFlags._bitfield;
    IfRow {
        // SAFETY: `NET_LUID_LH` is a u64 union.
        luid: unsafe { r.InterfaceLuid.Value },
        if_index: r.InterfaceIndex,
        guid: r.InterfaceGuid,
        alias: from_wide(&r.Alias),
        description: from_wide(&r.Description),
        oper_status: r.OperStatus.0,
        media_disconnected: r.MediaConnectState == MediaConnectStateDisconnected,
        permanent_mac: r.PermanentPhysicalAddress[..len].to_vec(),
        hardware: bits & 0x1 != 0,
        filter: bits & 0x2 != 0,
    }
}

/// Every NDIS interface (`GetIfTable2`), filter modules and hidden pseudo-interfaces included.
pub(super) fn if_rows() -> windows::core::Result<Vec<IfRow>> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: out-pointer to a local; on success the OS allocates the table.
    unsafe { GetIfTable2(&mut table) }.ok()?;
    let table = MibTable(table);
    // SAFETY: on success the table holds `NumEntries` rows and stays alive until `table` drops; the
    // rows are reached through a raw pointer, not through the declared one-element array.
    let rows = unsafe {
        let first = (&raw const (*table.0).Table).cast::<MIB_IF_ROW2>();
        std::slice::from_raw_parts(first, (*table.0).NumEntries as usize)
    };
    Ok(rows.iter().map(if_row_from).collect())
}

/// One interface by LUID (`GetIfEntry2`); `None` when no such interface exists.
pub(super) fn if_row(luid: u64) -> windows::core::Result<Option<IfRow>> {
    Ok(crate::counters::entry(luid)?.as_ref().map(if_row_from))
}

/// The route table of one family (`GetIpForwardTable2`).
pub(super) fn forward_table(family: ADDRESS_FAMILY) -> windows::core::Result<Vec<Route>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: out-pointer to a local; on success the OS allocates the table.
    unsafe { GetIpForwardTable2(family, &mut table) }.ok()?;
    let table = MibTable(table);
    // SAFETY: as in `if_rows`: `NumEntries` rows behind the header, reached through a raw pointer.
    let rows = unsafe {
        let first = (&raw const (*table.0).Table).cast::<MIB_IPFORWARD_ROW2>();
        std::slice::from_raw_parts(first, (*table.0).NumEntries as usize)
    };
    Ok(rows.iter().filter_map(route_from).collect())
}

fn route_from(r: &MIB_IPFORWARD_ROW2) -> Option<Route> {
    let prefix = inet_ip(&r.DestinationPrefix.Prefix)?;
    Some(Route {
        if_index: r.InterfaceIndex,
        // SAFETY: `NET_LUID_LH` is a u64 union.
        luid: unsafe { r.InterfaceLuid.Value },
        destination: IpNet::new(prefix, r.DestinationPrefix.PrefixLength).ok()?,
        next_hop: inet_ip(&r.NextHop).filter(|ip| !ip.is_unspecified()),
        metric: r.Metric,
        protocol: r.Protocol.0,
    })
}

/// `GetBestRoute2` output before validation (families are checked by the caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RawBest {
    pub if_index: u32,
    pub luid: u64,
    /// Destination prefix of the selected route; `None` when its family is neither IPv4 nor IPv6.
    pub prefix: Option<(IpAddr, u8)>,
    pub next_hop: Option<IpAddr>,
    pub source: Option<IpAddr>,
}

/// The route the stack would pick for `dst` (no packet is sent). Any interface, any source.
pub(super) fn best_route(dst: IpAddr) -> windows::core::Result<RawBest> {
    let dest = inet_from(dst);
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: all pointers refer to live locals of the documented types.
    unsafe { GetBestRoute2(None, 0, None, &dest, 0, &mut row, &mut source) }.ok()?;
    Ok(RawBest {
        if_index: row.InterfaceIndex,
        // SAFETY: `NET_LUID_LH` is a u64 union.
        luid: unsafe { row.InterfaceLuid.Value },
        prefix: inet_ip(&row.DestinationPrefix.Prefix)
            .map(|ip| (ip, row.DestinationPrefix.PrefixLength)),
        next_hop: inet_ip(&row.NextHop).filter(|ip| !ip.is_unspecified()),
        source: inet_ip(&source),
    })
}

/// Per-family IP interface settings (`GetIpInterfaceEntry`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct IpInterface {
    pub metric: u32,
    pub mtu: u32,
}

/// `None` when the interface has no binding of that family.
pub(super) fn ip_interface(
    luid: u64,
    family: ADDRESS_FAMILY,
) -> windows::core::Result<Option<IpInterface>> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: initialises a local row to the documented defaults.
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = family;
    row.InterfaceLuid.Value = luid;
    // SAFETY: `row` is initialised with family and LUID, as the API requires.
    match unsafe { GetIpInterfaceEntry(&mut row) } {
        NO_ERROR => Ok(Some(IpInterface {
            metric: row.Metric,
            mtu: row.NlMtu,
        })),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Ok(None),
        err => Err(err.into()),
    }
}

/// Connection name of an interface (`ConvertInterfaceLuidToAlias`).
pub(super) fn luid_alias(luid: u64) -> windows::core::Result<String> {
    let id = NET_LUID_LH { Value: luid };
    // NDIS_IF_MAX_STRING_SIZE + 1.
    let mut buf = [0u16; 257];
    // SAFETY: `id` is a valid LUID value and `buf` is a writable UTF-16 buffer of its stated
    // length.
    unsafe { ConvertInterfaceLuidToAlias(&id, &mut buf) }.ok()?;
    Ok(from_wide(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_text() {
        let want = GUID::from_u128(0x999d65fe_a8c4_4db3_9f7e_11edd6482144);
        assert_eq!(
            parse_guid("{999D65FE-A8C4-4DB3-9F7E-11EDD6482144}"),
            Some(want)
        );
        assert_eq!(
            parse_guid("999d65fe-a8c4-4db3-9f7e-11edd6482144"),
            Some(want)
        );
        assert_eq!(parse_guid("{not-a-guid}"), None);
        assert_eq!(parse_guid(""), None);
    }

    /// Live: after one read the remembered buffer fits the table, so later reads (the TUN waits
    /// poll them) take one call instead of an overflow plus a second call.
    #[test]
    fn buffer_size_is_remembered() {
        assert!(!adapters().expect("adapters").is_empty());
        let mut needed = 0u32;
        // SAFETY: a size query without a buffer; the OS only writes `needed`.
        let rc =
            unsafe { GetAdaptersAddresses(AF_UNSPEC.0.into(), GAA_FLAGS, None, None, &mut needed) };
        assert_eq!(WIN32_ERROR(rc), ERROR_BUFFER_OVERFLOW);
        assert!(
            GAA_BYTES.load(Ordering::Relaxed) >= needed,
            "{needed} bytes needed"
        );
    }
}
