//! Network identity: which physical network the PC is on, as one canonical text that is HMAC'd
//! before use and never logged (privacy rule of spec §3.4).
//!
//! Per physical adapter (winnet's "physical" predicate: Up, hardware-backed, burned-in MAC, not a
//! TUN / VPN / Hyper-V / VMware / VirtualBox / Bluetooth device — fixes A8): GUID, burned-in MAC,
//! IPv4 prefixes (IPv6 prefixes only without IPv4) and the default gateways with their MAC
//! addresses. Prefixes, not host addresses: a new DHCP lease or IPv6 privacy address is not a new
//! network. The gateway MAC tells apart two networks with the same subnet on the same card (a phone
//! hotspot vs. home Wi-Fi); Windows NLA identifies unmanaged networks by exactly that MAC, so it
//! replaces the old NLA name / id read without a COM round trip.
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use vpnte_winnet::adapters::{self, Adapter};

/// Upper bound of one read: an unresolved gateway may wait for ARP / neighbour discovery.
const READ_LIMIT: Duration = Duration::from_secs(3);

/// Canonical identity text of the current network. Sensitive (adapter GUIDs, MACs, gateways): it
/// is only ever fed into an HMAC.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkSnapshot(String);

impl NetworkSnapshot {
    pub(crate) fn text(&self) -> &str {
        &self.0
    }

    /// Builds a snapshot from rows; no rows → unknown network (no reuse, no learning).
    pub fn from_rows(rows: Vec<IdentityRow>) -> Option<Self> {
        let mut lines: Vec<String> = rows.iter().map(IdentityRow::line).collect();
        lines.sort();
        lines.dedup();
        (!lines.is_empty()).then(|| Self(lines.join("\n")))
    }
}

impl fmt::Debug for NetworkSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetworkSnapshot(..)")
    }
}

/// One physical adapter's share of the identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRow {
    pub guid: String,
    pub mac: String,
    /// `network/len`, sorted.
    pub prefixes: Vec<String>,
    /// `ip` or `ip@mac`, sorted.
    pub gateways: Vec<String>,
}

impl IdentityRow {
    fn line(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.guid,
            self.mac,
            self.prefixes.join(","),
            self.gateways.join(",")
        )
    }
}

/// Identity rows of the physical adapters; `gateway_mac(luid, ip)` looks up a gateway's MAC.
pub fn rows(
    adapters: &[Adapter],
    gateway_mac: impl Fn(u64, IpAddr) -> Option<String>,
) -> Vec<IdentityRow> {
    adapters
        .iter()
        .filter(|a| {
            a.physical
                && !a
                    .addresses
                    .iter()
                    .any(|u| adapters::is_own_tun_address(u.ip))
        })
        .map(|a| {
            let usable = || a.addresses.iter().filter(|u| u.usable());
            let mut prefixes: Vec<String> = usable()
                .filter(|u| matches!(u.ip, IpAddr::V4(v4) if !v4.is_link_local()))
                .map(|u| prefix(u.ip, u.prefix_len))
                .collect();
            if prefixes.is_empty() {
                prefixes = usable()
                    .filter(
                        |u| matches!(u.ip, IpAddr::V6(v6) if v6.segments()[0] & 0xe000 == 0x2000),
                    )
                    .map(|u| prefix(u.ip, u.prefix_len))
                    .collect();
            }
            let v4: Vec<IpAddr> = a.gateways.iter().copied().filter(IpAddr::is_ipv4).collect();
            let chosen = if v4.is_empty() {
                a.gateways.clone()
            } else {
                v4
            };
            let mut gateways: Vec<String> = chosen
                .into_iter()
                .map(|ip| match gateway_mac(a.luid, ip) {
                    Some(mac) => format!("{ip}@{mac}"),
                    None => ip.to_string(),
                })
                .collect();
            prefixes.sort();
            prefixes.dedup();
            gateways.sort();
            gateways.dedup();
            IdentityRow {
                guid: format!("{:032x}", a.guid.to_u128()),
                mac: hex(&a.permanent_mac),
                prefixes,
                gateways,
            }
        })
        .collect()
}

/// `network/len` of an address.
fn prefix(ip: IpAddr, len: u8) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let len = len.min(32);
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            format!("{}/{len}", std::net::Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let len = len.min(128);
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            format!("{}/{len}", std::net::Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads the identity of the current network (blocking pool, ≤ 3 s); `None` = unknown.
pub async fn read() -> Option<NetworkSnapshot> {
    let started = Instant::now();
    let read = tokio::task::spawn_blocking(|| {
        let adapters = adapters::inventory().ok()?;
        NetworkSnapshot::from_rows(rows(&adapters, ffi::gateway_mac))
    });
    let snapshot = tokio::time::timeout(READ_LIMIT, read)
        .await
        .ok()
        .and_then(Result::ok)
        .flatten();
    tracing::info!(
        reader = "win32",
        duration_ms = started.elapsed().as_millis() as u64,
        known = snapshot.is_some(),
        "Network identity read completed"
    );
    snapshot
}

mod ffi {
    use std::net::IpAddr;

    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetIpNetEntry2, MIB_IPNET_ROW2, ResolveIpNetEntry2,
    };
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, NlnsIncomplete,
        NlnsUnreachable, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
    };

    /// MAC of a neighbour (the default gateway) on interface `luid`: the cached entry, else one
    /// active ARP / neighbour-discovery resolution (blocks up to a few seconds).
    pub(super) fn gateway_mac(luid: u64, ip: IpAddr) -> Option<String> {
        let mut row = MIB_IPNET_ROW2 {
            Address: inet(ip),
            InterfaceLuid: NET_LUID_LH { Value: luid },
            ..Default::default()
        };
        // SAFETY: `row` is a fully initialised MIB_IPNET_ROW2 owned by this frame with `Address`
        // and `InterfaceLuid` set, as GetIpNetEntry2 requires; it only writes into `row`.
        let cached = unsafe { GetIpNetEntry2(&mut row) } == ERROR_SUCCESS && resolved(&row);
        // SAFETY: same row; a null source address lets the stack pick one.
        if !cached && (unsafe { ResolveIpNetEntry2(&mut row, None) } != ERROR_SUCCESS) {
            return None;
        }
        resolved(&row).then(|| {
            let len = (row.PhysicalAddressLength as usize).min(row.PhysicalAddress.len());
            super::hex(&row.PhysicalAddress[..len])
        })
    }

    fn resolved(row: &MIB_IPNET_ROW2) -> bool {
        let len = (row.PhysicalAddressLength as usize).min(row.PhysicalAddress.len());
        row.State != NlnsUnreachable
            && row.State != NlnsIncomplete
            && row.PhysicalAddress[..len].iter().any(|&b| b != 0)
    }

    fn inet(ip: IpAddr) -> SOCKADDR_INET {
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
}

#[cfg(test)]
mod tests {
    use vpnte_winnet::adapters::{AdapterStatus, UnicastAddress};
    use windows::core::GUID;

    use super::*;

    fn addr(ip: &str, prefix_len: u8) -> UnicastAddress {
        UnicastAddress {
            ip: ip.parse().unwrap(),
            prefix_len,
            dad_state: 4,
            temporary: false,
        }
    }

    fn wifi(addresses: Vec<UnicastAddress>, gateway: &str) -> Adapter {
        Adapter {
            if_index: 7,
            luid: 7,
            guid: GUID::from_u128(0x5e5e_0000_0000_0000_0000_0000_0000_0001),
            alias: "Wi-Fi".into(),
            description: "Intel(R) Wi-Fi 6 AX201".into(),
            if_type: 71,
            status: AdapterStatus::Up,
            mac: vec![0x02, 0, 0, 0, 0, 0x01],
            permanent_mac: vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            hardware: true,
            filter: false,
            hidden: false,
            driver: None,
            ipv4_enabled: true,
            ipv6_enabled: true,
            link_speed_bps: 1_000_000_000,
            addresses,
            gateways: vec![gateway.parse().unwrap()],
            dns: Vec::new(),
            dns_static: false,
            physical: true,
        }
    }

    fn tun() -> Adapter {
        Adapter {
            alias: "Ethernet 5".into(),
            description: "sing-box Tunnel".into(),
            luid: 9,
            guid: GUID::from_u128(9),
            hardware: false,
            permanent_mac: Vec::new(),
            physical: false,
            ..wifi(vec![addr("192.168.250.253", 30)], "192.168.250.254")
        }
    }

    fn mac_of(_luid: u64, ip: IpAddr) -> Option<String> {
        Some(
            if ip.to_string() == "192.168.1.1" {
                "aabbccddee01"
            } else {
                "aabbccddee02"
            }
            .into(),
        )
    }

    fn hash(adapters: &[Adapter]) -> Option<NetworkSnapshot> {
        NetworkSnapshot::from_rows(rows(adapters, mac_of))
    }

    /// AT-10-007 / AT-03-012: prefixes, not host addresses; IPv6 ignored next to IPv4; another
    /// gateway or subnet is another network; our own TUN never changes the identity.
    #[test]
    fn network_identity_vectors() {
        let base = hash(&[wifi(vec![addr("192.168.1.100", 24)], "192.168.1.1")]).unwrap();
        let same = [
            hash(&[wifi(vec![addr("192.168.1.111", 24)], "192.168.1.1")]),
            hash(&[wifi(
                vec![addr("192.168.1.100", 24), addr("2001:db8::1234", 64)],
                "192.168.1.1",
            )]),
            hash(&[wifi(vec![addr("192.168.1.100", 24)], "192.168.1.1"), tun()]),
        ];
        for (i, s) in same.iter().enumerate() {
            assert_eq!(s.as_ref(), Some(&base), "same #{i}");
        }
        let other = [
            hash(&[wifi(vec![addr("192.168.1.100", 24)], "192.168.1.254")]),
            hash(&[wifi(vec![addr("10.42.0.10", 24)], "192.168.1.1")]),
        ];
        for (i, o) in other.iter().enumerate() {
            assert_ne!(o.as_ref(), Some(&base), "other #{i}");
        }
        // A phone hotspot with the same subnet and gateway address: another gateway MAC.
        let hotspot = NetworkSnapshot::from_rows(rows(
            &[wifi(vec![addr("192.168.1.100", 24)], "192.168.1.1")],
            |_, _| Some("0011223344ff".into()),
        ));
        assert_ne!(hotspot.as_ref(), Some(&base));
        assert_eq!(format!("{base:?}"), "NetworkSnapshot(..)");
    }

    #[test]
    fn ipv6_only_networks_use_global_prefixes_and_gateways() {
        let v6 = wifi(
            vec![addr("fe80::1", 64), addr("2001:db8:5::77", 64)],
            "fe80::1",
        );
        let rows = rows(&[v6], |_, _| None);
        assert_eq!(rows[0].prefixes, vec!["2001:db8:5::/64".to_owned()]);
        assert_eq!(rows[0].gateways, vec!["fe80::1".to_owned()]);
    }

    #[test]
    fn no_physical_adapter_means_unknown() {
        assert_eq!(hash(&[tun()]), None);
        assert_eq!(hash(&[]), None);
    }

    /// The real reader on this machine (read-only, unelevated): bounded, and two reads in a row
    /// agree — an identity that flaps between reads would never reuse or learn anything.
    #[tokio::test]
    async fn win32_reader_is_bounded_and_stable() {
        let started = Instant::now();
        let first = read().await;
        let second = read().await;
        assert!(started.elapsed() < READ_LIMIT * 2 + Duration::from_secs(1));
        if let (Some(a), Some(b)) = (&first, &second) {
            assert!(!a.text().is_empty());
            assert_eq!(a, b, "identity must be stable between reads");
        }
    }
}
