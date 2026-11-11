//! Interface byte and packet counters by LUID (`GetIfEntry2`), exact `u64` values.
//!
//! The TUN is addressed by the LUID the runtime recorded for it, never by alias: a physical NIC
//! auto-named like our disguised alias must not be sampled by mistake.
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};
use windows::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};

/// One counters sample of an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct IfCounters {
    /// LUID of the sampled interface.
    pub luid: u64,
    /// `InterfaceGuid`: a new value means the adapter was recreated (engine restart), so
    /// counters restarted too.
    pub guid: u128,
    pub in_octets: u64,
    pub out_octets: u64,
    /// Unicast plus non-unicast packets.
    pub in_packets: u64,
    /// Unicast plus non-unicast packets.
    pub out_packets: u64,
    pub in_discards: u64,
    pub in_errors: u64,
    pub out_discards: u64,
    pub out_errors: u64,
    /// Operational status is Up.
    pub up: bool,
}

/// Reads the counters of the interface with `luid`; `None` when no such interface exists
/// (for example the TUN went away with its engine).
pub fn read(luid: u64) -> windows::core::Result<Option<IfCounters>> {
    Ok(entry(luid)?.as_ref().map(from_row))
}

/// The `MIB_IF_ROW2` of the interface with `luid` (`GetIfEntry2`); `None` when it does not exist.
pub(crate) fn entry(luid: u64) -> windows::core::Result<Option<MIB_IF_ROW2>> {
    // A zero LUID names no interface: GetIfEntry2 would fall back to InterfaceIndex 0 and fail
    // with ERROR_INVALID_PARAMETER instead of reporting "not found".
    if luid == 0 {
        return Ok(None);
    }
    let mut row = MIB_IF_ROW2 {
        InterfaceLuid: NET_LUID_LH { Value: luid },
        ..Default::default()
    };
    // SAFETY: `row` is a zeroed MIB_IF_ROW2 with the LUID set, as the API requires.
    match unsafe { GetIfEntry2(&mut row) } {
        NO_ERROR => Ok(Some(row)),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Ok(None),
        err => Err(err.into()),
    }
}

fn from_row(row: &MIB_IF_ROW2) -> IfCounters {
    IfCounters {
        // SAFETY: NET_LUID_LH is a union over one u64; every bit pattern is a valid `Value`.
        luid: unsafe { row.InterfaceLuid.Value },
        guid: row.InterfaceGuid.to_u128(),
        in_octets: row.InOctets,
        out_octets: row.OutOctets,
        in_packets: row.InUcastPkts.wrapping_add(row.InNUcastPkts),
        out_packets: row.OutUcastPkts.wrapping_add(row.OutNUcastPkts),
        in_discards: row.InDiscards,
        in_errors: row.InErrors,
        out_discards: row.OutDiscards,
        out_errors: row.OutErrors,
        up: row.OperStatus == IfOperStatusUp,
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;

    use super::*;

    /// AT-07-009 (trafficCounters.test.ts): counters cross the boundary exactly, beyond 2^53.
    #[test]
    fn counters_are_u64_exact() {
        let row = MIB_IF_ROW2 {
            InterfaceLuid: NET_LUID_LH {
                Value: 0x0006_0000_0100_0000,
            },
            InOctets: 18_446_744_073_709_551_615,
            OutOctets: 9_007_199_254_740_993,
            InUcastPkts: 5,
            InNUcastPkts: 2,
            OperStatus: IfOperStatusUp,
            ..Default::default()
        };
        let c = from_row(&row);
        assert_eq!(c.in_octets, u64::MAX);
        assert_eq!(c.out_octets, 9_007_199_254_740_993);
        assert_eq!(
            (c.in_packets, c.luid, c.up),
            (7, 0x0006_0000_0100_0000, true)
        );
    }

    #[test]
    fn reads_the_loopback_and_reports_missing_interfaces() {
        // Interface index 1 is the "Loopback Pseudo-Interface 1" on every Windows since Vista.
        let mut luid = NET_LUID_LH::default();
        // SAFETY: `luid` is a valid out pointer.
        unsafe { ConvertInterfaceIndexToLuid(1, &mut luid) }
            .ok()
            .unwrap();
        // SAFETY: plain u64 view of the union.
        let value = unsafe { luid.Value };
        let c = read(value).unwrap().expect("loopback exists");
        assert_eq!(c.luid, value);
        // Ethernet type, highest NET_LUID index: no such adapter.
        assert_eq!(read((6u64 << 48) | (0xFF_FFFF << 24)).unwrap(), None);
        // An unset (zero) LUID is "no such interface", not an OS error.
        assert_eq!(read(0).unwrap(), None);
    }
}
