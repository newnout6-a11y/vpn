//! Kill switch and leak protection as WFP filters in our own provider + sublayer.
//!
//! `standard` and leak protection live in a dynamic WFP session (BFE removes them when the
//! process dies, so a crash never leaves the user offline); only `strict` adds persistent
//! filters. This module changes nothing else on the machine: no Windows Firewall rules or
//! profiles (sing-box's own `sing-tun (<path>)` inbound rule is the cleanup crate's), no adapter
//! bindings, no DNS settings. Hyper-V guests (WSL 2, Sandbox, Docker) are NATed below the ALE
//! layers and not covered; the status reports such a switch.
//!
//! Layout: [`spec`] (filter catalogue, pure), `desired` (which filters are active, pure),
//! [`validate`] (exception rules), [`model`] (settings, status, errors), [`engine`] (the
//! `windows` crate calls), [`fwpolicy`] (read-only Windows Firewall check) and
//! [`protection`] (the [`Protection`] handle the tunnel drives).
//!
//! Every notice this module emits belongs to the `connectionError` preference category.

mod backend;
mod desired;
pub mod engine;
mod filters;
pub mod fwpolicy;
pub mod model;
pub mod protection;
pub mod spec;
pub mod validate;

use windows::core::GUID;

pub use backend::RemoveReport;
pub use engine::{Engine, SublayerInfo, WfpError};
pub use filters::{FilterInfo, ListQuery, app_id};
pub use fwpolicy::{FwProfile, FwProfileBlock, outbound_block_profiles, tun_inbound_blocked};
pub use model::{
    Conn, EnginePaths, ExceptionKind, ExceptionTarget, KillSwitchException, KillSwitchState,
    ProtectionError, ProtectionSettings, ProtectionStatus, Toggles, Unconfirmed,
};
pub use protection::{Persist, Protection, WATCHDOG_PERIOD, remove_all};
pub use spec::{Action, AppId, Cond, FilterSpec, Layer};
pub use validate::{
    ValidationError, broad_warning, canonical_exe, check_list, parse_ip_or_cidr, validate_exception,
};

/// Our WFP provider (persistent, owns every filter we add, dynamic or persistent).
pub const PROVIDER_KEY: GUID = GUID::from_u128(0x264e9b5c_78c7_42e7_abef_f2fdfd1e2f1c);
/// Our WFP sublayer (persistent, requested weight `0xFFFF`).
pub const SUBLAYER_KEY: GUID = GUID::from_u128(0xcd654d3d_0fd7_4f8e_b1a6_c424b2f5794a);
/// Sublayer of the old app's IPv6 helper (`VPNTE.IPv6.v1`); only ever deleted (legacy cleanup).
pub const LEGACY_IPV6_SUBLAYER: GUID = GUID::from_u128(0xfd44e2d2_94a0_4b6e_99c9_3d61dff1b418);
/// Most user exceptions (apps + CIDRs) one policy may hold.
pub const MAX_EXCEPTIONS: usize = 256;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::mem::{offset_of, size_of};
    use std::path::PathBuf;

    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER0, FWPM_SUBLAYER0,
    };

    use super::model::Unconfirmed;
    use super::*;

    /// The fragment holds exactly the keys the code emits, all under `winnet.wfp` (validity and
    /// ru / en agreement: `test_support`).
    #[test]
    fn locale_fragment_matches_the_code() {
        let ru = crate::test_support::package_keys("winnet-wfp");
        assert!(ru.iter().all(|k| k.starts_with("winnet.wfp.")));
        let validation = [
            ValidationError::LabelLength,
            ValidationError::ValueLength,
            ValidationError::InvalidIp,
            ValidationError::NotExecutable,
            ValidationError::NotLocalPath,
            ValidationError::Unreadable,
            ValidationError::Duplicate,
            ValidationError::TooMany,
            ValidationError::NotFound,
        ];
        let errors = [
            ProtectionError::BfeUnavailable { code: 1753 },
            ProtectionError::AccessDenied,
            ProtectionError::EngineMissing(PathBuf::from(r"C:\x\sing-box.exe")),
            ProtectionError::Wfp {
                op: "FwpmFilterAdd0",
                code: 0x8032_0004,
            },
            ProtectionError::Persist(std::sync::Arc::new(vpnte_base::AppError::new(
                vpnte_base::ErrorKind::Internal,
            ))),
            ProtectionError::SessionActive,
            ProtectionError::Unconfirmed(Unconfirmed::Level),
            ProtectionError::Unconfirmed(Unconfirmed::Exceptions),
        ];
        let mut used: Vec<String> = validation
            .iter()
            .map(|v| v.msg().key.into_owned())
            .collect();
        used.extend(errors.iter().map(|e| e.msg().key.into_owned()));
        let ip = ExceptionTarget::Ip(parse_ip_or_cidr("1.0.0.0/1").unwrap());
        used.extend(broad_warning(&ip).map(|m| m.key.into_owned()));
        for key in [
            "blockedTitle",
            "blockedStrict",
            "blockedStandard",
            "exceptionSkippedTitle",
            "exceptionSkipped",
            "unverifiedTitle",
            "unverified",
        ] {
            used.push(format!("winnet.wfp.notice.{key}"));
        }
        used.push("winnet.wfp.status.firewallOutboundBlock".into());
        used.push("winnet.wfp.status.hypervUnfiltered".into());
        for key in &used {
            assert!(ru.contains(key), "missing locale key {key}");
        }
        assert_eq!(
            used.iter().collect::<BTreeSet<_>>().len(),
            ru.len(),
            "no unused keys"
        );
    }

    /// AT-03-001 (§7.3): x64 ABI of the `windows` crate structs matches the old helper's layout.
    #[test]
    fn wfp_struct_layout() {
        assert_eq!(size_of::<FWPM_FILTER0>(), 200);
        assert_eq!(offset_of!(FWPM_FILTER0, filterCondition), 120);
        assert_eq!(size_of::<FWPM_SUBLAYER0>(), 72);
        assert_eq!(size_of::<FWPM_FILTER_CONDITION0>(), 40);
        assert_eq!(size_of::<FWPM_FILTER_ENUM_TEMPLATE0>(), 72);
        assert_eq!(offset_of!(FWPM_FILTER_ENUM_TEMPLATE0, flags), 28);
        assert_eq!(offset_of!(FWPM_FILTER_ENUM_TEMPLATE0, actionMask), 56);
    }
}
