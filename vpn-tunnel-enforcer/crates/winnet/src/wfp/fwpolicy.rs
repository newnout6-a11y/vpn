//! Read-only Windows Firewall checks (`INetFwPolicy2`); we never write the firewall.
//! - Outbound default Block: our permits are soft and a block in any sublayer beats a soft
//!   permit, so such a profile stops sing-box / xray whatever our sublayer allows.
//! - Inbound blocked: sing-tun's `system` TCP stack (`stack: "mixed"`) accepts the TUN's TCP
//!   connections on a local listener, i.e. as inbound flows, which then never arrive (review D4).
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, NET_FW_ACTION_BLOCK, NET_FW_MODIFY_STATE_OK, NET_FW_PROFILE_TYPE2,
    NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NetFwPolicy2,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};

use crate::win::{Apartment, Com};

/// A Windows Firewall profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FwProfile {
    Domain,
    Private,
    Public,
}

const PROFILES: [(FwProfile, NET_FW_PROFILE_TYPE2); 3] = [
    (FwProfile::Domain, NET_FW_PROFILE2_DOMAIN),
    (FwProfile::Private, NET_FW_PROFILE2_PRIVATE),
    (FwProfile::Public, NET_FW_PROFILE2_PUBLIC),
];

/// An enabled profile with outbound default Block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FwProfileBlock {
    pub profile: FwProfile,
    /// The profile applies to a connected network right now.
    pub active: bool,
}

/// Runs `f` on the firewall policy and the bit mask of the current profiles (cheap, in-process
/// COM, no elevation needed).
fn with_policy<R>(
    f: impl FnOnce(&INetFwPolicy2, i32) -> windows::core::Result<R>,
) -> windows::core::Result<R> {
    let _com = Com::enter(Apartment::Mta);
    // SAFETY: COM is initialised on this thread for the scope of `_com`.
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)? };
    // SAFETY: `policy` is a live interface pointer.
    let current = unsafe { policy.CurrentProfileTypes()? };
    f(&policy, current)
}

fn enabled(policy: &INetFwPolicy2, kind: NET_FW_PROFILE_TYPE2) -> windows::core::Result<bool> {
    // SAFETY: `policy` is a live interface pointer; `kind` is a single profile bit.
    Ok(unsafe { policy.get_FirewallEnabled(kind)? }.as_bool())
}

/// The enabled profiles whose outbound default is Block.
pub fn outbound_block_profiles() -> windows::core::Result<Vec<FwProfileBlock>> {
    with_policy(|policy, current| {
        let mut out = Vec::new();
        for (profile, kind) in PROFILES {
            // SAFETY: as in `enabled`.
            if enabled(policy, kind)?
                && unsafe { policy.get_DefaultOutboundAction(kind)? } == NET_FW_ACTION_BLOCK
            {
                out.push(FwProfileBlock {
                    profile,
                    active: current & kind.0 != 0,
                });
            }
        }
        Ok(out)
    })
}

/// Whether Windows Firewall would drop inbound connections on the TUN: local rules do not take
/// effect in the current profiles (group policy override or inbound blocked), or "block all
/// incoming connections" is on in an enabled current profile or in Public, where an
/// unidentified network such as the TUN lands. The tunnel then uses `stack: "gvisor"`.
pub fn tun_inbound_blocked() -> windows::core::Result<bool> {
    with_policy(|policy, current| {
        // SAFETY: `policy` is a live interface pointer.
        if unsafe { policy.LocalPolicyModifyState()? } != NET_FW_MODIFY_STATE_OK {
            return Ok(true);
        }
        for (profile, kind) in PROFILES {
            let relevant = profile == FwProfile::Public || current & kind.0 != 0;
            // SAFETY: as in `enabled`.
            if relevant
                && enabled(policy, kind)?
                && unsafe { policy.get_BlockAllInboundTraffic(kind)? }.as_bool()
            {
                return Ok(true);
            }
        }
        Ok(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only: works unelevated and never changes the firewall.
    #[test]
    fn reads_the_profiles() {
        let blocks = outbound_block_profiles().expect("INetFwPolicy2 read");
        let mut seen = std::collections::HashSet::new();
        assert!(blocks.iter().all(|b| seen.insert(b.profile)));
        tun_inbound_blocked().expect("inbound policy read");
    }
}
