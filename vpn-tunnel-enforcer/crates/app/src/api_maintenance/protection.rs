//! «Защита сети» read back from Windows: the WFP status of the protection this process hosts
//! (elevated only), else what an unelevated process can still read honestly (BFE state and the
//! Windows Firewall profiles) under a state line that says the filters need administrator
//! rights. Filter counts that could not be read are never shown as a verified state.
use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppResult, Msg};
use vpnte_ui::maintenance::{FirewallBlock, FwProfile, KillSwitchState, ProtectionView};
use vpnte_winnet::wfp::{self, FwProfileBlock, KillSwitchState as WfpState, ProtectionStatus};

use super::{Shared, project};
use crate::api_settings::blocking;

/// Reads the protection back, publishes it in the snapshot and returns it.
pub(crate) async fn verify(shared: &Shared) -> AppResult<ProtectionView> {
    let tunnel = shared.backend.tunnel()?.clone();
    let status = tunnel.kill_switch().await;
    let machine = blocking(|| Ok(read_machine())).await?;
    let view = match &status.wfp {
        Some(wfp) => from_status(wfp, &machine),
        None => unelevated(status.settings.level, &machine),
    };
    tracing::info!(
        level = ?view.level,
        dynamic = view.dynamic_filters,
        persistent = view.persistent_filters,
        bfe = view.bfe_running,
        hosted = status.wfp.is_some(),
        "maintenance: protection read back"
    );
    shared
        .state
        .send_modify(|s| s.protection = Some(view.clone()));
    Ok(view)
}

/// What any process may read: the BFE service and the firewall's outbound defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Machine {
    /// `None`: the service state could not be read.
    pub bfe_running: Option<bool>,
    /// `None`: the firewall policy could not be read.
    pub firewall_blocks: Option<Vec<FwProfileBlock>>,
}

fn read_machine() -> Machine {
    Machine {
        bfe_running: vpnte_probes::diagnostics::service("BFE").running,
        firewall_blocks: wfp::outbound_block_profiles().ok(),
    }
}

/// The view of a fresh WFP read-back. A count that could not be read turns the state line into
/// a failure: the counts shown as 0 are then explained, never taken for a verified state.
pub(crate) fn from_status(s: &ProtectionStatus, machine: &Machine) -> ProtectionView {
    let unread = s.dynamic_filters.is_none() || s.persistent_filters.is_none();
    let kill_switch = match s.kill_switch {
        WfpState::Failed => KillSwitchState::Failed(s.last_error.as_ref().map_or_else(
            || Msg::new("app.maintenance.protection.failed"),
            |e| e.msg(),
        )),
        _ if unread => KillSwitchState::Failed(Msg::new("app.maintenance.protection.unreadable")),
        WfpState::Off => KillSwitchState::Off,
        WfpState::Armed => KillSwitchState::Armed,
        WfpState::Engaged => KillSwitchState::Engaged,
        WfpState::Blocking => KillSwitchState::Blocking,
    };
    ProtectionView {
        level: s.level,
        kill_switch,
        leak_protection_active: s.leak_protection_active,
        dynamic_filters: s.dynamic_filters.unwrap_or(0),
        persistent_filters: s.persistent_filters.unwrap_or(0),
        bfe_running: s.bfe_running.or(machine.bfe_running).unwrap_or(false),
        firewall_blocks: blocks(
            s.windows_firewall_outbound_block
                .as_ref()
                .or(machine.firewall_blocks.as_ref()),
        ),
        last_verified: s.last_verified,
    }
}

/// Unelevated, our filters cannot be enumerated (BFE grants that to administrators): the state
/// line says so, the counts stay at 0 under it, the rest is read for real.
pub(crate) fn unelevated(level: KillSwitchLevel, machine: &Machine) -> ProtectionView {
    ProtectionView {
        level,
        kill_switch: KillSwitchState::Failed(project::needs_admin_msg()),
        leak_protection_active: false,
        dynamic_filters: 0,
        persistent_filters: 0,
        // Unknown counts as stopped: an unread service is never reported as running.
        bfe_running: machine.bfe_running.unwrap_or(false),
        firewall_blocks: blocks(machine.firewall_blocks.as_ref()),
        // Nothing of ours was verified: no "verified at" line.
        last_verified: None,
    }
}

fn blocks(list: Option<&Vec<FwProfileBlock>>) -> Vec<FirewallBlock> {
    list.map(|list| {
        list.iter()
            .map(|b| FirewallBlock {
                profile: match b.profile {
                    wfp::FwProfile::Domain => FwProfile::Domain,
                    wfp::FwProfile::Private => FwProfile::Private,
                    wfp::FwProfile::Public => FwProfile::Public,
                },
                active: b.active,
            })
            .collect()
    })
    .unwrap_or_default()
}
