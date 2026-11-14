//! Wire -> runtime types, for the app's remote runtime: what the service sends, as the app's
//! lifecycle, UI and kill-switch view read it (the other direction is in `wire`).
use vpnte_engine::xray_config::SelectReason;
use vpnte_tunnel::api::{
    EngineRun, SessionEndpoints, StartReceipt, SwitchFailure, SwitchReceipt, TunStatus,
};
use vpnte_winnet::wfp::{Conn, KillSwitchState, ProtectionStatus};

use super::wire::{
    EngineRunWire, KillSwitchStateWire, ProtectionWire, SessionWire, StartReceiptWire, StatusWire,
    SwitchReceiptWire,
};

/// The engine reasons the app can show again; a reason of another shape (sing-box only, with
/// its cause) reads as none: it only labels the run.
const REASONS: [SelectReason; 8] = [
    SelectReason::Default,
    SelectReason::Protocol,
    SelectReason::Preference,
    SelectReason::Reality,
    SelectReason::XrayTransport,
    SelectReason::NativeXray,
    SelectReason::CertPin,
    SelectReason::TlsHello,
];

impl From<EngineRunWire> for EngineRun {
    fn from(w: EngineRunWire) -> Self {
        let reason = w.reason.and_then(|value| {
            REASONS
                .into_iter()
                .find(|r| serde_json::to_value(r).ok().as_ref() == Some(&value))
        });
        Self {
            kind: w.kind,
            reason,
        }
    }
}

impl From<SessionWire> for SessionEndpoints {
    fn from(w: SessionWire) -> Self {
        Self {
            clash_port: w.clash_port,
            clash_secret: w.clash_secret,
            direct: w.direct.into(),
            probe: w.probe.map(Into::into),
            tun_luid: w.tun_luid,
            tun_alias: w.tun_alias,
            proxy_port: None,
            logs: w.logs,
        }
    }
}

impl From<StatusWire> for TunStatus {
    fn from(w: StatusWire) -> Self {
        Self {
            running: w.running,
            mode: w.mode,
            proxy_addr: w.proxy_addr,
            proxy_type: w.proxy_type,
            profile_name: w.profile_name,
            protocol: w.protocol,
            pid: w.pid,
            warning: w.warning,
            proxy_reachable: w.proxy_reachable,
            started_at: w.started_at,
            restart_attempt: w.restart_attempt,
            capture: w.capture,
            engine: w.engine.map(Into::into),
            session: w.session.map(Into::into),
        }
    }
}

impl From<StartReceiptWire> for StartReceipt {
    fn from(w: StartReceiptWire) -> Self {
        Self {
            generation: w.generation,
            pid: w.pid,
            started_at: w.started_at,
            engine: w.engine.into(),
            warnings: w.warnings,
        }
    }
}

impl From<SwitchReceiptWire> for SwitchReceipt {
    fn from(w: SwitchReceiptWire) -> Self {
        Self {
            outcome: w.outcome,
            committed: w.committed,
            active_slot: w.active_slot,
            previous_preserved: w.previous_preserved,
            candidate_stopped: w.candidate_stopped,
            previous_stopped: w.previous_stopped,
            ownership_lost: w.ownership_lost,
            failures: w
                .failures
                .into_iter()
                .map(|f| SwitchFailure {
                    phase: f.phase,
                    message: f.message,
                })
                .collect(),
            engine: w.engine.map(Into::into),
            warnings: w.warnings,
        }
    }
}

impl From<KillSwitchStateWire> for KillSwitchState {
    fn from(w: KillSwitchStateWire) -> Self {
        match w {
            KillSwitchStateWire::Off => Self::Off,
            KillSwitchStateWire::Armed => Self::Armed,
            KillSwitchStateWire::Engaged => Self::Engaged,
            KillSwitchStateWire::Blocking => Self::Blocking,
            KillSwitchStateWire::Failed => Self::Failed,
        }
    }
}

impl ProtectionWire {
    /// The status as the app shows it. What the wire does not carry stays unknown: the error
    /// detail (its message is in the service log), the sublayer weight, and the Windows Firewall
    /// / Hyper-V readings (the app reads those itself).
    pub fn to_status(&self) -> ProtectionStatus {
        ProtectionStatus {
            level: self.level,
            conn: Conn::default(),
            kill_switch: self.kill_switch.into(),
            last_error: None,
            leak_protection_active: self.leak_protection_active,
            dynamic_filters: self.dynamic_filters,
            persistent_filters: self.persistent_filters,
            sublayer_weight: None,
            bfe_running: self.bfe_running,
            last_verified: self.last_verified,
            skipped_exceptions: self.skipped_exceptions.clone(),
            windows_firewall_outbound_block: None,
            hyperv_switch_present: None,
        }
    }
}
