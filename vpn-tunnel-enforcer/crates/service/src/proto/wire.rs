//! Wire mirrors of the runtime's and the kill switch's output types (most of them are not
//! `Deserialize`, and `TunStatus` deliberately skips the session secrets that the controlling
//! client does need). Conversions go from the runtime's types (service side) and back where the
//! app needs the original type (its remote runtime).
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vpnte_base::Msg;
use vpnte_base::types::{Engine, KillSwitchLevel, ProxyKind, UnixMs};
use vpnte_probes::leak::SelfTestResult;
use vpnte_tunnel::api::{
    CaptureKind, ExitInfo, FailoverCause, ModeKind, ProxyEndpoint, SessionEndpoints, Slot,
    StartReceipt, StopReceipt, SwitchFailure, SwitchOutcome, SwitchPhase, SwitchReceipt, TunStatus,
    TunStatusKind, TunWarning, TunnelEvent,
};
use vpnte_winnet::wfp::{KillSwitchState, ProtectionStatus};

/// `TunStatus` with the session endpoints (Clash secret, loopback proxy credentials): they go to
/// the controlling client only, which needs them for statistics and probes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct StatusWire {
    pub running: bool,
    pub mode: Option<ModeKind>,
    pub proxy_addr: Option<String>,
    pub proxy_type: Option<ProxyKind>,
    pub profile_name: Option<String>,
    pub protocol: Option<String>,
    pub pid: Option<u32>,
    pub warning: Option<Msg>,
    pub proxy_reachable: bool,
    pub started_at: Option<UnixMs>,
    pub restart_attempt: u8,
    pub capture: Option<CaptureKind>,
    pub engine: Option<EngineRunWire>,
    pub session: Option<SessionWire>,
    /// The runtime's last engine exit, pushed to the session's own user only (the app's
    /// `Runtime::last_exit` reads it right after the status that goes with a crash).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exit: Option<ExitWire>,
    /// The runtime's recent outbound fault, to the session's own user only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_fault: Option<vpnte_base::types::OutboundFault>,
    /// The service's latest leak self-test of the running TUN session (protocol 2), to the
    /// session's own user only: the app shows it as it shows its own runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_test: Option<SelfTestResult>,
}

/// Which engine runs and why (`reason` is the engine crate's serialized `SelectReason`, for
/// display; `None` for a local upstream proxy).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineRunWire {
    pub kind: Engine,
    #[serde(default)]
    pub reason: Option<serde_json::Value>,
}

/// The loopback endpoints of a running session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionWire {
    pub clash_port: u16,
    pub clash_secret: String,
    pub direct: EndpointWire,
    #[serde(default)]
    pub probe: Option<EndpointWire>,
    #[serde(default)]
    pub tun_luid: Option<u64>,
    #[serde(default)]
    pub tun_alias: Option<String>,
    /// Engine logs of the session (under the service's data folder, readable by users).
    #[serde(default)]
    pub logs: Vec<PathBuf>,
}

impl std::fmt::Debug for SessionWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionWire")
            .field("clash_port", &self.clash_port)
            .field("tun_luid", &self.tun_luid)
            .finish_non_exhaustive()
    }
}

/// An authenticated loopback SOCKS / HTTP endpoint of the engine.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointWire {
    pub port: u16,
    pub user: String,
    pub pass: String,
}

impl Default for StatusWire {
    fn default() -> Self {
        Self::from(&TunStatus::default())
    }
}

impl From<&TunStatus> for StatusWire {
    fn from(s: &TunStatus) -> Self {
        Self {
            running: s.running,
            mode: s.mode,
            proxy_addr: s.proxy_addr.clone(),
            proxy_type: s.proxy_type,
            profile_name: s.profile_name.clone(),
            protocol: s.protocol.clone(),
            pid: s.pid,
            warning: s.warning.clone(),
            proxy_reachable: s.proxy_reachable,
            started_at: s.started_at,
            restart_attempt: s.restart_attempt,
            capture: s.capture,
            engine: s.engine.map(EngineRunWire::from),
            session: s.session.as_ref().map(SessionWire::from),
            last_exit: None,
            recent_fault: None,
            self_test: None,
        }
    }
}

impl From<vpnte_tunnel::api::EngineRun> for EngineRunWire {
    fn from(run: vpnte_tunnel::api::EngineRun) -> Self {
        Self {
            kind: run.kind,
            reason: run.reason.and_then(|r| serde_json::to_value(r).ok()),
        }
    }
}

impl From<&SessionEndpoints> for SessionWire {
    fn from(s: &SessionEndpoints) -> Self {
        Self {
            clash_port: s.clash_port,
            clash_secret: s.clash_secret.clone(),
            direct: EndpointWire::from(&s.direct),
            probe: s.probe.as_ref().map(EndpointWire::from),
            tun_luid: s.tun_luid,
            tun_alias: s.tun_alias.clone(),
            logs: s.logs.clone(),
        }
    }
}

impl From<&ProxyEndpoint> for EndpointWire {
    fn from(p: &ProxyEndpoint) -> Self {
        Self {
            port: p.port,
            user: p.user.clone(),
            pass: p.pass.clone(),
        }
    }
}

impl From<EndpointWire> for ProxyEndpoint {
    fn from(p: EndpointWire) -> Self {
        Self {
            port: p.port,
            user: p.user,
            pass: p.pass,
        }
    }
}

/// `TunStatusKind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum StatusKindWire {
    Stopping,
    Adapting,
    Stopped,
    Running,
    KillSwitchActive,
    Restarting { attempt: u8, max: u8 },
    ProxyDown { reason: Msg },
    Error { warning: Msg },
    PostTrialFailover { name: String },
    CompetingTun { name: String },
    CompetingTunCleared,
}

impl From<&TunStatusKind> for StatusKindWire {
    fn from(k: &TunStatusKind) -> Self {
        match k.clone() {
            TunStatusKind::Stopping => Self::Stopping,
            TunStatusKind::Adapting => Self::Adapting,
            TunStatusKind::Stopped => Self::Stopped,
            TunStatusKind::Running => Self::Running,
            TunStatusKind::KillSwitchActive => Self::KillSwitchActive,
            TunStatusKind::Restarting { attempt, max } => Self::Restarting { attempt, max },
            TunStatusKind::ProxyDown { reason } => Self::ProxyDown { reason },
            TunStatusKind::Error { warning } => Self::Error { warning },
            TunStatusKind::PostTrialFailover { name } => Self::PostTrialFailover { name },
            TunStatusKind::CompetingTun { name } => Self::CompetingTun { name },
            TunStatusKind::CompetingTunCleared => Self::CompetingTunCleared,
        }
    }
}

impl From<StatusKindWire> for TunStatusKind {
    fn from(k: StatusKindWire) -> Self {
        match k {
            StatusKindWire::Stopping => Self::Stopping,
            StatusKindWire::Adapting => Self::Adapting,
            StatusKindWire::Stopped => Self::Stopped,
            StatusKindWire::Running => Self::Running,
            StatusKindWire::KillSwitchActive => Self::KillSwitchActive,
            StatusKindWire::Restarting { attempt, max } => Self::Restarting { attempt, max },
            StatusKindWire::ProxyDown { reason } => Self::ProxyDown { reason },
            StatusKindWire::Error { warning } => Self::Error { warning },
            StatusKindWire::PostTrialFailover { name } => Self::PostTrialFailover { name },
            StatusKindWire::CompetingTun { name } => Self::CompetingTun { name },
            StatusKindWire::CompetingTunCleared => Self::CompetingTunCleared,
        }
    }
}

/// `TunnelEvent` (warnings travel as their `Msg`; `TunWarning::from_msg` restores the type).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "camelCase", deny_unknown_fields)]
pub enum TunnelEventWire {
    StartBegan {
        generation: u64,
    },
    StartFinished {
        generation: u64,
        ok: bool,
    },
    StopFinished {
        generation: u64,
        preserved: bool,
        receipt: StopReceiptWire,
    },
    SwitchBegan {
        generation: u64,
    },
    SwitchFinished {
        generation: u64,
        verified: bool,
    },
    ProtectedRestart {
        reason: String,
    },
    Status {
        status: StatusKindWire,
    },
    Warning {
        warning: Msg,
    },
    RestartScheduled {
        delay_ms: u64,
    },
    FailedOver {
        generation: u64,
        profile_id: String,
        server_fault: bool,
    },
}

impl From<&TunnelEvent> for TunnelEventWire {
    fn from(e: &TunnelEvent) -> Self {
        match e {
            TunnelEvent::StartBegan { generation } => Self::StartBegan {
                generation: *generation,
            },
            TunnelEvent::StartFinished { generation, ok } => Self::StartFinished {
                generation: *generation,
                ok: *ok,
            },
            TunnelEvent::StopFinished {
                generation,
                preserved,
                receipt,
            } => Self::StopFinished {
                generation: *generation,
                preserved: *preserved,
                receipt: receipt.into(),
            },
            TunnelEvent::SwitchBegan { generation } => Self::SwitchBegan {
                generation: *generation,
            },
            TunnelEvent::SwitchFinished {
                generation,
                verified,
            } => Self::SwitchFinished {
                generation: *generation,
                verified: *verified,
            },
            TunnelEvent::ProtectedRestart { reason } => Self::ProtectedRestart {
                reason: reason.clone(),
            },
            TunnelEvent::Status(kind) => Self::Status {
                status: kind.into(),
            },
            TunnelEvent::Warning(w) => Self::Warning { warning: w.msg() },
            TunnelEvent::RestartScheduled { delay } => Self::RestartScheduled {
                delay_ms: u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            },
            TunnelEvent::FailedOver {
                generation,
                profile_id,
                cause,
            } => Self::FailedOver {
                generation: *generation,
                profile_id: profile_id.clone(),
                server_fault: *cause == FailoverCause::ServerFault,
            },
        }
    }
}

impl From<TunnelEventWire> for TunnelEvent {
    fn from(e: TunnelEventWire) -> Self {
        match e {
            TunnelEventWire::StartBegan { generation } => Self::StartBegan { generation },
            TunnelEventWire::StartFinished { generation, ok } => {
                Self::StartFinished { generation, ok }
            }
            TunnelEventWire::StopFinished {
                generation,
                preserved,
                receipt,
            } => Self::StopFinished {
                generation,
                preserved,
                receipt: receipt.into(),
            },
            TunnelEventWire::SwitchBegan { generation } => Self::SwitchBegan { generation },
            TunnelEventWire::SwitchFinished {
                generation,
                verified,
            } => Self::SwitchFinished {
                generation,
                verified,
            },
            TunnelEventWire::ProtectedRestart { reason } => Self::ProtectedRestart { reason },
            TunnelEventWire::Status { status } => Self::Status(status.into()),
            TunnelEventWire::Warning { warning } => Self::Warning(TunWarning::from_msg(warning)),
            TunnelEventWire::RestartScheduled { delay_ms } => Self::RestartScheduled {
                delay: Duration::from_millis(delay_ms),
            },
            TunnelEventWire::FailedOver {
                generation,
                profile_id,
                server_fault,
            } => Self::FailedOver {
                generation,
                profile_id,
                cause: if server_fault {
                    FailoverCause::ServerFault
                } else {
                    FailoverCause::RestartsSpent
                },
            },
        }
    }
}

/// `StopReceipt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StopReceiptWire {
    pub operation_id: String,
    pub ok: bool,
    pub runtime_stopped: bool,
    pub forced: bool,
    pub protection_released: Option<bool>,
    pub baseline_restored: Option<bool>,
    pub adapter_gone: bool,
    #[serde(default)]
    pub warnings: Vec<Msg>,
}

impl From<&StopReceipt> for StopReceiptWire {
    fn from(r: &StopReceipt) -> Self {
        Self {
            operation_id: r.operation_id.clone(),
            ok: r.ok,
            runtime_stopped: r.runtime_stopped,
            forced: r.forced,
            protection_released: r.protection_released,
            baseline_restored: r.baseline_restored,
            adapter_gone: r.adapter_gone,
            warnings: r.warnings.clone(),
        }
    }
}

impl From<StopReceiptWire> for StopReceipt {
    fn from(r: StopReceiptWire) -> Self {
        Self {
            operation_id: r.operation_id,
            ok: r.ok,
            runtime_stopped: r.runtime_stopped,
            forced: r.forced,
            protection_released: r.protection_released,
            baseline_restored: r.baseline_restored,
            adapter_gone: r.adapter_gone,
            warnings: r.warnings,
        }
    }
}

/// `StartReceipt`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartReceiptWire {
    pub generation: u64,
    pub pid: u32,
    pub started_at: UnixMs,
    pub engine: EngineRunWire,
    #[serde(default)]
    pub warnings: Vec<Msg>,
}

impl From<&StartReceipt> for StartReceiptWire {
    fn from(r: &StartReceipt) -> Self {
        Self {
            generation: r.generation,
            pid: r.pid,
            started_at: r.started_at,
            engine: r.engine.into(),
            warnings: r.warnings.clone(),
        }
    }
}

/// `ExitInfo` of the last engine exit (`stderr_tail` is already redacted by the engine crate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExitWire {
    pub at: UnixMs,
    pub code: Option<i32>,
    pub stderr_tail: String,
    pub user_initiated: bool,
    pub graceful: bool,
}

impl From<&ExitInfo> for ExitWire {
    fn from(e: &ExitInfo) -> Self {
        Self {
            at: e.at,
            code: e.code,
            stderr_tail: e.stderr_tail.clone(),
            user_initiated: e.user_initiated,
            graceful: e.graceful,
        }
    }
}

impl From<ExitWire> for ExitInfo {
    fn from(e: ExitWire) -> Self {
        Self {
            at: e.at,
            code: e.code,
            stderr_tail: e.stderr_tail,
            user_initiated: e.user_initiated,
            graceful: e.graceful,
        }
    }
}

/// One failed step of a switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwitchFailureWire {
    pub phase: SwitchPhase,
    pub message: String,
}

/// `SwitchReceipt`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwitchReceiptWire {
    pub outcome: SwitchOutcome,
    pub committed: bool,
    pub active_slot: Option<Slot>,
    pub previous_preserved: bool,
    pub candidate_stopped: bool,
    pub previous_stopped: bool,
    pub ownership_lost: bool,
    #[serde(default)]
    pub failures: Vec<SwitchFailureWire>,
    #[serde(default)]
    pub engine: Option<EngineRunWire>,
    #[serde(default)]
    pub warnings: Vec<Msg>,
}

impl From<&SwitchReceipt> for SwitchReceiptWire {
    fn from(r: &SwitchReceipt) -> Self {
        Self {
            outcome: r.outcome,
            committed: r.committed,
            active_slot: r.active_slot,
            previous_preserved: r.previous_preserved,
            candidate_stopped: r.candidate_stopped,
            previous_stopped: r.previous_stopped,
            ownership_lost: r.ownership_lost,
            failures: r
                .failures
                .iter()
                .map(|f: &SwitchFailure| SwitchFailureWire {
                    phase: f.phase,
                    message: f.message.clone(),
                })
                .collect(),
            engine: r.engine.map(EngineRunWire::from),
            warnings: r.warnings.clone(),
        }
    }
}

/// `KillSwitchState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KillSwitchStateWire {
    Off,
    Armed,
    Engaged,
    Blocking,
    Failed,
}

impl From<KillSwitchState> for KillSwitchStateWire {
    fn from(s: KillSwitchState) -> Self {
        match s {
            KillSwitchState::Off => Self::Off,
            KillSwitchState::Armed => Self::Armed,
            KillSwitchState::Engaged => Self::Engaged,
            KillSwitchState::Blocking => Self::Blocking,
            KillSwitchState::Failed => Self::Failed,
        }
    }
}

/// What the kill switch enforces right now (`ProtectionStatus`, errors as their messages).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtectionWire {
    pub level: KillSwitchLevel,
    pub kill_switch: KillSwitchStateWire,
    pub leak_protection_active: bool,
    #[serde(default)]
    pub dynamic_filters: Option<u32>,
    #[serde(default)]
    pub persistent_filters: Option<u32>,
    #[serde(default)]
    pub bfe_running: Option<bool>,
    #[serde(default)]
    pub last_verified: Option<UnixMs>,
    #[serde(default)]
    pub last_error: Option<Msg>,
    /// Ids of app exceptions that could not be applied.
    #[serde(default)]
    pub skipped_exceptions: Vec<String>,
    /// Windows Firewall blocks outbound, a Hyper-V switch bypasses the filters.
    #[serde(default)]
    pub warnings: Vec<Msg>,
}

impl From<&ProtectionStatus> for ProtectionWire {
    fn from(s: &ProtectionStatus) -> Self {
        Self {
            level: s.level,
            kill_switch: s.kill_switch.into(),
            leak_protection_active: s.leak_protection_active,
            dynamic_filters: s.dynamic_filters,
            persistent_filters: s.persistent_filters,
            bfe_running: s.bfe_running,
            last_verified: s.last_verified,
            last_error: s.last_error.as_ref().map(|e| e.msg()),
            skipped_exceptions: s.skipped_exceptions.clone(),
            warnings: s
                .firewall_warning()
                .into_iter()
                .chain(s.hyperv_warning())
                .collect(),
        }
    }
}

impl ProtectionWire {
    /// The state could not be read (the status read itself failed).
    pub fn unknown(level: KillSwitchLevel) -> Self {
        Self {
            level,
            kill_switch: KillSwitchStateWire::Failed,
            leak_protection_active: false,
            dynamic_filters: None,
            persistent_filters: None,
            bfe_running: None,
            last_verified: None,
            last_error: None,
            skipped_exceptions: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

/// What a client asks the service's updater (p-svc-update). Answered as the first frame of a
/// connection, without `Hello` and the controller slot (like `ForgetMe`), and after `Hello`
/// alike; an older service answers `badRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum UpdateAsk {
    /// The service's version and update state.
    State,
    /// Right before the app runs the installer of release `version`: take that release's
    /// service from the signed feed first, so the installer finds it current (no prompt).
    Take { version: String },
}

/// Where the service's own update stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UpdatePhase {
    /// This build carries no update key: the service never checks (as the app).
    Off,
    /// Nothing to do (as of `checked_at`, when it checked at all).
    Idle,
    /// Checking the feed or downloading.
    Working,
    /// `target` is ready and goes in once no session runs (or at the service's next start).
    Waiting,
    /// `target` goes in now: the service restarts within seconds.
    Restarting,
    /// The last check failed; the service retries on its own.
    Failed,
}

/// The service's version and update state (the answer to every [`UpdateAsk`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceUpdateWire {
    /// The running service.
    pub version: String,
    pub phase: UpdatePhase,
    /// The version being taken or waiting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// When the service last accepted a feed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<UnixMs>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_self_test() -> StatusWire {
        StatusWire {
            self_test: Some(SelfTestResult::cancelled(KillSwitchLevel::Standard)),
            ..StatusWire::default()
        }
    }

    /// p-svc-recheck: every status carries the self-test and reads it back. A version-1 client,
    /// which would refuse the field, is refused at `Hello` (this build speaks 2 and 3 only).
    #[test]
    fn every_status_carries_the_self_test() {
        let status = with_self_test();
        let json = serde_json::to_string(&status).expect("json");
        assert!(json.contains("\"selfTest\""), "{json}");
        let back: StatusWire = serde_json::from_str(&json).expect("reads back");
        assert_eq!(back, status);
        assert_eq!(crate::proto::negotiate(1, crate::proto::PROTOCOL), None);
    }

    /// A version-1 service's status (no field) reads as "no self-test" in this build.
    #[test]
    fn a_status_without_the_field_reads() {
        let json = serde_json::to_string(&StatusWire::default()).expect("json");
        assert!(!json.contains("selfTest"));
        let back: StatusWire = serde_json::from_str(&json).expect("reads");
        assert_eq!(back.self_test, None);
    }
}
