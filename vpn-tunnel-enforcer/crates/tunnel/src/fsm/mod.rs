//! The pure connection state machine behind the one published UI state ([`TunnelSnapshot`]).
//!
//! Principle (old `tunnelStateMachine.ts`): the coordinator confirms protection, never a process
//! event. Every mutation re-checks the OS evidence the caller passes in, so a stray process event
//! can never publish "connected", and a live unowned process can never read as "disconnected".
//! Rejected transitions return [`Invalid`] and leave the snapshot untouched. No I/O here.
use serde::{Deserialize, Serialize};
use vpnte_base::types::UnixMs;
use vpnte_base::{AppError, ErrorKind};
use vpnte_core::ops::{OpId, OpKind, OpMeta, OpStatus};

use crate::api::{CaptureKind, StopReceipt, TunStatus, TunStatusKind};

/// Stable protection state. A running operation is a [`Transition`], not a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelState {
    Disconnected,
    Connected,
    Error,
    /// The kill switch blocks traffic with no tunnel behind it.
    Blocked,
    /// Not proven either way (lost evidence, a crash without a cleanup receipt).
    Unknown,
}

/// What is happening right now, on top of the stable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transition {
    Connecting,
    Disconnecting,
    Reconnecting,
}

/// Quality of a connected tunnel; `None` in every other state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Health {
    Ok,
    /// Upstream down or a competing TUN present.
    Degraded,
}

/// How protection is applied: our engine behind the TUN, or behind a loopback proxy the Soft-mode
/// system proxy points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelMode {
    Tun,
    Soft,
}

/// Whether our engine process exists (evidence, not protection).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessState {
    Running,
    Stopped,
}

/// State of the upstream behind the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyStatus {
    Running,
    ProxyDown,
    Stopped,
}

/// States a fault can force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultState {
    Error,
    Blocked,
    Unknown,
}

impl From<FaultState> for TunnelState {
    fn from(state: FaultState) -> Self {
        match state {
            FaultState::Error => TunnelState::Error,
            FaultState::Blocked => TunnelState::Blocked,
            FaultState::Unknown => TunnelState::Unknown,
        }
    }
}

/// The published tunnel state (wire shape of the old `TunnelSnapshot`, version 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelSnapshot {
    pub version: u8,
    /// Bumped on every accepted change.
    pub revision: u64,
    pub state: TunnelState,
    pub transition: Option<Transition>,
    pub health: Option<Health>,
    pub mode: Option<TunnelMode>,
    pub process_state: ProcessState,
    pub proxy_status: ProxyStatus,
    pub pid: Option<u32>,
    pub started_at: Option<UnixMs>,
    /// Display label of a foreign TUN adapter.
    pub competing_tun: Option<String>,
    /// Network rollback (protection, baseline) is still owed.
    pub cleanup_required: bool,
    /// The connection operation in progress, or the last one.
    pub operation: Option<OpMeta>,
}

impl Default for TunnelSnapshot {
    /// Disconnected, nothing running, nothing owed (revision 0).
    fn default() -> Self {
        Self {
            version: 1,
            revision: 0,
            state: TunnelState::Disconnected,
            transition: None,
            health: None,
            mode: None,
            process_state: ProcessState::Stopped,
            proxy_status: ProxyStatus::Stopped,
            pid: None,
            started_at: None,
            competing_tun: None,
            cleanup_required: false,
            operation: None,
        }
    }
}

/// What the OS shows right now. `None` where the methods take `Option<Evidence>` means the
/// evidence could not be read: the machine then fails closed to `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Evidence {
    /// Our sing-box is alive (process handle owned by the runtime).
    pub running: bool,
    pub pid: Option<u32>,
    /// The Soft-mode system proxy is applied by us and read back.
    pub soft_applied: bool,
    pub started_at: Option<UnixMs>,
    /// The running engine captures through its loopback proxy (Soft), not the TUN.
    pub proxy_capture: bool,
}

impl Evidence {
    /// Evidence from the runtime status plus the Soft module's own read-back.
    pub fn from_status(status: &TunStatus, soft_applied: bool) -> Self {
        Self {
            running: status.running,
            pid: status.pid,
            soft_applied,
            started_at: status.started_at,
            proxy_capture: status.capture == Some(CaptureKind::Proxy),
        }
    }

    /// Our engine is up with a real process (either capture).
    fn native_ready(&self) -> bool {
        self.running && self.pid.is_some_and(|pid| pid > 0)
    }

    /// Hard mode: our engine runs with the TUN capture.
    fn tun_ready(&self) -> bool {
        self.native_ready() && !self.proxy_capture
    }

    /// Soft mode needs both proofs (NOADMIN.md §2): the engine runs with the proxy capture and
    /// the system proxy points at it.
    fn soft_ready(&self) -> bool {
        self.native_ready() && self.proxy_capture && self.soft_applied
    }

    /// The mode the running engine serves.
    fn mode(&self) -> TunnelMode {
        if self.proxy_capture {
            TunnelMode::Soft
        } else {
            TunnelMode::Tun
        }
    }
}

/// A transition the current state does not allow (old `FSM_INVALID_TRANSITION`, category conflict).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid tunnel state transition")]
pub struct Invalid;

impl From<Invalid> for AppError {
    fn from(err: Invalid) -> Self {
        AppError::new(ErrorKind::Conflict).with_source(err)
    }
}

/// Snapshot of a rotation in progress: the mode and evidence it started from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rotation {
    mode: Option<TunnelMode>,
    evidence: Option<Evidence>,
}

/// The connection state machine (1:1 port of the old `TunnelStateMachine`, evidence explicit).
#[derive(Debug, Clone, Default)]
pub struct Fsm {
    snap: TunnelSnapshot,
    /// Evidence was lost or a fault was reported during the current operation.
    fault: bool,
    /// A native auto-recovery took over a connected tunnel and may confirm it again.
    reconnect_eligible: bool,
    native_gen: u64,
    /// The native generation whose finish may confirm the reconnect.
    expected_native_gen: Option<u64>,
    upstream_gen: u64,
    /// Pending in-place upstream switch: its generation and the TUN evidence it must keep.
    upstream: Option<(u64, Evidence)>,
    rotation: Option<Rotation>,
    /// Operation whose failure keeps the previous, still proven protection.
    kept: Option<OpId>,
}

impl Fsm {
    /// A machine in the initial disconnected state.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current published state.
    pub fn snapshot(&self) -> &TunnelSnapshot {
        &self.snap
    }

    /// A connect may be admitted.
    pub fn can_start(&self) -> bool {
        self.snap.state != TunnelState::Connected && self.snap.transition.is_none()
    }

    /// A rotation may be admitted.
    pub fn can_rotate(&self) -> bool {
        self.snap.transition.is_none()
            && matches!(
                self.snap.state,
                TunnelState::Connected | TunnelState::Disconnected
            )
    }

    /// `e` proves a successful start: our engine with a real process behind the TUN, or behind
    /// its loopback proxy with the Soft tweaks applied.
    pub fn can_confirm_start(&self, e: Option<Evidence>) -> bool {
        e.is_some_and(|e| !self.fault && (e.tun_ready() || e.soft_ready()))
    }

    /// `e` proves nothing of ours is left running or applied.
    pub fn can_confirm_stop(&self, e: Option<Evidence>) -> bool {
        e.is_some_and(|e| !e.running && e.pid.is_none() && !e.soft_applied)
    }

    fn running_op(&self) -> Option<&OpMeta> {
        self.snap
            .operation
            .as_ref()
            .filter(|op| op.status == OpStatus::Running)
    }

    fn can_confirm_rotation(&self, e: Option<Evidence>) -> bool {
        match self.rotation.and_then(|r| r.mode) {
            None => !self.fault && self.can_confirm_stop(e),
            Some(mode) => self.can_confirm_start(e) && e.is_some_and(|e| e.mode() == mode),
        }
    }

    /// The rotation failed but left the very same protection it started from.
    fn can_retain_rotation(&self, e: Option<Evidence>) -> bool {
        let previous = self.rotation.and_then(|r| r.evidence);
        !self.fault && e.is_some() && previous == e && self.can_confirm_rotation(e)
    }

    /// `op` failed on the network (the server or the path, not our machinery) and `e` proves
    /// nothing of ours is left: nothing for the user to clean up.
    fn clean_network_failure(&self, op: &OpMeta, e: Option<Evidence>) -> bool {
        op.category == Some(ErrorKind::Network) && !self.fault && self.can_confirm_stop(e)
    }

    /// Applies `patch`, then re-derives the evidence fields and fails closed on lost proof.
    fn commit(&mut self, e: Option<Evidence>, patch: impl FnOnce(&mut TunnelSnapshot)) {
        let mut s = self.snap.clone();
        patch(&mut s);
        s.revision += 1;
        match e {
            Some(e) => {
                s.pid = e.pid;
                s.process_state = if e.pid.is_some() {
                    ProcessState::Running
                } else {
                    ProcessState::Stopped
                };
                s.started_at = if e.running { e.started_at } else { None };
            }
            None => {
                s.state = TunnelState::Unknown;
                s.mode = None;
                s.cleanup_required = true;
            }
        }
        let lost_proof = match e {
            None => true,
            Some(e) => {
                s.transition.is_none()
                    && match s.state {
                        // A live process or applied proxy we do not account for.
                        TunnelState::Disconnected => e.running || e.pid.is_some() || e.soft_applied,
                        TunnelState::Connected => {
                            !if s.mode == Some(TunnelMode::Soft) {
                                e.soft_ready()
                            } else {
                                e.tun_ready()
                            }
                        }
                        _ => false,
                    }
            }
        };
        if lost_proof {
            self.fault = true;
            s.state = TunnelState::Unknown;
            s.mode = None;
            s.cleanup_required = true;
        }
        s.health = (s.state == TunnelState::Connected).then(|| {
            if s.proxy_status == ProxyStatus::ProxyDown || s.competing_tun.is_some() {
                Health::Degraded
            } else {
                Health::Ok
            }
        });
        self.snap = s;
    }
}

mod transitions;

#[cfg(test)]
mod tests;
