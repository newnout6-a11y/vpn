//! The in-place upstream switch as callers see it: slots, outcome, phases and the receipt.
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vpnte_base::Msg;

use super::EngineRun;

/// One of the two Xray upstream slots behind the sing-box selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Slot {
    A,
    B,
}

impl Slot {
    /// The other slot.
    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }
}

/// How an in-place upstream switch ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SwitchOutcome {
    Success,
    Cancelled,
    Failed,
}

/// Step of the protected switch in which a failure happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SwitchPhase {
    Stage,
    Probe,
    Select,
    Confirm,
    Commit,
    Restore,
    ConfirmPrevious,
    StopCandidate,
    StopPrevious,
    Ownership,
}

/// A failed switch step; `message` is a redacted English diagnostic for the log, never shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchFailure {
    pub phase: SwitchPhase,
    pub message: String,
}

/// What an in-place upstream switch did to both slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchReceipt {
    pub outcome: SwitchOutcome,
    /// The candidate was published as the active upstream (never rolled back afterwards).
    pub committed: bool,
    pub active_slot: Option<Slot>,
    /// The previous upstream was re-selected and re-confirmed after a failed attempt.
    pub previous_preserved: bool,
    pub candidate_stopped: bool,
    pub previous_stopped: bool,
    /// The caller stopped owning the tunnel while the switch ran.
    pub ownership_lost: bool,
    pub failures: Vec<SwitchFailure>,
    /// The engine run the committed candidate uses (`None` until committed).
    pub engine: Option<EngineRun>,
    /// Things the user should know about the new upstream (Xray's dropped settings).
    pub warnings: Vec<Msg>,
}

impl Default for SwitchReceipt {
    /// Nothing done yet: a failure until proven otherwise.
    fn default() -> Self {
        Self {
            outcome: SwitchOutcome::Failed,
            committed: false,
            active_slot: None,
            previous_preserved: false,
            candidate_stopped: false,
            previous_stopped: false,
            ownership_lost: false,
            failures: Vec::new(),
            engine: None,
            warnings: Vec::new(),
        }
    }
}

impl SwitchReceipt {
    /// The tunnel ends on a proven upstream: the candidate, or the preserved previous one.
    pub fn verified(&self) -> bool {
        !self.ownership_lost && (self.previous_preserved || self.outcome == SwitchOutcome::Success)
    }
}

/// Asked during a switch: does the caller still own the tunnel?
pub type OwnerCheck = Arc<dyn Fn() -> bool + Send + Sync>;
