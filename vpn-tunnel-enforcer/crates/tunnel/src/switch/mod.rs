//! Protected upstream switch: a 1:1 port of the old `runProtectedOutboundSwitch`.
//!
//! The running TUN and the previous upstream stay in place until a separately staged candidate
//! slot is probed, selected and freshly confirmed; any failure or cancellation drains only the
//! candidate and re-proves the previous upstream. The coordinator is generic over [`SwitchOps`]
//! and knows nothing about engines, the TUN or the kill switch.
use std::future::Future;

use tokio_util::sync::CancellationToken;
use vpnte_base::AppError;

use crate::api::{Slot, SwitchFailure, SwitchOutcome, SwitchPhase, SwitchReceipt};

/// The effects one protected switch needs. Calls never overlap (the coordinator awaits each).
pub trait SwitchOps {
    /// Starts the candidate upstream in `slot`. A rejected stage may already own a partially
    /// started child: the coordinator stops the slot afterwards in every failure path.
    fn stage(
        &mut self,
        slot: Slot,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(), AppError>> + Send;
    /// Proves the staged upstream reaches the internet on its own (before any selector write).
    fn probe(
        &mut self,
        slot: Slot,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(), AppError>> + Send;
    /// Points the tunnel's selector at `slot`; a write may take effect even when it errs.
    fn select(&mut self, slot: Slot) -> impl Future<Output = Result<(), AppError>> + Send;
    /// Fresh proof that the tunnel now egresses through `slot`.
    fn confirm(&mut self, slot: Slot) -> impl Future<Output = Result<(), AppError>> + Send;
    /// The slot's process is running.
    fn alive(&self, slot: Slot) -> bool;
    /// Stops the slot's process (idempotent); `alive` tells whether the exit was proven.
    fn stop(&mut self, slot: Slot) -> impl Future<Output = Result<(), AppError>> + Send;
    /// Publishes `slot` as the active upstream; never rolled back afterwards.
    fn commit(&mut self, slot: Slot) -> Result<(), AppError>;
    /// The caller still owns the tunnel.
    fn is_owner(&self) -> bool;
}

/// Runs one protected switch from `previous` to `candidate`. Never panics and never returns an
/// error: everything that happened is in the receipt.
pub async fn run_protected_switch<O: SwitchOps + Send>(
    previous: Slot,
    candidate: Slot,
    ops: &mut O,
    cancel: &CancellationToken,
) -> SwitchReceipt {
    let mut receipt = SwitchReceipt::default();
    let mut progress = Progress {
        phase: SwitchPhase::Ownership,
        staged: false,
        selected: false,
    };
    match forward(previous, candidate, ops, cancel, &mut progress).await {
        Ok(()) => {
            receipt.committed = true;
            receipt.active_slot = Some(candidate);
        }
        Err(message) => record(&mut receipt, progress.phase, message),
    }
    let Progress {
        staged, selected, ..
    } = progress;

    if receipt.committed {
        // The old slot stays owned if its exit cannot be confirmed; a published selection is
        // never rolled back.
        match ops.stop(previous).await {
            Ok(()) if ops.alive(previous) => record(
                &mut receipt,
                SwitchPhase::StopPrevious,
                "Previous upstream exit was not confirmed".into(),
            ),
            Ok(()) => receipt.previous_stopped = true,
            Err(e) => record(&mut receipt, SwitchPhase::StopPrevious, e.to_string()),
        }
        if !ops.is_owner() || cancel.is_cancelled() {
            receipt.outcome = SwitchOutcome::Cancelled;
            receipt.active_slot = None;
        } else {
            let candidate_alive = ops.alive(candidate);
            receipt.outcome = if receipt.previous_stopped && candidate_alive {
                SwitchOutcome::Success
            } else {
                SwitchOutcome::Failed
            };
            if !candidate_alive {
                receipt.active_slot = None;
                record(
                    &mut receipt,
                    SwitchPhase::Ownership,
                    "Committed upstream is no longer running".into(),
                );
            }
        }
        return receipt;
    }

    let mut restored = !selected;
    if selected && ops.is_owner() {
        match restore(previous, ops).await {
            Ok(()) => restored = true,
            Err(message) => record(&mut receipt, SwitchPhase::Restore, message),
        }
    }
    if staged {
        match ops.stop(candidate).await {
            Ok(()) if ops.alive(candidate) => record(
                &mut receipt,
                SwitchPhase::StopCandidate,
                "Candidate upstream exit was not confirmed".into(),
            ),
            Ok(()) => receipt.candidate_stopped = true,
            Err(e) => record(&mut receipt, SwitchPhase::StopCandidate, e.to_string()),
        }
    } else {
        // No stage was dispatched, so this owner has no candidate child to drain.
        receipt.candidate_stopped = !ops.alive(candidate);
    }
    if restored && receipt.candidate_stopped && ops.is_owner() && previous != candidate {
        match reconfirm(previous, ops).await {
            Ok(()) => {
                receipt.previous_preserved = true;
                receipt.active_slot = Some(previous);
            }
            Err(message) => record(&mut receipt, SwitchPhase::ConfirmPrevious, message),
        }
    }
    receipt.outcome = if !ops.is_owner() || cancel.is_cancelled() {
        SwitchOutcome::Cancelled
    } else {
        SwitchOutcome::Failed
    };
    receipt
}

/// How far the forward path got: decides what the failure path must undo.
struct Progress {
    phase: SwitchPhase,
    /// A rejected stage may already own a partially started child.
    staged: bool,
    /// A selector write can take effect even when its response or read-back fails.
    selected: bool,
}

/// Stage, probe, select, confirm and commit the candidate, fencing ownership and liveness of
/// both slots after every await.
async fn forward<O: SwitchOps + Send>(
    previous: Slot,
    candidate: Slot,
    ops: &mut O,
    cancel: &CancellationToken,
    progress: &mut Progress,
) -> Result<(), String> {
    if previous == candidate {
        return Err("Distinct upstream slots are required".into());
    }
    owned(ops, cancel)?;
    alive(ops, previous)?;
    // An occupied candidate is retained for its existing owner, never overwritten or reaped.
    if ops.alive(candidate) {
        return Err("Candidate upstream slot is already occupied".into());
    }
    progress.phase = SwitchPhase::Stage;
    progress.staged = true;
    ops.stage(candidate, cancel).await.map_err(text)?;
    fence(ops, cancel, previous, candidate)?;
    progress.phase = SwitchPhase::Probe;
    ops.probe(candidate, cancel).await.map_err(text)?;
    fence(ops, cancel, previous, candidate)?;
    progress.phase = SwitchPhase::Select;
    progress.selected = true;
    ops.select(candidate).await.map_err(text)?;
    fence(ops, cancel, previous, candidate)?;
    progress.phase = SwitchPhase::Confirm;
    ops.confirm(candidate).await.map_err(text)?;
    fence(ops, cancel, previous, candidate)?;
    progress.phase = SwitchPhase::Commit;
    ops.commit(candidate).map_err(text)
}

/// Re-selects the previous slot after a selector write for the candidate.
async fn restore<O: SwitchOps + Send>(previous: Slot, ops: &mut O) -> Result<(), String> {
    alive(ops, previous)?;
    ops.select(previous).await.map_err(text)?;
    if !ops.is_owner() {
        return Err("Outbound switch superseded during restoration".into());
    }
    Ok(())
}

/// Fresh proof of the retained previous upstream.
async fn reconfirm<O: SwitchOps + Send>(previous: Slot, ops: &mut O) -> Result<(), String> {
    alive(ops, previous)?;
    ops.confirm(previous).await.map_err(text)?;
    if !ops.is_owner() {
        return Err("Outbound switch superseded during verification".into());
    }
    alive(ops, previous)
}

fn fence<O: SwitchOps>(
    ops: &O,
    cancel: &CancellationToken,
    previous: Slot,
    candidate: Slot,
) -> Result<(), String> {
    owned(ops, cancel)?;
    alive(ops, previous)?;
    alive(ops, candidate)
}

fn owned<O: SwitchOps>(ops: &O, cancel: &CancellationToken) -> Result<(), String> {
    if !ops.is_owner() || cancel.is_cancelled() {
        return Err("Outbound switch cancelled".into());
    }
    Ok(())
}

fn alive<O: SwitchOps>(ops: &O, slot: Slot) -> Result<(), String> {
    if ops.alive(slot) {
        Ok(())
    } else {
        Err(format!("Upstream {} is no longer running", slot_name(slot)))
    }
}

fn slot_name(slot: Slot) -> &'static str {
    match slot {
        Slot::A => "a",
        Slot::B => "b",
    }
}

/// Engine errors are already redacted; the text is for the log only.
fn text(e: AppError) -> String {
    e.to_string()
}

fn record(receipt: &mut SwitchReceipt, phase: SwitchPhase, message: String) {
    tracing::warn!(?phase, %message, "protected upstream switch step failed");
    receipt.failures.push(SwitchFailure { phase, message });
}

#[cfg(test)]
mod tests;
