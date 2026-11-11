//! The pushed snapshot: the projection task re-reads the tunnel phase, the capture status, the
//! last caught error and the old version's leftovers whenever the tunnel or an action of this
//! page changes them, and publishes only what differs. Protection, repair and export progress
//! belong to the actions that produce them and are never touched here.
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_tunnel::fsm::{TunnelSnapshot, TunnelState};
use vpnte_ui::maintenance::{CaptureView, FaultView, LegacyView, MaintenanceState, TunnelPhase};

use super::{Shared, legacy, refused};
use crate::services::TunnelOps;
use crate::svc_core::needs_admin;

/// Coalesces bursts of tunnel events into one projection.
const DEBOUNCE: Duration = Duration::from_millis(40);

/// The phase the page gates its actions on. A transition wins over every state; `Blocked` (the
/// kill switch holds traffic after a drop) and any open session count as "on": the user ends
/// them with Disconnect, never through a repair.
pub(crate) fn phase(snap: &TunnelSnapshot, session_open: bool) -> TunnelPhase {
    if snap.transition.is_some() {
        return TunnelPhase::Busy;
    }
    match snap.state {
        TunnelState::Connected | TunnelState::Blocked => TunnelPhase::On,
        _ if session_open => TunnelPhase::On,
        TunnelState::Disconnected | TunnelState::Error | TunnelState::Unknown => TunnelPhase::Off,
    }
}

/// The tunnel's phase right now (not the possibly older published one).
pub(crate) fn live_phase(shared: &Shared) -> TunnelPhase {
    match shared.backend.tunnel() {
        Ok(tunnel) => tunnel_phase(tunnel.as_ref()),
        // Without a tunnel nothing can be proven idle.
        Err(_) => TunnelPhase::Busy,
    }
}

fn tunnel_phase(tunnel: &dyn TunnelOps) -> TunnelPhase {
    let open = tunnel.session().borrow().is_some();
    phase(&tunnel.snapshot().borrow(), open)
}

/// Every mutation of this page waits for a settled tunnel: `Conflict` while it connects,
/// switches or disconnects.
pub(crate) fn settled(shared: &Shared) -> AppResult<()> {
    match live_phase(shared) {
        TunnelPhase::Busy => Err(refused("app.maintenance.tunnelBusy")),
        TunnelPhase::Off | TunnelPhase::On => Ok(()),
    }
}

/// Packet capture is not hosted by this build; unelevated it could not run anyway.
pub(crate) fn capture_refusal(elevated: bool) -> AppError {
    if elevated {
        refused("app.maintenance.capture.unavailable")
    } else {
        needs_admin()
    }
}

/// The capture panel: nothing captures in this build, and the first warning says why (no
/// session dir is ever read, so nothing is shown as "stopped cleanly" beyond that fact).
pub(crate) fn capture_view(elevated: bool) -> CaptureView {
    let why = capture_refusal(elevated).user_msg();
    CaptureView {
        last_error: Some(why.clone()),
        warnings: vec![why],
        ..CaptureView::default()
    }
}

/// The last error a backend crate logged in this run (lifecycle faults, panics, failed
/// effects): English, already redacted by the log layer. UI action lines are left out.
pub(crate) fn last_fault(problems: &[vpnte_core::logging::Problem]) -> Option<FaultView> {
    problems
        .iter()
        .rev()
        .find(|p| p.level == tracing::Level::ERROR && p.target.starts_with("vpnte"))
        .map(|p| FaultView {
            at: p.at,
            code: p
                .target
                .strip_prefix("vpnte_")
                .unwrap_or(&p.target)
                .to_owned(),
            detail: p.msg.clone(),
        })
}

/// Publishes the first snapshot at once and starts the task that keeps it current until
/// `backend.shutdown`.
pub fn spawn(shared: &Arc<Shared>) {
    let tunnel = shared.backend.tunnel().ok().cloned();
    let phase = tunnel.as_deref().map_or(TunnelPhase::Busy, tunnel_phase);
    let capture = capture_view(shared.backend.elevated);
    shared.state.send_modify(|s| {
        s.tunnel = phase;
        s.capture = capture;
    });
    tokio::spawn(run(shared.clone(), tunnel));
}

async fn run(shared: Arc<Shared>, tunnel: Option<Arc<dyn TunnelOps>>) {
    let mut snapshot = tunnel.as_ref().map(|t| t.snapshot());
    let mut session = tunnel.as_ref().map(|t| t.session());
    // The old data (a directory walk) changes only through this page's actions.
    let mut legacy = legacy::view(&shared).await;
    loop {
        let phase = tunnel.as_deref().map_or(TunnelPhase::Busy, tunnel_phase);
        let fault = last_fault(&vpnte_core::logging::recent_problems());
        publish(&shared.state, phase, fault, legacy.clone());
        let acted = tokio::select! {
            () = shared.backend.shutdown.cancelled() => break,
            () = changed(&mut snapshot) => false,
            () = changed(&mut session) => false,
            () = shared.dirty.notified() => true,
        };
        tokio::time::sleep(DEBOUNCE).await;
        if acted {
            legacy = legacy::view(&shared).await;
        }
    }
}

/// Writes the projected fields; the page re-renders only when one of them differs.
fn publish(
    state: &watch::Sender<MaintenanceState>,
    phase: TunnelPhase,
    fault: Option<FaultView>,
    legacy: LegacyView,
) {
    state.send_if_modified(|s| {
        let modified = s.tunnel != phase || s.fault != fault || s.legacy != legacy;
        s.tunnel = phase;
        s.fault = fault;
        s.legacy = legacy;
        modified
    });
}

/// Resolves on the next change; never when the channel is absent or closed.
async fn changed<T>(rx: &mut Option<watch::Receiver<T>>) {
    if let Some(rx) = rx
        && rx.changed().await.is_ok()
    {
        return;
    }
    std::future::pending::<()>().await
}

/// A sentence for a step the user cannot run here.
pub(crate) fn needs_admin_msg() -> Msg {
    needs_admin().user_msg()
}
