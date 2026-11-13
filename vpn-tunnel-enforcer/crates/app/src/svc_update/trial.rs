//! The trial of a freshly installed engine (research §4.7 step 6): while it is on trial, every
//! start the tunnel attempts with it counts — one that reaches «подключено» ends the trial, three
//! that end in an error in a row switch back by themselves (`EngineStore::record_start`), said in
//! one line. Only the engine this run actually started counts: the paths are fixed at app start.
use std::sync::Arc;

use vpnte_base::Msg;
use vpnte_base::types::Engine;
use vpnte_tunnel::fsm::{Transition, TunnelState};
use vpnte_update::policy::XRAY;
use vpnte_update::store::{Choice, Origin};
use vpnte_update::version::Version;

use super::Updates;
use super::actions::engine_name;
use super::view::ENGINES;

/// Watches the tunnel's starts while an engine of this run is on trial.
pub(super) fn spawn(u: &Arc<Updates>) {
    let Ok(tunnel) = u.backend.tunnel() else {
        return;
    };
    let state = u.store.state();
    let on_trial: Vec<(&'static str, Version)> = ENGINES
        .iter()
        .filter_map(|&(id, _)| {
            state.engine(id)?.trial?;
            match u.store.resolve(id).origin {
                Origin::Downloaded { version, .. } => Some((id, version)),
                Origin::Bundled => None,
            }
        })
        .collect();
    if on_trial.is_empty() {
        return;
    }
    let (mut snapshot, status) = (tunnel.snapshot(), tunnel.runtime_status());
    let (this, cancel) = (u.clone(), u.backend.shutdown.child_token());
    tokio::spawn(async move {
        let mut starting = false;
        loop {
            tokio::select! {
                changed = snapshot.changed() => if changed.is_err() { return },
                () = cancel.cancelled() => return,
            }
            let (transition, state) = {
                let snap = snapshot.borrow_and_update();
                (snap.transition, snap.state)
            };
            if matches!(
                transition,
                Some(Transition::Connecting | Transition::Reconnecting)
            ) {
                starting = true;
                continue;
            }
            if !starting || transition.is_some() {
                continue;
            }
            starting = false;
            // A start the user cancelled or stopped says nothing about the engine.
            let ok = match state {
                TunnelState::Connected => true,
                TunnelState::Error => false,
                _ => continue,
            };
            let xray_ran = status
                .borrow()
                .engine
                .is_some_and(|e| e.kind == Engine::Xray);
            for &(id, version) in &on_trial {
                if ok && id == XRAY && !xray_ran {
                    continue;
                }
                this.count(id, version, ok);
            }
        }
    });
}

impl Updates {
    /// One start of `id` at `version` (the version this run runs).
    fn count(&self, id: &str, version: Version, ok: bool) {
        let active = self.store.state().engine(id).map(|r| r.active);
        // Installed again meanwhile: the new version's trial starts with the next app start.
        if active != Some(Choice::Downloaded(version)) {
            return;
        }
        match self.store.record_start(id, ok) {
            Ok(Some(rolled)) => {
                let to = match rolled.to {
                    Choice::Downloaded(v) => v.to_string(),
                    Choice::Bundled => vpnte_update::policy::bundled_version(id)
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                };
                let msg = Msg::new("app.update.trialFailed")
                    .arg("name", engine_name(id))
                    .arg("from", rolled.from)
                    .arg("to", to);
                self.note(msg, true);
            }
            Ok(None) => {}
            Err(err) => tracing::warn!(engine = id, %err, "engine trial not recorded"),
        }
    }
}
