//! The trial of a freshly installed engine (research §4.7 step 6): while it is on trial, every
//! start the tunnel attempts with it counts — one that reaches «подключено» ends the trial, three
//! that end in an error in a row switch back by themselves (`EngineStore::record_start`), said in
//! one line. Only starts that run this app's engines count: with engines that follow the update
//! channel (`switch`) a Proxy-mode start runs the versions active when it began (Tunnel mode runs
//! in the helper service, on its own engines); a process that keeps its engines counts every
//! start against the versions of the app start.
use std::sync::Arc;

use vpnte_base::Msg;
use vpnte_base::types::Engine;
use vpnte_core::settings::RoutingMode;
use vpnte_tunnel::fsm::{Transition, TunnelState};
use vpnte_update::policy::XRAY;
use vpnte_update::store::{Choice, Origin};
use vpnte_update::version::Version;

use super::Updates;
use super::actions::engine_name;
use super::view::ENGINES;

/// The engines on trial a start runs.
type OnTrial = Vec<(&'static str, Version)>;

/// Watches the tunnel's starts while an engine is on trial (or may be: engines that follow the
/// update channel start a trial at any install).
pub(super) fn spawn(u: &Arc<Updates>) {
    let Ok(tunnel) = u.backend.tunnel() else {
        return;
    };
    let at_start = u.on_trial();
    let live = u.apply_engines();
    if at_start.is_empty() && !live {
        return;
    }
    let (mut snapshot, status) = (tunnel.snapshot(), tunnel.runtime_status());
    let (this, cancel) = (u.clone(), u.backend.shutdown.child_token());
    tokio::spawn(async move {
        let mut starting: Option<OnTrial> = None;
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
                if starting.is_none() {
                    starting = Some(this.trial_of_start(live, &at_start));
                }
                continue;
            }
            if transition.is_some() {
                continue;
            }
            let Some(on_trial) = starting.take() else {
                continue;
            };
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
    /// The engines on trial: active downloaded versions whose trial is not over.
    fn on_trial(&self) -> OnTrial {
        let state = self.store.state();
        ENGINES
            .iter()
            .filter_map(|&(id, _)| {
                state.engine(id)?.trial?;
                match self.store.resolve(id).origin {
                    Origin::Downloaded { version, .. } => Some((id, version)),
                    Origin::Bundled => None,
                }
            })
            .collect()
    }

    /// The engines on trial a start that begins now runs: with engines that follow the update
    /// channel those active now, for a Proxy-mode start only; else those of the app start.
    fn trial_of_start(&self, live: bool, at_start: &OnTrial) -> OnTrial {
        if !live {
            return at_start.clone();
        }
        match self.backend.settings.read(|s| s.routing_mode) {
            RoutingMode::Soft => self.on_trial(),
            RoutingMode::Hard => Vec::new(),
        }
    }

    /// One start of `id` at `version` (the version that start ran).
    fn count(&self, id: &str, version: Version, ok: bool) {
        let active = self.store.state().engine(id).map(|r| r.active);
        // Installed again (or switched back) meanwhile: that version's trial is its own.
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
                // Engines that follow the update channel run the version switched back to from
                // the next start on; otherwise it waits for the app's restart.
                let key = if self.apply_engines() {
                    "app.update.trialRolledBack"
                } else {
                    "app.update.trialFailed"
                };
                let msg = Msg::new(key)
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
