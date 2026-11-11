//! One verification run: the stability window, the compatibility chain, sibling fallback and the
//! learning commit, interrupted by lifecycle events at every await point.
use std::collections::HashSet;
use std::future::Future;

use tokio::sync::broadcast::{self, error::RecvError};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::{AdaptiveMode, Level, Notice, OutboundFault, Owner, now_ms};

use super::{Adaptive, Context, Target};
use crate::adaptive::window::{self, NEEDED};
use crate::adaptive::{
    AdaptiveHost, AdaptiveStatus, MAX_SIBLINGS, Phase, capabilities, next_mode, order_siblings,
};
use crate::coordinator::{
    Coordinator, LifecycleEvent, NoticeCategory, OpError, RuntimeId, SessionKind, StopCause,
};

/// A network change restarts the window at most this often per runtime, so a flapping network
/// cannot keep the status at «verifying» forever.
const MAX_WINDOW_RESTARTS: u8 = 3;

/// How a run ended, for the task loop.
pub(super) enum Outcome {
    /// Verify this runtime next (a start this run did not ask for, or a retry).
    Next(Target),
    /// Done (verified, failed or ended); wait for the next start.
    Idle,
    Shutdown,
}

/// Why a run stopped early.
enum Stop {
    /// Another start replaced the runtime.
    Superseded(Target),
    /// The session ended (`None`: lost track after a lagged event stream).
    Ended(Option<StopCause>),
    /// A higher-priority operation refused or cancelled our restart; its own events follow.
    Preempted,
    /// The user asked for a fresh verification.
    Retry,
    /// The physical network changed during a window.
    NetworkChanged,
    Shutdown,
}

struct Run<'a, C: Coordinator, H: AdaptiveHost> {
    a: &'a Adaptive<C, H>,
    events: &'a mut broadcast::Receiver<LifecycleEvent>,
    cancel: &'a CancellationToken,
    ctx: Context,
    generation: u64,
    runtime: RuntimeId,
    /// Runtimes our own restarts produced (their `Started` events are not foreign).
    own: HashSet<RuntimeId>,
    fault: Option<(RuntimeId, OutboundFault)>,
    attempts: u8,
    /// Modes that already failed this connection (skipped by the chain).
    failed: Vec<AdaptiveMode>,
    window_restarts: u8,
    in_window: bool,
    restarting: bool,
    /// Foreign-looking `Started` events seen while our restart ran (sorted out afterwards).
    stash: Vec<Target>,
}

impl<C: Coordinator, H: AdaptiveHost> Adaptive<C, H> {
    pub(super) async fn verify(
        &self,
        target: Target,
        events: &mut broadcast::Receiver<LifecycleEvent>,
        cancel: &CancellationToken,
    ) -> Outcome {
        if target.kind == SessionKind::Soft {
            self.on_stopped(None);
            return Outcome::Idle;
        }
        let (ctx, generation) = self.attach(&target);
        let mut run = Run {
            a: self,
            events,
            cancel,
            ctx,
            generation,
            runtime: target.runtime,
            own: HashSet::new(),
            fault: None,
            attempts: 0,
            failed: Vec::new(),
            window_restarts: 0,
            in_window: false,
            restarting: false,
            stash: Vec::new(),
        };
        match run.chain().await {
            Ok(()) | Err(Stop::Preempted) | Err(Stop::NetworkChanged) => Outcome::Idle,
            Err(Stop::Superseded(next)) => Outcome::Next(next),
            Err(Stop::Retry) => match self.coord.session() {
                Some(s) => Outcome::Next(Target::from(&s)),
                None => Outcome::Idle,
            },
            Err(Stop::Ended(cause)) => {
                self.on_stopped(cause);
                Outcome::Idle
            }
            Err(Stop::Shutdown) => Outcome::Shutdown,
        }
    }
}

fn fault_reason(fault: OutboundFault) -> Msg {
    Msg::new(match fault {
        OutboundFault::RealityKeyMismatch => "automation.adaptive.reason.realityKeyMismatch",
        OutboundFault::TlsHandshakeFailed => "automation.adaptive.reason.tlsHandshakeFailed",
        OutboundFault::UpstreamUnreachable => "automation.adaptive.reason.upstreamUnreachable",
    })
}

impl<C: Coordinator, H: AdaptiveHost> Run<'_, C, H> {
    /// Drives `fut` while handling lifecycle events, retry requests and shutdown.
    async fn guard<T>(&mut self, fut: impl Future<Output = T>) -> Result<T, Stop> {
        tokio::pin!(fut);
        loop {
            let event = tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return Err(Stop::Shutdown),
                _ = self.a.retry.notified(), if !self.restarting => return Err(Stop::Retry),
                event = self.events.recv() => event,
                out = &mut fut => return Ok(out),
            };
            if let Some(stop) = self.on_event(event) {
                return Err(stop);
            }
        }
    }

    fn on_event(&mut self, event: Result<LifecycleEvent, RecvError>) -> Option<Stop> {
        let target = match event {
            Ok(LifecycleEvent::Started {
                runtime_id,
                kind,
                profile_id,
                mode,
                ..
            }) => Target {
                runtime: runtime_id,
                kind,
                profile_id,
                mode,
            },
            Ok(LifecycleEvent::Stopped { cause, .. }) => return Some(Stop::Ended(Some(cause))),
            Ok(LifecycleEvent::Fault { runtime_id, fault }) => {
                self.fault = Some((runtime_id, fault));
                return None;
            }
            Ok(LifecycleEvent::NetworkChanged) => {
                // What works on the new path proves nothing about the network we keyed on.
                self.ctx.key = None;
                let restart = self.in_window && self.window_restarts < MAX_WINDOW_RESTARTS;
                return restart.then_some(Stop::NetworkChanged);
            }
            Err(RecvError::Lagged(_)) => match self.a.coord.session() {
                Some(s) => Target::from(&s),
                None if self.restarting => return None,
                None => return Some(Stop::Ended(None)),
            },
            Err(RecvError::Closed) => return Some(Stop::Shutdown),
        };
        if target.runtime == self.runtime || self.own.contains(&target.runtime) {
            return None;
        }
        if self.restarting {
            self.stash.push(target);
            return None;
        }
        Some(Stop::Superseded(target))
    }

    /// Protected restart through the coordinator as `Owner::AdaptiveRetry`. `Ok(Err(e))`: the
    /// restart failed and no other operation took over.
    async fn restart(
        &mut self,
        mode: AdaptiveMode,
        sibling: Option<&str>,
    ) -> Result<Result<(), OpError>, Stop> {
        self.attempts = self.attempts.saturating_add(1);
        self.ctx.mode = mode;
        let message = if sibling.is_some() {
            "automation.adaptive.status.serverFailover"
        } else {
            "automation.adaptive.status.adapting"
        };
        self.status(Phase::Adapting, message, None);
        self.restarting = true;
        let a = self.a;
        let result = self
            .guard(
                a.coord
                    .adaptive_restart(Owner::AdaptiveRetry, mode, sibling),
            )
            .await;
        self.restarting = false;
        let stash = std::mem::take(&mut self.stash);
        let result = match result {
            Err(Stop::Ended(Some(StopCause::Fault))) => {
                // The protected restart failed and ended the session: keep the failure visible.
                let key = if sibling.is_some() {
                    "automation.adaptive.reason.siblingStartFailed"
                } else {
                    "automation.adaptive.reason.compatFailed"
                };
                self.fail(Msg::new(key))?;
                return Err(Stop::Ended(Some(StopCause::Fault)));
            }
            other => other?,
        };
        match result {
            Ok(runtime) => {
                self.own.insert(runtime);
                if let Some(foreign) = stash.into_iter().rfind(|t| t.runtime != runtime) {
                    return Err(Stop::Superseded(foreign));
                }
                self.runtime = runtime;
                self.window_restarts = 0;
                self.save();
                Ok(Ok(()))
            }
            Err(OpError::Cancelled | OpError::Conflict) => Err(stash
                .into_iter()
                .last()
                .map_or(Stop::Preempted, Stop::Superseded)),
            Err(err) => match stash.into_iter().last() {
                Some(foreign) => Err(Stop::Superseded(foreign)),
                None => Ok(Err(err)),
            },
        }
    }

    /// One stability window on the current runtime; a network change restarts it (bounded).
    async fn window(&mut self) -> Result<usize, Stop> {
        self.status(
            Phase::Verifying,
            "automation.adaptive.status.verifying",
            None,
        );
        loop {
            let token = self.cancel.child_token();
            let (a, timing) = (self.a, self.a.timing);
            self.in_window = true;
            let result = self
                .guard(window::stability_window(timing, &token, |t| {
                    a.host.probe(t)
                }))
                .await;
            self.in_window = false;
            token.cancel();
            match result {
                Ok(Some(samples)) => return Ok(samples.len()),
                Ok(None) => return Err(Stop::Shutdown),
                Err(Stop::NetworkChanged) => {
                    self.window_restarts += 1;
                    tracing::info!("adaptive: network changed, stability window restarted");
                }
                Err(stop) => return Err(stop),
            }
        }
    }

    fn current_fault(&self) -> Option<OutboundFault> {
        self.fault
            .filter(|(runtime, _)| *runtime == self.runtime)
            .map(|(_, fault)| fault)
    }

    /// The next mode of the chain that has not failed yet this connection.
    fn next_untried(&self) -> Option<AdaptiveMode> {
        let mut mode = self.ctx.mode;
        loop {
            mode = next_mode(mode, &self.ctx.caps)?;
            if !self.failed.contains(&mode) {
                return Some(mode);
            }
        }
    }

    fn save(&self) {
        self.a.shared.lock().current = Some((self.runtime, self.ctx.clone()));
    }

    fn status(&self, phase: Phase, message: &'static str, reason: Option<Msg>) -> bool {
        let status = AdaptiveStatus {
            phase,
            mode: self.ctx.mode,
            external: self.ctx.caps.external,
            attempts: self.attempts,
            message: Msg::new(message),
            reason,
            updated_at: now_ms(),
        };
        self.a.publish(self.generation, status)
    }
}

impl<C: Coordinator, H: AdaptiveHost> Run<'_, C, H> {
    /// Verify → (fix A1) → compatibility chain → siblings. At most two mode restarts (the chain
    /// has two steps and A1's baseline restart skips the mode that failed) plus [`MAX_SIBLINGS`].
    async fn chain(&mut self) -> Result<(), Stop> {
        if !self.a.settings.read(|s| s.adaptive_bypass) || self.ctx.caps.external {
            // Nothing to adapt: an external proxy owns the transport, or the user turned it off.
            return self.succeed().await;
        }
        loop {
            if self.window().await? >= NEEDED {
                return self.succeed().await;
            }
            self.failed.push(self.ctx.mode);
            // A rejected REALITY key, a failed TLS check or a dead upstream: no knob fixes that.
            if let Some(fault) = self.current_fault() {
                return self.fallback(fault_reason(fault)).await;
            }
            let reused = std::mem::take(&mut self.ctx.reused);
            let next = if reused && self.ctx.mode != AdaptiveMode::Baseline {
                // Fix A1: a learned mode that fails here is stale. Forget it, retry from baseline.
                if let Some(key) = &self.ctx.key {
                    self.a.learning.forget(key);
                }
                Some(AdaptiveMode::Baseline)
            } else {
                self.next_untried()
            };
            let Some(mode) = next else {
                let reason = Msg::new("automation.adaptive.reason.probeFailed");
                return self.fallback(reason).await;
            };
            if let Err(err) = self.restart(mode, None).await? {
                tracing::warn!("adaptive: compatibility restart failed: {err}");
                return self.fail(compat_reason(&err));
            }
        }
    }

    /// Up to [`MAX_SIBLINGS`] servers of the same group, started in the mode the chain reached; a
    /// sibling is committed only after its own window passed.
    async fn fallback(&mut self, reason: Msg) -> Result<(), Stop> {
        let allowed = self.ctx.kind == SessionKind::Direct
            && self.a.settings.read(|s| s.adaptive_bypass_server_fallback);
        let Some(active) = self.ctx.profile.clone().filter(|_| allowed) else {
            return self.fail(reason);
        };
        let candidates = order_siblings(&active, self.a.host.siblings(&active.id));
        let mut provisional = false;
        let mut reason = reason;
        for sibling in candidates.into_iter().take(MAX_SIBLINGS) {
            let mode = self.ctx.mode;
            if let Err(err) = self.restart(mode, Some(&sibling.profile.id)).await? {
                tracing::warn!("adaptive: sibling start failed: {err}");
                if self.a.coord.session().is_none() {
                    return self.fail(Msg::new("automation.adaptive.reason.siblingStartFailed"));
                }
                reason = Msg::new("automation.adaptive.reason.siblingStartFailed");
                continue;
            }
            provisional = true;
            // A different server: its own capabilities, and nothing learned for it here.
            self.ctx.caps = capabilities(SessionKind::Direct, Some(&sibling.profile));
            self.ctx.profile = Some(sibling.profile.clone());
            self.ctx.key = None;
            self.ctx.reused = false;
            self.save();
            if self.window().await? >= NEEDED {
                if let Err(err) = self.a.host.select(&sibling.profile.id) {
                    tracing::warn!("adaptive: verified sibling not saved as selected: {err}");
                }
                return self.succeed().await;
            }
            reason = Msg::new("automation.adaptive.reason.siblingFailed");
        }
        if provisional {
            // Never leave an unproven provisional server running as if it were connected.
            self.a.host.abandon().await;
        }
        self.fail(reason)
    }

    /// The runtime works: commit what was learned (if the network is still the one keyed on).
    async fn succeed(&mut self) -> Result<(), Stop> {
        if let Some(key) = self
            .ctx
            .key
            .clone()
            .filter(|_| self.ctx.mode != AdaptiveMode::Baseline)
        {
            let a = self.a;
            let now = self.guard(a.host.network_identity()).await?;
            let same_network = now.is_some() && now == self.ctx.identity;
            let same_key = match (&now, &self.ctx.profile) {
                (Some(net), Some(profile)) => a.learning.key(net, profile).as_deref() == Some(&key),
                _ => false,
            };
            // A network change during the re-read fenced the key; a newer start makes it stale.
            let fenced = self.ctx.key.is_none() || a.shared.lock().generation != self.generation;
            if same_network && same_key && !fenced {
                a.learning.learn(&key, self.ctx.mode, now_ms());
            }
        }
        let message = if self.ctx.caps.external {
            "automation.adaptive.status.externalManaged"
        } else if self.ctx.mode == AdaptiveMode::Baseline {
            "automation.adaptive.status.connectedBaseline"
        } else {
            "automation.adaptive.status.connectedCompatibility"
        };
        self.status(Phase::Connected, message, None);
        Ok(())
    }

    /// No working mode: the status says so and the user gets one notice. The tunnel stays up (its
    /// traffic stays inside the TUN), unless it was a provisional sibling (abandoned before).
    fn fail(&mut self, reason: Msg) -> Result<(), Stop> {
        tracing::warn!(mode = ?self.ctx.mode, attempts = self.attempts, "adaptive: no working mode");
        let failed = "automation.adaptive.status.failed";
        if self.status(Phase::Failed, failed, Some(reason.clone())) {
            let notice = Notice::new(Level::Warn, failed).body(reason);
            self.a.coord.notify(NoticeCategory::ConnectionError, notice);
        }
        Ok(())
    }
}

/// The reason shown when a compatibility restart failed.
fn compat_reason(err: &OpError) -> Msg {
    match err {
        OpError::Failed(e) if e.msg.is_some() => e.user_msg(),
        _ => Msg::new("automation.adaptive.reason.compatFailed"),
    }
}
