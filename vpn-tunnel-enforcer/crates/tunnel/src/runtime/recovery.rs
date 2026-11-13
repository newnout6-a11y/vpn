//! What happens after an unexpected engine exit (tunnel-core §3.5): the crash policy, backoff
//! restarts through the same start path (origin `Recovery`), the post-trial failover, the
//! terminal outcomes, and the active Xray slot's own restarts. Never names the capture kind.
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_engine::singbox_process::ExitInfo as EngineExit;
use vpnte_engine::xray_process::XrayEvent;

use super::MAX_RESTARTS;
use super::actor::{Actor, Crashed, Phase, Retained, Session};
use super::crash::{CrashAction, CrashFacts, decide, frozen_server};
use crate::api::{FailoverCause, Mode, Origin, StartRequest, TunStatusKind, TunnelEvent};

/// Xray slot restarts: backoff per attempt, at most three in this window (xray-engine §3).
const SLOT_BACKOFF: [Duration; 3] = [
    Duration::from_millis(500),
    Duration::from_secs(2),
    Duration::from_secs(5),
];
const SLOT_WINDOW: Duration = Duration::from_secs(60);
/// Failover candidates tried per exhausted window.
const FAILOVER_TRIES: usize = 5;

impl Actor {
    /// The running core exited (our own stops never reach this: they drop the exit watch).
    pub(super) async fn on_core_exit(&mut self, info: EngineExit) {
        self.exit = None;
        self.record_exit(&info);
        let Phase::Running(session) = std::mem::replace(&mut self.phase, Phase::Idle) else {
            return;
        };
        tracing::error!(code = ?info.code, "sing-box exited unexpectedly");
        self.crashed(session).await;
    }

    /// The session's core is gone: protection keeps blocking, supervision stops, the policy
    /// decides.
    async fn crashed(&mut self, session: Box<Session>) {
        session.watch.cancel();
        self.stable_at = None;
        self.slot_due = None;
        self.xray_rx = None;
        let fault = match &session.slots {
            Some(s) => s.slots.recent_fault(s.active),
            None => session.core.recent_fault(),
        };
        if let Some(id) = frozen_server(&session.req, fault) {
            tracing::warn!(
                ?fault,
                "crash with an outbound fault: the server stays quiet"
            );
            self.quiet = Some((id.to_owned(), Instant::now() + self.deps.timings.freeze));
        }
        // Removing the block here would defeat the kill switch: it exists for this moment.
        if let Err(e) = self.capture.lost().await {
            tracing::error!(error = %e, "protection did not follow the lost capture");
        }
        let Session { plan, slots, .. } = *session;
        self.phase = Phase::Crashed(Box::new(Crashed { plan, slots }));
        let status = self.idle_status();
        self.publish(|s| *s = status);
        self.after_crash().await;
    }

    /// Runs the crash policy on the current (crashed or failed-recovery) state.
    pub(super) async fn after_crash(&mut self) {
        let auto_restart = match self.deps.inputs.snapshot().await {
            Ok(user) => user.auto_restart_on_crash,
            Err(e) => {
                tracing::warn!(error = %e, "settings unreadable: no automatic restart");
                false
            }
        };
        let guard = match &self.phase {
            Phase::Crashed(c) => self.capture.guard(&c.plan),
            Phase::Adapting(plan) => self.capture.guard(plan),
            _ => vpnte_base::types::KillSwitchLevel::Off,
        };
        let facts = CrashFacts {
            attempt: self.attempt,
            slow: self.slow,
            auto_restart: auto_restart && self.last.is_some(),
            guard,
            failover_available: self.deps.failover.is_some() && !self.failover_tried,
            quiet: self.quiet_left(),
        };
        let timings = &self.deps.timings;
        match decide(facts, &timings.backoff, &timings.slow_retry) {
            CrashAction::Restart { attempt, delay } => {
                self.attempt = attempt;
                self.publish(|s| s.restart_attempt = attempt);
                self.announce(TunStatusKind::Restarting {
                    attempt,
                    max: MAX_RESTARTS,
                });
                self.emit(TunnelEvent::RestartScheduled { delay });
                self.restart_due = Some(Instant::now() + delay);
            }
            CrashAction::Failover => {
                self.failover_tried = true;
                // Only a fault on record ties the failover to the server; otherwise all that
                // was seen is an engine that kept stopping (the user is told just that).
                let cause = if facts.quiet.is_zero() {
                    FailoverCause::RestartsSpent
                } else {
                    FailoverCause::ServerFault
                };
                if !self.failover(cause).await {
                    Box::pin(self.after_crash()).await;
                }
            }
            CrashAction::SlowRetry { delay } => {
                self.slow = self.slow.saturating_add(1);
                // Held like a terminal block (Xray stopped, `KillSwitchActive`), then retried.
                self.terminal(false).await;
                if matches!(self.phase, Phase::Adapting(_)) {
                    tracing::info!(?delay, "kill switch holds the pause: slow retry scheduled");
                    self.emit(TunnelEvent::RestartScheduled { delay });
                    self.restart_due = Some(Instant::now() + delay);
                }
            }
            CrashAction::Block => self.terminal(false).await,
            CrashAction::Release => self.terminal(true).await,
        }
    }

    /// What is left of the freeze window of the server a restart of the last start would dial.
    fn quiet_left(&self) -> Duration {
        self.left_for_last(self.quiet.as_ref().map(|(id, until)| (id, *until)))
    }

    /// The time until `mark` (a server id and an instant) if it names the server of the last
    /// start (a local proxy's server is dialled by another client: never ours to keep quiet).
    fn left_for_last(&self, mark: Option<(&String, Instant)>) -> Duration {
        let Some((id, until)) = mark else {
            return Duration::ZERO;
        };
        match self.last.as_ref().map(|last| &last.mode) {
            Some(Mode::DirectVpn { profile }) if profile.id == *id => {
                until.saturating_duration_since(Instant::now())
            }
            _ => Duration::ZERO,
        }
    }

    /// The user's «Подключить» in the paused state: dials at once, unless the server must stay
    /// quiet (its freeze window, or an attempt less than `Timings::retry_spacing` ago). Then it
    /// runs as soon as it may and the paused state's countdown says when (fix-ks a4).
    pub(super) async fn retry_asked(&mut self) {
        let gap = self.deps.timings.retry_spacing;
        let spacing = self.tried.as_ref().map(|(id, at)| (id, *at + gap));
        let wait = self.quiet_left().max(self.left_for_last(spacing));
        if wait.is_zero() {
            return self.retry(true).await;
        }
        let at = Instant::now() + wait;
        tracing::info!(?wait, "the server must stay quiet: the asked retry waits");
        self.asked = true;
        if self.restart_due.is_none_or(|due| due > at) {
            self.restart_due = Some(at);
            self.emit(TunnelEvent::RestartScheduled { delay: wait });
        }
    }

    /// The backoff elapsed (or a deferred «Подключить» is due): restart the last start through
    /// the normal start path.
    pub(super) async fn recover(&mut self) {
        let asked = std::mem::take(&mut self.asked);
        self.retry(asked).await;
    }

    /// Restarts the last start (origin `Recovery`); `asked` = the user's «Подключить» in the
    /// paused state, which runs whatever the auto-restart setting says.
    pub(super) async fn retry(&mut self, asked: bool) {
        self.restart_due = None;
        let Some(last) = self.last.clone() else {
            return self.terminal(true).await;
        };
        let auto_restart = asked
            || self
                .deps
                .inputs
                .snapshot()
                .await
                .is_ok_and(|u| u.auto_restart_on_crash);
        if !auto_restart {
            // Turned off during the backoff (re-read at fire time): the terminal table decides.
            return self.after_crash().await;
        }
        if let Mode::DirectVpn { profile } = &last.mode {
            self.tried = Some((profile.id.clone(), Instant::now()));
        }
        let req = StartRequest {
            origin: Origin::Recovery,
            ..last
        };
        let op = CancellationToken::new();
        self.guard_op(&op);
        if self.stop_pending() {
            // A stop requested meanwhile ends the session: no restart (§7.20).
            return self.clear_op();
        }
        let result = self.start_run(req, &op, &[]).await;
        self.clear_op();
        if let Err(e) = result
            && !op.is_cancelled()
            && matches!(self.phase, Phase::Adapting(_) | Phase::Idle)
        {
            // The attempt is consumed; the policy runs again as if the core had exited again.
            tracing::warn!(error = %e, attempt = self.attempt, "recovery start failed");
            self.after_crash().await;
        }
    }
}

impl Actor {
    /// Terminal outcome: Xray stops (the old code left it running); `release` = the protection
    /// goes too (`Stopped`), else it keeps blocking with no tunnel (`KillSwitchActive`; only a
    /// start or a full stop leaves that state).
    async fn terminal(&mut self, release: bool) {
        self.restart_due = None;
        let (plan, slots) = match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Crashed(c) => (Some(c.plan), c.slots),
            Phase::Adapting(plan) => (Some(plan), None),
            other => {
                self.phase = other;
                return;
            }
        };
        if let Some(mut s) = slots
            && let Err(e) = s.slots.stop_all().await
        {
            tracing::error!(error = %e, "Xray of the crashed run did not stop");
            let warning = Msg::new("tunnel.runtime.cleanup.xray");
            self.phase = Phase::Faulted(Box::new(Retained {
                core: None,
                slots: Some(s),
                plan,
            }));
            self.publish(|st| st.warning = Some(warning.clone()));
            return self.announce(TunStatusKind::Error { warning });
        }
        if !release && let Some(plan) = plan {
            self.phase = Phase::Adapting(plan);
            return self.announce(TunStatusKind::KillSwitchActive);
        }
        let released = self.capture.release().await;
        self.protection_dirty = released.is_err();
        if let Err(e) = released {
            tracing::error!(error = %e, "protection not released after the crash");
            let warning = Msg::new("tunnel.runtime.cleanup.protection");
            self.publish(|st| st.warning = Some(warning.clone()));
            return self.announce(TunStatusKind::Error { warning });
        }
        self.announce(TunStatusKind::Stopped);
    }

    /// Failover after a crash the server cannot come back from (restart budget spent, or its
    /// freeze window): live siblings in the policy's order; the first that starts becomes the
    /// active server and is announced once, by name, only after it started (`FailedOver` with
    /// `cause` for the session, `PostTrialFailover` in the status). `true` = a sibling runs.
    async fn failover(&mut self, cause: FailoverCause) -> bool {
        let (Some(policy), Some(last)) = (self.deps.failover.clone(), self.last.clone()) else {
            return false;
        };
        let op = CancellationToken::new();
        self.guard_op(&op);
        if self.stop_pending() {
            op.cancel();
        }
        let mut started = false;
        for _ in 0..FAILOVER_TRIES {
            if op.is_cancelled() {
                break;
            }
            let Some(profile) = policy.next_live_sibling(&op).await else {
                break;
            };
            if op.is_cancelled() {
                break;
            }
            let (id, name) = (profile.id.clone(), profile.profile.name.clone());
            let req = StartRequest {
                mode: Mode::DirectVpn { profile },
                origin: Origin::Recovery,
                ..last.clone()
            };
            self.failing_over = Some((id.clone(), cause));
            match self.start_run(req, &op, &[]).await {
                Ok(_) => {
                    policy.commit(&id);
                    self.announce(TunStatusKind::PostTrialFailover { name });
                    started = true;
                    break;
                }
                Err(e) => tracing::warn!(error = %e, "failover candidate did not start"),
            }
            if !matches!(self.phase, Phase::Adapting(_) | Phase::Idle) {
                break;
            }
        }
        // A start refused before it began never reached its finish.
        self.failing_over = None;
        self.clear_op();
        started || op.is_cancelled()
    }

    /// An Xray slot exited. The active one: upstream down at once, then restarts with backoff
    /// (same port and credentials, sing-box untouched); exhausted = a crash of the session.
    pub(super) async fn on_xray(&mut self, event: XrayEvent) {
        let XrayEvent::Exited {
            slot,
            expected,
            code,
            ..
        } = event;
        let Phase::Running(s) = &mut self.phase else {
            return;
        };
        let Some(slots) = s.slots.as_mut() else {
            return;
        };
        if expected || slot != slots.active {
            tracing::info!(?slot, ?code, expected, "Xray slot exited");
            return;
        }
        tracing::error!(?slot, ?code, "active Xray slot exited");
        slots.restarts.retain(|t| t.elapsed() < SLOT_WINDOW);
        let tries = slots.restarts.len();
        let reason = super::watchdog::held(
            s.req.capture,
            "tunnel.runtime.watchdog.slotExited",
            "tunnel.runtime.watchdog.proxyMode.slotExited",
        );
        self.proxy_down(reason);
        match SLOT_BACKOFF.get(tries) {
            Some(delay) => self.slot_due = Some(Instant::now() + *delay),
            None => self.end_as_crash().await,
        }
    }

    /// The backoff of the active slot elapsed.
    pub(super) async fn restart_slot(&mut self) {
        self.slot_due = None;
        let Phase::Running(s) = &mut self.phase else {
            return;
        };
        let Some(slots) = s.slots.as_mut() else {
            return;
        };
        let active = slots.active;
        slots.restarts.push(Instant::now());
        let tries = slots.restarts.len();
        // A stop pre-empts the restart instead of waiting for the slot's readiness.
        let op = CancellationToken::new();
        *self.shared.op.lock() = Some(op.clone());
        let restarted = slots.slots.restart(active, &op).await;
        self.clear_op();
        match restarted {
            Ok(()) => {
                tracing::info!(slot = ?active, "active Xray slot restarted");
                self.proxy_up();
            }
            // A stop is queued: it ends the session.
            Err(_) if op.is_cancelled() => {}
            Err(e) => {
                tracing::warn!(error = %e, "Xray slot restart failed");
                match SLOT_BACKOFF.get(tries) {
                    Some(delay) => self.slot_due = Some(Instant::now() + *delay),
                    None => self.end_as_crash().await,
                }
            }
        }
    }

    /// The upstream or the capture cannot be kept alive: end the core and treat it as a crash.
    pub(super) async fn end_as_crash(&mut self) {
        let Phase::Running(session) = std::mem::replace(&mut self.phase, Phase::Idle) else {
            return;
        };
        self.exit = None;
        if let Err(e) = session.core.terminate(self.deps.timings.exit).await {
            tracing::error!(error = %e, "sing-box exit not proven after the upstream died");
            let Session {
                core, slots, plan, ..
            } = *session;
            let retained = Retained {
                core: Some(core),
                slots,
                plan: Some(plan),
            };
            let _ = self.retain(
                retained,
                vpnte_base::AppError::new(vpnte_base::ErrorKind::Internal),
                Vec::new(),
                "tunnel.runtime.cleanup.exitUnproven",
            );
            return;
        }
        self.crashed(session).await;
    }

    /// The upstream stopped answering: traffic stays inside the tunnel (fail closed), the
    /// status says so. Announced on the transition only.
    pub(super) fn proxy_down(&mut self, reason: Msg) {
        if !matches!(self.phase, Phase::Running(_)) || !self.status_now().proxy_reachable {
            return;
        }
        self.publish(|st| {
            st.proxy_reachable = false;
            st.warning = Some(reason.clone());
        });
        self.announce(TunStatusKind::ProxyDown { reason });
    }

    /// The upstream answers again.
    pub(super) fn proxy_up(&mut self) {
        if !matches!(self.phase, Phase::Running(_)) || self.status_now().proxy_reachable {
            return;
        }
        self.publish(|st| {
            st.proxy_reachable = true;
            st.warning = None;
        });
        self.announce(TunStatusKind::Running);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;
    use vpnte_base::types::EnginePref;

    use crate::api::{Runtime, TunStatusKind, TunnelEvent};
    use crate::runtime::TunnelHandle;
    use crate::runtime::tests::{NATIVE_KEY, World, deps, drain, until, vpn_req};

    /// The crash restart's wait follows `Restarting` as its own event: the freeze window of a
    /// faulted server here (the fake core reports a fault), not the short backoff. A Soft
    /// session with the kill switch off acts on it (NOADMIN §2).
    #[tokio::test]
    async fn the_restart_wait_is_announced() {
        let w = World::new();
        let mut d = deps(&w);
        d.timings.freeze = Duration::from_millis(700);
        let h = TunnelHandle::spawn(d);
        let mut events = h.subscribe();
        let req = vpn_req(NATIVE_KEY, EnginePref::Auto);
        h.start(req, CancellationToken::new()).await.unwrap();
        drain(&mut events);
        w.core(0).crash();
        let seen = until(&mut events, |e| {
            matches!(e, TunnelEvent::RestartScheduled { .. })
        })
        .await;
        let restarting = TunnelEvent::Status(TunStatusKind::Restarting { attempt: 1, max: 3 });
        let at = seen.iter().position(|e| *e == restarting);
        assert_eq!(at, Some(seen.len() - 2), "{seen:?}");
        let Some(TunnelEvent::RestartScheduled { delay }) = seen.last() else {
            unreachable!("until() ends on the event");
        };
        assert!(
            *delay > Duration::from_millis(500) && *delay <= Duration::from_millis(700),
            "{delay:?}"
        );
    }
}
