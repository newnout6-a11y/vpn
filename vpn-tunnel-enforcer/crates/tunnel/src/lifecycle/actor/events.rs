//! Runtime events and statuses: native reconnects, unexpected ends, lag resync.
use super::*;
use crate::api::FailoverCause;
use crate::history::SessionMode;

/// The longest crash-restart wait a Soft session with the kill switch `off` keeps its tweaks on
/// the dead port: the plain backoff (2 / 5 / 10 s, recorded deviation noadmin-tunnel 8). A frozen
/// server's quiet window (`Timings::freeze`, 130 s) is far longer.
const SOFT_HOLD_MAX: Duration = Duration::from_secs(10);

/// A crash failover's sibling run, named by the runtime right before its finish.
pub(super) struct Failover {
    generation: u64,
    profile_id: String,
    cause: FailoverCause,
    /// Its start finished while a lane operation owned the session: applied at its end.
    started: bool,
}

/// Runtime events (old `index.ts` fan-out, lifecycle-app §3.8, §3.12b, §6.4).
impl Actor {
    pub(super) async fn on_runtime(&mut self, event: TunnelEvent) {
        let e = self.evidence();
        match event {
            TunnelEvent::StartBegan { generation } => {
                let _ = self.fsm.native_start_began(generation);
                if self.lane_idle() {
                    // A recovery attempt runs now: no countdown in the paused state.
                    self.pause_next(None);
                }
            }
            TunnelEvent::StartFinished { generation, ok } => {
                if ok {
                    // Before the state machine judges the run: Soft needs the tweaks back too.
                    self.resume_soft().await;
                }
                let e = self.evidence();
                let accepted = self.fsm.native_start_finished(generation, ok, e).is_ok();
                let connected = self.fsm.snapshot().state == TunnelState::Connected;
                match self.failover.take_if(|f| f.generation == generation) {
                    // The sibling runs whatever the state machine concluded: the session names
                    // it now, or once the operation that owns the session ended.
                    Some(f) if ok && self.lane_idle() => self.failed_over(f).await,
                    Some(f) if ok => self.failover = Some(Failover { started: true, ..f }),
                    Some(_) => {}
                    None if accepted && connected => self.native_reconnected(generation),
                    None => {}
                }
            }
            TunnelEvent::FailedOver {
                generation,
                profile_id,
                cause,
            } => {
                // A fresh run of its own: its finish may confirm even after failed restarts.
                let _ = self.fsm.native_failover(generation, e);
                self.failover = Some(Failover {
                    generation,
                    profile_id,
                    cause,
                    started: false,
                });
            }
            TunnelEvent::StopFinished {
                generation,
                preserved,
                receipt,
            } => {
                let _ = self
                    .fsm
                    .native_stop_finished(generation, preserved, &receipt, e);
            }
            TunnelEvent::SwitchBegan { generation } => {
                let _ = self.fsm.upstream_began(generation, e);
            }
            TunnelEvent::SwitchFinished {
                generation,
                verified,
            } => {
                let _ = self.fsm.upstream_finished(generation, verified, e);
            }
            TunnelEvent::ProtectedRestart { reason } => {
                // Inside a lane operation its own ending decides about the session.
                if let Some(kind) = outcome::node_switch_kind(&reason)
                    && self.lane_idle()
                    && self.session.is_some()
                {
                    let ending = Captured::now(&self.deps);
                    // A restart outside the lane: the `Up` of its run is what comes next.
                    self.close_current(kind, None, ending, true).await;
                }
            }
            TunnelEvent::Status(kind) => self.on_status(kind, e).await,
            TunnelEvent::Warning(warning) => {
                tracing::info!(warning = %warning.msg().key, "runtime warning");
            }
            TunnelEvent::RestartScheduled { delay } => {
                self.pause_soft(delay).await;
                let wait = UnixMs::try_from(delay.as_millis()).unwrap_or(UnixMs::MAX);
                self.pause_next(Some(now_ms().saturating_add(wait)));
            }
        }
    }

    /// Soft with a kill switch that does not hold (NOADMIN §2): the tweaks may stay on the dead
    /// port only for a short backoff; a longer wait (a frozen server's quiet window) rolls them
    /// back now, so programs connect directly meanwhile, and the next run brings them back
    /// ([`Actor::resume_soft`]). A holding kill switch keeps them: that is its pause. The
    /// outage's one notice tells the user.
    async fn pause_soft(&mut self, delay: Duration) {
        let paused = self.session.as_ref().is_none_or(|s| s.soft_paused);
        if delay <= SOFT_HOLD_MAX
            || paused
            || !self.lane_idle()
            || !self.soft_session()
            || self.guard.pauses()
        {
            return;
        }
        match self.deps.soft.rollback().await {
            Ok(()) => {
                if let Some(live) = self.session.as_mut() {
                    live.soft_paused = true;
                }
            }
            Err(e) => tracing::warn!(error = %e, "soft rollback before a long restart wait failed"),
        }
    }

    /// The run is back after [`Actor::pause_soft`]: the tweaks point at its mixed port again and
    /// are read back. A failure rolls back what was applied (nothing half-set), so the state
    /// machine sees an engine without its proxy and does not call it connected.
    pub(super) async fn resume_soft(&mut self) {
        if !self.session.as_ref().is_some_and(|s| s.soft_paused) {
            return;
        }
        let resumed = match effects::session_port(&self.deps) {
            Some(port) => effects::apply_and_read_back(&self.deps, &effects::soft_addr(port)).await,
            None => Err(vpnte_base::AppError::new(ErrorKind::Internal)),
        };
        if let Err(e) = resumed {
            tracing::warn!(error = %e, "soft tweaks not re-applied after the restart");
            if let Err(e) = self.deps.soft.rollback().await {
                tracing::warn!(error = %e, "soft rollback after a failed re-apply failed");
            }
            self.notify(
                Level::Error,
                "softResumeFailed",
                NoticeKind::ConnectionError,
                None,
            );
            return;
        }
        if let Some(live) = self.session.as_mut() {
            live.soft_paused = false;
        }
    }

    pub(super) fn lane_idle(&self) -> bool {
        self.start.is_none() && self.stop.is_none()
    }

    pub(super) async fn on_status(&mut self, kind: TunStatusKind, e: Option<Evidence>) {
        if let Some(live) = self.session.as_mut() {
            match kind {
                TunStatusKind::ProxyDown { .. } => live.proxy_down = true,
                TunStatusKind::Running => live.proxy_down = false,
                _ => {}
            }
        }
        self.last_kind = Some(kind.clone());
        let lost = matches!(
            kind,
            TunStatusKind::Restarting { .. } | TunStatusKind::KillSwitchActive
        );
        if lost && self.session.is_some() && self.lane_idle() {
            if self.paused.is_none() {
                // Pause or not is decided by the kill switch as it is now: the level may have
                // changed, and the other VPN of a proxy session may be gone (fix-ks b1).
                self.refresh_guard().await;
            }
            // The session stays open while the runtime recovers it. The runtime holding the
            // block is the authority on a pause, whatever this session's guard says.
            let held = self.guard.pauses() || kind == TunStatusKind::KillSwitchActive;
            if !held {
                let _ = self.fsm.runtime(&kind, e);
            }
            let blocked = kind == TunStatusKind::KillSwitchActive;
            return self.enter_outage(e, held, blocked);
        }
        let _ = self.fsm.runtime(&kind, e);
        if !self.lane_idle() {
            return; // the operation in flight owns the session and the user's attention
        }
        // A held block (`KillSwitchActive`) with a session is a pause (above); without one there
        // is nothing to end. What is left: the runtime let the session go.
        match kind {
            TunStatusKind::Stopped if self.soft_session() => self.soft_engine_lost().await,
            TunStatusKind::Stopped if self.session.is_some() => self.unexpected_end(true).await,
            // `PostTrialFailover` is no notice of its own: the user hears of a failover only
            // once the session follows the sibling ([`Actor::failed_over`]).
            TunStatusKind::Error { warning } => {
                // A crash whose cleanup failed: the engine is gone and the session with it.
                if !self.runtime_running() && self.soft_session() {
                    self.soft_engine_lost().await;
                } else if !self.runtime_running() && self.session.is_some() {
                    self.unexpected_end(true).await;
                }
                let kind = NoticeKind::ConnectionError;
                self.notify(Level::Error, "restartFailed", kind, Some(warning));
            }
            _ => {}
        }
    }

    fn soft_session(&self) -> bool {
        self.session.as_ref().is_some_and(LiveSession::is_soft)
    }

    /// A failover that finished while a lane operation owned the session: at the operation's
    /// end, before its own ending, the session follows the sibling (a restart of the runtime's
    /// last run then restarts the sibling, not the crashed server). A stop waiting to run ends
    /// the session anyway: nothing to follow.
    pub(super) async fn follow_failover(&mut self) {
        let Some(f) = self.failover.take_if(|f| f.started) else {
            return;
        };
        if self.stop.is_none() {
            self.failed_over(f).await;
        }
    }

    /// The runtime replaced a crashed server with a sibling: the session goes on over the
    /// sibling, with a row for the crashed server and an `Up` for the new one, so everything
    /// downstream (automation, the next failover round, the handshake budget) names the server
    /// that actually runs. Holder, capture and adaptive mode stay. The notice says only what
    /// the runtime saw ([`FailoverCause`]).
    async fn failed_over(&mut self, f: Failover) {
        let Failover {
            generation,
            profile_id: id,
            cause,
            ..
        } = f;
        let holder = self.session.as_ref().map_or(Owner::Recovery, |s| s.holder);
        let adaptive = self.session.as_ref().map(|s| s.adaptive);
        let from = self.session.as_ref().map(|s| s.profile.name.clone());
        let soft = self.status.borrow().capture == Some(CaptureKind::Proxy);
        let choice = self.deps.profiles.resolve(Some(&id));
        let profile = match &choice {
            Some(c) if soft => SessionProfile::soft_server(&c.server),
            Some(c) => SessionProfile::direct(&c.server),
            // Gone from the list meanwhile: the id still names the run.
            None => SessionProfile {
                id: id.clone(),
                name: self
                    .status
                    .borrow()
                    .profile_name
                    .clone()
                    .unwrap_or_default(),
                mode: if soft {
                    SessionMode::Soft
                } else {
                    SessionMode::Direct
                },
            },
        };
        let headline = match cause {
            FailoverCause::ServerFault => key::OUTCOME_FAILOVER,
            FailoverCause::RestartsSpent => key::OUTCOME_FAILOVER_RESTARTS,
        };
        let ending = Captured::now(&self.deps);
        self.close_current(
            OutcomeKind::ServerSwitch,
            Some(Msg::new(headline)),
            ending,
            true,
        )
        .await;
        self.deps
            .forensics
            .start_session(profile.mode, &profile.name);
        let name = profile.name.clone();
        let mut live = LiveSession::open(profile, None, holder);
        live.country = choice.and_then(|c| c.country);
        live.generation = Some(generation);
        live.engine = self.status.borrow().engine;
        live.adaptive = adaptive.unwrap_or(live.adaptive);
        self.session = Some(live);
        self.deps.monitor.start(Some(generation));
        // The sibling carries the session: the outage is over (the failover notice says so).
        self.end_pause();
        // "Switched to", not "connected": the state machine confirms the run on its own.
        let body = match (from, cause) {
            (Some(from), FailoverCause::ServerFault) => {
                Msg::new(notice_key("failover", "body")).arg("from", from)
            }
            (Some(from), FailoverCause::RestartsSpent) => {
                Msg::new(notice_key("failover", "bodyRestarts")).arg("from", from)
            }
            // No session named the crashed server any more.
            (None, _) => Msg::new(notice_key("failover", "bodySwitched")),
        };
        let body = body.arg("name", name);
        self.notify(
            Level::Warn,
            "failover",
            NoticeKind::ProfileRotation,
            Some(body),
        );
        self.announce_up();
    }

    /// The engine of a Soft session is gone for good and the runtime let it go (its kill switch
    /// does not hold): the session ends and the tweaks are rolled back at once, so programs
    /// connect directly again, with one notice (NOADMIN.md §2).
    async fn soft_engine_lost(&mut self) {
        self.unexpected_end(false).await;
        match self.deps.soft.rollback().await {
            Ok(()) => {
                let kind = NoticeKind::ConnectionError;
                self.notify(Level::Warn, "softRestored", kind, None);
            }
            Err(e) => {
                tracing::warn!(error = %e, "soft rollback after the engine was lost failed");
                let body = Some(Msg::new(key::SOFT_ENV_ROLLBACK_FAILED));
                self.notify(Level::Error, "stopFailed", NoticeKind::VpnDisconnect, body);
            }
        }
        // The state follows what is left: nothing of ours (unknown, as after any lost run).
        let e = self.evidence();
        let _ = self.fsm.runtime(&TunStatusKind::Stopped, e);
    }

    /// The session ended without being asked to: classify it from what is known now
    /// (lifecycle-app §3.5), write its row, end forensics; `notify`: say so (a Soft session's
    /// own notice says it instead). Monitoring stays: a down TUN is exactly when a broken kill
    /// switch would leak.
    pub(super) async fn unexpected_end(&mut self, notify: bool) {
        let Some(live) = self.session.as_ref() else {
            return;
        };
        let status = self.status.borrow().clone();
        let engine_exit = self
            .deps
            .runtime
            .last_exit()
            .filter(|exit| exit.at >= live.started_at)
            .map(|exit| EngineExit {
                since: Duration::from_millis(
                    u64::try_from(now_ms().saturating_sub(exit.at)).unwrap_or(0),
                ),
                user_initiated: exit.user_initiated,
                code: exit.code.map(i64::from),
                stderr_tail: Some(exit.stderr_tail).filter(|t| !t.trim().is_empty()),
            });
        let signals = EndSignals {
            since_resume: self.last_resume.map(|t| t.elapsed()),
            since_network_change: self.last_network_change.map(|t| t.elapsed()),
            outbound_fault: self.deps.runtime.recent_fault(),
            // A held block is a pause: no session ends under it any more (ks-a).
            kill_switch_active: false,
            proxy_unreachable: live.proxy_down,
            warning: status.warning,
            restart_attempts: u32::from(status.restart_attempt),
            engine_exit,
        };
        let bytes = self.deps.forensics.session_bytes();
        let outcome = outcome::unexpected_end(&signals, live.facts(self.deps.monitor.egress_ip()));
        let headline = outcome.headline.clone();
        self.end_session(outcome, bytes, false).await;
        let forensics = self.deps.forensics.clone();
        tokio::spawn(async move {
            forensics.stop_session("status:stopped").await;
        });
        if notify {
            let kind = NoticeKind::VpnDisconnect;
            self.notify(Level::Warn, "stopped", kind, Some(headline));
        }
    }

    /// Events were lost: re-read the status and treat it as the latest one.
    pub(super) async fn resync(&mut self) {
        let e = self.evidence();
        if self.runtime_running() {
            self.on_status(TunStatusKind::Running, e).await;
        } else if self.fsm.snapshot().mode.is_some() {
            self.on_status(TunStatusKind::Stopped, e).await;
        }
    }
}
