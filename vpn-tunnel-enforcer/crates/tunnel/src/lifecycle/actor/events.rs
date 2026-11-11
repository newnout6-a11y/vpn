//! Runtime events and statuses: native reconnects, unexpected ends, lag resync.
use super::*;

/// Runtime events (old `index.ts` fan-out, lifecycle-app §3.8, §3.12b, §6.4).
impl Actor {
    pub(super) async fn on_runtime(&mut self, event: TunnelEvent) {
        let e = self.evidence();
        match event {
            TunnelEvent::StartBegan { generation } => {
                let _ = self.fsm.native_start_began(generation);
            }
            TunnelEvent::StartFinished { generation, ok } => {
                let accepted = self.fsm.native_start_finished(generation, ok, e).is_ok();
                if accepted && self.fsm.snapshot().state == TunnelState::Connected {
                    self.native_reconnected(generation);
                }
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
                    && self.tun_session()
                {
                    let ending = Captured::now(&self.deps);
                    self.close_current(kind, None, ending).await;
                }
            }
            TunnelEvent::Status(kind) => self.on_status(kind, e).await,
            TunnelEvent::Warning(warning) => {
                tracing::info!(warning = %warning.msg().key, "runtime warning");
            }
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
        let _ = self.fsm.runtime(&kind, e);
        if !self.lane_idle() {
            return; // the operation in flight owns the session and the user's attention
        }
        match kind {
            TunStatusKind::Stopped | TunStatusKind::KillSwitchActive => {
                if self.tun_session() {
                    let blocked = kind == TunStatusKind::KillSwitchActive;
                    self.unexpected_end(blocked).await;
                    if blocked {
                        self.notify(
                            Level::Warn,
                            "crashBlocked",
                            NoticeKind::ConnectionError,
                            None,
                        );
                    }
                }
            }
            TunStatusKind::Restarting { attempt, max } => {
                let body = Msg::new(notice_key("crashRestarting", "body"))
                    .arg("attempt", attempt)
                    .arg("max", max);
                let kind = NoticeKind::ConnectionError;
                self.notify(Level::Warn, "crashRestarting", kind, Some(body));
            }
            TunStatusKind::PostTrialFailover { name } => {
                let body = Msg::new(notice_key("failover", "body")).arg("name", name);
                let kind = NoticeKind::ProfileRotation;
                self.notify(Level::Warn, "failover", kind, Some(body));
            }
            TunStatusKind::Error { warning } => {
                // A crash whose cleanup failed: the engine is gone and the session with it.
                if !self.runtime_running() && self.tun_session() {
                    self.unexpected_end(false).await;
                }
                let kind = NoticeKind::ConnectionError;
                self.notify(Level::Error, "restartFailed", kind, Some(warning));
            }
            _ => {}
        }
    }

    fn tun_session(&self) -> bool {
        self.session.as_ref().is_some_and(|s| !s.is_soft())
    }

    /// The TUN session ended without being asked to: classify it from what is known now
    /// (lifecycle-app §3.5), write its row, end forensics. Monitoring stays: a down TUN is
    /// exactly when a broken kill switch would leak.
    pub(super) async fn unexpected_end(&mut self, kill_switch_active: bool) {
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
            kill_switch_active,
            proxy_unreachable: live.proxy_down,
            warning: status.warning,
            restart_attempts: u32::from(status.restart_attempt),
            engine_exit,
        };
        let bytes = self.deps.forensics.session_bytes();
        let outcome = outcome::unexpected_end(&signals, live.facts(self.deps.monitor.egress_ip()));
        let headline = outcome.headline.clone();
        self.end_session(outcome, bytes).await;
        let forensics = self.deps.forensics.clone();
        tokio::spawn(async move {
            forensics.stop_session("status:stopped").await;
        });
        self.notify(
            Level::Warn,
            "stopped",
            NoticeKind::VpnDisconnect,
            Some(headline),
        );
    }

    /// Events were lost: re-read the status and treat it as the latest one.
    pub(super) async fn resync(&mut self) {
        let e = self.evidence();
        if self.runtime_running() {
            self.on_status(TunStatusKind::Running, e).await;
        } else if self.fsm.snapshot().mode == Some(TunnelMode::Tun) {
            self.on_status(TunStatusKind::Stopped, e).await;
        }
    }
}
