//! The stop lane, stop completion, `cancel_pending`, maintenance and shutdown.
use super::*;

/// A failed stop, reproducible for every waiter.
pub(super) struct StopError {
    kind: ErrorKind,
    msg: &'static str,
    warnings: Vec<Msg>,
}

impl StopError {
    pub(super) fn conn(&self) -> ConnError {
        let error = TunError {
            error: vpnte_base::AppError::msg(self.kind, Msg::new(self.msg)),
            warnings: self.warnings.clone(),
        };
        ConnError::Failed(error)
    }
}

/// The stop lane (old `connectionLifecycle.stop` + `stopProtectionEffects`).
impl Actor {
    pub(super) fn admit_stop(&mut self, req: DisconnectReq, reply: Reply) {
        if let Some(stop) = self.stop.as_mut() {
            // A full stop never ends as a kept block: before the effect it turns the stop into
            // a full one, after that it runs right behind it.
            if stop.keep && !req.keep_protection {
                if stop.running {
                    stop.release.push((req, reply));
                    return;
                }
                stop.keep = false;
            }
            // Coalesce before any priority check: every later stop joins the running one.
            stop.waiters.push(reply);
            return;
        }
        if self.maintenance {
            return refuse(reply, key::MAINTENANCE_BUSY);
        }
        if self.start.as_ref().is_some_and(|s| req.owner < s.op.owner) {
            return refuse(reply, key::HIGHER_PRIORITY);
        }
        let keep = req.keep_protection && self.guard.pauses();
        let head = Head::new(req.owner, req.source, req.correlation, req.timeout);
        self.begin_stop_as(req.cause, head, vec![reply], keep);
    }

    /// A full stop: publishes it (reserving the lane), cancels a running start and runs the
    /// effect once that start drained. The caller's deadline never interrupts the rollback.
    pub(super) fn begin_stop(&mut self, cause: StopCause, head: Head, waiters: Vec<Reply>) {
        self.begin_stop_as(cause, head, waiters, false);
    }

    /// [`Actor::begin_stop`]; `keep` = the kill switch keeps blocking after it.
    fn begin_stop_as(&mut self, cause: StopCause, head: Head, waiters: Vec<Reply>, keep: bool) {
        if let Some(stop) = self.stop.as_mut() {
            // One stop at a time: a second one joins it.
            stop.waiters.extend(waiters);
            return;
        }
        let op = op_meta(OpKind::Disconnect, &head);
        self.publish(&op);
        if let Some(start) = self.start.as_mut().filter(|s| s.aborted.is_none()) {
            start.aborted = Some(ErrorKind::Cancelled);
            start.terminal_published = true;
            start.token.cancel();
            reply(
                start.reply.take(),
                Err(abort_error(ErrorKind::Cancelled, true)),
            );
            // Published after the stop: the state machine rejects it as stale (harmless).
            let record = terminal(&start.op, Some(ErrorKind::Cancelled));
            self.publish(&record);
        }
        let timer = CancellationToken::new();
        let (tx, id, timeout, done) = (self.tx.clone(), op.id, head.timeout, timer.clone());
        tokio::spawn(async move {
            tokio::select! {
                () = done.cancelled() => {}
                () = tokio::time::sleep(timeout) => {
                    let _ = tx.send(Cmd::StopTimeout { op: id });
                }
            }
        });
        self.stop = Some(Stop {
            op,
            cause,
            waiters,
            running: false,
            terminal_published: false,
            captured: Captured::default(),
            timer,
            shutdown: None,
            then: Vec::new(),
            keep,
            release: Vec::new(),
        });
        if self.start.is_none() {
            self.run_stop_effect();
        }
    }

    pub(super) fn run_stop_effect(&mut self) {
        let Some(stop) = self.stop.as_mut().filter(|s| !s.running) else {
            return;
        };
        stop.running = true;
        stop.captured = Captured::now(&self.deps);
        let quitting = stop.cause == StopCause::AppQuit;
        let keep = match self.session.as_ref().map(LiveSession::is_soft) {
            _ if !stop.keep => Keep::Nothing,
            Some(true) => Keep::Tweaks,
            Some(false) => Keep::Block,
            None => Keep::Nothing,
        };
        let (deps, tx, id) = (self.deps.clone(), self.tx.clone(), stop.op.id);
        supervise(
            &self.tx,
            effects::stop(deps, quitting, keep),
            StopReport::panicked,
            move |report| {
                let _ = tx.send(Cmd::StopDone {
                    op: id,
                    report: Box::new(report),
                });
            },
        );
    }

    /// The deadline passed: callers get `Timeout`, the rollback keeps running and the lane
    /// stays reserved until it ends.
    pub(super) fn stop_timeout(&mut self, op: OpId) {
        let Some(stop) = self
            .stop
            .as_mut()
            .filter(|s| s.op.id == op && !s.terminal_published)
        else {
            return;
        };
        stop.terminal_published = true;
        for waiter in stop.waiters.drain(..) {
            let _ = waiter.send(Err(abort_error(ErrorKind::Timeout, false)));
        }
        let record = terminal(&stop.op, Some(ErrorKind::Timeout));
        self.publish(&record);
    }
}

/// Stop completion, cancel, maintenance, shutdown.
impl Actor {
    pub(super) async fn stop_done(&mut self, op: OpId, report: StopReport) {
        let Some(stop) = self.stop.take_if(|s| s.op.id == op) else {
            return;
        };
        stop.timer.cancel();
        // The stop ended whatever the runtime ran, a failover's sibling included.
        self.failover = None;
        let holder = self.session.as_ref().map(|s| s.holder);
        let error = self.settle_stop(&stop, &report).await;
        if !stop.terminal_published {
            self.publish(&terminal(&stop.op, error.as_ref().map(|e| e.kind)));
        }
        if report.kept != Keep::Nothing && error.is_none() && stop.release.is_empty() {
            self.kept_blocked(report.kept);
            // Whoever ends this holder's run must be able to release the block.
            self.kept_by.send_replace(holder);
        }
        match (&error, stop.cause) {
            (None, StopCause::User) => {
                self.notify(Level::Info, "disconnected", NoticeKind::VpnDisconnect, None);
            }
            (Some(e), _) => {
                let body = Some(Msg::new(e.msg));
                self.notify(Level::Error, "stopFailed", NoticeKind::VpnDisconnect, body);
            }
            (None, _) => {}
        }
        for waiter in stop.waiters {
            let result = match &error {
                None => Ok(Done {
                    warnings: report.receipt.warnings.clone(),
                }),
                Some(e) => Err(e.conn()),
            };
            let _ = waiter.send(result);
        }
        if let Some(to) = stop.shutdown {
            let _ = to.send(ShutdownReport {
                engines_stopped: report.runtime_gone(),
                soft_restored: matches!(report.soft, Some(Ok(()))),
                capture_stopped: report.capture_stopped,
                timed_out: false,
            });
        }
        for cmd in stop.then {
            if error.is_none() {
                self.admit_start(cmd);
            } else {
                refuse(cmd.reply, key::PREEMPT_FAILED);
            }
        }
        for (req, reply) in stop.release {
            self.admit_stop(req, reply);
        }
        self.after_drain();
    }

    /// The stop kept the kill switch's block: nothing runs, and the state says it blocks.
    fn kept_blocked(&mut self, kept: Keep) {
        let e = self.evidence();
        self.fsm.fault(FaultState::Blocked, e);
        let name = if kept == Keep::Tweaks {
            "keptSoftBlocked"
        } else {
            "keptBlocked"
        };
        self.notify(Level::Warn, name, NoticeKind::ConnectionError, None);
    }

    /// Closes the sessions the stop ended and checks the result. A runtime whose exit is not
    /// proven keeps everything (protection retained, session open); a Soft session closes only
    /// once the user's proxy settings are back.
    pub(super) async fn settle_stop(
        &mut self,
        stop: &Stop,
        report: &StopReport,
    ) -> Option<StopError> {
        let warnings = report.receipt.warnings.clone();
        if !report.runtime_gone() {
            return Some(StopError {
                kind: ErrorKind::Internal,
                msg: key::CLEANUP_UNCONFIRMED,
                warnings,
            });
        }
        let soft_session = self.session.as_ref().is_some_and(LiveSession::is_soft);
        if !soft_session {
            self.close_for_stop(stop.cause, &stop.captured).await;
        }
        if let Some(Err(e)) = &report.soft {
            tracing::warn!(error = %e, "soft proxy rollback failed during stop");
            return Some(StopError {
                kind: e.kind,
                msg: key::SOFT_ENV_ROLLBACK_FAILED,
                warnings,
            });
        }
        if soft_session {
            self.close_for_stop(stop.cause, &stop.captured).await;
        }
        if report.kept != Keep::Nothing {
            // The block stays on purpose: not a clean state, and not a failed cleanup.
            return None;
        }
        let e = self.evidence();
        (!self.fsm.can_confirm_stop(e)).then_some(StopError {
            kind: ErrorKind::Internal,
            msg: key::CLEANUP_UNCONFIRMED,
            warnings,
        })
    }

    /// Ends the session with the stop's cause (L-05: compensations carry their real cause).
    pub(super) async fn close_for_stop(&mut self, cause: StopCause, captured: &Captured) {
        let Some(live) = self.session.as_ref() else {
            return;
        };
        let evidence = outcome::Evidence {
            leak_detected_during_session: Some(live.leak_detected),
            ..live.egress(captured.egress_ip.clone())
        };
        let headline = |k: &'static str| Msg::new(k);
        let outcome = match cause {
            StopCause::User => SessionOutcome::new(OutcomeKind::UserStop, evidence),
            StopCause::AppQuit => SessionOutcome::new(OutcomeKind::AppQuit, evidence),
            StopCause::Schedule => SessionOutcome::new(OutcomeKind::Schedule, evidence),
            StopCause::Timeout => unknown(evidence, headline(key::OUTCOME_TIMEOUT)),
            StopCause::Cancelled => unknown(evidence, headline(key::OUTCOME_CANCELLED)),
            StopCause::Preempted => unknown(evidence, headline(key::OUTCOME_PREEMPTED)),
            StopCause::Failed => unknown(evidence, headline(key::OUTCOME_FAILED)),
        };
        self.end_session(outcome, captured.bytes, false).await;
    }

    /// The lane changed: run a stop that waited for a drain, then a parked shutdown.
    pub(super) fn after_drain(&mut self) {
        if self.start.is_none() && self.stop.as_ref().is_some_and(|s| !s.running) {
            self.run_stop_effect();
        }
        if self.start.is_none()
            && self.stop.is_none()
            && !self.maintenance
            && let Some(to) = self.shutdown.take()
        {
            self.begin_shutdown_stop(to);
        }
    }
}

pub(super) fn unknown(evidence: outcome::Evidence, headline: Msg) -> SessionOutcome {
    SessionOutcome::with_headline(OutcomeKind::Unknown, evidence, headline)
}

impl Actor {
    /// "Cancel": stops a start in flight (unless a higher owner runs it) or a native reconnect.
    /// Nothing in flight → nothing happens (H-04).
    pub(super) fn cancel_pending(&mut self) {
        if self.stop.is_some() || self.maintenance {
            return;
        }
        let cause = match &self.start {
            Some(start) if start.aborted.is_none() && start.op.owner <= Owner::Manual => {
                StopCause::Cancelled
            }
            Some(_) => return,
            // Cancelling a native reconnect stops a session the user had: a user stop.
            None if self.fsm.snapshot().transition == Some(Transition::Reconnecting) => {
                StopCause::User
            }
            None => return,
        };
        let head = Head::new(Owner::Manual, Source::Ui, None, DEFAULT_TIMEOUT);
        self.begin_stop(cause, head, Vec::new());
    }

    /// Admits a maintenance action only on an idle lane outside "connected" (A-05).
    pub(super) fn admit_maintenance(
        &mut self,
        job: MaintenanceJob,
        admit: oneshot::Sender<Result<(), ConnError>>,
    ) {
        let snap = self.fsm.snapshot();
        let refusal = if self.closed || self.stop.is_some() {
            Some(key::STOP_IN_PROGRESS)
        } else if self.start.is_some() {
            Some(key::START_IN_PROGRESS)
        } else if self.maintenance {
            Some(key::MAINTENANCE_BUSY)
        } else if snap.transition.is_some() || snap.state == TunnelState::Connected {
            Some(key::MAINTENANCE_REFUSED)
        } else {
            None
        };
        if let Some(msg) = refusal {
            let _ = admit.send(Err(ConnError::Refused(Msg::new(msg))));
            return;
        }
        if admit.send(Ok(())).is_err() {
            return; // the caller is gone: do not run it
        }
        self.maintenance = true;
        let tx = self.tx.clone();
        supervise(
            &self.tx,
            job(),
            || (),
            move |()| {
                let _ = tx.send(Cmd::MaintenanceDone);
            },
        );
    }

    /// Closes admission for good, then (after a stop or maintenance in flight) stops as
    /// `app-quit`; a start in flight is cancelled and drained first.
    pub(super) fn begin_shutdown(&mut self, to: oneshot::Sender<ShutdownReport>) {
        self.closed = true;
        if self.stop.is_some() || self.maintenance {
            self.shutdown = Some(to);
        } else {
            self.begin_shutdown_stop(to);
        }
    }

    pub(super) fn begin_shutdown_stop(&mut self, to: oneshot::Sender<ShutdownReport>) {
        let head = Head::new(Owner::Recovery, Source::Lifecycle, None, DEFAULT_TIMEOUT);
        self.begin_stop(StopCause::AppQuit, head, Vec::new());
        if let Some(stop) = self.stop.as_mut() {
            stop.shutdown = Some(to);
        }
    }

    /// After a refused quit: admission again, only when drained and nothing of ours is left
    /// running or applied (A-06).
    pub(super) fn reopen(&mut self) -> bool {
        let idle = self.start.is_none()
            && self.stop.is_none()
            && !self.maintenance
            && self.shutdown.is_none();
        if self.closed && idle && self.fsm.can_confirm_stop(self.evidence()) {
            self.closed = false;
        }
        !self.closed
    }
}
