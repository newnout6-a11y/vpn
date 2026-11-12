//! Start-type operations: admission, effect supervision, abort handling, success and failure.
use super::*;

/// Lane admission of start-type operations (old `connectionLifecycle.start` / `rotate`).
impl Actor {
    pub(super) fn admit_start(&mut self, cmd: StartCmd) {
        if self.closed || self.stop.is_some() {
            return refuse(cmd.reply, key::STOP_IN_PROGRESS);
        }
        if self.maintenance {
            return refuse(cmd.reply, key::MAINTENANCE_BUSY);
        }
        // A caller already gone must not pre-empt anything.
        if cmd.token.is_cancelled() {
            let msg = Msg::new(key::START_CANCELLED);
            let _ = cmd.reply.send(Err(ConnError::Cancelled(msg)));
            return;
        }
        if let Some(start) = &self.start {
            if start.aborted.is_some() {
                return refuse(cmd.reply, key::CANCELLED_DRAINING);
            }
            if cmd.head.owner <= start.op.owner {
                return refuse(cmd.reply, key::START_IN_PROGRESS);
            }
            // A strictly higher owner pre-empts: the lower start is stopped (and compensated)
            // first; this one is admitted again once that stop succeeded.
            let head = Head {
                timeout: DEFAULT_TIMEOUT,
                ..cmd.head.clone()
            };
            self.begin_stop(StopCause::Preempted, head, Vec::new());
            if let Some(stop) = self.stop.as_mut() {
                stop.then.push(cmd);
            }
            return;
        }
        let allowed = match cmd.job {
            Job::Connect { .. } => self.fsm.can_start(),
            _ => self.fsm.can_rotate(),
        };
        if !allowed {
            return refuse(cmd.reply, key::STATE_REFUSES_START);
        }
        let op = op_meta(cmd.job.op_kind(), &cmd.head);
        self.publish(&op);
        let token = cmd.token.child_token();
        self.spawn_start_effect(&op, &cmd.job, token.clone());
        self.watch_start(op.id, cmd.head.timeout, cmd.token, token.clone());
        self.start = Some(Start {
            op,
            job: cmd.job,
            token,
            reply: Some(cmd.reply),
            aborted: None,
            terminal_published: false,
        });
    }

    pub(super) fn spawn_start_effect(&self, op: &OpMeta, job: &Job, token: CancellationToken) {
        let ctx = Ctx {
            deps: self.deps.clone(),
            token,
            confirm: effects::Confirmer {
                tx: self.tx.clone(),
                op: op.id,
            },
            owner: op.owner,
            guard: self.guard.clone(),
        };
        let adaptive = self
            .session
            .as_ref()
            .map_or(AdaptiveMode::Baseline, |s| s.adaptive);
        let job = job.clone();
        let fut = async move {
            match job {
                Job::Connect { target, adaptive } => {
                    let capture = if target.is_soft() {
                        CaptureKind::Proxy
                    } else {
                        CaptureKind::Tun
                    };
                    let target = match target {
                        ConnectTarget::LocalProxy { addr, kind }
                        | ConnectTarget::Soft { addr, kind } => Target::Proxy { addr, kind },
                        ConnectTarget::DirectVpn { profile_id }
                        | ConnectTarget::SoftVpn { profile_id } => Target::Direct(profile_id),
                    };
                    effects::connect(ctx, target, capture, adaptive).await
                }
                Job::Switch { profile_id, kind } => {
                    effects::switch(ctx, profile_id, kind, adaptive).await
                }
                Job::RestartLast { reason } => effects::restart_last(ctx, reason).await,
                Job::RestartAdaptive { mode, sibling } => {
                    effects::restart_adaptive(ctx, mode, sibling).await
                }
            }
        };
        let (tx, id) = (self.tx.clone(), op.id);
        supervise(&self.tx, fut, StartReport::panicked, move |report| {
            let _ = tx.send(Cmd::StartDone {
                op: id,
                report: Box::new(report),
            });
        });
    }

    /// Fires `StartAbort` when the caller goes away or the deadline passes, whichever first.
    pub(super) fn watch_start(
        &self,
        op: OpId,
        timeout: Duration,
        caller: CancellationToken,
        effect: CancellationToken,
    ) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let kind = tokio::select! {
                biased;
                () = caller.cancelled() => ErrorKind::Cancelled,
                () = effect.cancelled() => return,
                () = tokio::time::sleep(timeout) => ErrorKind::Timeout,
            };
            let _ = tx.send(Cmd::StartAbort { op, kind });
        });
    }
}

/// Ends of start-type operations.
impl Actor {
    /// Cancellation or deadline: the caller gets its answer now; the effect keeps the lane until
    /// it drained ("cancelling never releases a native effect").
    pub(super) fn abort_start(&mut self, op: OpId, kind: ErrorKind) {
        let Some(start) = self
            .start
            .as_mut()
            .filter(|s| s.op.id == op && s.aborted.is_none())
        else {
            return;
        };
        start.aborted = Some(kind);
        start.token.cancel();
        if let Some(reply) = start.reply.take() {
            let _ = reply.send(Err(abort_error(kind, true)));
        }
        if !matches!(start.job, Job::Connect { .. }) {
            // A switch or restart decides at the drain whether the old tunnel was touched.
            return;
        }
        start.terminal_published = true;
        let record = terminal(&start.op, Some(kind));
        let head = recovery_head(&start.op.correlation);
        self.publish(&record);
        // The compensating stop waits for the drain before it touches anything.
        self.begin_stop(stop_cause(kind), head, Vec::new());
    }

    pub(super) async fn start_done(&mut self, op: OpId, report: StartReport) {
        let Some(start) = self.start.take_if(|s| s.op.id == op) else {
            return;
        };
        start.token.cancel();
        // Before the operation's own ending, which would otherwise keep the crashed server.
        self.follow_failover().await;
        let mode_switch = report.mode_switch;
        let by = Provenance {
            owner: start.op.owner,
            source: start.op.source,
            correlation: start.op.correlation.clone(),
        };
        match (start.aborted, report.result) {
            (Some(kind), result) => {
                self.close_mode_switch(&start.job, mode_switch, false).await;
                self.drained_after_abort(&start, kind, result).await;
            }
            (None, Ok(up)) => self.start_succeeded(start, up, by, mode_switch).await,
            (None, Err(failure)) => {
                self.close_mode_switch(&start.job, mode_switch, false).await;
                self.start_failed(start, failure, by).await;
            }
        }
        self.after_drain();
    }

    /// A cancelled connect was published and is compensated by the stop already waiting. A
    /// cancelled switch / restart keeps the previous state when it never touched the tunnel,
    /// otherwise the session ends and a recovery stop cleans up.
    pub(super) async fn drained_after_abort(
        &mut self,
        start: &Start,
        kind: ErrorKind,
        result: EffectResult,
    ) {
        if start.terminal_published {
            return;
        }
        let touched = match &result {
            Ok(Up::Idle) => false,
            Ok(_) => true,
            Err(f) => f.touched,
        };
        if !touched {
            let e = self.evidence();
            let _ = self.fsm.keep_previous(start.op.id, e);
        }
        self.publish(&terminal(&start.op, Some(kind)));
        if touched {
            let headline = abort_error(kind, true).user_msg();
            self.close_switched(&start.job, headline).await;
            let head = recovery_head(&start.op.correlation);
            self.begin_stop(stop_cause(kind), head, Vec::new());
        }
    }
}

pub(super) type EffectResult = Result<Up, effects::Failure>;

pub(super) fn recovery_head(correlation: &CorrelationId) -> Head {
    Head::new(
        Owner::Recovery,
        Source::Lifecycle,
        Some(correlation.clone()),
        DEFAULT_TIMEOUT,
    )
}

pub(super) fn stop_cause(kind: ErrorKind) -> StopCause {
    match kind {
        ErrorKind::Timeout => StopCause::Timeout,
        ErrorKind::Cancelled => StopCause::Cancelled,
        _ => StopCause::Failed,
    }
}

/// The caller's answer to an aborted operation (`start` = a start-type operation).
pub(super) fn abort_error(kind: ErrorKind, start: bool) -> ConnError {
    match (kind, start) {
        (ErrorKind::Timeout, true) => ConnError::Timeout(Msg::new(key::START_TIMEOUT)),
        (ErrorKind::Timeout, false) => ConnError::Timeout(Msg::new(key::STOP_TIMEOUT)),
        _ => ConnError::Cancelled(Msg::new(key::START_CANCELLED)),
    }
}

/// Success and failure of start-type operations.
impl Actor {
    pub(super) async fn start_succeeded(
        &mut self,
        start: Start,
        up: Up,
        by: Provenance,
        mode_switch: Option<Captured>,
    ) {
        let warnings = match &up {
            Up::Run { warnings, .. } | Up::Restarted { warnings, .. } => warnings.clone(),
            Up::Idle => Vec::new(),
        };
        self.publish(&terminal(&start.op, None));
        let state = self.fsm.snapshot().state;
        let confirmed = match up {
            Up::Idle => matches!(state, TunnelState::Connected | TunnelState::Disconnected),
            _ => state == TunnelState::Connected,
        };
        let continues = confirmed && !matches!(up, Up::Idle);
        self.close_mode_switch(&start.job, mode_switch, continues)
            .await;
        if !confirmed {
            // Evidence changed between the effect's confirmation and the publish: never report
            // an unobserved success; roll back to a proven state instead.
            let head = recovery_head(&by.correlation);
            self.begin_stop(StopCause::Failed, head, Vec::new());
            let error = ConnError::Failed(TunError::new(
                ErrorKind::Internal,
                Msg::new(key::CONFIRMATION_MISSING),
            ));
            reply(start.reply, Err(error));
            return;
        }
        self.on_connected(&start.job, up, &by).await;
        reply(start.reply, Ok(Done { warnings }));
    }

    pub(super) async fn start_failed(
        &mut self,
        start: Start,
        failure: effects::Failure,
        by: Provenance,
    ) {
        let effects::Failure {
            error,
            kept_previous,
            mut touched,
            row,
        } = failure;
        let is_connect = matches!(start.job, Job::Connect { .. });
        if kept_previous {
            let e = self.evidence();
            if self.fsm.keep_previous(start.op.id, e).is_err() {
                // The read-back no longer holds: the previous protection is not proven.
                touched |= !is_connect;
            }
        }
        self.publish(&terminal(&start.op, Some(error.kind())));
        if !is_connect && touched && self.runtime_recovers() {
            // A planned reconnect that failed under a kill switch that holds counts as a drop
            // (ks-a, research 5.3): the runtime keeps the block and retries, the session stays
            // open and paused; no recovery stop.
            let e = self.evidence();
            self.enter_pause(e, true);
            touched = false;
        }
        if touched {
            if !is_connect {
                self.close_switched(&start.job, error.user_msg()).await;
            }
            // A switch or restart tore the old tunnel down (its services must go with it), or
            // something of ours may still be up unproven: roll back to a proven state.
            if !is_connect || self.runtime_running() || self.deps.soft.applied() != Some(false) {
                let head = recovery_head(&by.correlation);
                self.begin_stop(StopCause::Failed, head, Vec::new());
            }
        }
        if let Some(row) = row {
            let (profile, outcome) = *row;
            let row = start_failure_row(&profile, &by, outcome);
            session::write(&self.deps.history, row).await;
        }
        reply(start.reply, Err(error));
    }

    /// A switch or restart tore the previous tunnel down: its session ends as that switch
    /// (rotation / server switch) or, for a restart, as unknown with `headline`.
    pub(super) async fn close_switched(&mut self, job: &Job, headline: Msg) {
        if self.session.is_none() {
            return;
        }
        let ending = Captured::now(&self.deps);
        match job {
            // Nothing replaces it: the lane's recovery stop follows (`continues: false`).
            Job::Switch { kind, .. } => self.close_current(*kind, None, ending, false).await,
            _ => {
                self.close_current(OutcomeKind::Unknown, Some(headline), ending, false)
                    .await;
            }
        }
    }

    /// The other mode was ended before a start: its session closes as a mode switch (L-05).
    /// `continues`: the start is confirmed and its `Up` follows.
    pub(super) async fn close_mode_switch(
        &mut self,
        job: &Job,
        ending: Option<Captured>,
        continues: bool,
    ) {
        let Some(ending) = ending else {
            return;
        };
        let soft_start = matches!(job, Job::Connect { target, .. } if target.is_soft());
        // A session of the start's own mode was not ended by it (an unreadable Soft state
        // before a TUN start rolls back defensively).
        let Some(soft) = self.session.as_ref().map(LiveSession::is_soft) else {
            return;
        };
        if soft != soft_start {
            let headline = soft.then(|| Msg::new(key::OUTCOME_SOFT_MODE_SWITCH));
            self.close_current(OutcomeKind::ServerSwitch, headline, ending, continues)
                .await;
        }
    }

    /// Ends the live session with `kind` (headline composed unless given) and writes its row;
    /// `continues`: the `Up` of the run that replaces it follows.
    pub(super) async fn close_current(
        &mut self,
        kind: OutcomeKind,
        headline: Option<Msg>,
        ending: Captured,
        continues: bool,
    ) {
        let Some(live) = self.session.as_ref() else {
            return;
        };
        let evidence = live.egress(ending.egress_ip);
        let outcome = match headline {
            Some(headline) => SessionOutcome::with_headline(kind, evidence, headline),
            None => SessionOutcome::new(kind, evidence),
        };
        self.end_session(outcome, ending.bytes, continues).await;
    }

    pub(super) async fn end_session(
        &mut self,
        outcome: SessionOutcome,
        bytes: (u64, u64),
        continues: bool,
    ) {
        let Some(live) = self.session.take() else {
            return;
        };
        let kind = outcome.kind;
        session::write(&self.deps.history, live.row(outcome, bytes)).await;
        let _ = self.events.send(SessionEvent::Ended {
            session: live.view(),
            outcome: kind,
            continues,
        });
        if !continues {
            // Nothing runs on: no pause, no guard (the next connect decides anew).
            self.guard = SessionGuard::default();
            self.end_pause();
        }
        self.push_session();
    }
}

pub(super) fn reply(to: Option<Reply>, result: Result<Done, ConnError>) {
    if let Some(to) = to {
        let _ = to.send(result);
    }
}
