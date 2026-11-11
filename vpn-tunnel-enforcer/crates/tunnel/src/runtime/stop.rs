//! Stop (tunnel-core §3.6) and protected restart (§3.7): the exit is proven by the process
//! handle before anything is released; every cleanup step is independent and reported.
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_engine::singbox_process::KILL_CODE;

use std::sync::atomic::Ordering;

use super::actor::{Actor, DoneStop, Phase, Retained};
use super::handle::Next;
use super::with_current_settings;
use crate::api::{
    Mode, RestartOptions, StartReceipt, StartRequest, StopOptions, StopReceipt, TunError,
    TunStatus, TunStatusKind, TunWarning, TunnelEvent,
};

impl Actor {
    /// One stop. Preserved: engines gone, protection kept (`Adapting`). Full: engines gone,
    /// protection released, the capture interface awaited.
    pub(super) async fn stop(&mut self, opts: StopOptions) -> StopReceipt {
        let preserve = opts.preserve_protection;
        let generation = self.generation;
        let mut receipt = StopReceipt {
            operation_id: format!("stop_{}", uuid::Uuid::new_v4().simple()),
            ok: false,
            runtime_stopped: false,
            forced: false,
            protection_released: None,
            baseline_restored: None,
            adapter_gone: false,
            warnings: Vec::new(),
        };
        // A stop always wins over pending recovery and supervision of the old run.
        self.restart_due = None;
        self.slot_due = None;
        self.stable_at = None;
        if !opts.preserve_last {
            self.last = None;
            self.attempt = 0;
            self.failover_tried = false;
        }
        self.announce(if preserve {
            TunStatusKind::Adapting
        } else {
            TunStatusKind::Stopping
        });
        let (core, slots, plan) = match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Running(s) => {
                s.watch.cancel();
                (Some(s.core), s.slots, Some(s.plan))
            }
            Phase::Crashed(c) => (None, c.slots, Some(c.plan)),
            Phase::Faulted(r) => {
                self.protection_dirty = true;
                (r.core, r.slots, r.plan)
            }
            Phase::Adapting(plan) => (None, None, Some(plan)),
            Phase::Idle => (None, None, None),
        };
        self.exit = None;
        self.xray_rx = None;
        if let Some(proc) = core.clone() {
            match proc.terminate(self.deps.timings.exit).await {
                Ok(info) => {
                    receipt.forced = info.code == Some(KILL_CODE);
                    self.record_exit(&info);
                }
                Err(e) => {
                    tracing::error!(error = %e, "stop: sing-box exit not proven, protection kept");
                    let retained = Retained { core, slots, plan };
                    return self.stop_retained(retained, receipt, generation, preserve);
                }
            }
        }
        receipt.runtime_stopped = true;
        // Xray only after sing-box is gone: the upstream stays available until then.
        if let Some(mut s) = slots
            && let Err(e) = s.slots.stop_all().await
        {
            tracing::error!(error = %e, "stop: Xray exit not proven, protection kept");
            receipt.runtime_stopped = false;
            let retained = Retained {
                core: None,
                slots: Some(s),
                plan,
            };
            return self.stop_retained(retained, receipt, generation, preserve);
        }
        let status = self.idle_status();
        if preserve {
            receipt.ok = true;
            self.phase = plan.map_or(Phase::Idle, Phase::Adapting);
            self.publish(|s| *s = status);
        } else {
            // Nothing held and nothing failed earlier: no protection call at all.
            let released = if plan.is_some() || self.protection_dirty {
                self.capture.release().await
            } else {
                Ok(())
            };
            self.protection_dirty = released.is_err();
            if let Err(e) = &released {
                tracing::error!(error = %e, "stop: protection not released");
                receipt
                    .warnings
                    .push(Msg::new("tunnel.runtime.cleanup.protection"));
            }
            receipt.protection_released = Some(released.is_ok());
            // The app never rewrites adapter settings: nothing else to restore.
            receipt.baseline_restored = Some(true);
            receipt.adapter_gone = match &plan {
                Some(plan) => {
                    let never = CancellationToken::new();
                    let gone = self
                        .capture
                        .wait_gone(plan, self.deps.timings.release, &never);
                    gone.await
                }
                None => true,
            };
            receipt.ok = released.is_ok();
            self.publish(|s| *s = status);
            if receipt.ok {
                self.announce(TunStatusKind::Stopped);
            } else {
                let warning = Msg::new("tunnel.runtime.stopIncomplete");
                self.publish(|s| s.warning = Some(warning.clone()));
                self.announce(TunStatusKind::Error { warning });
            }
        }
        self.finish_stop(generation, preserve, &receipt);
        receipt
    }

    /// `StopFinished`, and the receipt later stop calls of this round share.
    fn finish_stop(&mut self, generation: u64, preserved: bool, receipt: &StopReceipt) {
        self.last_stop = Some(DoneStop {
            upto: self.shared.stops.load(Ordering::SeqCst),
            preserved,
            receipt: receipt.clone(),
        });
        self.emit(TunnelEvent::StopFinished {
            generation,
            preserved,
            receipt: receipt.clone(),
        });
    }

    /// An exit could not be proven: everything stays owned and blocking.
    fn stop_retained(
        &mut self,
        retained: Retained,
        mut receipt: StopReceipt,
        generation: u64,
        preserve: bool,
    ) -> StopReceipt {
        let warning = Msg::new("tunnel.runtime.cleanup.exitUnproven");
        receipt.warnings.push(warning.clone());
        self.phase = Phase::Faulted(Box::new(retained));
        let status = TunStatus {
            warning: Some(warning.clone()),
            ..self.idle_status()
        };
        self.publish(|s| *s = status);
        self.announce(TunStatusKind::Error { warning });
        self.finish_stop(generation, preserve, &receipt);
        receipt
    }
}

fn conflict(key: &'static str) -> TunError {
    TunError::new(ErrorKind::Conflict, Msg::new(key))
}

impl Actor {
    /// `restart_protected` / `restart_with_last` / `restart_adaptive`.
    pub(super) async fn cmd_restart(
        &mut self,
        reason: String,
        next: Next,
        opts: RestartOptions,
    ) -> Result<Option<StartReceipt>, TunError> {
        let running = matches!(self.phase, Phase::Running(_));
        let (reason, next) = match next {
            Next::Given(req) => (reason, req),
            Next::WithLast => {
                if !running {
                    return Ok(None);
                }
                let last = self
                    .last
                    .clone()
                    .ok_or_else(|| conflict("tunnel.runtime.noLastStart"))?;
                let now = self.deps.inputs.snapshot().await?;
                (
                    format!("config change: {reason}"),
                    with_current_settings(&last, &now),
                )
            }
            Next::Adaptive { mode, profile } => {
                if !running {
                    return Err(conflict("tunnel.runtime.notRunning"));
                }
                let mut req = self
                    .last
                    .clone()
                    .ok_or_else(|| conflict("tunnel.runtime.noLastStart"))?;
                req.adaptive = mode;
                if let Some(profile) = profile {
                    req.mode = Mode::DirectVpn { profile };
                }
                (format!("adaptive transition to {mode:?}: {reason}"), req)
            }
        };
        self.restart_protected(reason, next, opts).await.map(Some)
    }

    /// Preserved stop, wait for the old capture to disappear, start; protection is kept across
    /// the gap. A failure or a cancellation ends in a full stop (never returns in the
    /// "blocking with no tunnel" state).
    async fn restart_protected(
        &mut self,
        reason: String,
        next: StartRequest,
        opts: RestartOptions,
    ) -> Result<StartReceipt, TunError> {
        if opts.cancel.is_cancelled() {
            return Err(cancelled_restart(Vec::new()));
        }
        let op = opts.cancel.child_token();
        self.guard_op(&op);
        let result = self.restart_inner(reason, next, &op, opts).await;
        self.clear_op();
        result
    }

    async fn restart_inner(
        &mut self,
        reason: String,
        next: StartRequest,
        op: &CancellationToken,
        opts: RestartOptions,
    ) -> Result<StartReceipt, TunError> {
        tracing::info!(%reason, "protected restart");
        let old_plan = match &self.phase {
            Phase::Running(s) => {
                // Still up: history closes the session before anything changes.
                self.emit(TunnelEvent::ProtectedRestart { reason });
                Some(s.plan.clone())
            }
            Phase::Crashed(c) => Some(c.plan.clone()),
            Phase::Adapting(plan) => Some(plan.clone()),
            _ => None,
        };
        let preserved = StopOptions {
            preserve_protection: true,
            preserve_last: true,
        };
        let stopped = self.stop(preserved).await;
        if !stopped.ok {
            let full = self.stop(StopOptions::default()).await;
            let mut err = TunError::new(
                ErrorKind::Internal,
                Msg::new("tunnel.runtime.restartStopFailed"),
            );
            err.warnings = [stopped.warnings, full.warnings].concat();
            return Err(err);
        }
        if op.is_cancelled() {
            return Err(self.cancel_restart().await);
        }
        let mut warnings = stopped.warnings;
        let mut avoid = Vec::new();
        if let Some(plan) = &old_plan
            && !self.capture.wait_gone(plan, opts.release_timeout, op).await
        {
            if op.is_cancelled() {
                return Err(self.cancel_restart().await);
            }
            // The old engine is proven gone; a fresh identity cannot collide with the leftover.
            tracing::warn!("old capture not released in time: the restart uses a fresh identity");
            warnings.push(TunWarning::ReleaseUnverified.msg());
            self.warn(TunWarning::ReleaseUnverified);
            avoid.extend(plan.alias.iter().cloned());
        }
        match self.start_run(next, op, &avoid).await {
            Ok(mut receipt) if !op.is_cancelled() => {
                warnings.append(&mut receipt.warnings);
                receipt.warnings = warnings;
                Ok(receipt)
            }
            Ok(_) => Err(self.cancel_restart().await),
            Err(mut err) => {
                let cancelled = op.is_cancelled();
                let full = self.stop(StopOptions::default()).await;
                if cancelled {
                    return Err(cancelled_restart(full.warnings));
                }
                err.warnings.extend(full.warnings);
                Err(err)
            }
        }
    }

    async fn cancel_restart(&mut self) -> TunError {
        let full = self.stop(StopOptions::default()).await;
        cancelled_restart(full.warnings)
    }
}

fn cancelled_restart(warnings: Vec<Msg>) -> TunError {
    TunError {
        error: AppError::msg(
            ErrorKind::Cancelled,
            Msg::new("tunnel.runtime.restartCancelled"),
        ),
        warnings,
    }
}
