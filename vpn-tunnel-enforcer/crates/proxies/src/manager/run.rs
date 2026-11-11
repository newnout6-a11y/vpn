//! The tasks of a running slot (spec 3.12–3.19, 6.4): the health loop (one per slot; probes run
//! under the global permits), the exit watcher (it owns the exit from the moment of the spawn,
//! so an engine dying early is never missed, B-29) and the output pump (rate-limited warnings,
//! transport hints), plus the lease-expiry timer.
use std::future::pending;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Notify, Semaphore, broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_core::redact;

use super::Inner;
use super::launch::{Engine, Exit, STOP_TIMEOUT};
use super::registry::{Live, Registry};
use crate::health::{Duplicate, Next, ms, resolve_duplicate};
use crate::model::Degradation;
use crate::probe::{ProbeError, ProbeOk, Prober};
use crate::slot::Slot;

/// At most one engine-output warning per slot in this interval; the rest are counted
/// (old `RUNTIME_WARNING_LOG_INTERVAL_MS`).
const OUTPUT_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// A request to a slot's health loop.
pub(super) enum LoopCmd {
    /// Probe now, or join the probe in flight; the sender hears when a probe completed.
    Probe(Option<oneshot::Sender<()>>),
    /// Probe after this delay unless one is due sooner.
    Soon(Duration),
    /// Drop the schedule (the slot was quarantined from outside).
    Park,
}

/// What the health loop of one slot works with.
struct LoopCtx {
    inner: Weak<Inner>,
    permits: Arc<Semaphore>,
    prober: Arc<dyn Prober>,
    slot: Slot,
    generation: u64,
    port: u16,
    cancel: CancellationToken,
}

impl Inner {
    /// Starts the tasks of an engine that just became ready on `slot` and returns its handle.
    /// Called with the registry locked.
    pub(super) fn go_live(
        self: &Arc<Self>,
        slot: Slot,
        generation: u64,
        port: u16,
        engine: Arc<dyn Engine>,
    ) -> Live {
        let cancel = self.closing.child_token();
        let (probes, commands) = mpsc::unbounded_channel();
        let ctx = LoopCtx {
            inner: Arc::downgrade(self),
            permits: self.permits.clone(),
            prober: self.prober.clone(),
            slot,
            generation,
            port,
            cancel: cancel.clone(),
        };
        tokio::spawn(health_loop(ctx, commands, self.timing.first(slot)));
        let weak = Arc::downgrade(self);
        tokio::spawn(watch_exit(
            weak.clone(),
            slot,
            engine.clone(),
            cancel.clone(),
        ));
        tokio::spawn(pump_output(weak, slot, engine.lines(), cancel.clone()));
        Live {
            pid: engine.pid(),
            engine,
            cancel,
            probes,
        }
    }

    /// Applies a probe result to `slot` if it still runs `generation` (3.17); returns what the
    /// loop does next, or `None` when the result is stale.
    fn apply_probe(
        self: &Arc<Self>,
        slot: Slot,
        generation: u64,
        result: Result<ProbeOk, ProbeError>,
    ) -> Option<Next> {
        let now = now_ms();
        let mut guard = self.reg.lock();
        let reg = &mut *guard;
        let leased = reg.leases.lease(slot, now).is_some();
        let state = reg.slots.get_mut(&slot)?;
        if state.generation != generation || state.live.is_none() {
            return None;
        }
        let profile = state.profile.as_ref().map(|p| p.id.clone());
        let outcome = match result {
            Ok(ok) => Ok((ok.egress_ip, state.route.succeeded(ok, now))),
            Err(err) => {
                let next = state.route.failed(&err, now, &self.timing);
                tracing::warn!(slot = %slot, profile = profile.as_deref().unwrap_or_default(),
                    error = %err, failures = state.route.consecutive_failures, "health check failed");
                Err(next)
            }
        };
        let next = match outcome {
            Ok((ip, true)) => match resolve_duplicate(leased, &reg.healthy_peers(slot, ip, now)) {
                None => Next::In(self.timing.after_success(slot)),
                Some(Duplicate::QuarantinePeer(peer)) => {
                    let text = format!("Duplicate egress IP {ip} also reported by slot {slot}");
                    quarantine(reg, peer, text, now);
                    Next::In(self.timing.after_success(slot))
                }
                Some(Duplicate::Quarantine { keeper }) => {
                    let text = format!("Duplicate egress IP {ip} already belongs to slot {keeper}");
                    quarantine(reg, slot, text, now);
                    Next::Park
                }
            },
            // Drift or a rotation that kept its exit: degraded, no scheduled probe.
            Ok((_, false)) => Next::Park,
            Err(next) => next,
        };
        let state = reg.slots.get_mut(&slot)?;
        state.updated_at = Some(now);
        match next {
            Next::In(delay) => state.route.next_check_at = Some(now + ms(delay)),
            Next::Park | Next::Disable => state.route.next_check_at = None,
            Next::Kill => {
                // The listener refused: the engine is gone or hung while holding the port.
                let message = state.route.last_error.clone().unwrap_or_default();
                state.route.process_failed(message, now);
                if let Some(live) = state.take_live() {
                    tokio::spawn(async move { live.engine.terminate(STOP_TIMEOUT).await });
                }
            }
        }
        if next == Next::Disable {
            tokio::spawn(self.clone().auto_disable(slot, generation));
        }
        self.publish(reg);
        Some(next)
    }

    /// Records the time of the next scheduled probe of a live `slot`.
    fn set_next_check(&self, slot: Slot, generation: u64, delay: Duration) {
        let mut reg = self.reg.lock();
        if let Some(state) = reg
            .slots
            .get_mut(&slot)
            .filter(|s| s.generation == generation)
        {
            state.route.next_check_at = Some(now_ms() + ms(delay));
            self.publish(&reg);
        }
    }

    /// The engine of `slot` exited on its own (no automatic restart, 3.12).
    fn engine_exited(&self, slot: Slot, engine: &Arc<dyn Engine>, exit: &Exit) {
        let now = now_ms();
        let mut reg = self.reg.lock();
        let Some(state) = reg.slots.get_mut(&slot) else {
            return;
        };
        let current = state
            .live
            .as_ref()
            .is_some_and(|live| Arc::ptr_eq(&live.engine, engine));
        if !current {
            return;
        }
        state.take_live();
        let code = exit
            .code
            .map_or_else(|| "unknown".into(), |c| c.to_string());
        let message = format!("External proxy instance exited ({code})");
        state.route.process_failed(message, now);
        state.updated_at = Some(now);
        tracing::warn!(slot = %slot, code = %code, tail = %exit.tail, "external proxy instance exited");
        self.publish(&reg);
    }

    /// An engine output line of `slot`: a transport hint may pull the next probe in (3.19).
    fn engine_line(&self, slot: Slot, line: &str) {
        let mut reg = self.reg.lock();
        let Some(state) = reg.slots.get_mut(&slot) else {
            return;
        };
        let Some(live) = &state.live else {
            return;
        };
        if let Some(delay) = state.route.hint(line, now_ms(), &self.timing) {
            let _ = live.probes.send(LoopCmd::Soon(delay));
        }
    }
}

/// Degrades `slot` as a duplicate and parks its loop.
fn quarantine(reg: &mut Registry, slot: Slot, message: String, now: UnixMs) {
    if let Some(state) = reg.slots.get_mut(&slot) {
        state
            .route
            .degrade(Degradation::DuplicateEgressIp, message, true, now);
        state.updated_at = Some(now);
        if let Some(live) = &state.live {
            let _ = live.probes.send(LoopCmd::Park);
        }
    }
}

/// The health loop of one slot generation: sleeps until the next scheduled probe or a command,
/// probes under one of the global permits, applies the result. A probe asked for while one is
/// in flight joins it (its sender is answered when that probe completes).
async fn health_loop(
    ctx: LoopCtx,
    mut commands: mpsc::UnboundedReceiver<LoopCmd>,
    first: Duration,
) {
    let mut next = Some(tokio::time::Instant::now() + first);
    let mut waiters: Vec<oneshot::Sender<()>> = Vec::new();
    loop {
        let due = async {
            match next {
                Some(at) => tokio::time::sleep_until(at).await,
                None => pending().await,
            }
        };
        tokio::select! {
            biased;
            () = ctx.cancel.cancelled() => return,
            command = commands.recv() => match command {
                None => return,
                Some(LoopCmd::Probe(waiter)) => waiters.extend(waiter),
                Some(LoopCmd::Soon(delay)) => {
                    let at = tokio::time::Instant::now() + delay;
                    if next.is_none_or(|current| at < current) {
                        next = Some(at);
                        if let Some(inner) = ctx.inner.upgrade() {
                            inner.set_next_check(ctx.slot, ctx.generation, delay);
                        }
                    }
                    continue;
                }
                Some(LoopCmd::Park) => {
                    next = None;
                    continue;
                }
            },
            () = due => {}
        }
        let result = tokio::select! {
            () = ctx.cancel.cancelled() => return,
            result = probe_with_permit(&ctx) => result,
        };
        let Some(result) = result else {
            return;
        };
        while let Ok(command) = commands.try_recv() {
            // Schedule changes asked for during the probe are superseded by its result.
            if let LoopCmd::Probe(waiter) = command {
                waiters.extend(waiter);
            }
        }
        let decided = match ctx.inner.upgrade() {
            Some(inner) => inner.apply_probe(ctx.slot, ctx.generation, result),
            None => None,
        };
        for waiter in waiters.drain(..) {
            let _ = waiter.send(());
        }
        next = match decided {
            Some(Next::In(delay)) => Some(tokio::time::Instant::now() + delay),
            Some(Next::Park | Next::Disable) => None,
            Some(Next::Kill) | None => return,
        };
    }
}

async fn probe_with_permit(ctx: &LoopCtx) -> Option<Result<ProbeOk, ProbeError>> {
    let _permit = ctx.permits.acquire().await.ok()?;
    Some(ctx.prober.probe(ctx.port).await)
}

/// Waits for the slot's engine to exit and reports it unless the slot moved on.
async fn watch_exit(
    inner: Weak<Inner>,
    slot: Slot,
    engine: Arc<dyn Engine>,
    cancel: CancellationToken,
) {
    let exit = tokio::select! {
        () = cancel.cancelled() => return,
        exit = engine.exited() => exit,
    };
    if let Some(inner) = inner.upgrade() {
        inner.engine_exited(slot, &engine, &exit);
    }
}

/// Reads the engine's output lines: transport hints for the health loop, and at most one
/// warning per [`OUTPUT_LOG_INTERVAL`] in the app log (redacted; the rest are counted).
async fn pump_output(
    inner: Weak<Inner>,
    slot: Slot,
    mut lines: broadcast::Receiver<Arc<str>>,
    cancel: CancellationToken,
) {
    let mut last_logged: Option<Instant> = None;
    let mut suppressed: u64 = 0;
    loop {
        let line = tokio::select! {
            () = cancel.cancelled() => return,
            line = lines.recv() => line,
        };
        let line = match line {
            Ok(line) => line,
            Err(RecvError::Lagged(missed)) => {
                suppressed += missed;
                continue;
            }
            Err(RecvError::Closed) => return,
        };
        match inner.upgrade() {
            Some(inner) => inner.engine_line(slot, &line),
            None => return,
        }
        if last_logged.is_some_and(|at| at.elapsed() < OUTPUT_LOG_INTERVAL) {
            suppressed += 1;
            continue;
        }
        let text = redact::for_log(line.trim());
        tracing::warn!(slot = %slot, suppressed, line = %text, "external proxy engine output");
        last_logged = Some(Instant::now());
        suppressed = 0;
    }
}

/// Sweeps expired leases when they expire (the lease book also ignores them lazily); re-armed
/// through `wake` whenever a lease is granted or renewed.
pub(super) async fn lease_timer(inner: Weak<Inner>, wake: Arc<Notify>, cancel: CancellationToken) {
    loop {
        let next = match inner.upgrade() {
            Some(inner) => inner.reg.lock().leases.next_expiry(),
            None => return,
        };
        let due = async {
            match next {
                Some(at) => {
                    let wait = u64::try_from(at - now_ms()).unwrap_or(0);
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                }
                None => pending().await,
            }
        };
        tokio::select! {
            () = cancel.cancelled() => return,
            () = wake.notified() => continue,
            () = due => {}
        }
        match inner.upgrade() {
            Some(inner) => {
                inner.reg.lock().leases.sweep(now_ms());
            }
            None => return,
        }
    }
}
