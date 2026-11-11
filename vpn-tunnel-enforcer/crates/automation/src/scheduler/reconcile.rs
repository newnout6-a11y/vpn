//! The reconcile task: one pass per wake-up acts on the run active now.
use std::time::Duration;

use jiff::Timestamp;
use jiff::tz::TimeZone;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::{Level, Notice, Owner};

use super::{Scheduler, SchedulerStatus, Wake, system_zone, upcoming};
use crate::coordinator::{
    ConnectOutcome, ConnectRequest, Coordinator, LifecycleEvent, NoticeCategory, OpError, StopCause,
};
use crate::schedule::{self, Run, ScheduleEntry, ScheduleMode};

/// Delays of the retries after a failed scheduled connect (fix S2): 1, 2, 5, then every 10 min.
const RETRY_BACKOFF_S: [i64; 4] = [60, 120, 300, 600];
/// Longest sleep between passes: a missed resume or clock message costs at most this much.
const MAX_SLEEP_MS: i64 = 60_000;

fn backoff(attempt: usize) -> jiff::SignedDuration {
    let secs = RETRY_BACKOFF_S[attempt.min(RETRY_BACKOFF_S.len() - 1)];
    jiff::SignedDuration::from_secs(secs)
}

/// The run the task acted on. In memory only: after an app restart inside a run the task acts
/// again, because the engine died with the process; only the user's suppression is persisted.
struct Acted {
    /// An instant inside the run (when the task first saw it).
    at: Timestamp,
    /// Name of the schedule that currently ends the run (for the stop notice).
    last_name: String,
    failure_notified: bool,
    retry: Option<Retry>,
}

#[derive(Debug, Clone, Copy)]
struct Retry {
    attempt: usize,
    at: Timestamp,
}

/// Result of one connect fan-out over the schedules active now.
enum Attempt {
    Connected {
        name: String,
        fresh: bool,
    },
    /// Cancelled by a higher owner or the user, or the run was suppressed meanwhile.
    Abandoned,
    /// Refused while a higher-priority operation runs: retried quietly (usually the user acting).
    Busy,
    Failed {
        name: String,
        reason: Msg,
        unavailable: bool,
    },
}

/// State of the reconcile task; [`Reconciler::pass`] is one evaluation at a given instant.
pub(super) struct Reconciler<'a, C: Coordinator> {
    sched: &'a Scheduler<C>,
    events: Option<broadcast::Receiver<LifecycleEvent>>,
    acted: Option<Acted>,
    /// Redo the active run's connect on the next pass (the list was edited).
    redo: bool,
    /// Instant of the manual action that suppressed the active run; kept here (persisted best
    /// effort) so a read-only `schedules.json` cannot turn the fence off.
    suppressed_at: Option<Timestamp>,
}

impl<'a, C: Coordinator> Reconciler<'a, C> {
    pub(super) fn new(sched: &'a Scheduler<C>) -> Self {
        let stored = sched.store.read(|d| d.suppressed_at);
        Self {
            sched,
            events: Some(sched.coord.events()),
            acted: None,
            redo: false,
            suppressed_at: stored.and_then(|ms| Timestamp::from_millisecond(ms).ok()),
        }
    }

    /// Evaluates the schedules at `now`, acts, publishes the status; returns when to look again.
    pub(super) async fn pass(&mut self, now: Timestamp, tz: &TimeZone) -> Timestamp {
        self.drain_events(now, tz);
        let doc = self.sched.store.snapshot();
        let run = schedule::active_run(&doc.schedules, tz, now);
        let suppressed = self.check_suppression(run.as_ref());
        match run {
            Some(run) => {
                let known = self.acted.as_ref().is_some_and(|a| run.contains(a.at));
                let mut acted = self.acted.take().filter(|_| known).unwrap_or(Acted {
                    at: now,
                    last_name: String::new(),
                    failure_notified: false,
                    retry: None,
                });
                acted.last_name = name_of(&doc.schedules, run.last);
                let retry_due = acted.retry.is_some_and(|r| r.at <= now);
                if suppressed {
                    acted.retry = None;
                } else if !known || self.redo || retry_due {
                    self.redo = false;
                    self.connect(&mut acted, &run, now, tz, &doc.schedules)
                        .await;
                }
                self.acted = Some(acted);
            }
            None => {
                self.redo = false;
                if let Some(acted) = self.acted.take() {
                    self.end_run(&acted.last_name).await;
                }
            }
        }
        // A manual action seen during the fan-out may have suppressed the run just now.
        let suppressed = run.is_some() && self.suppressed_at.is_some();
        self.publish(now, tz, run, suppressed)
    }
}

impl<C: Coordinator> Reconciler<'_, C> {
    /// Connects for the active run unless a Manual / Recovery session already satisfies it (then
    /// nothing happens: no connect, no retry, no notice, no ownership change — fix S5).
    async fn connect(
        &mut self,
        acted: &mut Acted,
        run: &Run,
        now: Timestamp,
        tz: &TimeZone,
        entries: &[ScheduleEntry],
    ) {
        if self
            .sched
            .coord
            .session()
            .is_some_and(|s| s.owner > Owner::Schedule)
        {
            acted.retry = None;
            return;
        }
        // The schedule whose window started the run goes first, the others in list order.
        let mut order = schedule::active_entries(entries, tz, now);
        if let Some(pos) = order.iter().position(|&i| i == run.first) {
            order[..=pos].rotate_right(1);
        }
        let started = std::time::Instant::now();
        self.set_connecting(true);
        let attempt = self.fan_out(&order, entries, now, tz).await;
        self.set_connecting(false);
        // Backoff counts from the end of the attempt (a connect may take up to its deadline);
        // whole milliseconds keep the published retry instant exact.
        let elapsed_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let ended = now
            .checked_add(jiff::SignedDuration::from_millis(elapsed_ms))
            .unwrap_or(now);
        self.settle(acted, attempt, ended);
    }

    /// Tries the active schedules in `order`; only an unavailable profile moves on to the next one
    /// ("retry only an unavailable profile, never cancellation, conflict or network failure").
    async fn fan_out(
        &mut self,
        order: &[usize],
        entries: &[ScheduleEntry],
        now: Timestamp,
        tz: &TimeZone,
    ) -> Attempt {
        let mut unavailable = None;
        for &i in order {
            // A manual stop or start that happened meanwhile ends the fan-out: a late schedule must
            // not revive protection the user just turned off.
            self.drain_events(now, tz);
            if self.suppressed_at.is_some() {
                return Attempt::Abandoned;
            }
            let entry = &entries[i];
            let result = match request_for(entry) {
                Some(req) => self.sched.coord.connect(Owner::Schedule, req).await,
                None => Err(OpError::ProfileUnavailable),
            };
            let name = entry.name.clone();
            match result {
                Ok(outcome) => {
                    let fresh = outcome == ConnectOutcome::Connected;
                    return Attempt::Connected { name, fresh };
                }
                Err(OpError::ProfileUnavailable) => {
                    tracing::info!(schedule = %entry.id, "scheduled profile unavailable");
                    unavailable.get_or_insert(name);
                }
                Err(OpError::Cancelled) => return Attempt::Abandoned,
                Err(OpError::Conflict) => return Attempt::Busy,
                Err(e) => {
                    tracing::warn!(schedule = %entry.id, error = %e, "scheduled connect failed");
                    let reason = e.reason();
                    return Attempt::Failed {
                        name,
                        reason,
                        unavailable: false,
                    };
                }
            }
        }
        match unavailable {
            Some(name) => Attempt::Failed {
                name,
                reason: OpError::ProfileUnavailable.reason(),
                unavailable: true,
            },
            None => Attempt::Abandoned,
        }
    }

    fn settle(&self, acted: &mut Acted, attempt: Attempt, now: Timestamp) {
        let mut arm_retry = || {
            let attempt = acted.retry.map_or(0, |r| r.attempt + 1);
            acted.retry = Some(Retry {
                attempt,
                at: now + backoff(attempt),
            });
        };
        match attempt {
            Attempt::Busy => arm_retry(),
            Attempt::Connected { name, fresh } => {
                acted.retry = None;
                // A silent re-confirmation (already connected) is not news, unless a failure was.
                if fresh || acted.failure_notified {
                    let body = Msg::new("automation.scheduler.started").arg("name", name);
                    self.notify(NoticeCategory::ScheduleTriggered, Level::Info, body);
                }
                acted.failure_notified = false;
            }
            Attempt::Abandoned => acted.retry = None,
            Attempt::Failed {
                name,
                reason,
                unavailable,
            } => {
                arm_retry();
                if !acted.failure_notified {
                    acted.failure_notified = true;
                    let key = if unavailable {
                        "automation.scheduler.profileUnavailable"
                    } else {
                        "automation.scheduler.connectFailed"
                    };
                    let notice =
                        Notice::new(Level::Warn, Msg::new(key).arg("name", name)).body(reason);
                    self.sched
                        .coord
                        .notify(NoticeCategory::ConnectionError, notice);
                }
            }
        }
    }

    /// The run is over: end the session only if the schedule owns it (fixes S5, S9).
    async fn end_run(&mut self, name: &str) {
        let owned = self
            .sched
            .coord
            .session()
            .is_some_and(|s| s.owner == Owner::Schedule);
        if !owned {
            return;
        }
        match self.sched.coord.disconnect(Owner::Schedule).await {
            Ok(()) => {
                let body = Msg::new("automation.scheduler.stopped").arg("name", name);
                self.notify(NoticeCategory::ScheduleTriggered, Level::Info, body);
            }
            Err(e) => tracing::warn!(error = %e, "scheduled stop did not complete"),
        }
    }

    fn notify(&self, category: NoticeCategory, level: Level, body: Msg) {
        let notice = Notice::new(level, "automation.scheduler.title").body(body);
        self.sched.coord.notify(category, notice);
    }
}

impl<C: Coordinator> Reconciler<'_, C> {
    /// A manual start / stop inside a run suppresses that run (fix S8); a crash of the schedule's
    /// own session inside the run arms the retry (a crash is not a user stop).
    fn on_event(&mut self, event: LifecycleEvent, now: Timestamp, tz: &TimeZone) {
        let manual = matches!(
            event,
            LifecycleEvent::Started {
                owner: Owner::Manual,
                ..
            } | LifecycleEvent::Stopped {
                cause: StopCause::Requested(Owner::Manual),
                ..
            }
        );
        let crashed = matches!(
            event,
            LifecycleEvent::Stopped {
                owner: Owner::Schedule,
                cause: StopCause::Fault | StopCause::Requested(Owner::Recovery),
                ..
            }
        );
        if !manual && !crashed {
            return;
        }
        let Some(run) = self
            .sched
            .store
            .read(|d| schedule::active_run(&d.schedules, tz, now))
        else {
            return;
        };
        if manual {
            tracing::info!(
                "manual action inside a schedule run: the run is left alone until it ends"
            );
            self.set_suppressed(Some(now));
            if let Some(acted) = &mut self.acted {
                acted.retry = None;
            }
        } else if let Some(acted) = self.acted.as_mut().filter(|a| run.contains(a.at)) {
            tracing::warn!("scheduled session lost inside its run, retrying");
            acted.retry = Some(Retry {
                attempt: 0,
                at: now + backoff(0),
            });
        }
    }

    fn drain_events(&mut self, now: Timestamp, tz: &TimeZone) {
        loop {
            let received = match &mut self.events {
                Some(rx) => rx.try_recv(),
                None => return,
            };
            match received {
                Ok(event) => self.on_event(event, now, tz),
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    tracing::warn!(missed = n, "scheduler missed lifecycle events");
                }
                Err(broadcast::error::TryRecvError::Empty) => return,
                Err(broadcast::error::TryRecvError::Closed) => self.events = None,
            }
        }
    }

    /// Whether the active run is suppressed; forgets a suppression whose run is over.
    fn check_suppression(&mut self, run: Option<&Run>) -> bool {
        let Some(at) = self.suppressed_at else {
            return false;
        };
        let inside = run.is_some_and(|r| r.contains(at));
        if !inside {
            self.set_suppressed(None);
        }
        inside
    }

    fn set_suppressed(&mut self, at: Option<Timestamp>) {
        self.suppressed_at = at;
        let stored = at.map(Timestamp::as_millisecond);
        if let Err(e) = self.sched.store.update(|d| d.suppressed_at = stored) {
            tracing::warn!(error = %e, "schedule suppression not saved");
        }
    }

    fn set_connecting(&self, connecting: bool) {
        self.sched.status.send_if_modified(|s| {
            let changed = s.connecting != connecting;
            s.connecting = connecting;
            changed
        });
    }

    /// Publishes the status and returns the next instant to look again.
    fn publish(
        &self,
        now: Timestamp,
        tz: &TimeZone,
        run: Option<Run>,
        suppressed: bool,
    ) -> Timestamp {
        let entries = self.sched.list();
        let next = schedule::next_event(&entries, tz, now);
        let retry_at = self.acted.as_ref().and_then(|a| a.retry).map(|r| r.at);
        let status = SchedulerStatus {
            ready: true,
            run: run.map(|r| (r.start.as_millisecond(), r.stop.as_millisecond())),
            suppressed,
            connecting: false,
            retry_at: retry_at.map(Timestamp::as_millisecond),
            next: next.and_then(|n| upcoming(&entries, n)),
        };
        self.sched.status.send_if_modified(|s| {
            let changed = *s != status;
            *s = status;
            changed
        });
        let cap = now + jiff::SignedDuration::from_millis(MAX_SLEEP_MS);
        [next.map(|n| n.at()), retry_at]
            .into_iter()
            .flatten()
            .fold(cap, Timestamp::min)
    }
}

fn name_of(entries: &[ScheduleEntry], idx: usize) -> String {
    entries.get(idx).map(|e| e.name.clone()).unwrap_or_default()
}

/// The coordinator request of a schedule; `None` for a Direct schedule without a profile.
fn request_for(entry: &ScheduleEntry) -> Option<ConnectRequest> {
    match entry.mode {
        ScheduleMode::Direct if entry.profile_id.is_empty() => None,
        ScheduleMode::Direct => Some(ConnectRequest::Direct {
            profile_id: entry.profile_id.clone(),
        }),
        // Hard / Soft use the local proxy; the profile id is not touched (fix S6).
        ScheduleMode::Hard => Some(ConnectRequest::LocalProxyHard { endpoint: None }),
        ScheduleMode::Soft => Some(ConnectRequest::Soft { endpoint: None }),
    }
}

impl<C: Coordinator> Scheduler<C> {
    /// The reconcile task: runs until `cancel`. Start it after startup recovery and before the
    /// AutoPilot launch run (AutoPilot waits for `status().ready`). Only one runner at a time.
    pub async fn run(&self, cancel: CancellationToken) {
        let Some(mut wakes) = self.wake_rx.lock().take() else {
            tracing::warn!("scheduler task already running");
            return;
        };
        let mut task = Reconciler::new(self);
        loop {
            let tz = system_zone();
            let now = Timestamp::now();
            let deadline = tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                deadline = task.pass(now, &tz) => deadline,
            };
            let wait_ms = (deadline.as_millisecond() - now.as_millisecond()).clamp(0, MAX_SLEEP_MS);
            tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                wake = wakes.recv() => task.redo |= wake == Some(Wake::Edited),
                event = next_lifecycle(&mut task.events) => {
                    if let Some(event) = event {
                        task.on_event(event, Timestamp::now(), &tz);
                    }
                }
                () = tokio::time::sleep(Duration::from_millis(wait_ms.unsigned_abs())) => {}
            }
        }
        // Put the inbox back so the task can be started again (tests, a restarted supervisor).
        *self.wake_rx.lock() = Some(wakes);
    }
}

/// The next lifecycle event; pending forever once the channel is closed.
async fn next_lifecycle(
    events: &mut Option<broadcast::Receiver<LifecycleEvent>>,
) -> Option<LifecycleEvent> {
    let Some(rx) = events else {
        return std::future::pending().await;
    };
    match rx.recv().await {
        Ok(event) => Some(event),
        Err(broadcast::error::RecvError::Lagged(n)) => {
            tracing::warn!(missed = n, "scheduler missed lifecycle events");
            None
        }
        Err(broadcast::error::RecvError::Closed) => {
            *events = None;
            None
        }
    }
}
