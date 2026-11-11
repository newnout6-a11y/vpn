//! The `schedules.json` document and the reconcile task that turns protection on and off by the
//! schedule windows.
//!
//! The task re-evaluates wall-clock time on every pass (at least every 60 s, on resume and on
//! time-zone / clock changes), so sleep, hibernation and zone changes cannot make it act on a stale
//! boundary (fixes S1, S4). It connects through the [`Coordinator`] as `Owner::Schedule`, retries
//! failed connects with backoff (S2), never ends a session it does not own (S5, S9), and leaves a
//! run alone after the user stopped or took over the tunnel by hand, also across restarts (S8).
use std::sync::Arc;

use jiff::Timestamp;
use jiff::tz::TimeZone;
use parking_lot::Mutex;
use tokio::sync::{mpsc, watch};
use vpnte_base::types::UnixMs;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::store::Store;

use crate::coordinator::Coordinator;
use crate::schedule::{self, NextEvent, ScheduleEntry};

mod document;
mod reconcile;
#[cfg(test)]
mod tests;

pub use document::{ScheduleDraft, Schedules};

/// Why the reconcile task should look again right away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    /// The list changed outside this API (config import): the active run's connect is redone.
    Edited,
    /// The machine woke from sleep or hibernation (`WM_POWERBROADCAST` resume).
    Resume,
    /// The clock or the time zone changed (`WM_TIMECHANGE`). jiff caches the system zone for up
    /// to 5 minutes, so a zone change is applied within that time.
    TimeChanged,
}

/// Kind of a schedule boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryKind {
    Start,
    Stop,
}

/// The next start or stop, for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upcoming {
    pub kind: BoundaryKind,
    pub at: UnixMs,
    pub schedule_id: String,
}

/// What the reconcile task is doing, for the UI and the AutoPilot launch gate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchedulerStatus {
    /// The first pass after start finished (AutoPilot's launch run waits for it).
    pub ready: bool,
    /// The merged run active now: `(start, stop)`.
    pub run: Option<(UnixMs, UnixMs)>,
    /// The user stopped or took over the active run by hand; nothing happens until it ends.
    pub suppressed: bool,
    /// A scheduled connect is in flight.
    pub connecting: bool,
    /// When a failed scheduled connect is tried again.
    pub retry_at: Option<UnixMs>,
    /// The next boundary within the 8-day look-ahead.
    pub next: Option<Upcoming>,
}

/// Schedule list API plus the reconcile task ([`Scheduler::run`]).
pub struct Scheduler<C: Coordinator> {
    store: Arc<Store<Schedules>>,
    coord: Arc<C>,
    wake_tx: mpsc::UnboundedSender<Wake>,
    wake_rx: Mutex<Option<mpsc::UnboundedReceiver<Wake>>>,
    status: watch::Sender<SchedulerStatus>,
}

impl<C: Coordinator> Scheduler<C> {
    /// A scheduler over the `schedules.json` store; nothing runs until [`Scheduler::run`].
    pub fn new(store: Arc<Store<Schedules>>, coord: Arc<C>) -> Self {
        let (wake_tx, wake_rx) = mpsc::unbounded_channel();
        Self {
            store,
            coord,
            wake_tx,
            wake_rx: Mutex::new(Some(wake_rx)),
            status: watch::Sender::new(SchedulerStatus::default()),
        }
    }

    /// The schedules in stored order.
    pub fn list(&self) -> Vec<ScheduleEntry> {
        self.store.read(|d| d.schedules.clone())
    }

    /// Adds a schedule with a fresh id.
    pub fn create(&self, draft: ScheduleDraft) -> AppResult<ScheduleEntry> {
        let entry = draft.into_entry(uuid::Uuid::new_v4().to_string())?;
        self.store.update(|d| d.schedules.push(entry.clone()))?;
        self.wake(Wake::Edited);
        Ok(entry)
    }

    /// Replaces schedule `id` (the id never changes).
    pub fn update(&self, id: &str, draft: ScheduleDraft) -> AppResult<ScheduleEntry> {
        let entry = draft.into_entry(id.to_owned())?;
        let found = self.store.update(|d| {
            let slot = d.schedules.iter_mut().find(|e| e.id == id);
            slot.map(|slot| *slot = entry.clone()).is_some()
        })?;
        if !found {
            return Err(AppError::validation(Msg::new(
                "automation.scheduler.notFound",
            )));
        }
        self.wake(Wake::Edited);
        Ok(entry)
    }

    /// Removes schedule `id`; an unknown id is a no-op.
    pub fn delete(&self, id: &str) -> AppResult<()> {
        self.store.update(|d| d.schedules.retain(|e| e.id != id))?;
        self.wake(Wake::Edited);
        Ok(())
    }

    /// The next boundary from now in the system zone.
    pub fn next_event(&self) -> Option<Upcoming> {
        let entries = self.list();
        let next = schedule::next_event(&entries, &system_zone(), Timestamp::now())?;
        upcoming(&entries, next)
    }

    /// Live status of the reconcile task.
    pub fn status(&self) -> watch::Receiver<SchedulerStatus> {
        self.status.subscribe()
    }

    /// Asks the reconcile task to look again now (resume, clock / zone change, external edit).
    pub fn wake(&self, reason: Wake) {
        // The receiver lives as long as `self`; before `run` starts the message waits in the queue.
        let _ = self.wake_tx.send(reason);
    }
}

fn system_zone() -> TimeZone {
    TimeZone::try_system().unwrap_or_else(|e| {
        tracing::debug!(error = %e, "system time zone unknown, using UTC");
        TimeZone::UTC
    })
}

fn upcoming(entries: &[ScheduleEntry], event: NextEvent) -> Option<Upcoming> {
    let (kind, at, entry) = match event {
        NextEvent::Start { at, entry } => (BoundaryKind::Start, at, entry),
        NextEvent::Stop { at, entry } => (BoundaryKind::Stop, at, entry),
    };
    Some(Upcoming {
        kind,
        at: at.as_millisecond(),
        schedule_id: entries.get(entry)?.id.clone(),
    })
}
