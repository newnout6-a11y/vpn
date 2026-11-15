//! Schedule page: the list of `schedules.json` through the process's one automation
//! [`Scheduler`] (its reconcile task starts and stops the VPN on schedule), the next event that
//! task reports, and the servers a server schedule may use. A schedule stores two choices
//! (NOADMIN §2): how the traffic is taken (system proxy / TUN) and where it goes (a server of
//! the list / the local proxy).
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::sync::watch;
use vpnte_automation::coordinator::Coordinator;
use vpnte_automation::schedule::{Capture as CoreCapture, Upstream as CoreUpstream};
use vpnte_automation::schedule::{HhMm as CoreHhMm, ScheduleEntry as CoreEntry};
use vpnte_automation::scheduler::{BoundaryKind, ScheduleDraft, Scheduler, Schedules, Upcoming};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::store::Store;
use vpnte_servers::store::{Servers, ServersEvent};
use vpnte_ui::schedule::{
    Capture, HhMm, NextAction, NextEvent, ScheduleApi, ScheduleEntry, ScheduleInput,
    ScheduleSnapshot, ServerChoice, Upstream,
};
use vpnte_ui::widgets::Load;

use crate::services::Backend;
use crate::support::blocking;

/// [`ScheduleApi`] over the scheduler's list API.
pub struct ScheduleService<C: Coordinator>(Arc<Shared<C>>);

/// State shared by the actions and the projection task.
struct Shared<C: Coordinator> {
    backend: Arc<Backend>,
    /// `schedules.json`, the scheduler's own store (one per process).
    store: Arc<Store<Schedules>>,
    scheduler: Arc<Scheduler<C>>,
    state: watch::Sender<ScheduleSnapshot>,
    /// Serialises the read-modify-write of `set_enabled` with every other change.
    writes: Mutex<()>,
    /// Projection and send as one step, so a slower projection never sends an older list
    /// after a newer one (actions and the projection task both publish).
    publishing: Mutex<()>,
}

impl<C: Coordinator> ScheduleService<C> {
    /// The page over `scheduler` (whose store is `store`): publishes the first snapshot and
    /// starts the projection task. Call it inside the tokio runtime.
    pub fn start(
        backend: Arc<Backend>,
        store: Arc<Store<Schedules>>,
        scheduler: Arc<Scheduler<C>>,
    ) -> Self {
        let shared = Arc::new(Shared {
            backend,
            store,
            scheduler,
            state: watch::Sender::new(ScheduleSnapshot::default()),
            writes: Mutex::new(()),
            publishing: Mutex::new(()),
        });
        shared.publish();
        tokio::spawn(follow(shared.clone()));
        Self(shared)
    }
}

impl<C: Coordinator> Shared<C> {
    /// Projects the list, the next event and the servers; sends only a changed snapshot.
    fn publish(&self) {
        let _one = self.publishing.lock();
        // Whether a TUN schedule can connect is the capability view's (`api_helper`), live.
        let snapshot = project(
            &self.scheduler.list(),
            self.scheduler.status().borrow().next.as_ref(),
            server_choices(&self.backend.servers),
        );
        self.state.send_if_modified(|current| {
            let changed = *current != snapshot;
            if changed {
                *current = snapshot;
            }
            changed
        });
    }

    /// The scheduler's draft for `input`. «Текущий сервер» (an empty server of a server
    /// schedule) becomes the server selected now: the scheduler stores a concrete one.
    fn draft(&self, input: ScheduleInput) -> AppResult<ScheduleDraft> {
        let profile_id = if input.upstream.uses_profile() && input.profile_id.trim().is_empty() {
            self.backend
                .servers
                .active()
                .map(|active| active.row.id.as_str().to_owned())
                .unwrap_or_default()
        } else {
            input.profile_id
        };
        Ok(ScheduleDraft {
            name: input.name,
            enabled: input.enabled,
            days: input.days,
            start_time: core_time(input.start)?,
            end_time: core_time(input.end)?,
            profile_id,
            capture: core_capture(input.capture),
            upstream: core_upstream(input.upstream),
        })
    }
}

#[async_trait(?Send)]
impl<C: Coordinator> ScheduleApi for ScheduleService<C> {
    fn state(&self) -> watch::Receiver<ScheduleSnapshot> {
        self.0.state.subscribe()
    }

    async fn reload(&self) -> AppResult<()> {
        self.0.publish();
        Ok(())
    }

    async fn create(&self, input: ScheduleInput) -> AppResult<()> {
        let shared = self.0.clone();
        // Store writes are blocking file I/O; the blocking pool also finishes them when the
        // page drops this call. The scheduler wakes its task itself.
        blocking(move || {
            let _one = shared.writes.lock();
            shared.scheduler.create(shared.draft(input)?)?;
            shared.publish();
            Ok(())
        })
        .await
    }

    async fn update(&self, id: String, input: ScheduleInput) -> AppResult<()> {
        let shared = self.0.clone();
        blocking(move || {
            let _one = shared.writes.lock();
            shared.scheduler.update(&id, shared.draft(input)?)?;
            shared.publish();
            Ok(())
        })
        .await
    }

    async fn set_enabled(&self, id: String, enabled: bool) -> AppResult<()> {
        let shared = self.0.clone();
        blocking(move || {
            let _one = shared.writes.lock();
            let entry = shared
                .scheduler
                .list()
                .into_iter()
                .find(|e| e.id == id)
                .ok_or_else(|| AppError::validation(Msg::new("automation.scheduler.notFound")))?;
            let draft = ScheduleDraft {
                enabled,
                ..ScheduleDraft::from(entry)
            };
            shared.scheduler.update(&id, draft)?;
            shared.publish();
            Ok(())
        })
        .await
    }

    async fn delete(&self, id: String) -> AppResult<()> {
        let shared = self.0.clone();
        blocking(move || {
            let _one = shared.writes.lock();
            shared.scheduler.delete(&id)?;
            shared.publish();
            Ok(())
        })
        .await
    }
}

/// Re-projects on every change of the list (any writer, a config import), of the reconcile
/// task's status and of the server list, until `backend.shutdown`.
async fn follow<C: Coordinator>(shared: Arc<Shared<C>>) {
    let mut doc = shared.store.subscribe();
    let mut status = shared.scheduler.status();
    let mut servers = shared.backend.servers.subscribe();
    let shutdown = shared.backend.shutdown.clone();
    loop {
        let alive = tokio::select! {
            () = shutdown.cancelled() => false,
            changed = doc.changed() => changed.is_ok(),
            changed = status.changed() => changed.is_ok(),
            alive = servers_changed(&mut servers) => alive,
        };
        if !alive {
            return;
        }
        shared.publish();
    }
}

/// Waits for a change of the server rows (`false`: the list is gone); pings and refresh
/// progress do not change what a schedule may pick.
async fn servers_changed(events: &mut broadcast::Receiver<ServersEvent>) -> bool {
    loop {
        match events.recv().await {
            Ok(ServersEvent::Changed) | Err(RecvError::Lagged(_)) => return true,
            Ok(_) => {}
            Err(RecvError::Closed) => return false,
        }
    }
}

/// The page's snapshot: the stored list in order, the next event of the reconcile task (only
/// it knows one), the servers.
fn project(
    entries: &[CoreEntry],
    next: Option<&Upcoming>,
    servers: Vec<ServerChoice>,
) -> ScheduleSnapshot {
    ScheduleSnapshot {
        schedules: Load::Ready(entries.iter().filter_map(entry_view).collect()),
        next: next.and_then(|upcoming| next_event(upcoming, entries)),
        servers,
    }
}

/// One stored schedule as the page shows it; days keep the stored numbering (0 = Sunday).
fn entry_view(e: &CoreEntry) -> Option<ScheduleEntry> {
    Some(ScheduleEntry {
        id: e.id.clone(),
        name: e.name.clone(),
        enabled: e.enabled,
        days: e.days.clone(),
        start: ui_time(e.start_time)?,
        end: ui_time(e.end_time)?,
        profile_id: e.profile_id.clone(),
        capture: ui_capture(e.capture),
        upstream: match e.upstream {
            CoreUpstream::Server => Upstream::Server,
            CoreUpstream::LocalProxy => Upstream::LocalProxy,
        },
    })
}

fn ui_capture(capture: CoreCapture) -> Capture {
    match capture {
        CoreCapture::Tun => Capture::Tun,
        CoreCapture::Proxy => Capture::Proxy,
    }
}

/// The reconcile task's next boundary, named after its schedule (with how it takes the
/// traffic: the page marks a TUN one unavailable in an unelevated app).
pub(super) fn next_event(upcoming: &Upcoming, entries: &[CoreEntry]) -> Option<NextEvent> {
    let entry = entries.iter().find(|e| e.id == upcoming.schedule_id)?;
    Some(NextEvent {
        action: match upcoming.kind {
            BoundaryKind::Start => NextAction::Start,
            BoundaryKind::Stop => NextAction::Stop,
        },
        at: upcoming.at,
        name: entry.name.clone(),
        capture: ui_capture(entry.capture),
    })
}

/// Servers a server schedule can use: not archived, readable on this PC (name and protocol
/// only).
fn server_choices(servers: &Servers) -> Vec<ServerChoice> {
    servers.read(|doc| {
        doc.profiles
            .iter()
            .filter(|row| row.archived.is_none() && !row.is_locked())
            .map(|row| ServerChoice {
                id: row.id.as_str().to_owned(),
                name: row.name.clone(),
                protocol: row.protocol.clone(),
            })
            .collect()
    })
}

fn ui_time(t: CoreHhMm) -> Option<HhMm> {
    HhMm::new(t.minutes() / 60, t.minutes() % 60)
}

fn core_time(t: HhMm) -> AppResult<CoreHhMm> {
    let (hour, minute) = (t.minutes() / 60, t.minutes() % 60);
    u8::try_from(hour)
        .ok()
        .zip(u8::try_from(minute).ok())
        .and_then(|(h, m)| CoreHhMm::new(h, m))
        .ok_or_else(|| AppError::new(ErrorKind::Validation))
}

fn core_capture(capture: Capture) -> CoreCapture {
    match capture {
        Capture::Tun => CoreCapture::Tun,
        Capture::Proxy => CoreCapture::Proxy,
    }
}

fn core_upstream(upstream: Upstream) -> CoreUpstream {
    match upstream {
        Upstream::Server => CoreUpstream::Server,
        Upstream::LocalProxy => CoreUpstream::LocalProxy,
    }
}
