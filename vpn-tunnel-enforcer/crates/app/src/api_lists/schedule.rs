//! Schedule page: the list of `schedules.json` through the automation [`Scheduler`], the next
//! event its reconcile task reports, and the servers a Direct schedule may use.
//!
//! The reconcile task (`Scheduler::run`) is what starts and stops the VPN on schedule. It needs
//! an automation `Coordinator` over the tunnel lifecycle, which this build does not expose, so
//! it is not spawned: the list can be read and edited, a schedule can only be saved switched
//! off (`app.lists.schedule.unavailable`), and no next event is shown. Both follow
//! `SchedulerStatus` (`ready`, `next`), so they become live as soon as the task runs.
use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::sync::watch;
use vpnte_automation::coordinator::{
    ConnectOutcome, ConnectRequest, Coordinator, LifecycleEvent, NoticeCategory, OpError,
    RuntimeId, SessionInfo, SwitchError,
};
use vpnte_automation::schedule::ScheduleMode as CoreMode;
use vpnte_automation::schedule::{HhMm as CoreHhMm, ScheduleEntry as CoreEntry};
use vpnte_automation::scheduler::{BoundaryKind, ScheduleDraft, Scheduler, Schedules, Upcoming};
use vpnte_base::types::{AdaptiveMode, Notice, Owner};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::store::Store;
use vpnte_servers::store::{Servers, ServersEvent};
use vpnte_ui::schedule::{
    HhMm, NextAction, NextEvent, ScheduleApi, ScheduleEntry, ScheduleInput, ScheduleMode,
    ScheduleSnapshot, ServerChoice,
};
use vpnte_ui::widgets::Load;

use super::refused;
use crate::api_settings::blocking;
use crate::services::Backend;

/// [`ScheduleApi`] over the scheduler's list API.
pub struct ScheduleService(Arc<Shared>);

/// State shared by the actions and the projection task.
struct Shared {
    backend: Arc<Backend>,
    /// `schedules.json`: this package is the only one that opens it.
    store: Arc<Store<Schedules>>,
    scheduler: Scheduler<Unwired>,
    state: watch::Sender<ScheduleSnapshot>,
    /// Serialises the read-modify-write of `set_enabled` with every other change.
    writes: Mutex<()>,
    /// Projection and send as one step, so a slower projection never sends an older list
    /// after a newer one (actions and the projection task both publish).
    publishing: Mutex<()>,
}

impl ScheduleService {
    /// Opens the schedule list, publishes the first snapshot and starts the projection task.
    /// Call it inside the tokio runtime.
    pub fn start(backend: Arc<Backend>) -> Self {
        let store = Arc::new(Store::<Schedules>::open(&backend.dirs.root));
        let scheduler = Scheduler::new(store.clone(), Arc::new(Unwired));
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

impl Shared {
    /// Projects the list, the next event and the servers; sends only a changed snapshot.
    fn publish(&self) {
        let _one = self.publishing.lock();
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

    /// Enabling needs the reconcile task: without it an enabled schedule would look armed and
    /// never start the VPN.
    fn may_enable(&self) -> AppResult<()> {
        if self.scheduler.status().borrow().ready {
            Ok(())
        } else {
            Err(refused("app.lists.schedule.unavailable"))
        }
    }

    /// The scheduler's draft for `input`. «Текущий сервер» (an empty server of a Direct
    /// schedule) becomes the server selected now: the scheduler stores a concrete one.
    fn draft(&self, input: ScheduleInput) -> AppResult<ScheduleDraft> {
        if input.enabled {
            self.may_enable()?;
        }
        let profile_id = if input.mode.uses_profile() && input.profile_id.trim().is_empty() {
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
            mode: core_mode(input.mode),
        })
    }
}

#[async_trait(?Send)]
impl ScheduleApi for ScheduleService {
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
        // page drops this call.
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
            if enabled {
                shared.may_enable()?;
            }
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
async fn follow(shared: Arc<Shared>) {
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
        mode: ui_mode(e.mode),
    })
}

/// The reconcile task's next boundary, named after its schedule.
fn next_event(upcoming: &Upcoming, entries: &[CoreEntry]) -> Option<NextEvent> {
    let entry = entries.iter().find(|e| e.id == upcoming.schedule_id)?;
    Some(NextEvent {
        action: match upcoming.kind {
            BoundaryKind::Start => NextAction::Start,
            BoundaryKind::Stop => NextAction::Stop,
        },
        at: upcoming.at,
        name: entry.name.clone(),
    })
}

/// Servers a Direct schedule can use: not archived, readable on this PC (name and protocol
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

fn ui_mode(mode: CoreMode) -> ScheduleMode {
    match mode {
        CoreMode::Hard => ScheduleMode::Hard,
        CoreMode::Soft => ScheduleMode::Soft,
        CoreMode::Direct => ScheduleMode::Direct,
    }
}

fn core_mode(mode: ScheduleMode) -> CoreMode {
    match mode {
        ScheduleMode::Hard => CoreMode::Hard,
        ScheduleMode::Soft => CoreMode::Soft,
        ScheduleMode::Direct => CoreMode::Direct,
    }
}

/// The coordinator of a scheduler whose reconcile task does not run in this build: the list API
/// of [`Scheduler`] needs one, and none of these methods is reached while `run` is not spawned.
/// Should it ever run, every tunnel operation is refused with the page's own sentence and no
/// session is claimed.
struct Unwired;

fn unwired() -> OpError {
    OpError::Failed(refused("app.lists.schedule.unavailable"))
}

impl Coordinator for Unwired {
    fn session(&self) -> Option<SessionInfo> {
        None
    }

    fn busy(&self) -> bool {
        false
    }

    fn connect(
        &self,
        _owner: Owner,
        _req: ConnectRequest,
    ) -> impl Future<Output = Result<ConnectOutcome, OpError>> + Send {
        std::future::ready(Err(unwired()))
    }

    fn disconnect(&self, _owner: Owner) -> impl Future<Output = Result<(), OpError>> + Send {
        // No session of the scheduler's exists, so there is nothing to stop.
        std::future::ready(Ok(()))
    }

    fn switch_profile(
        &self,
        _owner: Owner,
        _profile_id: &str,
    ) -> impl Future<Output = Result<(), SwitchError>> + Send {
        std::future::ready(Err(SwitchError::NotStarted(unwired())))
    }

    fn adaptive_restart(
        &self,
        _owner: Owner,
        _mode: AdaptiveMode,
        _sibling: Option<&str>,
    ) -> impl Future<Output = Result<RuntimeId, OpError>> + Send {
        std::future::ready(Err(unwired()))
    }

    fn events(&self) -> broadcast::Receiver<LifecycleEvent> {
        broadcast::channel(1).1
    }

    fn notify(&self, _category: NoticeCategory, notice: Notice) {
        tracing::warn!(
            title = %notice.title.key,
            "scheduler notice without a coordinator"
        );
    }
}
