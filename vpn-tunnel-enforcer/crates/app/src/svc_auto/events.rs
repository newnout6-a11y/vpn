//! The forwarder task: the lane's session changes as automation's [`LifecycleEvent`]s, engine
//! faults, physical network changes, and the location privacy that follows the session.
use std::sync::Arc;

use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Mutex, mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_automation::adaptive::identity;
use vpnte_automation::coordinator::{LifecycleEvent, RuntimeId, StopCause};
use vpnte_automation::hardening::{self, Location};
use vpnte_base::Msg;
use vpnte_base::types::{Level, Notice, OutboundFault, Owner};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_tunnel::api::{Runtime, TunStatusKind, TunnelEvent};
use vpnte_tunnel::lifecycle::{SessionEvent, SessionView};
use vpnte_tunnel::outcome::OutcomeKind;
use vpnte_winnet::adapters::NetChange;

use super::coord::AppCoordinator;
use super::decide;
use crate::svc_core::notify::{NoticeCategory, Notifier};

/// Location privacy for the length of a session (`settings.location_privacy`, NOADMIN §3).
pub struct Privacy {
    pub location: Location,
    settings: Arc<Store<Settings>>,
    notifier: Arc<Notifier>,
    /// The lane's session as it is now (not a page's debounced projection of it).
    session: watch::Receiver<Option<SessionView>>,
    /// One change at a time: the forwarder's session up / down and the Settings toggle each read
    /// the setting and the session and then apply or roll back under it, so a toggle never lands
    /// between another one's read and its write.
    one: Mutex<()>,
}

/// What a toggle did with the consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Followed {
    /// The consent follows the setting now (denied with a session, given back without).
    Applied,
    /// Windows refused the change: the consent is as it was.
    NotApplied,
    /// Nothing to do until the next connect.
    Stored,
}

impl Privacy {
    pub fn new(
        location: Location,
        settings: Arc<Store<Settings>>,
        notifier: Arc<Notifier>,
        session: watch::Receiver<Option<SessionView>>,
    ) -> Self {
        Self {
            location,
            settings,
            notifier,
            session,
            one: Mutex::new(()),
        }
    }

    fn running(&self) -> bool {
        self.session.borrow().is_some()
    }

    /// Connected: the user's location consent is denied while the setting is on.
    pub async fn session_up(&self) {
        let _one = self.one.lock().await;
        self.deny_if_wanted().await;
    }

    /// The session ended (or the app quits / recovers): the consent goes back to the user's.
    pub async fn session_down(&self) {
        let _one = self.one.lock().await;
        self.give_back().await;
    }

    /// The Settings toggle changed `settings.location_privacy`: the consent follows at once,
    /// judged by the lane's session itself; denied only while a session runs.
    pub async fn follow_setting(&self) -> Followed {
        let _one = self.one.lock().await;
        let on = self.settings.read(|s| s.location_privacy);
        let held = self.location.is_applied();
        if on && self.running() {
            self.deny_if_wanted().await;
        }
        // Denied only while a session runs: it may have ended meanwhile, or never begun.
        if !(on && self.running()) {
            self.give_back().await;
        }
        let applied = self.location.is_applied();
        let done = |ok: bool| {
            if ok {
                Followed::Applied
            } else {
                Followed::NotApplied
            }
        };
        match (on, self.running()) {
            (true, true) => done(applied),
            (false, _) if held => done(!applied),
            _ => Followed::Stored,
        }
    }

    async fn deny_if_wanted(&self) {
        let on = self.settings.read(|s| s.location_privacy);
        if !on || !self.running() || self.location.is_applied() {
            return;
        }
        if let Err(e) = self.location.apply().await {
            tracing::warn!(error = %e, "location privacy not applied");
            self.warn(e.user_msg());
        }
    }

    async fn give_back(&self) {
        if !self.location.is_applied() {
            return;
        }
        match self.location.rollback().await {
            Ok(report) => {
                if let Some(msg) = hardening::location::rollback_failure_msg(&report) {
                    self.warn(msg);
                }
            }
            Err(e) => self.warn(e.user_msg()),
        }
    }

    fn warn(&self, msg: Msg) {
        let notice = Notice::new(Level::Warn, msg);
        self.notifier
            .notify(notice, Some(NoticeCategory::ConnectionError));
    }
}

/// Why a session ended, as automation reads it: a stop this coordinator asked for names its
/// owner; the user's and the schedule's stops theirs; anything unasked is a fault.
pub fn stop_cause(outcome: OutcomeKind, asked: Option<Owner>) -> StopCause {
    match (outcome, asked) {
        (OutcomeKind::AppQuit, _) => StopCause::Shutdown,
        (OutcomeKind::UserStop, _) => StopCause::Requested(Owner::Manual),
        (OutcomeKind::Schedule, _) => StopCause::Requested(Owner::Schedule),
        (_, Some(owner)) => StopCause::Requested(owner),
        _ => StopCause::Fault,
    }
}

/// The lifecycle event of a session change; `None` for the row of a session another run
/// replaces at once (a switch that took, a failover: only its `Started` goes out). A switch that
/// lost the tunnel ends the session with the switch's outcome and nothing after it: `Stopped`.
pub fn lifecycle_event(event: &SessionEvent, asked: Option<Owner>) -> Option<LifecycleEvent> {
    match event {
        SessionEvent::Up(view) => {
            let info = decide::session_info(view);
            Some(LifecycleEvent::Started {
                owner: info.owner,
                runtime_id: info.runtime_id,
                kind: info.kind,
                profile_id: info.profile_id,
                mode: info.mode,
            })
        }
        SessionEvent::Ended {
            continues: true, ..
        } => None,
        SessionEvent::Ended {
            session, outcome, ..
        } => Some(LifecycleEvent::Stopped {
            owner: session.owner,
            runtime_id: RuntimeId(session.generation.unwrap_or(0)),
            cause: stop_cause(*outcome, asked),
        }),
    }
}

/// Session changes as lifecycle events (and location privacy with them), until `cancel`.
pub async fn sessions(
    coord: Arc<AppCoordinator>,
    privacy: Option<Arc<Privacy>>,
    cancel: CancellationToken,
) {
    let mut sessions = coord.lane.events();
    loop {
        let event = tokio::select! {
            () = cancel.cancelled() => return,
            event = sessions.recv() => event,
        };
        match event {
            Ok(event) => on_session(&coord, privacy.as_deref(), &event).await,
            Err(RecvError::Lagged(_)) => resync(&coord, privacy.as_deref()).await,
            Err(RecvError::Closed) => return,
        }
    }
}

/// Engine faults and physical network changes as lifecycle events, until `cancel`. `changes` =
/// the network watch (`None`: no network-change events; the reactions' memory then lasts the
/// app run).
pub async fn engine(
    coord: Arc<AppCoordinator>,
    runtime: Arc<dyn Runtime>,
    mut changes: Option<mpsc::Receiver<NetChange>>,
    cancel: CancellationToken,
) {
    let mut engine = runtime.subscribe();
    let mut network = identity::read().await;
    let mut fault: Option<(RuntimeId, OutboundFault)> = None;
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            event = engine.recv() => match event {
                Ok(TunnelEvent::Status(
                    TunStatusKind::Restarting { .. } | TunStatusKind::ProxyDown { .. },
                )) => on_fault(&coord, runtime.recent_fault(), &mut fault),
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return,
            },
            Some(_) = next_change(&mut changes) => {
                // Our own TUN coming and going changes the adapter list too: only another
                // physical network (gateway, adapter) counts.
                let now = identity::read().await;
                if now.is_none() || now != network {
                    network = now;
                    let _ = coord.events.send(LifecycleEvent::NetworkChanged);
                }
            }
        }
    }
}

async fn next_change(changes: &mut Option<mpsc::Receiver<NetChange>>) -> Option<NetChange> {
    match changes {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

async fn on_session(coord: &AppCoordinator, privacy: Option<&Privacy>, event: &SessionEvent) {
    let asked = match event {
        SessionEvent::Ended {
            continues: false, ..
        } => coord.pending_stop.lock().take(),
        SessionEvent::Ended { .. } | SessionEvent::Up(_) => None,
    };
    let Some(mapped) = lifecycle_event(event, asked) else {
        return;
    };
    let up = match &mapped {
        LifecycleEvent::Started { runtime_id, .. } => Some(runtime_id.0),
        _ => None,
    };
    let _ = coord.events.send(mapped);
    if let Some(generation) = up {
        coord.started.send_replace(generation);
    }
    if let Some(privacy) = privacy {
        match up {
            Some(_) => privacy.session_up().await,
            None => privacy.session_down().await,
        }
    }
}

/// Session events were lost: what runs now is the latest truth (a missed end must not leave the
/// location consent denied).
async fn resync(coord: &AppCoordinator, privacy: Option<&Privacy>) {
    use vpnte_automation::coordinator::Coordinator;
    let session = coord.session();
    if let Some(info) = &session {
        let _ = coord.events.send(LifecycleEvent::Started {
            owner: info.owner,
            runtime_id: info.runtime_id,
            kind: info.kind,
            profile_id: info.profile_id.clone(),
            mode: info.mode,
        });
        coord.started.send_replace(info.runtime_id.0);
    }
    match (privacy, session) {
        (Some(privacy), Some(_)) => privacy.session_up().await,
        (Some(privacy), None) => privacy.session_down().await,
        (None, _) => {}
    }
}

/// An upstream fault of the running engine (once per run and fault).
fn on_fault(
    coord: &AppCoordinator,
    seen: Option<OutboundFault>,
    last: &mut Option<(RuntimeId, OutboundFault)>,
) {
    use vpnte_automation::coordinator::Coordinator;
    let (Some(fault), Some(info)) = (seen, coord.session()) else {
        return;
    };
    let key = (info.runtime_id, fault);
    if *last != Some(key) {
        *last = Some(key);
        let _ = coord.events.send(LifecycleEvent::Fault {
            runtime_id: info.runtime_id,
            fault,
        });
    }
}
