//! [`AppCoordinator`]: the automation `Coordinator` over the tunnel lifecycle. Every tunnel change
//! automation asks for goes through here, so the owner order (a higher owner pre-empts a lower
//! one, never the reverse) is applied in one place; the user's own starts pass [`AppCoordinator::start`]
//! too, so the adaptive bypass picks the mode of every start.
use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use tokio::sync::{broadcast, watch};
use vpnte_automation::autopick::UserActs;
use vpnte_automation::coordinator::{
    ConnectOutcome, ConnectRequest, Coordinator, LifecycleEvent, NoticeCategory, OpError,
    ProxyEndpoint, RuntimeId, SessionInfo, SessionKind, SwitchError,
};
use vpnte_base::types::{AdaptiveMode, Notice, Owner, UnixMs};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::ops::Source;
use vpnte_servers::model::{HealthReason, HealthRecord, ProfileId};
use vpnte_servers::store::{HealthUpdate, SelectBy, Servers};
use vpnte_tunnel::lifecycle::{
    ConnError, ConnectReq, ConnectTarget, DisconnectReq, Done, SwitchReq,
};

use super::decide::{self, Admit};
use super::lane::Lane;
use super::{AppAdaptive, ServerHost};
use crate::svc_core::notify::{self, Notifier};

/// The local proxy a manual connect would use: the settings override, else detection.
pub type Detect = Arc<dyn Fn() -> BoxFuture<'static, Option<ProxyEndpoint>> + Send + Sync>;

/// How long `adaptive_restart` waits for its run's `Started` to go out (the forwarder task).
const STARTED_WAIT: Duration = Duration::from_secs(5);
/// How long a restore after a lost switch waits for the lane's own recovery stop (a Soft
/// rollback and an engine stop: seconds; its own budget is the lane's 120 s).
const RESTORE_WAIT: Duration = Duration::from_secs(30);

/// What the user did, as the automatic paths count it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAct {
    /// Connect (window or tray).
    Connect,
    /// Disconnect, or Cancel of a connect or switch in flight: nothing automatic until the user
    /// connects again.
    Stop,
    /// A server picked by hand.
    Pick,
    /// A changed setting.
    Change,
    /// «Отменить» on the automatic choice's strip: every automatic step stops and the session
    /// that runs stays as it is, left alone until the user acts again or another session starts
    /// (psmall-b1/b2).
    EndAuto,
}

/// The adaptive bypass and the profile views it starts from (set once after both exist: they
/// hold the coordinator themselves).
pub struct Hooks {
    pub adaptive: Arc<AppAdaptive>,
    pub host: Arc<ServerHost>,
}

/// A start's adaptive preparation until the lane answered. A start dropped before that (a
/// reaction or rotation attempt cancelled mid-connect) never reaches `start_failed` and would
/// hold the adaptive status at "connecting" for minutes: dropping ends it as cancelled.
struct Preparation {
    adaptive: Arc<AppAdaptive>,
    ticket: Option<u64>,
}

impl Preparation {
    fn end(mut self, reason: Option<Msg>) {
        if let Some(ticket) = self.ticket.take() {
            self.adaptive.start_failed(ticket, reason);
        }
    }
}

impl Drop for Preparation {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            self.adaptive.start_failed(ticket, None);
        }
    }
}

pub struct AppCoordinator {
    pub(super) lane: Arc<dyn Lane>,
    servers: Arc<Servers>,
    notifier: Arc<Notifier>,
    detect: Detect,
    /// TUN capture exists in this process (elevated, NOADMIN §0).
    tun: bool,
    pub(super) events: broadcast::Sender<LifecycleEvent>,
    /// Generation of the last `Started` the forwarder sent.
    pub(super) started: watch::Sender<u64>,
    /// A stop this coordinator asked for, so its `Stopped` names the owner (not a fault).
    pub(super) pending_stop: Mutex<Option<Owner>>,
    /// The owner of a restore waiting for the lane after a lost switch; a stop meanwhile takes
    /// it (that owner's, a higher one's, the user's), and the restore then starts nothing.
    restoring: Mutex<Option<Owner>>,
    /// The user's own actions: automation that started before gives up (the automatic server
    /// choice never acts against the user).
    user_acts: watch::Sender<UserActs>,
    pub(super) hooks: OnceLock<Hooks>,
}

/// The runtime's answer to a start whose exit proof got nothing back through the server.
const SILENT_EXIT: &str = "tunnel.runtime.exitSilent";

/// Lab F-4 (p-live2): a start whose exit stayed silent proved the server dead from here. Its
/// health says so, so the automatic choices (the crash failover, the automatic pick's rank) try
/// another server first instead of this one again.
pub(super) fn silent_exit(servers: &Servers, id: &str, at: UnixMs) {
    let id = ProfileId::from(id);
    let Some(identity) = servers.get(&id).and_then(|row| row.identity()) else {
        return;
    };
    let record = HealthRecord {
        online: false,
        at,
        rtt_ms: None,
        reason: Some(HealthReason::Timeout),
        egress_ip: None,
    };
    let update = HealthUpdate {
        id,
        identity,
        record,
        country: None,
    };
    if let Err(e) = servers.record_health(vec![update]) {
        tracing::warn!(error = %e, "silent server not recorded");
    }
}

impl AppCoordinator {
    pub fn new(
        lane: Arc<dyn Lane>,
        servers: Arc<Servers>,
        notifier: Arc<Notifier>,
        detect: Detect,
        tun: bool,
    ) -> Self {
        Self {
            lane,
            servers,
            notifier,
            detect,
            tun,
            events: broadcast::channel(64).0,
            started: watch::Sender::new(0),
            pending_stop: Mutex::new(None),
            restoring: Mutex::new(None),
            user_acts: watch::Sender::new(UserActs::default()),
            hooks: OnceLock::new(),
        }
    }

    /// The user acted. A connect, a stop or a server picked by hand also drops a restore on its
    /// way after a lost switch: it must not undo the user's choice (a changed setting and the
    /// strip's «Отменить» do not decide the lane, so the restore goes on).
    pub fn user_acted(&self, act: UserAct) {
        if !matches!(act, UserAct::Change | UserAct::EndAuto) {
            self.restoring.lock().take();
        }
        self.user_acts.send_modify(|a| {
            a.seq += 1;
            a.held = act == UserAct::EndAuto;
            match act {
                UserAct::Connect => a.stopped = false,
                UserAct::Stop => a.stopped = true,
                UserAct::Pick | UserAct::Change | UserAct::EndAuto => {}
            }
        });
    }

    /// The user's own actions.
    pub fn user_acts(&self) -> watch::Receiver<UserActs> {
        self.user_acts.subscribe()
    }

    /// TUN capture exists in this process (what `connect` refuses without).
    pub fn tun_capture(&self) -> bool {
        self.tun
    }

    /// Starts `target` for `owner` in the mode the adaptive bypass picks for this network and
    /// server; a failed or cancelled start ends the bypass's run. Every start goes here.
    pub async fn start(
        &self,
        target: ConnectTarget,
        owner: Owner,
        source: Source,
    ) -> Result<Done, ConnError> {
        // The user's own connect (window or tray); a restore of their session is not one.
        if owner == Owner::Manual && matches!(source, Source::Ui | Source::Tray) {
            self.user_acted(UserAct::Connect);
        }
        let kind = decide::target_kind(&target);
        let profile = match &target {
            ConnectTarget::DirectVpn { profile_id } | ConnectTarget::SoftVpn { profile_id } => {
                profile_id.clone().or_else(|| self.active_server())
            }
            _ => None,
        };
        let mut req = ConnectReq::new(target, owner, source);
        let mut preparation = None;
        if let Some(hooks) = self.hooks.get() {
            let view = profile.as_deref().and_then(|id| hooks.host.view(id));
            let begun = hooks.adaptive.begin(kind, view).await;
            req.adaptive = begun.mode;
            preparation = Some(Preparation {
                adaptive: hooks.adaptive.clone(),
                ticket: Some(begun.ticket),
            });
        }
        let result = self.lane.connect(req).await;
        if let (Err(err), Some(id)) = (&result, profile.as_deref())
            && err.user_msg().key == SILENT_EXIT
        {
            silent_exit(&self.servers, id, vpnte_base::types::now_ms());
        }
        if let Some(mut preparation) = preparation {
            match &result {
                // Ends this start's preparation only: another start may be in flight meanwhile.
                Err(err) => {
                    let shown = !matches!(err, ConnError::Cancelled(_));
                    preparation.end(shown.then(|| err.user_msg()));
                }
                // The run's `Started` attaches it.
                Ok(_) => preparation.ticket = None,
            }
        }
        result
    }

    fn active_server(&self) -> Option<String> {
        self.servers.active().map(|a| a.row.id.0)
    }

    /// A server automation may start: in the list, not archived, readable on this PC.
    fn usable(&self, id: &str) -> Result<(), OpError> {
        let row = self.servers.get(&ProfileId::from(id));
        match row {
            Some(row) if row.archived.is_none() && !row.is_locked() => Ok(()),
            _ => Err(OpError::ProfileUnavailable),
        }
    }

    /// What `req` would start, validated before anything running is touched.
    async fn resolve(&self, req: &ConnectRequest) -> Result<ConnectTarget, OpError> {
        if req.kind().tun() && !self.tun {
            // Never fall back to Soft silently (NOADMIN §2).
            return Err(OpError::Failed(AppError::msg(
                ErrorKind::Permission,
                Msg::new("tunnel.runtime.tunUnavailable"),
            )));
        }
        if let Some(id) = req.profile_id() {
            self.usable(id)?;
        }
        let endpoint = match req {
            ConnectRequest::LocalProxyHard { endpoint } | ConnectRequest::Soft { endpoint } => {
                match endpoint {
                    Some(ep) => Some(ep.clone()),
                    None => Some((self.detect)().await.ok_or(OpError::NoLocalProxy)?),
                }
            }
            ConnectRequest::Direct { .. } | ConnectRequest::SoftDirect { .. } => None,
        };
        decide::target(req, endpoint.as_ref()).ok_or(OpError::NoLocalProxy)
    }
}

impl AppCoordinator {
    async fn connect_as(
        &self,
        owner: Owner,
        req: ConnectRequest,
    ) -> Result<ConnectOutcome, OpError> {
        let session = self.session();
        let admit = decide::admit_connect(session.as_ref(), owner, &req);
        let (switch, replace) = match admit {
            Admit::Refuse => return Err(OpError::Conflict),
            Admit::Already { adopt } => {
                if adopt {
                    self.lane.adopt(owner);
                }
                return Ok(ConnectOutcome::AlreadyConnected);
            }
            Admit::Switch => (true, false),
            Admit::Replace => (false, true),
            Admit::Start => (false, false),
        };
        let target = self.resolve(&req).await?;
        if switch {
            let id = req.profile_id().unwrap_or_default();
            self.switch_as(owner, id).await.map_err(|e| match e {
                SwitchError::NotStarted(reason) | SwitchError::Failed { reason, .. } => reason,
            })?;
            if session.is_some_and(|s| owner > s.owner) {
                self.lane.adopt(owner);
            }
            return Ok(ConnectOutcome::Connected);
        }
        if replace {
            self.stop_as(owner).await?;
        }
        self.start(target, owner, Source::Lifecycle)
            .await
            .map_err(decide::op_error)?;
        Ok(ConnectOutcome::Connected)
    }

    async fn stop_as(&self, owner: Owner) -> Result<(), OpError> {
        let session = self.session();
        if session.is_none() {
            return self.release(owner).await;
        }
        if !decide::admit_disconnect(session.as_ref(), owner)? {
            return Ok(());
        }
        *self.pending_stop.lock() = Some(owner);
        let req = DisconnectReq::new(decide::stop_cause(owner), owner, Source::Lifecycle);
        let result = self.lane.disconnect(req).await;
        if result.is_err() {
            self.pending_stop.lock().take();
        }
        result.map(drop).map_err(decide::op_error)
    }

    /// No session runs: releases what a session of `owner` (or of a lower owner) left in the
    /// lane: a restore on its way, the kill switch's block of a kept stop. A full stop; no
    /// `pending_stop` (no session ends, so no `Ended` would take it).
    async fn release(&self, owner: Owner) -> Result<(), OpError> {
        let restore = self.restoring.lock().take_if(|o| *o <= owner).is_some();
        let kept = self.lane.kept_by().is_some_and(|o| o <= owner);
        if !restore && !kept {
            return Ok(());
        }
        let req = DisconnectReq::new(decide::stop_cause(owner), owner, Source::Lifecycle);
        let result = self.lane.disconnect(req).await;
        result.map(drop).map_err(decide::op_error)
    }

    /// Moves a session over the server list to `id`, keeping its capture and owner; the
    /// selection follows only a success. A switch that never took leaves the previous server
    /// running (`NotStarted`); one that lost it brings it back under the session's owner.
    async fn switch_as(&self, owner: Owner, id: &str) -> Result<(), SwitchError> {
        let before = self
            .session()
            .filter(|s| s.kind.server())
            .ok_or(SwitchError::NotStarted(OpError::Conflict))?;
        if before.profile_id.as_deref() == Some(id) {
            return Ok(());
        }
        self.usable(id).map_err(SwitchError::NotStarted)?;
        let req = SwitchReq::new(id, owner, Source::Lifecycle);
        let Err(err) = self.lane.switch(req, owner == Owner::Rotation).await else {
            self.commit_selection(id).await;
            return Ok(());
        };
        let reason = decide::op_error(err);
        let now = self.session();
        if now
            .as_ref()
            .is_some_and(|s| s.profile_id == before.profile_id)
        {
            return Err(SwitchError::NotStarted(reason));
        }
        let restored = match (now, before.profile_id) {
            (None, Some(previous)) => self.restore(before.kind, previous, before.owner).await,
            _ => false,
        };
        Err(SwitchError::Failed {
            reason,
            restored_previous: restored,
        })
    }

    /// Starts the previous server again after a failed switch, once the lane's own recovery stop
    /// let go of the lane (the switch answers before that stop ran: a start right then would be
    /// refused); `false` leaves nothing running. A stop that came meanwhile (the user's, the
    /// owner's run ending) wins: nothing starts, or what started is stopped again.
    async fn restore(&self, kind: SessionKind, previous: String, owner: Owner) -> bool {
        *self.restoring.lock() = Some(owner);
        if tokio::time::timeout(RESTORE_WAIT, self.lane.idle())
            .await
            .is_err()
        {
            self.restoring.lock().take();
            tracing::warn!("previous server not restored: the lane is still busy");
            return false;
        }
        if self.restoring.lock().is_none() {
            tracing::info!("previous server not restored: stopped while waiting for the lane");
            return false;
        }
        let profile_id = Some(previous);
        let target = match kind {
            SessionKind::SoftDirect => ConnectTarget::SoftVpn { profile_id },
            _ => ConnectTarget::DirectVpn { profile_id },
        };
        let started = self.start(target, owner, Source::Lifecycle).await.is_ok();
        let stopped = self.restoring.lock().take().is_none();
        if started && stopped {
            // The stop reached the lane before this start did: it still wins.
            if let Err(e) = self.stop_as(owner).await {
                tracing::warn!(error = %e, "restored server not stopped again");
            }
            return false;
        }
        started
    }

    async fn commit_selection(&self, id: &str) {
        let (servers, id) = (self.servers.clone(), ProfileId::from(id));
        let selected =
            tokio::task::spawn_blocking(move || servers.select(&id, SelectBy::Automation));
        match selected.await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "switched server not saved as the selection"),
            Err(e) => tracing::warn!(error = %e, "selection task failed"),
        }
    }

    async fn restart_as(
        &self,
        owner: Owner,
        mode: AdaptiveMode,
        sibling: Option<String>,
    ) -> Result<RuntimeId, OpError> {
        self.lane
            .restart_adaptive(mode, sibling, owner)
            .await
            .map_err(decide::op_error)?;
        let runtime = self
            .session()
            .map(|s| s.runtime_id)
            .ok_or(OpError::Cancelled)?;
        // The contract: the caller hears of the new run only after its `Started` went out.
        let mut started = self.started.subscribe();
        let sent = started.wait_for(|g| *g >= runtime.0);
        if tokio::time::timeout(STARTED_WAIT, sent).await.is_err() {
            tracing::warn!("adaptive restart: Started not forwarded in time");
        }
        Ok(runtime)
    }
}

impl Coordinator for AppCoordinator {
    fn session(&self) -> Option<SessionInfo> {
        self.lane
            .session()
            .borrow()
            .as_ref()
            .map(decide::session_info)
    }

    fn left_by(&self) -> Option<Owner> {
        if self.session().is_some() {
            return None;
        }
        let restoring = *self.restoring.lock();
        restoring.or_else(|| self.lane.kept_by())
    }

    fn busy(&self) -> bool {
        self.lane.busy()
    }

    fn connect(
        &self,
        owner: Owner,
        req: ConnectRequest,
    ) -> impl Future<Output = Result<ConnectOutcome, OpError>> + Send {
        self.connect_as(owner, req)
    }

    fn disconnect(&self, owner: Owner) -> impl Future<Output = Result<(), OpError>> + Send {
        self.stop_as(owner)
    }

    fn switch_profile(
        &self,
        owner: Owner,
        profile_id: &str,
    ) -> impl Future<Output = Result<(), SwitchError>> + Send {
        let id = profile_id.to_owned();
        async move { self.switch_as(owner, &id).await }
    }

    fn adaptive_restart(
        &self,
        owner: Owner,
        mode: AdaptiveMode,
        sibling: Option<&str>,
    ) -> impl Future<Output = Result<RuntimeId, OpError>> + Send {
        self.restart_as(owner, mode, sibling.map(str::to_owned))
    }

    fn events(&self) -> broadcast::Receiver<LifecycleEvent> {
        self.events.subscribe()
    }

    fn notify(&self, category: NoticeCategory, notice: Notice) {
        let category = match category {
            NoticeCategory::ScheduleTriggered => notify::NoticeCategory::ScheduleTriggered,
            NoticeCategory::ProfileRotation => notify::NoticeCategory::ProfileRotation,
            NoticeCategory::ConnectionError => notify::NoticeCategory::ConnectionError,
        };
        self.notifier.notify(notice, Some(category));
    }
}
