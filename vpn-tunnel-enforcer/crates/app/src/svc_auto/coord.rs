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
use vpnte_automation::coordinator::{
    ConnectOutcome, ConnectRequest, Coordinator, LifecycleEvent, NoticeCategory, OpError,
    ProxyEndpoint, RuntimeId, SessionInfo, SessionKind, SwitchError,
};
use vpnte_base::types::{AdaptiveMode, Notice, Owner};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::ops::Source;
use vpnte_servers::model::ProfileId;
use vpnte_servers::store::{SelectBy, Servers};
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

/// The adaptive bypass and the profile views it starts from (set once after both exist: they
/// hold the coordinator themselves).
pub struct Hooks {
    pub adaptive: Arc<AppAdaptive>,
    pub host: Arc<ServerHost>,
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
    pub(super) hooks: OnceLock<Hooks>,
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
            hooks: OnceLock::new(),
        }
    }

    /// Starts `target` for `owner` in the mode the adaptive bypass picks for this network and
    /// server; a failed or cancelled start ends the bypass's run. Every start goes here.
    pub async fn start(
        &self,
        target: ConnectTarget,
        owner: Owner,
        source: Source,
    ) -> Result<Done, ConnError> {
        let kind = decide::target_kind(&target);
        let profile = match &target {
            ConnectTarget::DirectVpn { profile_id } | ConnectTarget::SoftVpn { profile_id } => {
                profile_id.clone().or_else(|| self.active_server())
            }
            _ => None,
        };
        let mut req = ConnectReq::new(target, owner, source);
        if let Some(hooks) = self.hooks.get() {
            let view = profile.as_deref().and_then(|id| hooks.host.view(id));
            req.adaptive = hooks.adaptive.begin(kind, view).await;
        }
        let result = self.lane.connect(req).await;
        if let (Err(err), Some(hooks)) = (&result, self.hooks.get()) {
            let shown = !matches!(err, ConnError::Cancelled(_));
            hooks.adaptive.start_failed(shown.then(|| err.user_msg()));
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
        if !decide::admit_disconnect(self.session().as_ref(), owner)? {
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

    /// Starts the previous server again after a failed switch; `false` leaves nothing running
    /// (the lane's own recovery stop undid the failed start).
    async fn restore(&self, kind: SessionKind, previous: String, owner: Owner) -> bool {
        let profile_id = Some(previous);
        let target = match kind {
            SessionKind::SoftDirect => ConnectTarget::SoftVpn { profile_id },
            _ => ConnectTarget::DirectVpn { profile_id },
        };
        self.start(target, owner, Source::Lifecycle).await.is_ok()
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
