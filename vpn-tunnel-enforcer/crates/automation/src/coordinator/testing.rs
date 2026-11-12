//! Test double of the [`Coordinator`] shared by the scheduler, rotation, AutoPilot and adaptive
//! bypass tests.
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::Mutex;

use super::*;

/// A coordinator call, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Call {
    Connect(Owner, ConnectRequest),
    Disconnect(Owner),
    Switch(Owner, String),
}

/// In-memory coordinator: scripted results, otherwise the contract's happy path.
pub(crate) struct FakeCoordinator {
    pub(crate) session: Mutex<Option<SessionInfo>>,
    pub(crate) calls: Mutex<Vec<Call>>,
    pub(crate) connect_results: Mutex<VecDeque<Result<ConnectOutcome, OpError>>>,
    pub(crate) switch_results: Mutex<VecDeque<Result<(), SwitchError>>>,
    pub(crate) notices: Mutex<Vec<(NoticeCategory, Notice)>>,
    pub(crate) events: broadcast::Sender<LifecycleEvent>,
    /// Emitted while the next connect runs: a manual action racing a scheduled connect.
    pub(crate) during_connect: Mutex<Option<LifecycleEvent>>,
    /// Every `adaptive_restart` as `(mode, sibling)`, in order.
    pub(crate) restarts: Mutex<Vec<(AdaptiveMode, Option<String>)>>,
    /// Scripted `adaptive_restart` results; exhausted = success.
    pub(crate) restart_results: Mutex<VecDeque<Result<(), OpError>>>,
    /// Emitted while the next restart runs (a manual action racing it); a `Started` also
    /// replaces the session.
    pub(crate) during_restart: Mutex<Option<LifecycleEvent>>,
    /// A failed restart ends the session with `Stopped { cause: Fault }` (protected restart).
    pub(crate) end_on_error: AtomicBool,
    /// Runtime ids are handed out from 100 up, so literal ids below 100 in tests never collide.
    next_runtime: AtomicU64,
}

impl FakeCoordinator {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            session: Mutex::new(None),
            calls: Mutex::new(Vec::new()),
            connect_results: Mutex::new(VecDeque::new()),
            switch_results: Mutex::new(VecDeque::new()),
            notices: Mutex::new(Vec::new()),
            events: broadcast::channel(64).0,
            during_connect: Mutex::new(None),
            restarts: Mutex::new(Vec::new()),
            restart_results: Mutex::new(VecDeque::new()),
            during_restart: Mutex::new(None),
            end_on_error: AtomicBool::new(false),
            next_runtime: AtomicU64::new(100),
        })
    }

    fn fresh_runtime(&self) -> u64 {
        self.next_runtime.fetch_add(1, Ordering::SeqCst)
    }

    /// Ends the session (if any) with `cause`.
    pub(crate) fn stop(&self, cause: StopCause) {
        if let Some(s) = self.session.lock().take() {
            self.emit(LifecycleEvent::Stopped {
                owner: s.owner,
                runtime_id: s.runtime_id,
                cause,
            });
        }
    }

    pub(crate) fn set_session(&self, kind: SessionKind, owner: Owner, profile: Option<&str>) {
        *self.session.lock() = Some(SessionInfo {
            kind,
            owner,
            profile_id: profile.map(str::to_owned),
            runtime_id: RuntimeId(self.fresh_runtime()),
            mode: AdaptiveMode::Baseline,
        });
    }

    pub(crate) fn calls(&self) -> Vec<Call> {
        self.calls.lock().clone()
    }

    pub(crate) fn connects(&self) -> usize {
        self.calls()
            .iter()
            .filter(|c| matches!(c, Call::Connect(..)))
            .count()
    }

    pub(crate) fn disconnects(&self) -> usize {
        self.calls()
            .iter()
            .filter(|c| matches!(c, Call::Disconnect(..)))
            .count()
    }

    /// Title and body keys of every notice, in order.
    pub(crate) fn notice_keys(&self) -> Vec<String> {
        let notices = self.notices.lock();
        let keys = notices.iter().flat_map(|(_, n)| {
            std::iter::once(n.title.key.to_string()).chain(n.body.iter().map(|b| b.key.to_string()))
        });
        keys.collect()
    }

    pub(crate) fn emit(&self, event: LifecycleEvent) {
        let _ = self.events.send(event);
    }

    fn do_connect(&self, owner: Owner, req: ConnectRequest) -> Result<ConnectOutcome, OpError> {
        self.calls.lock().push(Call::Connect(owner, req.clone()));
        if let Some(event) = self.during_connect.lock().take() {
            self.emit(event);
        }
        let profile_id = match &req {
            ConnectRequest::Direct { profile_id } => Some(profile_id.clone()),
            _ => None,
        };
        let mut session = self.session.lock();
        let same = session
            .as_ref()
            .is_some_and(|s| s.kind == req.kind() && s.profile_id == profile_id);
        let scripted = self.connect_results.lock().pop_front();
        let result = scripted.unwrap_or(Ok(if same {
            ConnectOutcome::AlreadyConnected
        } else {
            ConnectOutcome::Connected
        }));
        match (&result, session.as_mut()) {
            (Ok(ConnectOutcome::AlreadyConnected), Some(s)) => s.owner = s.owner.max(owner),
            (Ok(_), _) => {
                *session = Some(SessionInfo {
                    kind: req.kind(),
                    owner,
                    profile_id,
                    runtime_id: RuntimeId(self.fresh_runtime()),
                    mode: AdaptiveMode::Baseline,
                });
            }
            (Err(_), _) => {}
        }
        result
    }

    fn do_disconnect(&self, owner: Owner) -> Result<(), OpError> {
        self.calls.lock().push(Call::Disconnect(owner));
        let mut session = self.session.lock();
        if session.as_ref().is_some_and(|s| s.owner > owner) {
            return Err(OpError::Conflict);
        }
        *session = None;
        Ok(())
    }

    fn do_switch(&self, owner: Owner, profile_id: &str) -> Result<(), SwitchError> {
        self.calls
            .lock()
            .push(Call::Switch(owner, profile_id.to_owned()));
        let result = self.switch_results.lock().pop_front().unwrap_or(Ok(()));
        if result.is_ok()
            && let Some(s) = self.session.lock().as_mut()
        {
            s.profile_id = Some(profile_id.to_owned());
            s.runtime_id = RuntimeId(self.fresh_runtime());
        }
        result
    }
}

/// Driving the session from the adaptive bypass tests.
impl FakeCoordinator {
    /// A tunnel start by someone else (the app's connect path, a crash restart, a switch): the
    /// session becomes the user's and `Started` is emitted.
    pub(crate) fn start(
        &self,
        kind: SessionKind,
        profile: Option<&str>,
        mode: AdaptiveMode,
    ) -> RuntimeId {
        let runtime_id = RuntimeId(self.fresh_runtime());
        let profile_id = profile.map(str::to_owned);
        *self.session.lock() = Some(SessionInfo {
            kind,
            owner: Owner::Manual,
            profile_id: profile_id.clone(),
            runtime_id,
            mode,
        });
        self.emit(LifecycleEvent::Started {
            owner: Owner::Manual,
            runtime_id,
            kind,
            profile_id,
            mode,
        });
        runtime_id
    }

    pub(crate) fn restarts(&self) -> Vec<(AdaptiveMode, Option<String>)> {
        self.restarts.lock().clone()
    }

    /// Runtime of the running session; panics without one.
    pub(crate) fn runtime(&self) -> RuntimeId {
        self.session.lock().as_ref().unwrap().runtime_id
    }
}

impl Coordinator for FakeCoordinator {
    fn session(&self) -> Option<SessionInfo> {
        self.session.lock().clone()
    }

    fn busy(&self) -> bool {
        false
    }

    async fn connect(&self, owner: Owner, req: ConnectRequest) -> Result<ConnectOutcome, OpError> {
        self.do_connect(owner, req)
    }

    async fn disconnect(&self, owner: Owner) -> Result<(), OpError> {
        self.do_disconnect(owner)
    }

    async fn switch_profile(&self, owner: Owner, profile_id: &str) -> Result<(), SwitchError> {
        self.do_switch(owner, profile_id)
    }

    async fn adaptive_restart(
        &self,
        owner: Owner,
        mode: AdaptiveMode,
        sibling: Option<&str>,
    ) -> Result<RuntimeId, OpError> {
        assert_eq!(owner, Owner::AdaptiveRetry);
        self.restarts
            .lock()
            .push((mode, sibling.map(str::to_owned)));
        if let Some(event) = self.during_restart.lock().take() {
            if let LifecycleEvent::Started {
                runtime_id,
                kind,
                ref profile_id,
                mode,
                ..
            } = event
            {
                *self.session.lock() = Some(SessionInfo {
                    kind,
                    owner: Owner::Manual,
                    profile_id: profile_id.clone(),
                    runtime_id,
                    mode,
                });
            }
            self.emit(event);
        }
        tokio::task::yield_now().await;
        if let Err(err) = self.restart_results.lock().pop_front().unwrap_or(Ok(())) {
            if self.end_on_error.load(Ordering::SeqCst) {
                self.stop(StopCause::Fault);
            }
            return Err(err);
        }
        let mut session = self.session.lock();
        let s = session.as_mut().ok_or(OpError::Cancelled)?;
        s.runtime_id = RuntimeId(self.fresh_runtime());
        s.mode = mode;
        if let Some(id) = sibling {
            s.profile_id = Some(id.to_owned());
        }
        self.emit(LifecycleEvent::Started {
            owner: s.owner,
            runtime_id: s.runtime_id,
            kind: s.kind,
            profile_id: s.profile_id.clone(),
            mode,
        });
        Ok(s.runtime_id)
    }

    fn events(&self) -> broadcast::Receiver<LifecycleEvent> {
        self.events.subscribe()
    }

    fn notify(&self, category: NoticeCategory, notice: Notice) {
        self.notices.lock().push((category, notice));
    }
}
