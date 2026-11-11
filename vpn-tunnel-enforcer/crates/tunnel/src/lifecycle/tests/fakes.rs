//! Fakes of every collaborator, a temp-dir history and a harness that wires them to a lifecycle.
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Engine, Notice, OutboundFault, ProxyKind, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use crate::api::{
    ExitInfo, ModeKind, OwnerCheck, RestartOptions, Runtime, StartReceipt, StartRequest,
    StopOptions, StopReceipt, SwitchReceipt, TunError, TunStatus, TunStatusKind, TunnelEvent,
    VpnProfile,
};
use crate::test_support::TempDir;

/// A latch tests open to let a blocked fake continue.
#[derive(Clone)]
pub struct Gate(Arc<watch::Sender<bool>>);

impl Gate {
    pub fn new() -> Self {
        Self(Arc::new(watch::channel(false).0))
    }
    pub fn open(&self) {
        self.0.send_replace(true);
    }
    pub async fn wait(&self) {
        let mut rx = self.0.subscribe();
        let _ = rx.wait_for(|open| *open).await;
    }
}

/// Scripted behaviour and counters of the fake runtime.
#[derive(Default)]
pub struct RtScript {
    pub starts: u32,
    pub stops: u32,
    pub switches: u32,
    pub restarts: u32,
    pub requests: Vec<StartRequest>,
    /// The next start waits for this gate (ignoring cancellation: a native effect in flight).
    pub start_gate: Option<Gate>,
    /// The next start fails with this error.
    pub start_error: Option<TunError>,
    /// The next start reports success but leaves no process id (unconfirmable).
    pub start_without_pid: bool,
    /// The next stop cannot prove the engine exit.
    pub stop_unproven: bool,
    /// The next stop waits for this gate.
    pub stop_gate: Option<Gate>,
    /// `switch_upstream` answers with this receipt (otherwise "not possible in place").
    pub in_place: Option<SwitchReceipt>,
    /// The next protected / adaptive restart fails (ending in a full stop).
    pub restart_error: bool,
    /// The next restart is refused before anything is touched.
    pub restart_refusal: Option<TunError>,
    pub fault: Option<OutboundFault>,
    pub exit: Option<ExitInfo>,
}

pub struct FakeRuntime {
    status: watch::Sender<TunStatus>,
    events: broadcast::Sender<TunnelEvent>,
    pub script: Mutex<RtScript>,
    generation: AtomicU64,
    next_pid: AtomicU64,
}

impl FakeRuntime {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            status: watch::channel(TunStatus::default()).0,
            events: broadcast::channel(256).0,
            script: Mutex::new(RtScript::default()),
            generation: AtomicU64::new(0),
            next_pid: AtomicU64::new(100),
        })
    }

    pub fn emit(&self, event: TunnelEvent) {
        let _ = self.events.send(event);
    }

    pub fn running(&self) -> bool {
        self.status.borrow().running
    }

    pub fn pid(&self) -> Option<u32> {
        self.status.borrow().pid
    }

    /// Our engine is up with a fresh pid; returns the generation.
    pub fn bring_up(&self, req: Option<&StartRequest>, with_pid: bool) -> u64 {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let pid = u32::try_from(self.next_pid.fetch_add(1, Ordering::SeqCst)).unwrap_or(1);
        let (mode, name) = match req.map(|r| &r.mode) {
            Some(crate::api::Mode::DirectVpn { profile }) => (
                Some(ModeKind::DirectVpn),
                Some(profile.profile.name.clone()),
            ),
            Some(crate::api::Mode::LocalProxy { .. }) => (Some(ModeKind::LocalProxy), None),
            None => (
                self.status.borrow().mode,
                self.status.borrow().profile_name.clone(),
            ),
        };
        self.status.send_modify(|s| {
            s.running = true;
            s.pid = with_pid.then_some(pid);
            s.started_at = Some(now_ms() + i64::from(pid));
            s.mode = mode;
            s.profile_name = name;
            s.restart_attempt = 0;
        });
        generation
    }

    /// Everything of ours is gone (no events).
    pub fn bring_down(&self) {
        self.status.send_replace(TunStatus::default());
    }

    /// The engine died on its own; the runtime gave up (no restart).
    pub fn crash(&self, code: i32) {
        self.script.lock().exit = Some(ExitInfo {
            at: now_ms(),
            code: Some(code),
            stderr_tail: "fatal: outbound failed".into(),
            user_initiated: false,
        });
        self.bring_down();
        self.emit(TunnelEvent::Status(TunStatusKind::Stopped));
    }

    /// The runtime restarts a crashed engine by itself (attempt 1 of 3).
    pub fn auto_restart(&self) -> u64 {
        self.emit(TunnelEvent::Status(TunStatusKind::Restarting {
            attempt: 1,
            max: 3,
        }));
        let generation = self.generation.load(Ordering::SeqCst) + 1;
        self.emit(TunnelEvent::StartBegan { generation });
        self.bring_up(None, true);
        self.status.send_modify(|s| s.restart_attempt = 1);
        self.emit(TunnelEvent::StartFinished {
            generation,
            ok: true,
        });
        generation
    }

    fn receipt(&self, generation: u64) -> StartReceipt {
        StartReceipt {
            generation,
            pid: self.pid().unwrap_or(0),
            started_at: now_ms(),
            engine: Engine::SingBox,
            warnings: Vec::new(),
        }
    }

    fn full_stop_receipt() -> StopReceipt {
        StopReceipt {
            operation_id: format!("stop_{}", "0".repeat(32)),
            ok: true,
            runtime_stopped: true,
            forced: false,
            protection_released: Some(true),
            baseline_restored: Some(true),
            adapter_gone: true,
            warnings: Vec::new(),
        }
    }
}

#[async_trait]
impl Runtime for FakeRuntime {
    async fn start(
        &self,
        req: StartRequest,
        _cancel: CancellationToken,
    ) -> Result<StartReceipt, TunError> {
        let (gate, error, no_pid) = {
            let mut s = self.script.lock();
            s.starts += 1;
            s.requests.push(req.clone());
            (
                s.start_gate.take(),
                s.start_error.take(),
                std::mem::take(&mut s.start_without_pid),
            )
        };
        let generation = self.generation.load(Ordering::SeqCst) + 1;
        self.emit(TunnelEvent::StartBegan { generation });
        if let Some(gate) = gate {
            gate.wait().await;
        }
        if let Some(error) = error {
            self.generation.fetch_add(1, Ordering::SeqCst);
            self.emit(TunnelEvent::StartFinished {
                generation,
                ok: false,
            });
            return Err(error);
        }
        self.bring_up(Some(&req), !no_pid);
        self.emit(TunnelEvent::Status(TunStatusKind::Running));
        self.emit(TunnelEvent::StartFinished {
            generation,
            ok: true,
        });
        Ok(self.receipt(generation))
    }

    async fn stop(&self, _opts: StopOptions) -> StopReceipt {
        let (unproven, gate) = {
            let mut s = self.script.lock();
            s.stops += 1;
            (std::mem::take(&mut s.stop_unproven), s.stop_gate.take())
        };
        if let Some(gate) = gate {
            gate.wait().await;
        }
        if unproven {
            return StopReceipt {
                ok: false,
                runtime_stopped: false,
                protection_released: None,
                baseline_restored: None,
                adapter_gone: false,
                ..Self::full_stop_receipt()
            };
        }
        let generation = self.generation.load(Ordering::SeqCst);
        self.emit(TunnelEvent::Status(TunStatusKind::Stopping));
        self.bring_down();
        self.emit(TunnelEvent::Status(TunStatusKind::Stopped));
        let receipt = Self::full_stop_receipt();
        self.emit(TunnelEvent::StopFinished {
            generation,
            preserved: false,
            receipt: receipt.clone(),
        });
        receipt
    }

    async fn restart_protected(
        &self,
        reason: String,
        next: StartRequest,
        _opts: RestartOptions,
    ) -> Result<StartReceipt, TunError> {
        let (fail, refusal) = {
            let mut s = self.script.lock();
            s.restarts += 1;
            s.requests.push(next.clone());
            (
                std::mem::take(&mut s.restart_error),
                s.restart_refusal.take(),
            )
        };
        if let Some(refusal) = refusal {
            return Err(refusal);
        }
        self.emit(TunnelEvent::ProtectedRestart { reason });
        self.emit(TunnelEvent::Status(TunStatusKind::Adapting));
        if fail {
            self.bring_down();
            self.emit(TunnelEvent::Status(TunStatusKind::Stopped));
            return Err(TunError::new(
                ErrorKind::Network,
                Msg::new("test.restartFailed"),
            ));
        }
        let generation = self.generation.load(Ordering::SeqCst) + 1;
        self.emit(TunnelEvent::StartBegan { generation });
        self.bring_up(Some(&next), true);
        self.emit(TunnelEvent::StartFinished {
            generation,
            ok: true,
        });
        Ok(self.receipt(generation))
    }

    async fn restart_with_last(&self, reason: String) -> Result<Option<StartReceipt>, TunError> {
        if !self.running() {
            return Ok(None);
        }
        let next = self.script.lock().requests.last().cloned();
        match next {
            Some(next) => self
                .restart_protected(reason, next, RestartOptions::default())
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn restart_adaptive(
        &self,
        mode: vpnte_base::types::AdaptiveMode,
        reason: String,
        profile: Option<VpnProfile>,
    ) -> Result<StartReceipt, TunError> {
        let mut next =
            self.script.lock().requests.last().cloned().ok_or_else(|| {
                TunError::new(ErrorKind::Conflict, Msg::new("test.nothingRunning"))
            })?;
        next.adaptive = mode;
        if let Some(profile) = profile {
            next.mode = crate::api::Mode::DirectVpn { profile };
        }
        self.restart_protected(reason, next, RestartOptions::default())
            .await
    }

    async fn switch_upstream(
        &self,
        next: StartRequest,
        _cancel: CancellationToken,
        _is_owner: OwnerCheck,
    ) -> Option<SwitchReceipt> {
        let receipt = {
            let mut s = self.script.lock();
            s.switches += 1;
            s.in_place.take()
        }?;
        if receipt.verified() && receipt.outcome == crate::api::SwitchOutcome::Success {
            self.script.lock().requests.push(next.clone());
            if let crate::api::Mode::DirectVpn { profile } = &next.mode {
                let name = profile.profile.name.clone();
                self.status.send_modify(|s| s.profile_name = Some(name));
            }
        }
        Some(receipt)
    }

    fn status(&self) -> watch::Receiver<TunStatus> {
        self.status.subscribe()
    }

    fn subscribe(&self) -> broadcast::Receiver<TunnelEvent> {
        self.events.subscribe()
    }

    fn last_exit(&self) -> Option<ExitInfo> {
        self.script.lock().exit.clone()
    }

    fn recent_fault(&self) -> Option<OutboundFault> {
        self.script.lock().fault
    }
}

/// Soft-mode proxy settings held in memory.
#[derive(Default)]
pub struct SoftState {
    pub applied: Option<(String, ProxyKind)>,
    /// The read-back fails (evidence unreadable).
    pub unreadable: bool,
    pub applies: u32,
    pub rollbacks: u32,
    /// The next N applies fail (the previous settings stay as they were).
    pub apply_failures: u32,
    /// A failed apply also clobbers the previous settings.
    pub failure_clears: bool,
    pub rollback_failures: u32,
    pub read_back_fails: bool,
    /// The endpoint read-back waits for this gate.
    pub read_back_gate: Option<Gate>,
    /// The next apply waits for this gate.
    pub apply_gate: Option<Gate>,
    /// The next apply panics (a broken collaborator).
    pub apply_panics: bool,
}

#[derive(Default)]
pub struct FakeSoft {
    pub state: Mutex<SoftState>,
}

#[async_trait]
impl super::super::SoftProxy for FakeSoft {
    fn applied(&self) -> Option<bool> {
        let s = self.state.lock();
        (!s.unreadable).then_some(s.applied.is_some())
    }

    async fn apply(&self, addr: &str, kind: ProxyKind) -> AppResult<()> {
        let gate = self.state.lock().apply_gate.take();
        if let Some(gate) = gate {
            gate.wait().await;
        }
        let panics = std::mem::take(&mut self.state.lock().apply_panics);
        assert!(!panics, "test: the soft proxy apply panicked");
        let mut s = self.state.lock();
        s.applies += 1;
        if s.apply_failures > 0 {
            s.apply_failures -= 1;
            if s.failure_clears {
                s.applied = Some(("127.0.0.1:1".into(), ProxyKind::Http));
            }
            return Err(AppError::new(ErrorKind::Permission));
        }
        s.applied = Some((addr.to_owned(), kind));
        Ok(())
    }

    async fn rollback(&self) -> AppResult<()> {
        let mut s = self.state.lock();
        s.rollbacks += 1;
        if s.rollback_failures > 0 {
            s.rollback_failures -= 1;
            return Err(AppError::new(ErrorKind::Permission));
        }
        s.applied = None;
        Ok(())
    }

    async fn is_configured(&self, addr: &str, kind: ProxyKind) -> AppResult<bool> {
        let gate = self.state.lock().read_back_gate.take();
        if let Some(gate) = gate {
            gate.wait().await;
        }
        let s = self.state.lock();
        if s.read_back_fails {
            return Err(AppError::new(ErrorKind::Internal));
        }
        Ok(s.applied.as_ref() == Some(&(addr.to_owned(), kind)))
    }
}

#[derive(Default)]
pub struct FakeProfiles {
    pub servers: Mutex<HashMap<String, super::super::ServerChoice>>,
    pub active: Mutex<Option<String>>,
}

impl FakeProfiles {
    pub fn add(&self, id: &str, name: &str, active: bool) {
        self.servers.lock().insert(id.to_owned(), server(id, name));
        if active {
            *self.active.lock() = Some(id.to_owned());
        }
    }
}

impl super::super::ProfileSource for FakeProfiles {
    fn resolve(&self, id: Option<&str>) -> Option<super::super::ServerChoice> {
        let id = id
            .map(str::to_owned)
            .or_else(|| self.active.lock().clone())?;
        self.servers.lock().get(&id).cloned()
    }
}

/// A server with obviously fake credentials.
pub fn server(id: &str, name: &str) -> super::super::ServerChoice {
    use vpnte_profiles::model::{DialPrefs, Host, Kind, Profile, Source};
    let profile = Profile {
        name: name.to_owned(),
        description: None,
        server: Host::Domain("vpn.example.test".into()),
        port: 443,
        kind: Kind::Trojan {
            password: "fake-password".into(),
        },
        tls: None,
        transport: None,
        mux: None,
        dial: DialPrefs::default(),
        native_xray: None,
        singbox_extra: serde_json::Map::new(),
        source: Source::Json,
        notes: Vec::new(),
    };
    super::super::ServerChoice {
        server: VpnProfile {
            id: id.to_owned(),
            profile: Arc::new(profile),
            device: None,
        },
        country: Some("NL".into()),
    }
}

#[derive(Default)]
pub struct Counters {
    pub monitor_starts: u32,
    pub monitor_stops: u32,
    pub suppressed: u32,
    pub forensics_starts: u32,
    pub forensics_stops: u32,
    pub proxies_stops: u32,
}

/// Monitor, forensics and external proxies in one recorder.
#[derive(Default)]
pub struct Services {
    pub counters: Mutex<Counters>,
    pub egress_ip: Mutex<Option<String>>,
    pub bytes: Mutex<(u64, u64)>,
    pub capture_stop_fails: Mutex<bool>,
}

impl super::super::Monitor for Services {
    fn suppress_leak_tests(&self, _span: Duration) {
        self.counters.lock().suppressed += 1;
    }
    fn start(&self, _generation: Option<u64>) {
        self.counters.lock().monitor_starts += 1;
    }
    fn stop(&self) {
        self.counters.lock().monitor_stops += 1;
        *self.egress_ip.lock() = None;
    }
    fn egress_ip(&self) -> Option<String> {
        self.egress_ip.lock().clone()
    }
}

#[async_trait]
impl super::super::Forensics for Services {
    fn start_session(&self, _mode: crate::history::SessionMode, _target: &str) {
        self.counters.lock().forensics_starts += 1;
    }
    async fn stop_session(&self, _reason: &str) -> bool {
        self.counters.lock().forensics_stops += 1;
        *self.bytes.lock() = (0, 0);
        !*self.capture_stop_fails.lock()
    }
    fn session_bytes(&self) -> (u64, u64) {
        *self.bytes.lock()
    }
}

#[async_trait]
impl super::super::ExternalProxies for Services {
    async fn stop_all(&self, _reason: &str) {
        self.counters.lock().proxies_stops += 1;
    }
}

#[derive(Default)]
pub struct FakeNotifier {
    pub notices: Mutex<Vec<(Notice, super::super::NoticeKind)>>,
}

impl FakeNotifier {
    pub fn titles(&self) -> Vec<String> {
        let notices = self.notices.lock();
        notices
            .iter()
            .map(|(n, _)| n.title.key.to_string())
            .collect()
    }
}

impl super::super::Notifier for FakeNotifier {
    fn notify(&self, notice: Notice, kind: super::super::NoticeKind) {
        self.notices.lock().push((notice, kind));
    }
}

/// A lifecycle wired to fakes.
pub struct Harness {
    pub lc: super::super::Lifecycle,
    pub rt: Arc<FakeRuntime>,
    pub soft: Arc<FakeSoft>,
    pub profiles: Arc<FakeProfiles>,
    pub services: Arc<Services>,
    pub notifier: Arc<FakeNotifier>,
    pub history: crate::history::History,
    pub settings: Arc<vpnte_core::store::Store<vpnte_core::settings::Settings>>,
    _dir: TempDir,
}

impl Harness {
    pub fn new() -> Self {
        use vpnte_core::settings::Settings;
        use vpnte_core::store::Store;
        let dir = TempDir::new("lifecycle");
        let rt = FakeRuntime::new();
        let soft = Arc::new(FakeSoft::default());
        let profiles = Arc::new(FakeProfiles::default());
        let services = Arc::new(Services::default());
        let notifier = Arc::new(FakeNotifier::default());
        let history = crate::history::History::open(&dir.0);
        let settings = Arc::new(Store::<Settings>::open(&dir.0));
        let deps = super::super::LifecycleDeps {
            runtime: rt.clone(),
            profiles: profiles.clone(),
            soft: soft.clone(),
            monitor: services.clone(),
            forensics: services.clone(),
            proxies: services.clone(),
            notifier: notifier.clone(),
            history: history.clone(),
            settings: settings.clone(),
        };
        Self {
            lc: super::super::Lifecycle::spawn(deps),
            rt,
            soft,
            profiles,
            services,
            notifier,
            history,
            settings,
            _dir: dir,
        }
    }

    pub fn snap(&self) -> crate::fsm::TunnelSnapshot {
        self.lc.snapshot().borrow().clone()
    }

    /// Waits until the actor handled everything sent so far (and every queued runtime event).
    pub async fn settle(&self) {
        self.lc.barrier().await;
    }

    pub fn rows(&self) -> Vec<crate::history::Entry> {
        self.history.list()
    }
}

/// Polls `f` for up to two seconds.
pub async fn eventually(what: &str, f: impl Fn() -> bool) {
    for _ in 0..400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("timed out waiting for {what}");
}
