//! The remote runtime against the service's real session host (fake runtime and kill switch
//! behind a private pipe): starts, the kept session of a crashed window and its take-over, and
//! the kill switch through the service.
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::types::{
    AdaptiveMode, Engine, EnginePref, KillSwitchLevel, Notice, OutboundFault, ProxyKind,
};
use vpnte_core::store::Store;
use vpnte_service::host::{Host, HostDeps, KillSwitch, SharedInputs};
use vpnte_service::pipe::client::{Client, ServerCheck};
use vpnte_service::pipe::{Listener, PipeConfig, admit_all};
use vpnte_service::proto::{ProtectionWire, Request};
use vpnte_service::users::Users;
use vpnte_tunnel::api::{
    CaptureKind, EngineRun, ExitInfo, Mode, Origin, OwnerCheck, RestartOptions, Runtime,
    StartReceipt, StartRequest, StopOptions, StopReceipt, SwitchReceipt, TunError, TunStatus,
    TunStatusKind, TunnelEvent, VpnProfile,
};
use vpnte_tunnel::runtime::{InputsSource, UserInputs};
use vpnte_winnet::wfp::{ProtectionSettings, RemoveReport};

use super::Remote;
use crate::api_settings::test_support::TempDir;
use crate::svc_core::docs::ProtectionDoc;

mod takeover;

/// A runtime that runs whatever it is asked to, at once.
pub(super) struct FakeRuntime {
    status: watch::Sender<TunStatus>,
    events: broadcast::Sender<TunnelEvent>,
    starts: AtomicU32,
    stops: AtomicU32,
    /// Stops that kept the kill switch's block.
    kept: AtomicU32,
    /// Starts fail (the server out of reach), as a failed start ends in the real runtime.
    fail: std::sync::atomic::AtomicBool,
}

impl FakeRuntime {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            status: watch::channel(TunStatus::default()).0,
            events: broadcast::channel(64).0,
            starts: AtomicU32::new(0),
            stops: AtomicU32::new(0),
            kept: AtomicU32::new(0),
            fail: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl Runtime for FakeRuntime {
    async fn start(&self, _: StartRequest, _: CancellationToken) -> Result<StartReceipt, TunError> {
        let generation = u64::from(self.starts.fetch_add(1, Ordering::SeqCst)) + 1;
        let _ = self.events.send(TunnelEvent::StartBegan { generation });
        if self.fail.load(Ordering::SeqCst) {
            let _ = self
                .events
                .send(TunnelEvent::Status(TunStatusKind::Stopped));
            let _ = self.events.send(TunnelEvent::StartFinished {
                generation,
                ok: false,
            });
            return Err(vpnte_base::AppError::new(vpnte_base::ErrorKind::Network).into());
        }
        let engine = EngineRun {
            kind: Engine::SingBox,
            reason: None,
        };
        self.status.send_modify(|s| {
            s.running = true;
            s.pid = Some(4242);
            s.started_at = Some(7);
            s.capture = Some(CaptureKind::Tun);
            s.engine = Some(engine);
        });
        let _ = self
            .events
            .send(TunnelEvent::Status(TunStatusKind::Running));
        let _ = self.events.send(TunnelEvent::StartFinished {
            generation,
            ok: true,
        });
        Ok(StartReceipt {
            generation,
            pid: 4242,
            started_at: 7,
            engine,
            warnings: Vec::new(),
        })
    }
    /// As the real runtime: a preserved stop announces `Adapting` and keeps the block (its
    /// `StopFinished` says so), a full one announces `Stopped`.
    async fn stop(&self, opts: StopOptions) -> StopReceipt {
        self.stops.fetch_add(1, Ordering::SeqCst);
        let preserved = opts.preserve_protection;
        if preserved {
            self.kept.fetch_add(1, Ordering::SeqCst);
        }
        self.status.send_replace(TunStatus::default());
        let receipt = StopReceipt {
            operation_id: "stop_test".into(),
            ok: true,
            runtime_stopped: true,
            forced: false,
            protection_released: (!preserved).then_some(true),
            baseline_restored: Some(true),
            adapter_gone: true,
            warnings: Vec::new(),
        };
        let kind = if preserved {
            TunStatusKind::Adapting
        } else {
            TunStatusKind::Stopped
        };
        let _ = self.events.send(TunnelEvent::Status(kind));
        if preserved {
            let _ = self.events.send(TunnelEvent::StopFinished {
                generation: u64::from(self.starts.load(Ordering::SeqCst)),
                preserved,
                receipt: receipt.clone(),
            });
        }
        receipt
    }
    async fn restart_protected(
        &self,
        _: String,
        next: StartRequest,
        _: RestartOptions,
    ) -> Result<StartReceipt, TunError> {
        self.start(next, CancellationToken::new()).await
    }
    async fn restart_with_last(&self, _: String) -> Result<Option<StartReceipt>, TunError> {
        Ok(None)
    }
    async fn restart_adaptive(
        &self,
        _: AdaptiveMode,
        _: String,
        _: Option<VpnProfile>,
    ) -> Result<StartReceipt, TunError> {
        Err(vpnte_base::AppError::cancelled().into())
    }
    async fn switch_upstream(
        &self,
        _: StartRequest,
        _: CancellationToken,
        _: OwnerCheck,
    ) -> Option<SwitchReceipt> {
        None
    }
    fn status(&self) -> watch::Receiver<TunStatus> {
        self.status.subscribe()
    }
    fn subscribe(&self) -> broadcast::Receiver<TunnelEvent> {
        self.events.subscribe()
    }
    fn last_exit(&self) -> Option<ExitInfo> {
        None
    }
    fn recent_fault(&self) -> Option<OutboundFault> {
        None
    }
}

struct FakeKillSwitch {
    level: Mutex<KillSwitchLevel>,
    notices: broadcast::Sender<Notice>,
}

#[async_trait]
impl KillSwitch for FakeKillSwitch {
    async fn apply(&self, settings: ProtectionSettings) -> AppResult<()> {
        *self.level.lock() = settings.level;
        Ok(())
    }
    fn level(&self) -> KillSwitchLevel {
        *self.level.lock()
    }
    fn level_in_force(&self) -> KillSwitchLevel {
        self.level()
    }
    async fn status(&self) -> ProtectionWire {
        ProtectionWire::unknown(self.level())
    }
    fn notices(&self) -> broadcast::Receiver<Notice> {
        self.notices.subscribe()
    }
    async fn cleanup(&self) -> AppResult<RemoveReport> {
        Ok(RemoveReport {
            filters: 3,
            sublayer: true,
            provider: true,
        })
    }
    async fn remove_all(&self) -> AppResult<()> {
        Ok(())
    }
}

pub(super) struct NoInputs;

#[async_trait]
impl InputsSource for NoInputs {
    async fn snapshot(&self) -> AppResult<UserInputs> {
        Ok(UserInputs::default())
    }
}

pub(super) static NEXT: AtomicU32 = AtomicU32::new(0);

struct Service {
    pipe: String,
    runtime: Arc<FakeRuntime>,
    kill: Arc<FakeKillSwitch>,
    protection: Arc<Store<ProtectionDoc>>,
    cancel: CancellationToken,
    _dir: TempDir,
}

impl Drop for Service {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn pipe_config(name: &str) -> PipeConfig {
    PipeConfig {
        name: name.to_owned(),
        sddl: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)".into(),
    }
}

fn kill_switch() -> Arc<FakeKillSwitch> {
    Arc::new(FakeKillSwitch {
        level: Mutex::new(KillSwitchLevel::Off),
        notices: broadcast::channel(4).0,
    })
}

/// A session host over `runtime` with its users in `dir`.
fn host(runtime: Arc<FakeRuntime>, kill: Arc<FakeKillSwitch>, dir: &Path) -> Arc<Host> {
    Host::new(HostDeps {
        runtime,
        kill_switch: kill,
        inputs: Arc::new(SharedInputs::new(None)),
        users: Arc::new(Users::open(&dir.join("users.json"))),
        check: admit_all(),
        on_last_user: Arc::new(|| {}),
        service_version: "2.0.0-test".into(),
        refuse_tunnel: None,
    })
}

pub(super) fn pipe_name(n: u32) -> String {
    format!(r"\\.\pipe\vpnte-app-remote-{}-{n}", std::process::id())
}

/// The service's session host on a private pipe.
fn service() -> Service {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let pipe = pipe_name(n);
    let dir = TempDir::new(&format!("remote-{n}"));
    let listener = Listener::bind(&pipe_config(&pipe)).expect("private pipe");
    let (runtime, kill) = (FakeRuntime::new(), kill_switch());
    let host = host(runtime.clone(), kill.clone(), &dir.0);
    let cancel = CancellationToken::new();
    tokio::spawn(host.serve(listener, cancel.clone()));
    let protection = Arc::new(Store::<ProtectionDoc>::open(&dir.0));
    Service {
        pipe,
        runtime,
        kill,
        protection,
        cancel,
        _dir: dir,
    }
}

fn remote(s: &Service) -> Remote {
    Remote::on_pipe(&s.pipe, Arc::new(NoInputs), s.protection.clone())
}

fn tun_request() -> StartRequest {
    StartRequest {
        mode: Mode::LocalProxy {
            addr: "127.0.0.1:10808".into(),
            kind: ProxyKind::Socks5,
        },
        capture: CaptureKind::Tun,
        kill_switch: KillSwitchLevel::Standard,
        public_wifi: false,
        stealth: false,
        adaptive: AdaptiveMode::default(),
        engine: EnginePref::Auto,
        origin: Origin::User,
    }
}

/// The lifecycle's contract over the pipe: the status and every event of the start are out
/// before the receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_publishes_its_events_before_the_receipt() {
    let s = service();
    let r = remote(&s);
    let mut events = r.subscribe();
    let receipt = r
        .start(tun_request(), CancellationToken::new())
        .await
        .expect("started");
    assert!(r.status().borrow().running);
    let mut seen = Vec::new();
    while let Ok(e) = events.try_recv() {
        seen.push(e);
    }
    assert!(
        matches!(seen.first(), Some(TunnelEvent::StartBegan { generation }) if *generation == receipt.generation),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|e| matches!(e, TunnelEvent::StartFinished { ok: true, .. }))
    );
    let stopped = r.stop(StopOptions::default()).await;
    assert!(stopped.ok && !r.status().borrow().running);
}

/// Owner question 23: the window crashed (its connection dropped without a stop); the next app
/// parks the kept session (not shown as running, so nothing stops it) until its own connect of
/// the same upstream takes it over: no second start in the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kept_session_is_taken_over_not_restarted() {
    let s = service();
    let mut crashed = Client::connect(&s.pipe, &ServerCheck::Any, Duration::from_secs(5))
        .await
        .expect("connect");
    crashed.hello("2.0.0").await.expect("hello");
    let start = super::start::tunnel_start(
        &tun_request(),
        &UserInputs::default(),
        ProtectionSettings::default(),
    )
    .expect("start");
    crashed
        .call(Request::Start(Box::new(start)))
        .await
        .expect("started");
    drop(crashed);
    let r = remote(&s);
    let kept = loop {
        // The slot frees once the old connection ended.
        if let Some(kept) = r.attach().await {
            break kept;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(
        kept.local_proxy,
        Some("127.0.0.1:10808".parse().expect("addr"))
    );
    assert!(!r.status().borrow().running, "parked, not shown");
    let receipt = r
        .start(tun_request(), CancellationToken::new())
        .await
        .expect("taken over");
    assert_eq!(
        s.runtime.starts.load(Ordering::SeqCst),
        1,
        "no second start"
    );
    assert!(receipt.generation >= 1);
    assert!(r.status().borrow().running);
}

/// The kill switch goes through the service from the guard's blocking thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_kill_switch_is_applied_in_the_service() {
    let s = service();
    let r = remote(&s);
    let strict = ProtectionSettings {
        level: KillSwitchLevel::Strict,
        ..ProtectionSettings::default()
    };
    let applied = {
        let r = r.clone();
        tokio::task::spawn_blocking(move || r.apply_protection(strict))
            .await
            .expect("join")
    };
    applied.expect("applied");
    assert_eq!(*s.kill.level.lock(), KillSwitchLevel::Strict);
    let report = tokio::task::spawn_blocking(move || r.cleanup())
        .await
        .expect("join")
        .expect("cleaned");
    assert_eq!(report.filters, 3);
}

/// The split runtime: proxy mode stays in this process, Tunnel mode goes to the service; one
/// event stream whose generations keep increasing across the hosts, every event of a start out
/// before the call returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_split_routes_by_capture_with_increasing_generations() {
    let s = service();
    let local = FakeRuntime::new();
    let split = super::Split::spawn(local.clone(), remote(&s), CancellationToken::new());
    let mut events = split.subscribe();
    let proxy = StartRequest {
        capture: CaptureKind::Proxy,
        ..tun_request()
    };
    let first = split
        .start(proxy, CancellationToken::new())
        .await
        .expect("proxy start");
    assert_eq!(
        local.starts.load(Ordering::SeqCst),
        1,
        "proxy mode stays here"
    );
    let _ = split.stop(StopOptions::default()).await;
    let second = split
        .start(tun_request(), CancellationToken::new())
        .await
        .expect("tunnel start");
    assert_eq!(
        s.runtime.starts.load(Ordering::SeqCst),
        1,
        "Tunnel mode in the service"
    );
    assert!(second.generation > first.generation, "{first:?} {second:?}");
    let mut began = Vec::new();
    while let Ok(e) = events.try_recv() {
        if let TunnelEvent::StartBegan { generation } = e {
            began.push(generation);
        }
    }
    assert_eq!(began, [first.generation, second.generation]);
    assert!(split.status().borrow().running);
}

/// A restarted service on `pipe` keeping its sessions in `memory`: its session host, runtime and
/// stop token. The previous instance's pipe may still be closing: binding is retried.
pub(super) async fn restarted(
    pipe: &str,
    dir: &Path,
) -> (Arc<Host>, Arc<FakeRuntime>, CancellationToken) {
    let mut tries = 0;
    let listener = loop {
        match Listener::bind(&pipe_config(pipe)) {
            Ok(listener) => break listener,
            Err(err) if tries < 250 => {
                tries += 1;
                tracing::debug!(%err, "pipe still taken");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(err) => panic!("pipe not free again: {err}"),
        }
    };
    let runtime = FakeRuntime::new();
    let host = host(runtime.clone(), kill_switch(), dir);
    host.keep_sessions_in(dir.join("session.json"));
    let cancel = CancellationToken::new();
    tokio::spawn(host.clone().serve(listener, cancel.clone()));
    (host, runtime, cancel)
}

/// p-follow (ks-d follow-up): the helper service restarted (the link dropped without a stop) and
/// resumes the session after the app connected again. The app shows the session ended, connects
/// again as at start-up, holds the resumed session's own events back and offers it for the
/// lifecycle's take-over: one start in the restarted service, none from the app.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_service_is_attached_again() {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let (pipe, dir) = (pipe_name(n), TempDir::new(&format!("remote-restart-{n}")));
    let protection = Arc::new(Store::<ProtectionDoc>::open(&dir.0));
    let (_, _, first) = restarted(&pipe, &dir.0).await;
    let r = Remote::on_pipe(&pipe, Arc::new(NoInputs), protection);
    r.start(tun_request(), CancellationToken::new())
        .await
        .expect("started");
    let losses = r.losses();
    first.cancel();
    // A real restart ends the service's process and with it the pipe; the stopped host here
    // lets go of the pipe at the next request its reader takes.
    let lost = async {
        while !losses.has_changed().unwrap_or(true) {
            let _ = r.refresh().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), lost)
        .await
        .expect("loss seen");
    assert!(!r.status().borrow().running, "shown as ended");

    let (host, runtime, second) = restarted(&pipe, &dir.0).await;
    let mut events = r.subscribe();
    let reattach = tokio::spawn({
        let r = r.clone();
        async move { r.reattach().await }
    });
    let linked = || {
        r.0.link
            .try_lock()
            .is_ok_and(|link| link.as_ref().is_some_and(|l| !l.gone.is_cancelled()))
    };
    for _ in 0..500 {
        if linked() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(linked(), "connected again");
    assert!(host.resume(CancellationToken::new()).await, "resumed");
    let kept = reattach
        .await
        .expect("task")
        .expect("offered for a take-over");
    assert_eq!(
        kept.local_proxy,
        Some("127.0.0.1:10808".parse().expect("addr"))
    );
    assert!(
        events.try_recv().is_err(),
        "the resume's own events held back"
    );
    assert!(!r.status().borrow().running, "parked, not shown");
    r.start(tun_request(), CancellationToken::new())
        .await
        .expect("taken over");
    assert_eq!(runtime.starts.load(Ordering::SeqCst), 1, "no second start");
    assert!(r.status().borrow().running);
    second.cancel();
}
