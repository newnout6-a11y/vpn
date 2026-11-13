//! Host tests: a fake runtime and kill switch behind a private pipe (no SCM, no WFP, no engine).
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{
    AdaptiveMode, Engine, EnginePref, KillSwitchLevel, Notice, OutboundFault, ProxyKind,
};
use vpnte_base::{AppResult, ErrorKind, Msg};
use vpnte_tunnel::api::{
    EngineRun, ExitInfo, OwnerCheck, RestartOptions, Runtime, StartReceipt, StartRequest,
    StopOptions, StopReceipt, SwitchReceipt, TunError, TunStatus, TunStatusKind, TunnelEvent,
    VpnProfile,
};
use vpnte_winnet::wfp::{ProtectionSettings, RemoveReport};

use super::*;
use crate::pipe::client::{CallError, Client, ServerCheck};
use crate::pipe::{PipeConfig, admit_all};
use crate::proto::{
    ErrorCode, Event, Hello, ProtectionWire, Reply, Request, RoutingInputs, ServerFrame,
    StopTunnel, TunnelEventWire, TunnelStart, Upstream, frame,
};

mod access;
mod order;
mod resume;
mod selftest;

/// Records calls; `start` emits the runtime's event sequence.
struct FakeRuntime {
    status: watch::Sender<TunStatus>,
    events: broadcast::Sender<TunnelEvent>,
    stops: Mutex<Vec<StopOptions>>,
    starts: Mutex<Vec<StartRequest>>,
}

impl FakeRuntime {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            status: watch::channel(TunStatus::default()).0,
            events: broadcast::channel(64).0,
            stops: Mutex::new(Vec::new()),
            starts: Mutex::new(Vec::new()),
        })
    }

    fn emit(&self, kind: TunStatusKind, running: bool) {
        self.status.send_modify(|s| s.running = running);
        let _ = self.events.send(TunnelEvent::Status(kind));
    }
}

#[async_trait]
impl Runtime for FakeRuntime {
    async fn start(
        &self,
        req: StartRequest,
        cancel: CancellationToken,
    ) -> Result<StartReceipt, TunError> {
        // As the real runtime: a start whose token is cancelled is refused before anything runs.
        if cancel.is_cancelled() {
            return Err(vpnte_base::AppError::cancelled().into());
        }
        self.starts.lock().push(req);
        let _ = self.events.send(TunnelEvent::StartBegan { generation: 1 });
        self.status.send_modify(|s| {
            s.pid = Some(4242);
            s.started_at = Some(1);
            s.engine = Some(EngineRun {
                kind: Engine::SingBox,
                reason: None,
            });
        });
        self.emit(TunStatusKind::Running, true);
        let _ = self.events.send(TunnelEvent::StartFinished {
            generation: 1,
            ok: true,
        });
        Ok(StartReceipt {
            generation: 1,
            pid: 4242,
            started_at: 1,
            engine: EngineRun {
                kind: Engine::SingBox,
                reason: None,
            },
            warnings: Vec::new(),
        })
    }

    async fn stop(&self, opts: StopOptions) -> StopReceipt {
        self.stops.lock().push(opts);
        self.emit(TunStatusKind::Stopped, false);
        StopReceipt {
            operation_id: "stop_test".into(),
            ok: true,
            runtime_stopped: true,
            forced: false,
            protection_released: Some(!opts.preserve_protection),
            baseline_restored: Some(true),
            adapter_gone: true,
            warnings: Vec::new(),
        }
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
        Err(TunError::new(
            ErrorKind::Conflict,
            Msg::new("tunnel.runtime.notRunning"),
        ))
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
        Some(OutboundFault::TlsHandshakeFailed)
    }
}

struct FakeKillSwitch {
    level: Mutex<KillSwitchLevel>,
    /// "Always" can be kept safe (`Protection::set_always_available`).
    always: AtomicBool,
    notices: broadcast::Sender<Notice>,
    /// `apply` and `status` wait while this is `false`; `applying` / `asking` count the calls
    /// that got that far.
    gate: watch::Sender<bool>,
    applying: AtomicU32,
    asking: AtomicU32,
    /// `remove_all` fails (WFP objects could not be removed).
    stuck: AtomicBool,
}

#[async_trait]
impl KillSwitch for FakeKillSwitch {
    async fn apply(&self, settings: ProtectionSettings) -> AppResult<()> {
        self.applying.fetch_add(1, Ordering::SeqCst);
        let _ = self.gate.subscribe().wait_for(|open| *open).await;
        *self.level.lock() = settings.level;
        Ok(())
    }
    fn level(&self) -> KillSwitchLevel {
        *self.level.lock()
    }
    fn level_in_force(&self) -> KillSwitchLevel {
        self.level().effective(self.always.load(Ordering::SeqCst))
    }
    async fn status(&self) -> ProtectionWire {
        self.asking.fetch_add(1, Ordering::SeqCst);
        let _ = self.gate.subscribe().wait_for(|open| *open).await;
        ProtectionWire::unknown(self.level())
    }
    fn notices(&self) -> broadcast::Receiver<Notice> {
        self.notices.subscribe()
    }
    async fn cleanup(&self) -> AppResult<RemoveReport> {
        Ok(RemoveReport {
            filters: 0,
            sublayer: false,
            provider: false,
        })
    }
    async fn remove_all(&self) -> AppResult<()> {
        if self.stuck.load(Ordering::SeqCst) {
            return Err(vpnte_base::AppError::new(ErrorKind::Internal));
        }
        *self.level.lock() = KillSwitchLevel::Off;
        Ok(())
    }
}

/// Test pipes grant every authenticated user full access: the unelevated test process must be
/// able to create further instances of its own pipe (the service, as SYSTEM, always can).
const TEST_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)";

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Harness {
    host: Arc<Host>,
    runtime: Arc<FakeRuntime>,
    kill: Arc<FakeKillSwitch>,
    inputs: Arc<SharedInputs>,
    name: String,
    removed: Arc<AtomicU32>,
    cancel: CancellationToken,
    dir: std::path::PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.cancel.cancel();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn harness() -> Harness {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let name = format!(r"\\.\pipe\vpnte-test-{}-{n}", std::process::id());
    let dir = std::env::temp_dir().join(format!("vpnte-svc-host-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let config = PipeConfig {
        name: name.clone(),
        sddl: TEST_SDDL.into(),
    };
    let listener = Listener::bind(&config).expect("bind a private pipe");
    let runtime = FakeRuntime::new();
    let kill = Arc::new(FakeKillSwitch {
        level: Mutex::new(KillSwitchLevel::Off),
        always: AtomicBool::new(false),
        notices: broadcast::channel(8).0,
        gate: watch::channel(true).0,
        applying: AtomicU32::new(0),
        asking: AtomicU32::new(0),
        stuck: AtomicBool::new(false),
    });
    let inputs = Arc::new(SharedInputs::new(None));
    let removed = Arc::new(AtomicU32::new(0));
    let counter = removed.clone();
    let host = Host::new(HostDeps {
        runtime: runtime.clone(),
        kill_switch: kill.clone(),
        inputs: inputs.clone(),
        users: Arc::new(Users::open(&dir.join("users.json"))),
        check: admit_all(),
        on_last_user: Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }),
        service_version: "2.0.0-test".into(),
        refuse_tunnel: None,
    });
    host.keep_sessions_in(dir.join("session.json"));
    let cancel = CancellationToken::new();
    tokio::spawn(host.clone().serve(listener, cancel.clone()));
    Harness {
        host,
        runtime,
        kill,
        inputs,
        name,
        removed,
        cancel,
        dir,
    }
}

async fn connect(h: &Harness) -> Client {
    Client::connect(&h.name, &ServerCheck::Any, Duration::from_secs(5))
        .await
        .expect("connect")
}

fn local_start(level: KillSwitchLevel) -> Request {
    Request::Start(Box::new(TunnelStart {
        upstream: Upstream::LocalProxy {
            addr: "127.0.0.1:10808".parse().expect("addr"),
            kind: ProxyKind::Socks5,
        },
        routing: RoutingInputs::default(),
        protection: ProtectionSettings {
            level,
            ..ProtectionSettings::default()
        },
        adaptive: AdaptiveMode::Baseline,
        engine: EnginePref::Auto,
        origin: vpnte_tunnel::api::Origin::User,
    }))
}

fn code(err: CallError) -> ErrorCode {
    match err {
        CallError::Service(e) => e.code,
        CallError::Pipe(e) => panic!("pipe error: {e:?}"),
    }
}

async fn wait_for(what: &str, cond: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A raw protocol connection: these tests overlap requests or check where a reply sits among the
/// events, which the one-call-at-a-time `Client` cannot show.
struct Raw(tokio::net::windows::named_pipe::NamedPipeClient);

impl Raw {
    async fn open(h: &Harness) -> Self {
        let pipe = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&h.name)
            .expect("open");
        let mut raw = Raw(pipe);
        let hello = Hello {
            protocol: crate::proto::PROTOCOL,
            app_version: "2.0.0".into(),
        };
        raw.send(1, Request::Hello(hello)).await;
        assert!(
            matches!(raw.answer(1).await, ServerFrame::Reply { .. }),
            "welcome"
        );
        raw
    }

    async fn send(&mut self, id: u64, request: Request) {
        let frame = crate::proto::ClientFrame { id, request };
        frame::write_frame(&mut self.0, &frame).await.expect("send");
    }

    async fn next(&mut self) -> ServerFrame {
        let read = tokio::time::timeout(Duration::from_secs(5), frame::read_frame(&mut self.0));
        let body = read.await.expect("a frame in time").expect("frame");
        frame::decode(&body).expect("decode")
    }

    /// The answer to `id`; events and other answers on the way are skipped.
    async fn answer(&mut self, id: u64) -> ServerFrame {
        loop {
            match self.next().await {
                ServerFrame::Reply { id: got, .. } | ServerFrame::Failed { id: got, .. }
                    if got != id => {}
                ServerFrame::Event { .. } => {}
                answer => return answer,
            }
        }
    }
}

/// Review service-a11: the events of an operation are on the wire before its reply (read raw;
/// repeated, since without the drain the order would only be wrong some of the time).
#[tokio::test]
async fn hello_start_events_before_reply_then_stop() {
    let h = harness();
    let mut c = Raw::open(&h).await;
    for round in 0..10u64 {
        let id = 2 + 2 * round;
        c.send(id, local_start(KillSwitchLevel::Standard)).await;
        let mut before = Vec::new();
        let reply = loop {
            match c.next().await {
                ServerFrame::Event { event } => before.push(*event),
                ServerFrame::Reply { id: got, reply } if got == id => break *reply,
                other => panic!("unexpected {other:?}"),
            }
        };
        assert!(matches!(reply, Reply::Started(Some(r)) if r.pid == 4242));
        let began = before
            .iter()
            .position(|e| matches!(e, Event::Tunnel(TunnelEventWire::StartBegan { .. })));
        let finished = before.iter().position(|e| {
            matches!(
                e,
                Event::Tunnel(TunnelEventWire::StartFinished { ok: true, .. })
            )
        });
        assert!(began.is_some() && finished > began, "{before:?}");
        assert!(
            before
                .iter()
                .any(|e| matches!(e, Event::Status(s) if s.running)),
            "{before:?}"
        );
        c.send(id + 1, Request::Stop(StopTunnel::default())).await;
        let stop = c.answer(id + 1).await;
        assert!(
            matches!(stop, ServerFrame::Reply { reply, .. } if matches!(*reply, Reply::Stopped(ref r) if r.ok))
        );
    }
    assert_eq!(
        h.kill.level(),
        KillSwitchLevel::Standard,
        "settings applied first"
    );
    let started = h.runtime.starts.lock()[0].clone();
    assert_eq!(started.capture, vpnte_tunnel::api::CaptureKind::Tun);
}

#[tokio::test]
async fn a_second_client_gets_busy_until_the_first_leaves() {
    let h = harness();
    let mut first = connect(&h).await;
    assert_eq!(
        first.hello("2.0.0").await.expect("first hello"),
        (crate::proto::PROTOCOL, "2.0.0-test".into())
    );
    let mut second = connect(&h).await;
    assert_eq!(
        code(second.hello("2.0.0").await.expect_err("busy")),
        ErrorCode::Busy
    );
    drop(first);
    let mut third = connect(&h).await;
    let mut ok = third.hello("2.0.0").await;
    for _ in 0..50 {
        if ok.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        third = connect(&h).await;
        ok = third.hello("2.0.0").await;
    }
    assert!(ok.is_ok(), "the slot is free again");
    assert!(h.runtime.stops.lock().is_empty(), "leaving stops nothing");
}

#[tokio::test]
async fn hello_comes_first_and_versions_must_be_close() {
    let h = harness();
    let mut c = connect(&h).await;
    assert_eq!(
        code(c.call(Request::Status).await.expect_err("no hello")),
        ErrorCode::HelloFirst
    );
    let mut c = connect(&h).await;
    let far = Request::Hello(Hello {
        protocol: crate::proto::PROTOCOL + 2,
        app_version: "9.0.0".into(),
    });
    assert_eq!(
        code(c.call(far).await.expect_err("too new")),
        ErrorCode::Version
    );
}

/// Owner question 23: a connection that drops without a stop (the app window crashed) leaves the
/// session running; the same user's next app takes it over with its upstream and generation.
#[tokio::test]
async fn a_dropped_connection_keeps_the_session_for_its_user() {
    let h = harness();
    let mut c = connect(&h).await;
    c.hello("2.0.0").await.expect("hello");
    c.call(local_start(KillSwitchLevel::Standard))
        .await
        .expect("start");
    drop(c);
    // The slot frees once the old connection ended; then the same user is admitted again.
    let mut c = loop {
        let mut c = connect(&h).await;
        match c.hello("2.0.0").await {
            Ok(_) => break c,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    assert!(h.runtime.stops.lock().is_empty(), "nothing stopped");
    let Ok(Reply::Status(status)) = c.call(Request::Status).await else {
        panic!("status");
    };
    let kept = status.kept.expect("the running session, for a take-over");
    assert_eq!(kept.receipt.generation, 1);
    assert_eq!(kept.receipt.pid, 4242);
    assert_eq!(kept.server_id, None);
    assert_eq!(
        kept.local_proxy,
        Some("127.0.0.1:10808".parse().expect("addr"))
    );
}

/// Another Windows user who takes the free slot ends a session kept for someone else first (its
/// secrets and last exit are its user's); only "Always" in force keeps a block (ks-a).
#[tokio::test]
async fn another_user_ends_a_kept_session_first() {
    for (level, always, keep_block) in [
        (KillSwitchLevel::Standard, false, false),
        (KillSwitchLevel::Strict, false, false),
        (KillSwitchLevel::Strict, true, true),
    ] {
        let kill = Arc::new(FakeKillSwitch {
            level: Mutex::new(level),
            always: AtomicBool::new(always),
            notices: broadcast::channel(8).0,
            gate: watch::channel(true).0,
            applying: AtomicU32::new(0),
            asking: AtomicU32::new(0),
            stuck: AtomicBool::new(false),
        });
        let runtime = FakeRuntime::new();
        let dir = std::env::temp_dir().join(format!("vpnte-svc-admit-{}", std::process::id()));
        let host = Host::new(HostDeps {
            runtime: runtime.clone(),
            kill_switch: kill,
            inputs: Arc::new(SharedInputs::new(None)),
            users: Arc::new(Users::open(&dir.join("users.json"))),
            check: admit_all(),
            on_last_user: Arc::new(|| {}),
            service_version: "2.0.0-test".into(),
            refuse_tunnel: None,
        });
        *host.session_user.lock() = Some("S-1-5-21-1-2-3-1001".into());
        host.admit("S-1-5-21-1-2-3-1001").await;
        assert!(runtime.stops.lock().is_empty(), "his own session is his");
        host.admit("S-1-5-21-1-2-3-1002").await;
        let stops = runtime.stops.lock().clone();
        assert_eq!(stops.len(), 1, "{level:?}");
        assert_eq!(
            stops[0].preserve_protection, keep_block,
            "{level:?} {always}"
        );
        assert!(host.session_user.lock().is_none());
    }
}

/// Review 4555679938: the last user's leave removes the WFP objects before the answer; when that
/// fails he stays recorded, the uninstaller hears so, and his retry repeats it.
#[tokio::test]
async fn a_last_leave_whose_filters_stay_keeps_the_service() {
    let h = harness();
    let mut c = connect(&h).await;
    c.hello("2.0.0").await.expect("hello records the user");
    drop(c);
    h.kill.stuck.store(true, Ordering::SeqCst);
    let mut c = connect(&h).await;
    let err = match c.call(Request::ForgetMe).await {
        Err(CallError::Service(e)) => e,
        other => panic!("{other:?}"),
    };
    assert_eq!(err.msg.key, crate::install::flow::FILTERS_KEPT);
    assert_eq!(h.removed.load(Ordering::SeqCst), 0, "the service stays");
    h.kill.stuck.store(false, Ordering::SeqCst);
    let mut c = connect(&h).await;
    let reply = c.call(Request::ForgetMe).await.expect("retry");
    assert_eq!(reply, Reply::Done { removing: true });
    assert_eq!(*h.kill.level.lock(), KillSwitchLevel::Off);
    wait_for("removal", || h.removed.load(Ordering::SeqCst) == 1).await;
}

#[tokio::test]
async fn refused_inputs_never_reach_the_runtime() {
    let h = harness();
    let mut c = connect(&h).await;
    c.hello("2.0.0").await.expect("hello");
    let lan = Request::Start(Box::new(TunnelStart {
        upstream: Upstream::LocalProxy {
            addr: "192.168.1.5:1080".parse().expect("addr"),
            kind: ProxyKind::Socks5,
        },
        ..match local_start(KillSwitchLevel::Off) {
            Request::Start(s) => *s,
            _ => unreachable!(),
        }
    }));
    assert_eq!(
        code(c.call(lan).await.expect_err("refused")),
        ErrorCode::Refused
    );
    assert!(h.runtime.starts.lock().is_empty());
    // Still connected and in control.
    assert!(matches!(
        c.call(Request::Status).await,
        Ok(Reply::Status(_))
    ));
}

#[tokio::test]
async fn an_unknown_request_is_answered_and_the_connection_stays() {
    use crate::proto::frame;
    use tokio::net::windows::named_pipe::ClientOptions;
    let h = harness();
    let mut pipe = ClientOptions::new().open(&h.name).expect("open");
    let hello = crate::proto::ClientFrame {
        id: 1,
        request: Request::Hello(Hello {
            protocol: 1,
            app_version: "2".into(),
        }),
    };
    frame::write_frame(&mut pipe, &hello).await.expect("hello");
    let newer = br#"{"id":2,"request":{"type":"fromTheFuture","data":{}}}"#;
    let mut raw = (newer.len() as u32).to_le_bytes().to_vec();
    raw.extend_from_slice(newer);
    tokio::io::AsyncWriteExt::write_all(&mut pipe, &raw)
        .await
        .expect("write");
    let mut answers = Vec::new();
    while answers.len() < 2 {
        let body = frame::read_frame(&mut pipe).await.expect("frame");
        match frame::decode::<crate::proto::ServerFrame>(&body).expect("decode") {
            crate::proto::ServerFrame::Event { .. } => {}
            other => answers.push(other),
        }
    }
    assert!(
        matches!(&answers[1], crate::proto::ServerFrame::Failed { id: 2, error } if error.code == ErrorCode::BadRequest)
    );
}

#[tokio::test]
async fn the_last_user_forgetting_triggers_removal_once() {
    let h = harness();
    let mut c = connect(&h).await;
    c.hello("2.0.0").await.expect("hello");
    assert_eq!(
        c.call(Request::ForgetMe).await.expect("forget"),
        Reply::Done { removing: true }
    );
    assert_eq!(h.removed.load(Ordering::SeqCst), 1);
    assert_eq!(
        c.call(Request::ForgetMe).await.expect("again"),
        Reply::Done { removing: false }
    );
    assert_eq!(h.removed.load(Ordering::SeqCst), 1);
}
