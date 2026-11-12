//! Host tests: a fake runtime and kill switch behind a private pipe (no SCM, no WFP, no engine).
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
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
    ErrorCode, Event, Hello, ProtectionWire, Reply, Request, RoutingInputs, StopTunnel,
    TunnelEventWire, TunnelStart, Upstream,
};

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
        _: CancellationToken,
    ) -> Result<StartReceipt, TunError> {
        self.starts.lock().push(req);
        let _ = self.events.send(TunnelEvent::StartBegan { generation: 1 });
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
    async fn status(&self) -> ProtectionWire {
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
}

/// Test pipes grant every authenticated user full access: the unelevated test process must be
/// able to create further instances of its own pipe (the service, as SYSTEM, always can).
const TEST_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)";

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Harness {
    runtime: Arc<FakeRuntime>,
    kill: Arc<FakeKillSwitch>,
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
        notices: broadcast::channel(8).0,
    });
    let removed = Arc::new(AtomicU32::new(0));
    let counter = removed.clone();
    let host = Host::new(HostDeps {
        runtime: runtime.clone(),
        kill_switch: kill.clone(),
        inputs: Arc::new(SharedInputs::new(None)),
        users: Arc::new(Users::open(&dir.join("users.json"))),
        check: admit_all(),
        on_last_user: Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }),
        service_version: "2.0.0-test".into(),
        refuse_tunnel: None,
    });
    let cancel = CancellationToken::new();
    tokio::spawn(host.serve(listener, cancel.clone()));
    Harness {
        runtime,
        kill,
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

#[tokio::test]
async fn hello_start_events_before_reply_then_stop() {
    let h = harness();
    let mut c = connect(&h).await;
    assert_eq!(
        c.hello("2.0.0").await.expect("hello"),
        (1, "2.0.0-test".into())
    );
    let reply = c
        .call(local_start(KillSwitchLevel::Standard))
        .await
        .expect("start");
    assert!(matches!(reply, Reply::Started(Some(r)) if r.pid == 4242));
    let mut seen = Vec::new();
    while let Ok(Ok(e)) = tokio::time::timeout(Duration::from_millis(200), c.next_event()).await {
        seen.push(e);
    }
    let began = seen
        .iter()
        .position(|e| matches!(e, Event::Tunnel(TunnelEventWire::StartBegan { .. })));
    let finished = seen.iter().position(|e| {
        matches!(
            e,
            Event::Tunnel(TunnelEventWire::StartFinished { ok: true, .. })
        )
    });
    assert!(began.is_some() && finished > began, "{seen:?}");
    assert!(
        seen.iter()
            .any(|e| matches!(e, Event::Status(s) if s.running)),
        "{seen:?}"
    );
    assert_eq!(
        h.kill.level(),
        KillSwitchLevel::Standard,
        "settings applied first"
    );
    let started = h.runtime.starts.lock()[0].clone();
    assert_eq!(started.capture, vpnte_tunnel::api::CaptureKind::Tun);
    let stop = c
        .call(Request::Stop(StopTunnel::default()))
        .await
        .expect("stop");
    assert!(matches!(stop, Reply::Stopped(r) if r.ok));
}

#[tokio::test]
async fn a_second_client_gets_busy_until_the_first_leaves() {
    let h = harness();
    let mut first = connect(&h).await;
    first.hello("2.0.0").await.expect("first hello");
    let mut second = connect(&h).await;
    assert_eq!(
        code(second.hello("2.0.0").await.expect_err("busy")),
        ErrorCode::Busy
    );
    drop(first);
    wait_for("the first session stopped", || {
        !h.runtime.stops.lock().is_empty()
    })
    .await;
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

#[tokio::test]
async fn the_client_going_away_stops_the_session() {
    for (level, keep_block) in [
        (KillSwitchLevel::Standard, false),
        (KillSwitchLevel::Strict, true),
    ] {
        let h = harness();
        let mut c = connect(&h).await;
        c.hello("2.0.0").await.expect("hello");
        c.call(local_start(level)).await.expect("start");
        drop(c);
        wait_for("stop after the client left", || {
            !h.runtime.stops.lock().is_empty()
        })
        .await;
        let stop = h.runtime.stops.lock()[0];
        assert_eq!(stop.preserve_protection, keep_block, "{level:?}");
        assert!(!stop.preserve_last);
    }
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
