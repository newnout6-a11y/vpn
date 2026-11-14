//! pfollow-a1: the take-over of a session the service kept, with the real lifecycle over the
//! split runtime and the service's session host behind a private pipe. Neither a held drop nor
//! the user's own connect in flight may end in a stop that lifts the kill switch's block.
use std::net::SocketAddr;

use vpnte_base::types::Owner;
use vpnte_core::ops::Source;
use vpnte_core::settings::Settings;
use vpnte_service::proto::KeptSession;
use vpnte_tunnel::fsm::TunnelState;
use vpnte_tunnel::history::{History, SessionMode};
use vpnte_tunnel::lifecycle::{
    ConnError, ConnectReq, ConnectTarget, Done, ExternalProxies, ForeignVpn, Forensics, Lifecycle,
    LifecycleDeps, Monitor, NoticeKind, Notifier, ProfileSource, ServerChoice, SoftProxy,
};

use super::*;
use crate::svc_tunnel::remote::Split;

/// The kept session's upstream: data only, nothing listens there.
const UPSTREAM: &str = "127.0.0.1:18999";

/// Every lifecycle collaborator but the runtime: quiet, Hard mode only.
struct Quiet;

impl ProfileSource for Quiet {
    fn resolve(&self, _: Option<&str>) -> Option<ServerChoice> {
        None
    }
}

#[async_trait]
impl SoftProxy for Quiet {
    fn applied(&self) -> Option<bool> {
        Some(false)
    }
    async fn apply(&self, _: &str, _: ProxyKind) -> AppResult<()> {
        Ok(())
    }
    async fn rollback(&self) -> AppResult<()> {
        Ok(())
    }
    async fn is_configured(&self, _: &str, _: ProxyKind) -> AppResult<bool> {
        Ok(false)
    }
}

impl Monitor for Quiet {
    fn suppress_leak_tests(&self, _: Duration) {}
    fn start(&self, _: Option<u64>) {}
    fn stop(&self) {}
    fn egress_ip(&self) -> Option<String> {
        None
    }
}

#[async_trait]
impl Forensics for Quiet {
    fn start_session(&self, _: SessionMode, _: &str) {}
    async fn stop_session(&self, _: &str) -> bool {
        true
    }
    fn session_bytes(&self) -> (u64, u64) {
        (0, 0)
    }
}

#[async_trait]
impl ExternalProxies for Quiet {
    async fn stop_all(&self, _: &str) {}
}

impl Notifier for Quiet {
    fn notify(&self, _: Notice, _: NoticeKind) {}
}

impl ForeignVpn for Quiet {
    fn full_tunnel(&self) -> Option<String> {
        None
    }
}

/// Routing inputs that wait for `open` (holds a start of the app before it reaches the service).
struct Gated(watch::Receiver<bool>);

#[async_trait]
impl InputsSource for Gated {
    async fn snapshot(&self) -> AppResult<UserInputs> {
        let mut open = self.0.clone();
        let _ = open.wait_for(|open| *open).await;
        Ok(UserInputs::default())
    }
}

/// The lifecycle over a split runtime whose Tunnel mode is `remote`, kill switch "If the VPN
/// drops" (stored in `dir`), and that split.
fn lifecycle(remote: &Remote, dir: &Path) -> (Lifecycle, Split) {
    let settings = Arc::new(Store::<Settings>::open(dir));
    settings
        .update(|s| s.kill_switch = KillSwitchLevel::Standard)
        .expect("settings");
    let split = Split::spawn(FakeRuntime::new(), remote.clone(), CancellationToken::new());
    let lifecycle = Lifecycle::spawn(LifecycleDeps {
        runtime: Arc::new(split.clone()),
        profiles: Arc::new(Quiet),
        soft: Arc::new(Quiet),
        monitor: Arc::new(Quiet),
        forensics: Arc::new(Quiet),
        proxies: Arc::new(Quiet),
        notifier: Arc::new(Quiet),
        history: History::open(dir),
        settings,
        always_available: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        foreign_vpn: Arc::new(Quiet),
    });
    (lifecycle, split)
}

fn target() -> ConnectTarget {
    ConnectTarget::LocalProxy {
        addr: UPSTREAM.into(),
        kind: ProxyKind::Socks5,
    }
}

fn protected(dir: &Path) -> Arc<Store<ProtectionDoc>> {
    let protection = Arc::new(Store::<ProtectionDoc>::open(dir));
    protection
        .update(|d| d.settings.level = KillSwitchLevel::Standard)
        .expect("protection");
    protection
}

/// The production connect of a kept session, minus the coordinator's adaptive bookkeeping.
async fn connect(lc: &Lifecycle, target: ConnectTarget) -> Result<Done, ConnError> {
    lc.connect(ConnectReq::new(target, Owner::Manual, Source::Lifecycle))
        .await
}

/// Waits (5 s at most) until `done` holds.
async fn until(what: &str, done: impl Fn() -> bool) {
    for _ in 0..500 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{what}: not reached");
}

/// The stopped host lets go of the pipe at the next request its reader takes (a real restart
/// ends the process): requests until the loss is counted.
async fn lose(r: &Remote, losses: &watch::Receiver<u64>) {
    let lost = async {
        while !losses.has_changed().unwrap_or(true) {
            let _ = r.refresh().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), lost)
        .await
        .expect("loss seen");
}

/// Links to the restarted `host` again, which then brings its kept session back: the session
/// offered for the take-over.
async fn resumed(r: &Remote, host: &Arc<Host>) -> KeptSession {
    let reattach = tokio::spawn({
        let r = r.clone();
        async move { r.reattach().await }
    });
    let linked = || {
        r.0.link
            .try_lock()
            .is_ok_and(|link| link.as_ref().is_some_and(|l| !l.gone.is_cancelled()))
    };
    until("linked again", linked).await;
    assert!(host.resume(CancellationToken::new()).await, "resumed");
    reattach
        .await
        .expect("task")
        .expect("offered for a take-over")
}

/// The service's session host with a session a crashed window left running ("If the VPN
/// drops" in force).
async fn crashed_window() -> Service {
    let s = service();
    s.protection
        .update(|d| d.settings.level = KillSwitchLevel::Standard)
        .expect("protection");
    let mut crashed = Client::connect(&s.pipe, &ServerCheck::Any, Duration::from_secs(5))
        .await
        .expect("connect");
    crashed.hello("2.0.0").await.expect("hello");
    let request = StartRequest {
        mode: Mode::LocalProxy {
            addr: UPSTREAM.into(),
            kind: ProxyKind::Socks5,
        },
        ..tun_request()
    };
    let inputs = UserInputs::default();
    let start = super::super::start::tunnel_start(&request, &inputs, ProtectionSettings::default())
        .expect("start");
    crashed
        .call(Request::Start(Box::new(start)))
        .await
        .expect("started");
    s
}

/// The kept session, once the crashed window's connection is gone.
async fn attach(r: &Remote) -> KeptSession {
    let kept = loop {
        if let Some(kept) = r.attach().await {
            break kept;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let upstream: SocketAddr = UPSTREAM.parse().expect("addr");
    assert_eq!(kept.local_proxy, Some(upstream));
    kept
}

/// The server drops: the runtime restarts its engine while the kill switch holds, and the
/// lifecycle pauses.
async fn held_drop(rt: &FakeRuntime, lc: &Lifecycle) {
    rt.status.send_modify(|s| {
        s.running = false;
        s.pid = None;
    });
    let restarting = TunStatusKind::Restarting { attempt: 1, max: 3 };
    let _ = rt.events.send(TunnelEvent::Status(restarting));
    let pause = lc.kill_switch();
    until("paused", || pause.borrow().pause.is_some()).await;
}

/// pfollow-a1, first trigger: the service restarts while the kill switch holds a drop ("If the
/// VPN drops", the lifecycle paused). The session it brings back joins the pause as its
/// recovery: connected again, the pause over, nothing stopped in the service (before the fix the
/// refused connect ended in a stop that lifted the block).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_drop_takes_the_resumed_session_back() {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let (pipe, dir) = (pipe_name(n), TempDir::new(&format!("takeover-held-{n}")));
    let (_, first_rt, first) = restarted(&pipe, &dir.0).await;
    let r = Remote::on_pipe(&pipe, Arc::new(NoInputs), protected(&dir.0));
    let (lc, split) = lifecycle(&r, &dir.0);
    connect(&lc, target()).await.expect("connected");
    let snap = lc.snapshot();
    assert_eq!(snap.borrow().state, TunnelState::Connected);

    held_drop(&first_rt, &lc).await;
    let pause = lc.kill_switch();

    let losses = r.losses();
    first.cancel();
    lose(&r, &losses).await;
    assert!(
        pause.borrow().pause.is_some(),
        "still paused after the loss"
    );

    let (host, second_rt, second) = restarted(&pipe, &dir.0).await;
    let kept = resumed(&r, &host).await;
    crate::svc_tunnel::takeover::take_over(&split, &lc, kept, |t| connect(&lc, t)).await;
    until("connected again", || {
        snap.borrow().state == TunnelState::Connected
    })
    .await;
    assert!(pause.borrow().pause.is_none(), "the pause is over");
    assert_eq!(
        second_rt.starts.load(Ordering::SeqCst),
        1,
        "the resume only"
    );
    assert_eq!(second_rt.stops.load(Ordering::SeqCst), 0, "nothing stopped");
    second.cancel();
}

/// pfollow-a1, second trigger: the user's own connect is in flight (it has not reached the
/// service yet) when the take-over comes. The take-over leaves the kept session to it: the
/// connect takes it over, nothing is stopped in between (before the fix the refused take-over
/// stopped it without the block, and the connect then started a second run).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connect_in_flight_takes_the_kept_session_over() {
    let s = crashed_window().await;
    let (open, gate) = watch::channel(false);
    let r = Remote::on_pipe(&s.pipe, Arc::new(Gated(gate)), s.protection.clone());
    let kept = attach(&r).await;
    let (lc, split) = lifecycle(&r, &s._dir.0);
    let user = tokio::spawn({
        let lc = lc.clone();
        async move { connect(&lc, target()).await }
    });
    until("the user's connect in flight", || lc.busy()).await;
    let taking = tokio::spawn({
        let (split, lc) = (split.clone(), lc.clone());
        async move {
            crate::svc_tunnel::takeover::take_over(&split, &lc, kept, |t| connect(&lc, t)).await
        }
    });
    // The take-over meets the connect in flight before it reaches the service.
    tokio::time::sleep(Duration::from_millis(200)).await;
    open.send_replace(true);
    user.await.expect("task").expect("the user's connect");
    tokio::time::timeout(Duration::from_secs(5), taking)
        .await
        .expect("take-over over")
        .expect("task");
    assert_eq!(lc.snapshot().borrow().state, TunnelState::Connected);
    assert_eq!(s.runtime.starts.load(Ordering::SeqCst), 1, "no second run");
    assert_eq!(s.runtime.stops.load(Ordering::SeqCst), 0, "nothing stopped");
}

/// Routing inputs that cannot be read: a start fails before it reaches the service.
struct Unreadable;

#[async_trait]
impl InputsSource for Unreadable {
    async fn snapshot(&self) -> AppResult<UserInputs> {
        Err(vpnte_base::AppError::new(vpnte_base::ErrorKind::Internal))
    }
}

/// pfollow-a1, fixfollow-a2: a take-over that cannot run through ends the kept session through
/// the lifecycle. The kill switch keeps blocking while its level holds ("If the VPN drops"
/// here), so programs never go direct, and the lifecycle shows it: `blocked`, nothing in
/// flight, a later connect admitted (before the fix the stop went past the lifecycle and the
/// runtime's `Adapting` left it in «reconnecting» with every connect refused).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_take_over_keeps_the_block() {
    let s = crashed_window().await;
    let r = Remote::on_pipe(&s.pipe, Arc::new(Unreadable), s.protection.clone());
    let kept = attach(&r).await;
    let (lc, split) = lifecycle(&r, &s._dir.0);
    crate::svc_tunnel::takeover::take_over(&split, &lc, kept, |t| connect(&lc, t)).await;
    assert_eq!(s.runtime.stops.load(Ordering::SeqCst), 1, "stopped");
    assert_eq!(s.runtime.kept.load(Ordering::SeqCst), 1, "the block kept");
    assert!(r.parked().is_none());
    let snap = lc.snapshot().borrow().clone();
    assert_eq!(snap.state, TunnelState::Blocked, "the block shows");
    assert_eq!(snap.transition, None, "nothing left in flight");
    let again = connect(&lc, target()).await;
    assert!(
        !matches!(again, Err(ConnError::Refused(_))),
        "a connect is admitted: {again:?}"
    );
}

/// fixfollow-a2, second form: the take-over's connect fails before it reaches the service (the
/// kept server is gone from the list), so the split still drives this process's runtime. The
/// stop reaches the service all the same, and the block it keeps shows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_take_over_that_never_reached_the_service_ends_there() {
    let s = crashed_window().await;
    let r = Remote::on_pipe(&s.pipe, Arc::new(NoInputs), s.protection.clone());
    let kept = attach(&r).await;
    let (lc, split) = lifecycle(&r, &s._dir.0);
    let gone = |_| async {
        let error = vpnte_base::AppError::new(vpnte_base::ErrorKind::Internal);
        Err(ConnError::Failed(error.into()))
    };
    crate::svc_tunnel::takeover::take_over(&split, &lc, kept, gone).await;
    assert_eq!(s.runtime.stops.load(Ordering::SeqCst), 1, "stopped there");
    assert_eq!(s.runtime.kept.load(Ordering::SeqCst), 1, "the block kept");
    assert_eq!(lc.snapshot().borrow().state, TunnelState::Blocked);
}

/// fixfollow-a1: the service restarts while the kill switch holds a drop, and its resume fails
/// (the server is still out of reach), so the restarted service lifts the block. The pause must
/// not stay on screen while programs go direct: the lifecycle hears the run's end, the pause
/// ends, and a connect is admitted again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_drop_whose_resume_fails_ends_the_pause() {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let (pipe, dir) = (pipe_name(n), TempDir::new(&format!("takeover-lost-{n}")));
    let (_, first_rt, first) = restarted(&pipe, &dir.0).await;
    let r = Remote::on_pipe(&pipe, Arc::new(NoInputs), protected(&dir.0));
    let (lc, split) = lifecycle(&r, &dir.0);
    connect(&lc, target()).await.expect("connected");
    held_drop(&first_rt, &lc).await;
    let losses = r.losses();
    first.cancel();
    lose(&r, &losses).await;

    let (host, second_rt, second) = restarted(&pipe, &dir.0).await;
    second_rt.fail.store(true, Ordering::SeqCst);
    let resume = tokio::spawn(async move { host.resume(CancellationToken::new()).await });
    crate::svc_tunnel::takeover::after_loss(&split, &lc, |t| connect(&lc, t)).await;
    assert!(!resume.await.expect("task"), "the resume failed");
    let pause = lc.kill_switch();
    until("the pause ended", || pause.borrow().pause.is_none()).await;
    assert_ne!(lc.snapshot().borrow().state, TunnelState::Connected);

    second_rt.fail.store(false, Ordering::SeqCst);
    connect(&lc, target())
        .await
        .expect("a connect is admitted again");
    second.cancel();
}
