//! Speed-test runs against the loopback server (small sizes, no Internet).
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;
use vpnte_core::ops::{OperationRegistry, RunOpts};
use vpnte_core::store::{Document, Store};

use super::testsrv::{Reply, Server, bytes_param};
use super::*;

const KIB: u64 = 1024;

/// A throw-away data root, removed on drop.
pub(crate) struct TempRoot(pub PathBuf);

impl TempRoot {
    pub(crate) fn new() -> TempRoot {
        let dir = std::env::temp_dir().join(format!(
            "vpnte-probes-web-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempRoot(dir)
    }

    pub(crate) fn store<T: Document>(&self) -> Arc<Store<T>> {
        Arc::new(Store::open(&self.0))
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Routes of a healthy speed-test server.
fn healthy(req: &super::testsrv::Request) -> Reply {
    let path = req.target.split('?').next().unwrap_or_default();
    match path {
        "/ping" => Reply::Full(204, vec![], vec![]),
        "/down" => Reply::Stream {
            len: bytes_param(&req.target).unwrap_or(0),
            delay: None,
        },
        "/static" => Reply::Stream {
            len: 8 * 1024 * KIB,
            delay: None,
        },
        "/slow" => Reply::Stream {
            len: 8 * 1024 * KIB,
            delay: Some(Duration::from_millis(40)),
        },
        "/short" => Reply::Full(200, vec![], vec![b'x'; 512]),
        "/fail" => Reply::Full(503, vec![], vec![]),
        "/hang" => Reply::Hang,
        // Stream 0 fails while its sibling hangs.
        "/mixed" if req.target.contains("stream=0") => Reply::Full(503, vec![], vec![]),
        "/mixed" => Reply::Hang,
        "/up" => Reply::Full(200, vec![], b"ok".to_vec()),
        "/up-fail" => Reply::Full(500, vec![], vec![]),
        _ => Reply::Full(404, vec![], vec![]),
    }
}

fn target(
    server: &Server,
    name: &str,
    path: &str,
    sized: bool,
    plain_http: bool,
) -> DownloadTarget {
    DownloadTarget {
        name: name.into(),
        url: server.url(path),
        sized,
        plain_http,
    }
}

fn plan(server: &Server) -> Plan {
    let round = |streams, kib: u64| Round {
        streams,
        bytes_per_stream: kib * KIB,
        time_box: Duration::from_secs(3),
    };
    Plan {
        latency_urls: vec![server.url("/ping")],
        download: vec![target(server, "Loop", "/down", true, false)],
        upload_url: server.url("/up"),
        download_probe: round(2, 256),
        download_sustained: round(3, 512),
        download_fast_mbps: 0.0,
        upload_probe: round(2, 128),
        upload_sustained: round(3, 256),
        upload_fast_mbps: 0.0,
        min_round_bytes: 64 * KIB,
        latency_timeout: Duration::from_secs(2),
        latency_budget: Duration::from_secs(5),
        setup_timeout: Duration::from_secs(3),
        run_budget: Duration::from_secs(30),
    }
}

fn connection() -> Connection {
    Connection {
        tun_v4: None,
        profile: Some("poland1".into()),
    }
}

struct FakeEgress {
    reference: EgressRef,
    seen: Option<IpAddr>,
}

impl EgressSource for FakeEgress {
    fn reference(&self) -> EgressRef {
        self.reference
    }
    fn sample(&self, _family: IpFamily) -> BoxFuture<'_, Option<IpAddr>> {
        Box::pin(async move { self.seen })
    }
}

fn env(plan: Plan, egress: Option<Arc<dyn EgressSource>>) -> SpeedEnv {
    SpeedEnv {
        connection: Some(connection()),
        egress,
        plan,
    }
}

/// speedTestOperations.test.ts (AT-00-007): a fast link runs both rounds of each direction,
/// commits one history row and ends with the `complete` frame.
#[tokio::test]
async fn fast_link_full_run() {
    let server = Server::start(healthy).await;
    let root = TempRoot::new();
    let history = root.store::<SpeedTests>();
    let ops = OperationRegistry::new();
    let exit: IpAddr = "198.51.100.9".parse().unwrap();
    let egress = FakeEgress {
        reference: EgressRef {
            baseline: Some(exit),
            real_ip: None,
        },
        seen: Some(exit),
    };
    let (tx, rx) = watch::channel(SpeedProgress::default());
    let pending = std::future::pending::<()>();
    let result = run(
        &ops,
        history.clone(),
        env(plan(&server), Some(Arc::new(egress))),
        pending,
        tx,
        RunOpts::default(),
    )
    .await
    .unwrap();
    assert!(result.download_mbps > 0.0 && result.upload_mbps.unwrap() > 0.0);
    assert_eq!(result.server_name, "Loop");
    assert_eq!(result.profile_used.as_deref(), Some("poland1"));
    assert_eq!(result.egress, Egress::Match);
    assert_eq!(result.transport_warning, None);
    assert_eq!(
        *rx.borrow(),
        SpeedProgress {
            percent: 100,
            phase: SpeedPhase::Complete
        }
    );
    let requests = server.requests();
    assert!(
        requests
            .iter()
            .any(|r| r.target.contains(&format!("bytes={}", 512 * KIB)))
    );
    assert!(
        requests
            .iter()
            .any(|r| r.method == "POST" && r.content_length == Some(256 * KIB))
    );
    assert_eq!(history.snapshot().history, vec![result]);
}

/// speedTestOperations.test.ts: a failing server falls through to the next one; a captive
/// portal's short answer is no figure (B-ST-2); a plain-HTTP fallback is flagged (B-ST-4).
#[tokio::test]
async fn failing_servers_fall_through() {
    let server = Server::start(healthy).await;
    let mut plan = plan(&server);
    plan.download = vec![
        target(&server, "Broken", "/fail", true, false),
        target(&server, "Portal", "/short", true, false),
        target(&server, "Plain", "/static", false, true),
    ];
    let (tx, _rx) = watch::channel(SpeedProgress::default());
    let result = measure(&connection(), None, &plan, &tx, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(result.server_name, "Plain");
    assert_eq!(result.transport_warning, Some(TransportWarning::PlainHttp));
    assert_eq!(result.egress, Egress::NotChecked);
    assert!(
        server
            .requests()
            .iter()
            .any(|r| r.target.starts_with("/static?cb="))
    );
}

/// speedTestOperations.test.ts: VPN off → typed conflict, no request, empty history.
#[tokio::test]
async fn refused_without_a_connection() {
    let server = Server::start(healthy).await;
    let root = TempRoot::new();
    let history = root.store::<SpeedTests>();
    let ops = OperationRegistry::new();
    let (tx, rx) = watch::channel(SpeedProgress::default());
    let env = SpeedEnv {
        connection: None,
        egress: None,
        plan: plan(&server),
    };
    let err = run(
        &ops,
        history.clone(),
        env,
        std::future::pending(),
        tx,
        RunOpts::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert_eq!(err.user_msg().key, "probes.speed.notConnected");
    assert!(server.requests().is_empty());
    assert!(history.snapshot().history.is_empty());
    assert_eq!(*rx.borrow(), SpeedProgress::default());
}

/// speedTestOperations.test.ts (AT-00-005): cancelling mid-transfer ends the run promptly,
/// closes the real loopback connection and sends no further frame.
#[tokio::test]
async fn cancel_aborts_the_streams() {
    let server = Server::start(healthy).await;
    let mut plan = plan(&server);
    plan.download = vec![target(&server, "Hang", "/hang", true, false)];
    plan.setup_timeout = Duration::from_secs(20);
    let (tx, rx) = watch::channel(SpeedProgress::default());
    let cancel = CancellationToken::new();
    let run = {
        let (cancel, tx) = (cancel.clone(), tx.clone());
        tokio::spawn(async move { measure(&connection(), None, &plan, &tx, &cancel).await })
    };
    server.hanging.notified().await;
    let frame = *rx.borrow();
    assert_eq!(frame.phase, SpeedPhase::Download);
    let asked = Instant::now();
    cancel.cancel();
    let err = run.await.unwrap().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
    assert!(asked.elapsed() < Duration::from_millis(900));
    tokio::time::timeout(Duration::from_secs(5), server.closed.notified())
        .await
        .expect("server saw the close");
    assert_eq!(*rx.borrow(), frame, "no frame after the cancellation");
}

/// B-ST-5: the connection changing mid-test aborts it with a conflict; nothing is stored and an
/// error frame is sent. A second run meanwhile is refused as busy.
#[tokio::test]
async fn switching_servers_aborts_and_busy_refuses() {
    let server = Server::start(healthy).await;
    let root = TempRoot::new();
    let history = root.store::<SpeedTests>();
    let ops = OperationRegistry::new();
    let mut plan = plan(&server);
    plan.download = vec![target(&server, "Hang", "/hang", true, false)];
    plan.setup_timeout = Duration::from_secs(20);
    let (switch_tx, switch_rx) = tokio::sync::oneshot::channel::<()>();
    let switched = async move {
        let _ = switch_rx.await;
    };
    let (tx, rx) = watch::channel(SpeedProgress::default());
    let first = {
        let (ops, history, env) = (ops.clone(), history.clone(), env(plan.clone(), None));
        tokio::spawn(async move { run(&ops, history, env, switched, tx, RunOpts::default()).await })
    };
    server.hanging.notified().await;
    let (tx2, _rx2) = watch::channel(SpeedProgress::default());
    let busy = run(
        &ops,
        history.clone(),
        env(plan, None),
        std::future::pending(),
        tx2,
        RunOpts::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(busy.user_msg().key, "core.ops.busy");
    switch_tx.send(()).unwrap();
    let err = first.await.unwrap().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert_eq!(err.user_msg().key, "probes.speed.serverChanged");
    assert_eq!(
        *rx.borrow(),
        SpeedProgress {
            percent: 0,
            phase: SpeedPhase::Error
        }
    );
    assert!(history.snapshot().history.is_empty());
}

/// B-ST-4: a failed upload keeps the download and latency figures.
#[tokio::test]
async fn upload_failure_keeps_the_download() {
    let server = Server::start(healthy).await;
    let mut plan = plan(&server);
    plan.upload_url = server.url("/up-fail");
    let (tx, _rx) = watch::channel(SpeedProgress::default());
    let result = measure(&connection(), None, &plan, &tx, &CancellationToken::new())
        .await
        .unwrap();
    assert!(result.download_mbps > 0.0);
    assert_eq!(result.upload_mbps, None);
}

/// B-ST-3: a slow link is cut by the time box and still yields a figure.
#[tokio::test]
async fn slow_link_is_time_boxed() {
    let server = Server::start(healthy).await;
    let mut plan = plan(&server);
    plan.download = vec![target(&server, "Slow", "/slow", false, false)];
    plan.download_probe.time_box = Duration::from_millis(600);
    plan.download_fast_mbps = f64::MAX;
    plan.upload_fast_mbps = f64::MAX;
    let (tx, _rx) = watch::channel(SpeedProgress::default());
    let started = Instant::now();
    let result = measure(&connection(), None, &plan, &tx, &CancellationToken::new())
        .await
        .unwrap();
    assert!(result.download_mbps > 0.0);
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// The old latency error: no URL answers.
#[tokio::test]
async fn latency_failure_is_a_network_error() {
    let server = Server::start(healthy).await;
    let mut plan = plan(&server);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("http://{}/", closed.local_addr().unwrap());
    drop(closed);
    plan.latency_urls = vec![url::Url::parse(&dead).unwrap()];
    let (tx, _rx) = watch::channel(SpeedProgress::default());
    let err = measure(&connection(), None, &plan, &tx, &CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Network);
    assert_eq!(err.user_msg().key, "probes.speed.latencyFailed");
}

/// speedTestOperations.test.ts: the first server fails while its sibling stream hangs → the
/// sibling is aborted (its connection closed) and the next server gives the result.
#[tokio::test]
async fn failed_stream_aborts_its_sibling() {
    let server = Server::start(healthy).await;
    let mut plan = plan(&server);
    plan.download = vec![
        target(&server, "Mixed", "/mixed", true, false),
        target(&server, "OVH", "/down", true, false),
    ];
    let (tx, _rx) = watch::channel(SpeedProgress::default());
    let result = measure(&connection(), None, &plan, &tx, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(result.server_name, "OVH");
    tokio::time::timeout(Duration::from_secs(5), server.closed.notified())
        .await
        .expect("the hanging sibling was closed");
}

/// speedTestOperations.test.ts (AT-00-003): an operation deadline ends the run with a typed
/// timeout, nothing stored, an error frame sent.
#[tokio::test]
async fn operation_deadline_is_a_timeout() {
    let server = Server::start(healthy).await;
    let root = TempRoot::new();
    let history = root.store::<SpeedTests>();
    let ops = OperationRegistry::new();
    let mut plan = plan(&server);
    plan.latency_urls = vec![server.url("/hang")];
    let (tx, rx) = watch::channel(SpeedProgress::default());
    let opts = RunOpts {
        timeout: Some(Duration::from_millis(25)),
        ..RunOpts::default()
    };
    let started = Instant::now();
    let err = run(
        &ops,
        history.clone(),
        env(plan, None),
        std::future::pending(),
        tx,
        opts,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(history.snapshot().history.is_empty());
    assert_eq!(rx.borrow().phase, SpeedPhase::Error);
}

/// The production plan: HTTPS first, plain HTTP only as flagged fallbacks, HTTPS upload, the
/// sizes and time boxes of B-ST-3 and the 90 s bound of B-ST-7.
#[test]
fn standard_plan() {
    let plan = Plan::standard();
    let first_plain = plan.download.iter().position(|t| t.plain_http).unwrap();
    assert!(
        plan.download[..first_plain]
            .iter()
            .all(|t| t.url.scheme() == "https" && !t.plain_http)
    );
    assert!(
        plan.download[first_plain..]
            .iter()
            .all(|t| t.url.scheme() == "http" && t.plain_http)
    );
    assert_eq!(plan.upload_url.scheme(), "https");
    assert_eq!(plan.download[0].name, "Cloudflare");
    assert!(plan.download[0].sized);
    let url = rounds::stream_url(&plan.download[0], 52_428_800, "run1", 3);
    assert_eq!(
        url.as_str(),
        "https://speed.cloudflare.com/__down?bytes=52428800&run=run1&stream=3"
    );
    let url = rounds::stream_url(&plan.download[1], 1, "run1", 0);
    assert_eq!(url.query(), Some("cb=run10"));
    assert_eq!(
        (
            plan.download_probe.streams,
            plan.download_probe.bytes_per_stream
        ),
        (2, 10 * MIB)
    );
    assert_eq!(
        (
            plan.download_sustained.streams,
            plan.download_sustained.bytes_per_stream
        ),
        (6, 50 * MIB)
    );
    assert_eq!(
        (
            plan.upload_probe.streams,
            plan.upload_probe.bytes_per_stream
        ),
        (4, 2 * MIB)
    );
    assert_eq!(
        (
            plan.upload_sustained.streams,
            plan.upload_sustained.bytes_per_stream
        ),
        (20, 4 * MIB)
    );
    assert_eq!(plan.min_round_bytes, MIB);
    assert_eq!(plan.run_budget, Duration::from_secs(90));
}
