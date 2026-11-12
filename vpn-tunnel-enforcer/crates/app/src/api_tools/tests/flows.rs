//! The pages' flows over a fake tunnel (no engine, no Internet, no system change): a check of a
//! loopback site with the tunnel off, its history and push, a bad link, a cancelled check,
//! clearing, the routing test without a session, the speed test's refusals, the pushed session
//! flag, the progress bridge and the server-switch trigger.
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, Owner};
use vpnte_base::{AppResult, ErrorKind};
use vpnte_probes::speedtest as probe;
use vpnte_tunnel::api::{CaptureKind, ProxyEndpoint, SessionEndpoints, TunStatus};
use vpnte_tunnel::history::SessionMode;
use vpnte_tunnel::lifecycle::SessionView;
use vpnte_ui::availability::{AvailabilityApi, RoutingVerdict, UrlVerdict};
use vpnte_ui::speedtest::{SpeedPhase, SpeedProgress, SpeedTestApi};

use super::super::speed::{forward, server_switched};
use super::super::{Availability, Shared, SpeedTest};
use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};

/// Both pages' shared state over a throw-away backend and a fake, idle tunnel.
fn shared(name: &str) -> (TempDir, Arc<FakeTunnel>, Arc<Shared>) {
    let dir = TempDir::new(name);
    let tunnel = FakeTunnel::new(false);
    let shared = Shared::start(backend(&dir, tunnel.clone()));
    (dir, tunnel, shared)
}

const PAGE: &str = "<html><head><title>Loop</title></head><body><p>a normal page with plenty of content</p></body></html>";

/// A loopback site: every request gets a small 200 page; the TCP stage only connects.
async fn site() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                let body = if request.starts_with(b"HEAD") {
                    ""
                } else {
                    PAGE
                };
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    PAGE.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

fn running(capture: CaptureKind) -> TunStatus {
    TunStatus {
        running: true,
        capture: Some(capture),
        profile_name: Some("Test".into()),
        ..TunStatus::default()
    }
}

/// AT-07-003, B-UA-5: with the tunnel off the native probe is the direct path; the result is
/// saved (normalised URL, no query) and pushed before the answer.
#[tokio::test]
async fn a_check_with_the_tunnel_off_is_saved_and_pushed_before_the_answer() {
    let (_dir, _tunnel, shared) = shared("tools-check");
    let api = Availability(shared.clone());
    let state = api.state();
    let addr = site().await;
    let check = api
        .check_url(
            format!("  http://{addr}/page?token=x "),
            CancellationToken::new(),
        )
        .await
        .expect("check");
    assert_eq!(check.url, format!("http://{addr}/page"));
    assert!(!check.tunnel_active && check.protected.is_none());
    let direct = check
        .direct
        .clone()
        .expect("the native path is the direct one");
    assert!(direct.measured && direct.available, "{direct:?}");
    assert_eq!(check.verdict, UrlVerdict::WorksBoth);
    assert_eq!(
        check.recommendation.key,
        "probes.availability.rec.reachableWithoutVpn"
    );
    let pushed = state.borrow().clone();
    assert!(!pushed.tunnel_running);
    assert_eq!(pushed.history.first(), Some(&check));
    assert_eq!(shared.url_checks.read(|d| d.history.len()), 1);
}

/// An unusable link is `Validation` before anything runs; a cancelled check saves nothing.
#[tokio::test]
async fn bad_or_cancelled_checks_save_nothing() {
    let (_dir, _tunnel, shared) = shared("tools-refused");
    let api = Availability(shared.clone());
    let err = api
        .check_url("ftp://example.test/".into(), CancellationToken::new())
        .await
        .expect_err("refused");
    assert_eq!(err.kind, ErrorKind::Validation);
    let addr = site().await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let err = api
        .check_url(format!("http://{addr}/"), cancel)
        .await
        .expect_err("cancelled");
    assert_eq!(err.kind, ErrorKind::Cancelled);
    assert_eq!(shared.url_checks.read(|d| d.history.len()), 0);
    assert!(api.state().borrow().history.is_empty());
}

/// «Очистить историю» empties the saved list and pushes it.
#[tokio::test]
async fn clearing_forgets_the_saved_checks() {
    let (_dir, _tunnel, shared) = shared("tools-clear");
    let api = Availability(shared.clone());
    let addr = site().await;
    api.check_url(format!("http://{addr}/"), CancellationToken::new())
        .await
        .expect("check");
    assert_eq!(api.state().borrow().history.len(), 1);
    api.clear_history().await.expect("cleared");
    assert!(api.state().borrow().history.is_empty());
    assert_eq!(shared.url_checks.read(|d| d.history.len()), 0);
}

/// Without a session the self-test answers "protection is off" without asking any echo.
#[tokio::test]
async fn the_routing_test_without_a_session_reports_the_tunnel_off() {
    let (_dir, _tunnel, shared) = shared("tools-routing");
    let report = Availability(shared)
        .routing_test(CancellationToken::new())
        .await
        .expect("report");
    assert_eq!(report.verdict, RoutingVerdict::TunnelOff);
    assert_eq!(report.message.key, "probes.routing.tunnelOff");
    assert_eq!((report.vpn_ip, report.direct_ip), (None, None));
}

/// B-ST-6 / NOADMIN §2: no session is refused before any request; a Soft session too, since
/// the measurement would time the direct line. Nothing is saved and no frame is sent.
#[tokio::test]
async fn the_speed_test_refuses_without_a_tun_session() {
    let (_dir, tunnel, shared) = shared("tools-speed");
    let api = SpeedTest(shared.clone());
    let (progress, frames) = watch::channel(SpeedProgress::default());
    let err = api
        .run(progress.clone(), CancellationToken::new())
        .await
        .expect_err("no session");
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert_eq!(
        err.msg.map(|m| m.key),
        Some("probes.speed.notConnected".into())
    );
    tunnel.status.send_replace(running(CaptureKind::Proxy));
    let err = api
        .run(progress.clone(), CancellationToken::new())
        .await
        .expect_err("soft");
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert_eq!(
        err.msg.map(|m| m.key),
        Some("app.tools.speed.softUnavailable".into())
    );
    // `progress` is still held here, so the channel is open and simply untouched.
    assert!(!frames.has_changed().expect("open"));
    drop(progress);
    assert_eq!(shared.speed_tests.read(|d| d.history.len()), 0);
}

/// The session flag follows the tunnel on both pages without a page action.
#[tokio::test]
async fn the_session_flag_is_pushed_to_both_pages() {
    let (_dir, tunnel, shared) = shared("tools-flag");
    let mut availability = Availability(shared.clone()).state();
    let mut speed = SpeedTest(shared).state();
    assert!(!availability.borrow().tunnel_running && !speed.borrow().tunnel_running);
    tunnel.status.send_replace(running(CaptureKind::Tun));
    let within = Duration::from_secs(5);
    tokio::time::timeout(within, availability.wait_for(|s| s.tunnel_running))
        .await
        .expect("availability pushed")
        .expect("open");
    tokio::time::timeout(within, speed.wait_for(|s| s.tunnel_running))
        .await
        .expect("speed pushed")
        .expect("open");
    tunnel.status.send_replace(TunStatus::default());
    tokio::time::timeout(within, speed.wait_for(|s| !s.tunnel_running))
        .await
        .expect("stop pushed")
        .expect("open");
}

/// The run's frames reach the page's own channel while it runs; the probes' error frame does
/// not; the last frame is copied even when it lands together with the answer.
#[tokio::test]
async fn progress_is_forwarded_into_the_page_channel() {
    let (frames, seen) = watch::channel(probe::SpeedProgress::default());
    let (page, mut shown) = watch::channel(SpeedProgress::default());
    let (step, mut next) = tokio::sync::mpsc::unbounded_channel::<probe::SpeedProgress>();
    let work = async move {
        while let Some(frame) = next.recv().await {
            frames.send_replace(frame);
            if frame.phase == probe::SpeedPhase::Complete {
                return AppResult::Ok(7);
            }
            tokio::task::yield_now().await;
        }
        AppResult::Ok(0)
    };
    let frame = |percent, phase| probe::SpeedProgress { percent, phase };
    let driver = tokio::spawn(async move {
        step.send(frame(30, probe::SpeedPhase::Download))
            .expect("send");
        tokio::time::sleep(Duration::from_millis(50)).await;
        step.send(frame(0, probe::SpeedPhase::Error)).expect("send");
        tokio::time::sleep(Duration::from_millis(50)).await;
        step.send(frame(100, probe::SpeedPhase::Complete))
            .expect("send");
    });
    let mut phases = Vec::new();
    let watcher = async {
        while shown.changed().await.is_ok() {
            let now = *shown.borrow_and_update();
            phases.push(now.phase);
            if now.phase == SpeedPhase::Complete {
                break;
            }
        }
    };
    let (answer, ()) = tokio::join!(forward(work, seen, &page), async {
        tokio::time::timeout(Duration::from_secs(5), watcher)
            .await
            .expect("frames arrive");
    });
    driver.await.expect("driver");
    assert_eq!(answer.expect("answer"), 7);
    assert_eq!(phases, [SpeedPhase::Download, SpeedPhase::Complete]);
    assert_eq!(page.borrow().percent, 100);
}

fn session(profile: &str, generation: u64) -> Option<SessionView> {
    Some(SessionView {
        owner: Owner::Manual,
        profile_id: profile.into(),
        profile_name: "Test".into(),
        mode: SessionMode::Soft,
        generation: Some(generation),
        adaptive: AdaptiveMode::Baseline,
        started_at: 1,
        engine: None,
    })
}

/// B-ST-5: another server ends the run; an engine restart on the same server, a session that
/// ended or a closed channel do not.
#[tokio::test]
async fn only_another_server_counts_as_a_switch() {
    let short = Duration::from_millis(60);
    let (tx, rx) = watch::channel(session("a", 1));
    let mut switched = std::pin::pin!(server_switched(rx));
    tx.send_replace(session("a", 2));
    assert!(tokio::time::timeout(short, &mut switched).await.is_err());
    tx.send_replace(None);
    assert!(tokio::time::timeout(short, &mut switched).await.is_err());
    tx.send_replace(session("b", 3));
    tokio::time::timeout(Duration::from_secs(5), &mut switched)
        .await
        .expect("a new server ends the run");
    let (tx, rx) = watch::channel(session("a", 1));
    let quiet = server_switched(rx);
    drop(tx);
    assert!(tokio::time::timeout(short, quiet).await.is_err());
}

/// A loopback port nobody listens on (bound once, then released).
fn dead_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

/// NOADMIN §2: a Soft session whose mixed inbound is unknown cannot show the VPN exit, so the
/// self-test is inconclusive, never a leak (only loopback is dialled: the direct echo meets a
/// dead `mixed-direct-in`).
#[tokio::test]
async fn a_soft_session_without_its_inbound_is_inconclusive() {
    let (_dir, tunnel, shared) = shared("tools-soft-routing");
    tunnel.status.send_replace(TunStatus {
        session: Some(SessionEndpoints {
            clash_port: dead_port(),
            clash_secret: "0".repeat(32),
            direct: ProxyEndpoint {
                port: dead_port(),
                user: "fake-user".into(),
                pass: "fake-pass".into(),
            },
            probe: None,
            tun_luid: None,
            tun_alias: None,
            proxy_port: None,
            logs: Vec::new(),
        }),
        ..running(CaptureKind::Proxy)
    });
    let report = Availability(shared)
        .routing_test(CancellationToken::new())
        .await
        .expect("report");
    assert_eq!(report.verdict, RoutingVerdict::Inconclusive);
    assert_eq!(report.message.key, "probes.routing.inconclusive");
    assert_eq!(report.vpn_ip, None);
}
