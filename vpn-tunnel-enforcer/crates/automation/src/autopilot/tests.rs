//! AutoPilot: listener ranking, handshake probes and the planner against fakes.
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use vpnte_base::AppResult;
use vpnte_base::types::{Owner, ProxyKind};
use vpnte_core::net::HostPort;
use vpnte_core::settings::{ConnectionMode, RoutingMode, Settings};
use vpnte_core::store::Store;

use super::probe::{self, Timing};
use super::*;
use crate::coordinator::testing::{Call, FakeCoordinator};
use crate::coordinator::{ConnectRequest, ProxyEndpoint, SessionKind};
use crate::test_support::{TempDir, has_key};

const FAST: Timing = Timing {
    tcp: Duration::from_millis(300),
    handshake: Duration::from_millis(300),
};

fn listener(host: &str, port: u16, process: &str) -> Listener {
    Listener {
        host: host.into(),
        port,
        process: process.into(),
    }
}

fn hp(host: &str, port: u16) -> HostPort {
    HostPort::new(host, port).unwrap()
}

/// `autoPilot.test.ts`: wildcard / IPv6-loopback hosts → 127.0.0.1, others unchanged.
#[test]
fn listener_hosts_are_normalized() {
    for host in ["::", "::1", "0.0.0.0", ""] {
        assert_eq!(normalize_host(host), "127.0.0.1");
    }
    assert_eq!(normalize_host("192.168.1.100"), "192.168.1.100");
}

/// AP:90-98 verbatim.
#[test]
fn listener_score_vectors() {
    assert_eq!(score(10808, "xray"), 15);
    assert_eq!(score(7890, "clash"), 15);
    assert_eq!(score(2080, "sing-box"), 15);
    assert_eq!(score(9999, "custom"), 0);
    assert_eq!(score(1080, "happ"), 15);
    assert_eq!(score(9999, "Xray-core"), 5);
}

/// Best first, stable on ties, one entry per normalised endpoint (`::`, `0.0.0.0` and
/// `127.0.0.1` on one port are probed once).
#[test]
fn listeners_rank_and_dedupe() {
    let table = [
        listener("127.0.0.1", 9999, "custom"),
        listener("::", 10808, "xray"),
        listener("0.0.0.0", 10808, "xray"),
        listener("127.0.0.1", 10808, "xray"),
        listener("127.0.0.1", 7000, "clash"),
    ];
    let ranked: Vec<String> = rank_listeners(&table)
        .iter()
        .map(|(a, _)| a.to_string())
        .collect();
    assert_eq!(
        ranked,
        ["127.0.0.1:10808", "127.0.0.1:7000", "127.0.0.1:9999"]
    );
}

/// Every key `step` and `result` compose exists (literal keys are checked crate-wide).
#[test]
fn composed_keys_exist() {
    let steps = [
        "busy",
        "active",
        "external",
        "tunnelsUnknown",
        "proxy",
        "start",
    ];
    for name in steps {
        let s = step(name, StepStatus::Info);
        for key in [s.label.key, s.before.key, s.after.key] {
            assert!(has_key(&key), "missing in the fragments: {key}");
        }
    }
    let results = [
        "busy",
        "active",
        "external",
        "tunnelsUnknown",
        "noProxy",
        "success",
        "failed",
    ];
    for name in results {
        let r = result(StepStatus::Info, AutoPilotMode::Off, name, Vec::new());
        for key in [r.title.key, r.message.key] {
            assert!(has_key(&key), "missing in the fragments: {key}");
        }
    }
}

// ---------- probes against local test servers ----------

/// A one-shot server on 127.0.0.1 that answers the first connection with `reply` after `delay`.
async fn server(reply: &'static [u8], delay: Duration) -> (u16, tokio::task::JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return false;
        };
        let mut buf = [0u8; 512];
        let _ = stream.read(&mut buf).await;
        tokio::time::sleep(delay).await;
        if stream.write_all(reply).await.is_err() {
            return true;
        }
        // Wait until the client closes its side (EOF) or goes away.
        let mut rest = [0u8; 64];
        matches!(
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut rest)).await,
            Ok(Ok(0) | Err(_))
        )
    });
    (port, task)
}

/// A SOCKS5 server: greeting → no-auth, CONNECT → `rep`.
async fn socks_server(rep: u8, delay: Duration) -> (u16, tokio::task::JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        // Connections that close without a greeting are TCP pre-probes: take the next one.
        let mut s = loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return false;
            };
            let mut greeting = [0u8; 3];
            if s.read_exact(&mut greeting).await.is_ok() {
                assert_eq!(greeting, [5, 1, 0]);
                break s;
            }
        };
        s.write_all(&[5, 0]).await.unwrap();
        let mut head = [0u8; 5];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..4], &[5, 1, 0, 3], "CONNECT by name (ATYP 3)");
        let mut name = vec![0u8; usize::from(head[4]) + 2];
        s.read_exact(&mut name).await.unwrap();
        assert_eq!(&name[..name.len() - 2], b"api.ipify.org");
        tokio::time::sleep(delay).await;
        let _ = s.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        let mut rest = [0u8; 16];
        matches!(
            tokio::time::timeout(Duration::from_secs(2), s.read(&mut rest)).await,
            Ok(Ok(0) | Err(_))
        )
    });
    (port, task)
}

/// `autoPilot.test.ts` SOCKS probe: success → true (socket closed); refusal → false; a success
/// arriving after the deadline → false (socket closed).
#[tokio::test]
async fn socks5_probe_vectors() {
    let (port, task) = socks_server(0, Duration::ZERO).await;
    assert!(probe::socks5_ok(&hp("127.0.0.1", port), None, FAST.handshake).await);
    assert!(task.await.unwrap(), "socket closed after the probe");

    let (port, task) = socks_server(5, Duration::ZERO).await;
    assert!(!probe::socks5_ok(&hp("127.0.0.1", port), None, FAST.handshake).await);
    task.await.unwrap();

    let (port, task) = socks_server(0, Duration::from_millis(200)).await;
    assert!(!probe::socks5_ok(&hp("127.0.0.1", port), None, Duration::from_millis(50)).await);
    assert!(task.await.unwrap(), "socket closed after the timeout");
}

/// HTTP probe: `CONNECT` answered 2xx → true; an error status or a refused port → false.
#[tokio::test]
async fn http_connect_probe_vectors() {
    let (port, task) = server(
        b"HTTP/1.1 200 Connection established\r\n\r\n",
        Duration::ZERO,
    )
    .await;
    assert!(probe::http_ok(&hp("127.0.0.1", port), None, FAST.handshake).await);
    assert!(task.await.unwrap());

    let (port, task) = server(
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
        Duration::ZERO,
    )
    .await;
    assert!(!probe::http_ok(&hp("127.0.0.1", port), None, FAST.handshake).await);
    task.await.unwrap();

    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    assert!(!probe::http_ok(&hp("127.0.0.1", port), None, FAST.handshake).await);
}

/// `verifyListener`: TCP refused → None; an `Xray-core` listener answering SOCKS5 →
/// `127.0.0.1:<port> socks5`.
#[tokio::test]
async fn verify_listener_vectors() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap().port();
    drop(closed);
    assert_eq!(
        probe::verify_listener(&hp("127.0.0.1", dead), "custom", FAST).await,
        None
    );

    let (port, task) = socks_server(0, Duration::ZERO).await;
    let ep = probe::verify_listener(&hp("127.0.0.1", port), "Xray-core", FAST).await;
    let got = ep.map(|e| (e.addr.to_string(), e.kind));
    assert_eq!(got, Some((format!("127.0.0.1:{port}"), ProxyKind::Socks5)));
    assert!(task.await.unwrap());
}

// ---------- the planner ----------

#[derive(Default)]
struct Env {
    listeners: Vec<Listener>,
    detected: Option<ProxyEndpoint>,
    /// `None` = the adapter list could not be read.
    tunnels: Option<Vec<String>>,
    /// `detect` waits for this gate (a run kept in flight).
    gate: Option<Arc<tokio::sync::Notify>>,
    detect_calls: Mutex<usize>,
}

impl AutoPilotEnv for Env {
    fn listeners(&self) -> Vec<Listener> {
        self.listeners.clone()
    }
    async fn detect(&self) -> Option<ProxyEndpoint> {
        *self.detect_calls.lock() += 1;
        if let Some(gate) = &self.gate {
            gate.notified().await;
        }
        self.detected.clone()
    }
    async fn foreign_tunnels(&self) -> AppResult<Vec<String>> {
        self.tunnels
            .clone()
            .ok_or_else(|| vpnte_base::AppError::internal(std::io::Error::other("no adapter list")))
    }
}

struct Setup {
    coord: Arc<FakeCoordinator>,
    settings: Arc<Store<Settings>>,
    _dir: TempDir,
}

impl Setup {
    fn new() -> Self {
        let dir = TempDir::new("autopilot");
        let settings = Arc::new(Store::<Settings>::open(dir.path()));
        Self {
            coord: FakeCoordinator::new(),
            settings,
            _dir: dir,
        }
    }

    fn pilot(
        &self,
        env: Env,
        schedule: Option<watch::Receiver<SchedulerStatus>>,
    ) -> AutoPilot<FakeCoordinator, Env> {
        AutoPilot::with_timing(
            self.coord.clone(),
            Arc::new(env),
            self.settings.clone(),
            schedule,
            FAST,
        )
    }
}

async fn dead_port() -> u16 {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    port
}

fn keys(result: &AutoPilotResult) -> (StepStatus, AutoPilotMode, String) {
    (result.summary, result.mode, result.title.key.to_string())
}

/// `autoPilot.test.ts`: a foreign tunnel (`WireGuard-Corp`) → mode `external`, nothing started.
#[tokio::test]
async fn foreign_tunnel_means_observe_only() {
    let s = Setup::new();
    let env = Env {
        tunnels: Some(vec!["WireGuard-Corp".into()]),
        ..Env::default()
    };
    let r = s
        .pilot(env, None)
        .run(AutoPilotTrigger::AppLaunch)
        .await
        .unwrap();
    assert_eq!(
        keys(&r),
        (
            StepStatus::Ok,
            AutoPilotMode::External,
            "automation.autopilot.externalTitle".into()
        )
    );
    assert_eq!(s.coord.connects(), 0);
}

/// P6: an unreadable adapter list → `warn`, nothing started.
#[tokio::test]
async fn unknown_tunnels_mean_no_start() {
    let s = Setup::new();
    let r = s
        .pilot(
            Env {
                tunnels: None,
                ..Env::default()
            },
            None,
        )
        .run(AutoPilotTrigger::AppLaunch)
        .await
        .unwrap();
    assert_eq!(r.summary, StepStatus::Warn);
    assert_eq!(r.title.key, "automation.autopilot.tunnelsUnknownTitle");
    assert_eq!(s.coord.connects(), 0);
}

/// A listener `127.0.0.1:<dead> 'custom'` whose TCP connect fails → `fail` / `off`, no start.
#[tokio::test]
async fn no_working_proxy_starts_nothing() {
    let s = Setup::new();
    let env = Env {
        tunnels: Some(vec![]),
        listeners: vec![listener("127.0.0.1", dead_port().await, "custom")],
        ..Env::default()
    };
    let r = s
        .pilot(env, None)
        .run(AutoPilotTrigger::AppLaunch)
        .await
        .unwrap();
    assert_eq!(
        keys(&r),
        (
            StepStatus::Fail,
            AutoPilotMode::Off,
            "automation.autopilot.noProxyTitle".into()
        )
    );
    assert_eq!(s.coord.connects(), 0);
}

/// An `xray` listener answering SOCKS5 → connect as `Owner::Autopilot` with that endpoint →
/// `ok` / `hard`; the endpoint is not written to the settings (P4).
#[tokio::test]
async fn working_listener_starts_hard_tun_through_the_coordinator() {
    let s = Setup::new();
    let (port, _task) = socks_server(0, Duration::ZERO).await;
    let env = Env {
        tunnels: Some(vec![]),
        listeners: vec![
            listener("127.0.0.1", dead_port().await, "custom"),
            listener("::", port, "xray"),
        ],
        ..Env::default()
    };
    let r = s
        .pilot(env, None)
        .run(AutoPilotTrigger::AppLaunch)
        .await
        .unwrap();
    assert_eq!(
        keys(&r),
        (
            StepStatus::Ok,
            AutoPilotMode::Hard,
            "automation.autopilot.successTitle".into()
        )
    );
    assert!(r.changed);
    let endpoint = ProxyEndpoint {
        addr: hp("127.0.0.1", port),
        kind: ProxyKind::Socks5,
        creds: None,
    };
    let expected = Call::Connect(
        Owner::Autopilot,
        ConnectRequest::LocalProxyHard {
            endpoint: Some(endpoint),
        },
    );
    assert_eq!(s.coord.calls(), vec![expected]);
    assert_eq!(s.settings.read(|st| st.proxy_override.clone()), None);
}

/// Changed vs. the old app (P1/P2): an existing session is left alone — no stop, no start.
#[tokio::test]
async fn existing_session_is_never_touched() {
    let s = Setup::new();
    s.coord
        .set_session(SessionKind::Direct, Owner::Schedule, Some("p1"));
    let r = s
        .pilot(Env::default(), None)
        .run(AutoPilotTrigger::AppLaunch)
        .await
        .unwrap();
    assert_eq!(
        keys(&r),
        (
            StepStatus::Ok,
            AutoPilotMode::Hard,
            "automation.autopilot.activeTitle".into()
        )
    );
    assert!(s.coord.calls().is_empty());
}

/// The launch run waits for the scheduler's first pass and stays out of an active run.
#[tokio::test]
async fn app_launch_yields_to_an_active_schedule_run() {
    let s = Setup::new();
    let (tx, rx) = watch::channel(SchedulerStatus::default());
    let pilot = Arc::new(s.pilot(
        Env {
            tunnels: Some(vec![]),
            ..Env::default()
        },
        Some(rx),
    ));
    let run = tokio::spawn({
        let p = pilot.clone();
        async move { p.run(AutoPilotTrigger::AppLaunch).await }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!run.is_finished(), "waits for the first pass");
    tx.send_replace(SchedulerStatus {
        ready: true,
        run: Some((0, 1)),
        ..SchedulerStatus::default()
    });
    assert_eq!(run.await.unwrap(), None);
    assert_eq!(s.coord.connects(), 0);
}

/// A verified proxy override is used before detection and listeners; the detected endpoint
/// comes next.
#[tokio::test]
async fn override_then_detection_then_listeners() {
    let s = Setup::new();
    let (over, _t1) = socks_server(0, Duration::ZERO).await;
    let (other, _t2) = socks_server(0, Duration::ZERO).await;
    let (over_cfg, _) =
        vpnte_core::settings::ProxyOverride::parse(&format!("127.0.0.1:{over}")).unwrap();
    s.settings
        .update(|st| st.proxy_override = Some(over_cfg))
        .unwrap();
    let env = Env {
        tunnels: Some(vec![]),
        listeners: vec![listener("127.0.0.1", other, "xray")],
        ..Env::default()
    };
    let pilot = s.pilot(env, None);
    pilot.run(AutoPilotTrigger::UserRequest).await.unwrap();
    let Call::Connect(_, ConnectRequest::LocalProxyHard { endpoint: Some(ep) }) =
        &s.coord.calls()[0]
    else {
        panic!("connect expected");
    };
    assert_eq!(ep.addr, hp("127.0.0.1", over));
    assert_eq!(
        *pilot.env.detect_calls.lock(),
        0,
        "the override answered first"
    );

    let s = Setup::new();
    let (found, _t3) = socks_server(0, Duration::ZERO).await;
    let detected = ProxyEndpoint {
        addr: hp("127.0.0.1", found),
        kind: ProxyKind::Socks5,
        creds: None,
    };
    let env = Env {
        tunnels: Some(vec![]),
        detected: Some(detected.clone()),
        ..Env::default()
    };
    s.pilot(env, None)
        .run(AutoPilotTrigger::UserRequest)
        .await
        .unwrap();
    let expected = Call::Connect(
        Owner::Autopilot,
        ConnectRequest::LocalProxyHard {
            endpoint: Some(detected),
        },
    );
    assert_eq!(s.coord.calls(), vec![expected]);
}

/// A second run while one is in flight → `warn`, «Автопилот уже выполняется».
#[tokio::test]
async fn second_run_while_one_is_in_flight_is_skipped() {
    let s = Setup::new();
    let gate = Arc::new(tokio::sync::Notify::new());
    let env = Env {
        tunnels: Some(vec![]),
        gate: Some(gate.clone()),
        ..Env::default()
    };
    let pilot = Arc::new(s.pilot(env, None));
    let first = tokio::spawn({
        let p = pilot.clone();
        async move { p.run(AutoPilotTrigger::UserRequest).await }
    });
    while *pilot.env.detect_calls.lock() == 0 {
        tokio::task::yield_now().await;
    }
    let second = pilot.run(AutoPilotTrigger::UserRequest).await.unwrap();
    assert_eq!(second.summary, StepStatus::Warn);
    assert_eq!(second.title.key, "automation.autopilot.busyTitle");
    gate.notify_one();
    assert_eq!(
        first.await.unwrap().unwrap().title.key,
        "automation.autopilot.noProxyTitle"
    );
}

/// Gate: local-proxy Hard mode only; the `autopilot` switch governs only the launch run.
#[tokio::test]
async fn launch_gate() {
    let s = Setup::new();
    s.settings.update(|st| st.autopilot = false).unwrap();
    let pilot = s.pilot(
        Env {
            tunnels: Some(vec!["Corp VPN".into()]),
            ..Env::default()
        },
        None,
    );
    assert_eq!(pilot.run(AutoPilotTrigger::AppLaunch).await, None);
    assert!(pilot.run(AutoPilotTrigger::UserRequest).await.is_some());
    s.settings
        .update(|st| st.routing_mode = RoutingMode::Soft)
        .unwrap();
    assert_eq!(pilot.run(AutoPilotTrigger::UserRequest).await, None);
    s.settings
        .update(|st| {
            st.routing_mode = RoutingMode::Hard;
            st.connection_mode = ConnectionMode::DirectVpn;
        })
        .unwrap();
    assert_eq!(pilot.run(AutoPilotTrigger::UserRequest).await, None);
}

/// A refused connect → `fail` / `off` with the coordinator's reason as the message.
#[tokio::test]
async fn failed_connect_reports_the_reason() {
    let s = Setup::new();
    let (port, _task) = socks_server(0, Duration::ZERO).await;
    s.coord
        .connect_results
        .lock()
        .push_back(Err(crate::coordinator::OpError::Conflict));
    let env = Env {
        tunnels: Some(vec![]),
        listeners: vec![listener("127.0.0.1", port, "xray")],
        ..Env::default()
    };
    let r = s
        .pilot(env, None)
        .run(AutoPilotTrigger::AppLaunch)
        .await
        .unwrap();
    assert_eq!(
        keys(&r),
        (
            StepStatus::Fail,
            AutoPilotMode::Off,
            "automation.autopilot.failedTitle".into()
        )
    );
    assert_eq!(r.message.key, "automation.coordinator.conflict");
    assert!(!r.changed);
}
