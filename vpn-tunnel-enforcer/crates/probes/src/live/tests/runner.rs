//! The job runner and the check pipeline end to end, with a fake resolver and app (live-probe
//! §7.4: AT-00-003 / AT-00-005 / AT-00-007; §7.14 B-06).
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use vpnte_base::types::EnginePref;
use vpnte_base::{AppResult, ErrorKind};

use super::Root;
use super::engine::{hysteria2, no_engines, target, vless};
use crate::live::check::{Budget, Stages, engine_setup};
use crate::live::wire::Wire;
use crate::live::{
    CheckMode, CheckRequest, CheckTarget, EngineSetup, FindingCode, HistoryStore, ItemState,
    JobHandle, JobOutcome, JobRequest, JobState, LiveCheck, LiveCheckService, LiveEnv,
    ProfileTarget, ProgressStatus, SplitTunnelRules, StageId, TunnelView,
};
use crate::live_stages::dns::{Answer, AnswerData, DnsBackend, DohResolver, DohResponse};
use crate::live_stages::geo::{GeoCache, OtherProfile};
use crate::live_stages::{NotCheckedReason, TimedStatus};

/// Resolver: fixed answers, names that never answer, and a call log.
#[derive(Default)]
struct FakeDns {
    table: HashMap<String, IpAddr>,
    hang: HashSet<String>,
    calls: Arc<Mutex<Vec<String>>>,
}

impl DnsBackend for FakeDns {
    fn lookup(
        &self,
        name: &str,
        v6: bool,
    ) -> impl Future<Output = Result<Vec<Answer>, String>> + Send {
        self.calls.lock().push(name.to_owned());
        let hang = self.hang.contains(name);
        let answer: Vec<Answer> = self
            .table
            .get(name)
            .filter(|ip| ip.is_ipv6() == v6)
            .map(|ip| Answer {
                name: name.to_owned(),
                data: AnswerData::Addr(*ip),
                ttl: 60,
            })
            .into_iter()
            .collect();
        async move {
            if hang {
                std::future::pending::<()>().await;
            }
            Ok(answer)
        }
    }

    async fn reverse(&self, _ip: IpAddr) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }

    async fn doh(&self, _r: DohResolver, _name: &str, _v6: bool) -> Result<DohResponse, String> {
        Err("disabled in tests".into())
    }
}

/// The app side: tunnel down, geo off, saved profiles `p1` (VLESS) and `h2` (Hysteria2).
struct FakeEnv;

impl LiveEnv for FakeEnv {
    fn profile(&self, id: &str) -> Option<ProfileTarget> {
        match id {
            "p1" => Some(target(vless())),
            "h2" => Some(ProfileTarget {
                id: "h2".into(),
                ..target(hysteria2())
            }),
            _ => None,
        }
    }
    fn tunnel(&self) -> TunnelView {
        TunnelView::down()
    }
    fn other_profiles(&self, _except: Option<&str>) -> Vec<OtherProfile> {
        Vec::new()
    }
    fn split_tunnel(&self) -> Result<SplitTunnelRules, String> {
        Ok(SplitTunnelRules::default())
    }
    fn engine_setup(&self) -> EngineSetup {
        no_engines()
    }
    fn server_engine(&self, id: &str) -> EnginePref {
        if id == "forced-xray" {
            EnginePref::Xray
        } else {
            EnginePref::Auto
        }
    }
    fn geo_enabled(&self) -> bool {
        false
    }
}

/// A server's own engine choice wins over the app setting; `Auto` follows it
/// (engine-choice-visible: one rule for tunnel, key health and the live check).
#[test]
fn the_server_engine_choice_wins_over_the_setting() {
    let setting = no_engines().engine_pref;
    assert_eq!(setting, EnginePref::Auto);
    assert_eq!(
        engine_setup(&FakeEnv, "forced-xray").engine_pref,
        EnginePref::Xray
    );
    assert_eq!(engine_setup(&FakeEnv, "p1").engine_pref, setting);
}

fn service(dns: FakeDns, budget: Budget, root: &Root) -> LiveCheckService<FakeDns> {
    let stages = Stages {
        dns,
        geo: GeoCache::new().unwrap(),
        wire: Wire::plain(),
        budget,
    };
    LiveCheckService::with_stages(
        stages,
        Arc::new(FakeEnv),
        Arc::new(HistoryStore::open(&root.0)),
    )
}

fn endpoint(host: &str, port: u16) -> JobRequest {
    JobRequest::Single(CheckRequest {
        target: CheckTarget::Endpoint {
            host: host.into(),
            port: Some(port),
        },
        mode: CheckMode::Basic,
        throughput: false,
    })
}

async fn single(handle: JobHandle) -> AppResult<LiveCheck> {
    match tokio::time::timeout(Duration::from_secs(30), handle.done)
        .await
        .unwrap()
        .unwrap()
    {
        JobOutcome::Single(r) => r.map(|b| *b),
        JobOutcome::Batch(_) => panic!("batch outcome for a single job"),
    }
}

/// A local non-loopback address with a listener on it (loopback targets are refused, B-06);
/// `None` on a machine without one, and `None` unless `VPNTE_LAN_TESTS` is set: a listener on the
/// LAN address makes Windows Firewall ask the person at the desk to allow every rebuilt test
/// binary, so these tests run in CI (which sets the variable) and are skipped on a workstation.
async fn local_server() -> Option<(IpAddr, tokio::net::TcpListener)> {
    std::env::var_os("VPNTE_LAN_TESTS")?;
    let probe = UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("192.0.2.1:9").ok()?;
    let ip = probe.local_addr().ok()?.ip();
    if ip.is_unspecified()
        || ip.is_loopback()
        || crate::live_stages::classify_target(ip) == crate::live_stages::TargetClass::Refused
    {
        return None;
    }
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(ip, 0))
        .await
        .ok()?;
    Some((ip, listener))
}

/// §7.4 (149-157) AT-00-007: a finished check is stored exactly once, every stage ended, and a
/// cancel after completion changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finished_check_is_stored_once() {
    let Some((ip, listener)) = local_server().await else {
        return;
    };
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            drop(s);
        }
    });
    let root = Root::new();
    let dns = FakeDns {
        table: [("lan.example".to_owned(), ip)].into(),
        ..FakeDns::default()
    };
    let svc = service(dns, Budget::default(), &root);
    let handle = svc.submit(endpoint("lan.example", port)).unwrap();
    let progress = handle.progress.clone();
    let cancel = handle.cancel.clone();
    let check = single(handle).await.unwrap();
    assert_eq!(check.reachability.timed.status, TimedStatus::Ok);
    assert_eq!(
        check.handshake.as_ref().unwrap().status,
        crate::live::HandshakeStatus::Skipped
    );
    let rows = svc.history().list(None, Some("lan.example"));
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], check, "the returned check is the stored one");
    cancel.cancel();
    assert_eq!(svc.history().list(None, None).len(), 1);
    let snap = progress.borrow().clone();
    assert_eq!(
        (snap.state, snap.items[0].state),
        (JobState::Done, ItemState::Completed)
    );
    let stages = snap.items[0].stages;
    assert!(
        stages
            .iter()
            .all(|s| s.is_some_and(|s| s != ProgressStatus::Running)),
        "{stages:?}"
    );
    // Audit defects 3 & 7: a second check gets its own id, and the comparison with the first
    // is attached before the row is stored.
    let second = single(svc.submit(endpoint("lan.example", port)).unwrap())
        .await
        .unwrap();
    assert_ne!(second.id, check.id);
    let changes = second
        .infrastructure
        .as_ref()
        .unwrap()
        .changes_from_previous
        .clone();
    assert_eq!(changes.as_ref().and_then(|c| c.ip_changed), Some(false));
    assert_eq!(svc.history().list(None, Some("lan.example"))[0], second);
    svc.shutdown().await;
}

/// §7.4 (74-96) AT-00-003: a cancel while DNS is pending returns at once, emits nothing more
/// and stores nothing.
#[tokio::test]
async fn cancel_while_dns_pending() {
    let root = Root::new();
    let dns = FakeDns {
        hang: ["slow.example".to_owned()].into(),
        ..FakeDns::default()
    };
    let svc = service(dns, Budget::default(), &root);
    let handle = svc.submit(endpoint("slow.example", 443)).unwrap();
    let progress = handle.progress.clone();
    let cancel = handle.cancel.clone();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let started = Instant::now();
    cancel.cancel();
    assert_eq!(single(handle).await.unwrap_err().kind, ErrorKind::Cancelled);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert!(svc.history().list(None, None).is_empty());
    let snap = progress.borrow().clone();
    let item = &snap.items[0];
    assert_eq!(
        item.stages[StageId::Dns as usize],
        Some(ProgressStatus::Running)
    );
    assert!(
        item.stages.iter().skip(1).all(Option::is_none),
        "{:?}",
        item.stages
    );
    assert_eq!(
        (snap.state, item.state),
        (JobState::Done, ItemState::Cancelled),
        "no stage event after the cancel; the item ends as cancelled"
    );
    svc.shutdown().await;
}

/// §7.4 (74-96) AT-00-005: the mode's deadline ends the check as a timeout; nothing stored.
#[tokio::test]
async fn deadline_while_dns_pending() {
    let root = Root::new();
    let dns = FakeDns {
        hang: ["slow.example".to_owned()].into(),
        ..FakeDns::default()
    };
    let budget = Budget {
        basic: Duration::from_millis(300),
        extended: Duration::from_millis(300),
    };
    let svc = service(dns, budget, &root);
    let started = Instant::now();
    let handle = svc.submit(endpoint("slow.example", 443)).unwrap();
    assert_eq!(single(handle).await.unwrap_err().kind, ErrorKind::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert!(svc.history().list(None, None).is_empty());
    svc.shutdown().await;
}

/// §7.4 (109-114) + B-23: jobs run one at a time in order; a job cancelled while queued never
/// starts (no DNS query) and ends as cancelled.
#[tokio::test]
async fn queued_job_cancelled_before_start() {
    let root = Root::new();
    let dns = FakeDns {
        hang: ["slow.example".to_owned()].into(),
        ..FakeDns::default()
    };
    let calls = dns.calls.clone();
    let svc = service(dns, Budget::default(), &root);
    let first = svc.submit(endpoint("slow.example", 443)).unwrap();
    let second = svc.submit(endpoint("b.example", 443)).unwrap();
    assert_ne!(first.id, second.id);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(second.progress.borrow().state, JobState::Queued);
    second.cancel.cancel();
    first.cancel.cancel();
    assert_eq!(single(first).await.unwrap_err().kind, ErrorKind::Cancelled);
    assert_eq!(single(second).await.unwrap_err().kind, ErrorKind::Cancelled);
    assert!(
        !calls.lock().iter().any(|c| c == "b.example"),
        "the queued job never resolved"
    );
    svc.shutdown().await;
}

/// B-06: an empty host is refused before DNS; a name resolving to loopback is refused before
/// any socket opens.
#[tokio::test]
async fn refused_targets() {
    let root = Root::new();
    let dns = FakeDns {
        table: [("local.example".to_owned(), IpAddr::from([127, 0, 0, 1]))].into(),
        ..FakeDns::default()
    };
    let svc = service(dns, Budget::default(), &root);
    let empty = single(svc.submit(endpoint("  ", 443)).unwrap())
        .await
        .unwrap_err();
    assert_eq!(empty.kind, ErrorKind::Validation);
    let local = single(svc.submit(endpoint("local.example", 443)).unwrap())
        .await
        .unwrap_err();
    assert_eq!(local.user_msg().key, "probes.liveStages.target.refused");
    assert!(svc.history().list(None, None).is_empty());
    svc.shutdown().await;
}

/// §3.21 + §2.2: 1..=12 profiles; duplicates checked once; unknown / disabled ones reported.
#[tokio::test]
async fn batch_limits_and_ineligible() {
    let root = Root::new();
    let svc = service(FakeDns::default(), Budget::default(), &root);
    let batch = |profiles: Vec<String>| JobRequest::Batch {
        profiles,
        mode: CheckMode::Basic,
        throughput: false,
    };
    assert_eq!(
        svc.submit(batch(Vec::new())).err().unwrap().kind,
        ErrorKind::Validation
    );
    let thirteen: Vec<String> = (0..13).map(|i| format!("p{i}")).collect();
    assert_eq!(
        svc.submit(batch(thirteen)).err().unwrap().kind,
        ErrorKind::Validation
    );
    let handle = svc
        .submit(batch(vec!["missing".into(), "missing".into()]))
        .unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(30), handle.done)
        .await
        .unwrap()
        .unwrap();
    let JobOutcome::Batch(result) = outcome else {
        panic!("single outcome for a batch")
    };
    assert!(result.results.is_empty() && !result.cancelled);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].error.key, "probes.live.batch.notEligible");
    svc.shutdown().await;
}

/// A profile check whose probe engine cannot start still yields a stored row: the engine
/// stages say why they did not run, nothing is reported as working.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profile_check_without_engine() {
    let root = Root::new();
    let svc = service(FakeDns::default(), Budget::default(), &root);
    let request = JobRequest::Single(CheckRequest {
        target: CheckTarget::Profile("p1".into()),
        mode: CheckMode::Basic,
        throughput: false,
    });
    let check = single(svc.submit(request).unwrap()).await.unwrap();
    let h = check.handshake.as_ref().unwrap();
    assert_eq!(h.status, crate::live::HandshakeStatus::Skipped);
    assert!(h.note.is_some() && h.error.is_some(), "{h:?}");
    assert_eq!(
        check.reachability.timed.error.as_deref(),
        Some("no address resolved")
    );
    assert_eq!(svc.history().list(Some("p1"), None).len(), 1);
    svc.shutdown().await;
}

/// B-03 (review fix): a UDP-transport profile whose name does not resolve here gets no TCP
/// verdict: reachability is `not_checked` (`udp-transport`), never `TCP_UNREACHABLE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_profile_without_address_has_no_tcp_verdict() {
    let root = Root::new();
    let svc = service(FakeDns::default(), Budget::default(), &root);
    let request = JobRequest::Single(CheckRequest {
        target: CheckTarget::Profile("h2".into()),
        mode: CheckMode::Basic,
        throughput: false,
    });
    let check = single(svc.submit(request).unwrap()).await.unwrap();
    let reach = &check.reachability.timed;
    assert_eq!(
        (reach.status, reach.reason),
        (
            TimedStatus::NotChecked,
            Some(NotCheckedReason::UdpTransport)
        )
    );
    assert!(
        check
            .findings
            .iter()
            .all(|f| f.code != FindingCode::TcpUnreachable),
        "{:?}",
        check.findings
    );
    svc.shutdown().await;
}

/// §7.14 (B-03): a Hysteria2 profile with an address gets no TCP, TLS, HTTP or port probe
/// (`udp-transport`) and no finding built on them; its engine stage still runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_profile_skips_tcp_probes() {
    let Some((ip, _listener)) = local_server().await else {
        return;
    };
    let root = Root::new();
    let dns = FakeDns {
        table: [("vpn.example.test".to_owned(), ip)].into(),
        ..FakeDns::default()
    };
    let svc = service(dns, Budget::default(), &root);
    let request = JobRequest::Single(CheckRequest {
        target: CheckTarget::Profile("h2".into()),
        mode: CheckMode::Basic,
        throughput: false,
    });
    let check = single(svc.submit(request).unwrap()).await.unwrap();
    let udp = Some(NotCheckedReason::UdpTransport);
    assert_eq!(check.reachability.timed.reason, udp);
    assert_eq!(check.tls.as_ref().and_then(|t| t.timed.reason), udp);
    assert_eq!(check.http.as_ref().and_then(|h| h.timed.reason), udp);
    assert!(check.open_ports.is_none() && check.latency.is_none());
    let tcp_based = [
        FindingCode::TcpUnreachable,
        FindingCode::PacketLoss,
        FindingCode::LatencyHigh,
        FindingCode::PortOpen,
    ];
    assert!(
        check.findings.iter().all(|f| !tcp_based.contains(&f.code)),
        "{:?}",
        check.findings
    );
    assert!(check.handshake.is_some());
    svc.shutdown().await;
}

/// §7.4 (171-180): a failed history write fails the check (a newer version's file is never
/// overwritten).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_write_failure_fails_the_check() {
    let root = Root::new();
    root.write(r#"{"schemaVersion": 9, "targets": {}}"#);
    let svc = service(FakeDns::default(), Budget::default(), &root);
    let request = JobRequest::Single(CheckRequest {
        target: CheckTarget::Profile("p1".into()),
        mode: CheckMode::Basic,
        throughput: false,
    });
    let err = single(svc.submit(request).unwrap()).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    svc.shutdown().await;
}

/// Shutdown cancels the running job, waits for it and refuses new ones.
#[tokio::test]
async fn shutdown_cancels_and_refuses() {
    let root = Root::new();
    let dns = FakeDns {
        hang: ["slow.example".to_owned()].into(),
        ..FakeDns::default()
    };
    let svc = service(dns, Budget::default(), &root);
    let running = svc.submit(endpoint("slow.example", 443)).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::time::timeout(Duration::from_secs(5), svc.shutdown())
        .await
        .unwrap();
    assert_eq!(
        single(running).await.unwrap_err().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(
        svc.submit(endpoint("slow.example", 443))
            .err()
            .unwrap()
            .kind,
        ErrorKind::Conflict
    );
}

/// Review fix: the samples alone may take 3 × 8 s, so a check that measures throughput gets the
/// extended budget in basic mode too (a throttled server would otherwise always time out).
#[test]
fn throughput_gets_the_extended_budget() {
    let b = Budget::default();
    assert_eq!(b.of(CheckMode::Basic, false), crate::live::BASIC_DEADLINE);
    assert_eq!(b.of(CheckMode::Basic, true), crate::live::EXTENDED_DEADLINE);
    assert_eq!(
        b.of(CheckMode::Extended, false),
        crate::live::EXTENDED_DEADLINE
    );
}
