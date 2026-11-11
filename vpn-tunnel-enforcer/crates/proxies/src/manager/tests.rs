//! Flow tests of the manager with a scripted engine and prober, and one real sing-box slot.
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use futures_util::future::join_all;
use parking_lot::Mutex;
use serde_json::{Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, ErrorKind};
use vpnte_profiles::model::{DialPrefs, Host, Kind, Profile, Source, Tls};

use super::launch::{Engine, Engines, Exit, Launch, Plan};
use super::{EngineChoice, ProfileSource, ProxyManager, ProxyProfile};
use crate::health::Timing;
use crate::model::{
    Action, Aggregate, BatchSkip, BatchSkipReason, Degradation, GroupHealth, Health,
    InstanceStatus, Lifecycle, ProxyError, ProxyOps, Reservation, ReserveRequest, ServerStatus,
    StartRequest, StopReason, StopScope,
};
use crate::probe::{ProbeError, ProbeOk, Prober};
use crate::slot::Slot;

/// The servers of a test, the main VPN's choice and a group health answer.
#[derive(Default)]
pub(super) struct FakeSource {
    pub profiles: Mutex<Vec<ProxyProfile>>,
    pub active_vpn: Mutex<Option<String>>,
    pub group_health: Mutex<Option<ErrorKind>>,
}

#[async_trait::async_trait]
impl ProfileSource for FakeSource {
    fn profiles(&self) -> Vec<ProxyProfile> {
        self.profiles.lock().clone()
    }
    fn active_vpn_profile_id(&self) -> Option<String> {
        self.active_vpn.lock().clone()
    }
    fn engine_choice(&self) -> EngineChoice {
        EngineChoice::default()
    }
    async fn check_group_health(&self, _group_id: &str) -> AppResult<GroupHealth> {
        match *self.group_health.lock() {
            Some(kind) => Err(AppError::new(kind)),
            None => Ok(GroupHealth {
                ok: true,
                results: Vec::new(),
            }),
        }
    }
}

/// An engine that runs until told otherwise.
pub(super) struct FakeEngine {
    pid: u32,
    exit: watch::Sender<Option<Exit>>,
    lines: broadcast::Sender<Arc<str>>,
}

impl FakeEngine {
    /// Ends the engine the way a crash would.
    pub(super) fn crash(&self, code: i32) {
        self.exit.send_replace(Some(Exit {
            code: Some(code),
            tail: String::new(),
        }));
    }
    /// Emits one output line.
    pub(super) fn say(&self, line: &str) {
        let _ = self.lines.send(Arc::from(line));
    }
}

#[async_trait::async_trait]
impl Engine for FakeEngine {
    fn pid(&self) -> u32 {
        self.pid
    }
    async fn exited(&self) -> Exit {
        let mut rx = self.exit.subscribe();
        let exit = rx.wait_for(Option::is_some).await;
        exit.ok().and_then(|e| e.clone()).unwrap_or(Exit {
            code: None,
            tail: String::new(),
        })
    }
    fn lines(&self) -> broadcast::Receiver<Arc<str>> {
        self.lines.subscribe()
    }
    async fn terminate(&self, _within: Duration) -> bool {
        self.exit.send_if_modified(|e| {
            let first = e.is_none();
            if first {
                *e = Some(Exit {
                    code: Some(1),
                    tail: String::new(),
                });
            }
            first
        });
        true
    }
}

/// Records every start (the sing-box config) and hands out fake engines.
#[derive(Default)]
pub(super) struct FakeLaunch {
    pub configs: Mutex<Vec<Value>>,
    pub engines: Mutex<Vec<Arc<FakeEngine>>>,
    pub busy_ports: Mutex<HashSet<u16>>,
    pub fail_next: Mutex<Option<ProxyError>>,
    next_pid: AtomicU32,
}

impl FakeLaunch {
    pub(super) fn starts(&self) -> usize {
        self.configs.lock().len()
    }
    pub(super) fn engine(&self, index: usize) -> Arc<FakeEngine> {
        self.engines.lock()[index].clone()
    }
}

#[async_trait::async_trait]
impl Launch for FakeLaunch {
    fn check_port(&self, port: u16) -> Result<(), String> {
        if self.busy_ports.lock().contains(&port) {
            return Err("in use".into());
        }
        Ok(())
    }
    async fn start(
        &self,
        plan: Plan,
        _cancel: &CancellationToken,
    ) -> Result<Arc<dyn Engine>, ProxyError> {
        if let Some(err) = self.fail_next.lock().take() {
            return Err(err);
        }
        self.configs
            .lock()
            .push(serde_json::from_slice(&plan.singbox).unwrap());
        let pid = 4000 + self.next_pid.fetch_add(1, Ordering::SeqCst);
        let engine = Arc::new(FakeEngine {
            pid,
            exit: watch::channel(None).0,
            lines: broadcast::channel(64).0,
        });
        self.engines.lock().push(engine.clone());
        Ok(engine)
    }
}

type Script = Box<dyn FnMut(u16) -> Result<ProbeOk, ProbeError> + Send>;

/// Answers probes from a per-test script and counts them per port.
pub(super) struct FakeProber {
    script: Mutex<Script>,
    pub calls: Mutex<HashMap<u16, u32>>,
}

impl FakeProber {
    pub(super) fn new(
        script: impl FnMut(u16) -> Result<ProbeOk, ProbeError> + Send + 'static,
    ) -> Self {
        Self {
            script: Mutex::new(Box::new(script)),
            calls: Mutex::new(HashMap::new()),
        }
    }
    pub(super) fn set(
        &self,
        script: impl FnMut(u16) -> Result<ProbeOk, ProbeError> + Send + 'static,
    ) {
        *self.script.lock() = Box::new(script);
    }
    pub(super) fn total(&self) -> u32 {
        self.calls.lock().values().sum()
    }
}

#[async_trait::async_trait]
impl Prober for FakeProber {
    async fn probe(&self, port: u16) -> Result<ProbeOk, ProbeError> {
        *self.calls.lock().entry(port).or_default() += 1;
        let result = (self.script.lock())(port);
        tokio::task::yield_now().await;
        result
    }
}

/// A probe answer.
pub(super) fn egress(ip: &str) -> Result<ProbeOk, ProbeError> {
    Ok(ProbeOk {
        egress_ip: ip.parse().unwrap(),
        latency_ms: 123,
    })
}

/// Timing for tests: nothing is scheduled within a test unless it shortens a field.
pub(super) fn slow_timing() -> Timing {
    let long = Duration::from_secs(3600);
    Timing {
        first_probe: long,
        success: long,
        cooldowns: [long; 3],
        recheck: long,
        leased_recheck: long,
        ..Timing::default()
    }
}

/// A manager over fakes.
pub(super) struct Rig {
    pub manager: ProxyManager,
    pub source: Arc<FakeSource>,
    pub launch: Arc<FakeLaunch>,
    pub prober: Arc<FakeProber>,
}

pub(super) fn rig(profiles: Vec<ProxyProfile>, timing: Timing) -> Rig {
    let source = Arc::new(FakeSource::default());
    *source.profiles.lock() = profiles;
    let launch = Arc::new(FakeLaunch::default());
    let prober = Arc::new(FakeProber::new(|_| egress("198.51.100.42")));
    let manager = ProxyManager::with_parts(source.clone(), launch.clone(), prober.clone(), timing);
    Rig {
        manager,
        source,
        launch,
        prober,
    }
}

/// Polls `check` every 10 ms for up to 5 s.
pub(super) async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..500 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    check()
}

/// The old fixture profile (spec §7): VLESS + TLS to a documentation address. Fake credentials.
pub(super) fn vless(server: &str) -> Profile {
    Profile {
        name: "sample".into(),
        description: None,
        server: server
            .parse()
            .map_or_else(|_| Host::Domain(server.into()), Host::Ip),
        port: 443,
        kind: Kind::Vless {
            uuid: "00000000-0000-4000-8000-000000000001".into(),
            flow: None,
            packet_encoding: None,
            encryption: None,
        },
        tls: Some(Tls::default()),
        transport: None,
        mux: None,
        dial: DialPrefs::default(),
        native_xray: None,
        singbox_extra: Map::new(),
        source: Source::Json,
        notes: Vec::new(),
    }
}

/// `profile-<n>` (old `sampleProfiles(n)`): country Netherlands, key health unknown.
pub(super) fn sample(n: u32) -> ProxyProfile {
    ProxyProfile {
        id: format!("profile-{n}"),
        name: format!("profile-{n}"),
        country: Some("Netherlands".into()),
        group_id: None,
        profile: vless("203.0.113.10"),
        status: ServerStatus::Unknown,
        ping_ms: None,
        health_latency_ms: None,
        health_reason: None,
        last_checked_at: None,
        enabled: true,
        removed: false,
    }
}

/// A profile with `name` and `country`, for the country filter.
pub(super) fn named(id: &str, name: &str, country: Option<&str>) -> ProxyProfile {
    ProxyProfile {
        id: id.into(),
        name: name.into(),
        country: country.map(Into::into),
        ..sample(1)
    }
}

pub(super) fn samples(n: u32) -> Vec<ProxyProfile> {
    (1..=n).map(sample).collect()
}

fn slot(n: u64) -> Slot {
    Slot::new(n).unwrap()
}

fn connect(n: u64, profile: &str) -> StartRequest {
    StartRequest {
        slot: Some(slot(n)),
        profile_id: Some(profile.into()),
        action: Action::Connect,
        ..StartRequest::default()
    }
}

/// The inbound port of a recorded sing-box config.
fn listen_port(config: &Value) -> u64 {
    config["inbounds"][0]["listen_port"].as_u64().unwrap()
}

/// Spec external-proxy §7.4: the main VPN's profile is marked, nothing runs it; a profile
/// removed from its subscription is neither listed nor startable.
#[tokio::test]
async fn profile_list_marks_the_vpn_profile_and_hides_removed_ones() {
    let r = rig(samples(1), slow_timing());
    *r.source.active_vpn.lock() = Some("profile-1".into());
    let rows = r.manager.list(None).await;
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.id, "profile-1");
    assert_eq!(row.status, ServerStatus::Unknown);
    assert_eq!((row.ping_ms, row.last_checked_at), (None, None));
    assert!(row.selected_for_vpn && !row.active && row.active_slots.is_empty());
    assert_eq!((row.protocol.as_str(), row.port), ("vless", 443));

    let removed = ProxyProfile {
        removed: true,
        ..sample(2)
    };
    *r.source.profiles.lock() = vec![removed];
    assert!(r.manager.list(None).await.is_empty());
    let err = r.manager.start(connect(1, "profile-2")).await.unwrap_err();
    assert_eq!(
        err,
        ProxyError::Engine("VPN profile not found or unusable: profile-2".into())
    );
    assert_eq!(r.launch.starts(), 0);
}

/// Spec external-proxy §7.5: a fresh manager has no placeholder slots; two slots run two
/// engines with their own configs and ports, listed in slot order.
#[tokio::test]
async fn slots_are_separate_processes() {
    let r = rig(samples(2), slow_timing());
    let status = r.manager.status(Slot::DEFAULT).await;
    assert_eq!(status.instance.slot, Slot::DEFAULT);
    assert!(status.instances.is_empty());
    assert_eq!(
        serde_json::to_value(&status).unwrap()["maxInstances"],
        Value::Null
    );

    let a = r
        .manager
        .start(connect(1, "profile-1"))
        .await
        .unwrap()
        .instance;
    let b = r
        .manager
        .start(connect(2, "profile-2"))
        .await
        .unwrap()
        .instance;
    for (i, port) in [(&a, 17990), (&b, 17991)] {
        assert!(i.process_running && !i.running);
        assert_eq!((i.health, i.port), (Health::Starting, Some(port)));
        assert_eq!(
            i.proxy_url.as_deref(),
            Some(&*format!("http://127.0.0.1:{port}"))
        );
    }
    assert_ne!(a.pid, b.pid);
    let list = r.manager.instances().await.instances;
    let seen: Vec<_> = list.iter().map(|i| (i.slot, i.port, i.pid)).collect();
    assert_eq!(seen, [(a.slot, a.port, a.pid), (b.slot, b.port, b.pid)]);
    let configs = r.launch.configs.lock().clone();
    assert_eq!(
        configs.iter().map(listen_port).collect::<Vec<_>>(),
        [17990, 17991]
    );
    assert!(
        configs
            .iter()
            .all(|c| c["outbounds"][0]["tag"] == "proxy-out")
    );
}

/// Spec external-proxy §7.5: a start is not "running" until a probe confirmed the route; a
/// failed probe degrades it with the probe's error.
#[tokio::test]
async fn running_needs_a_confirmed_route() {
    let r = rig(samples(1), slow_timing());
    let started = r
        .manager
        .start(connect(1, "profile-1"))
        .await
        .unwrap()
        .instance;
    assert!(started.process_running && !started.running);
    assert_eq!(started.health, Health::Starting);
    let checked = r.manager.check_health(Slot::DEFAULT).await;
    assert!(checked.process_running && checked.running && checked.ready);
    assert_eq!(checked.health, Health::Healthy);
    assert_eq!(checked.egress_ip, Some("198.51.100.42".parse().unwrap()));
    assert_eq!(checked.latency_ms, Some(123));
    assert!(checked.last_checked_at.is_some() && checked.last_success_at.is_some());

    r.prober
        .set(|_| Err(ProbeError::Transport("ConnectTimeout after 10000ms".into())));
    let failed = r.manager.check_health(Slot::DEFAULT).await;
    assert!(failed.process_running && !failed.running);
    assert_eq!(failed.health, Health::Degraded);
    assert_eq!(failed.proxy_url.as_deref(), Some("http://127.0.0.1:17990"));
    assert!(failed.last_error.unwrap().contains("ConnectTimeout"));
}

fn timeout_error() -> Result<ProbeOk, ProbeError> {
    Err(ProbeError::Transport("ConnectTimeout after 10000ms".into()))
}

/// Spec external-proxy §7.6: engine-log timeouts do not bypass the cooldown of a degraded
/// route: twenty of them cause no probe before the cooldown ends.
#[tokio::test]
async fn runtime_timeouts_do_not_bypass_the_cooldown() {
    let timing = Timing {
        cooldowns: [
            Duration::from_millis(1500),
            Duration::from_secs(60),
            Duration::from_secs(60),
        ],
        hint_delay: Duration::from_millis(1),
        hint_spacing: Duration::from_millis(1),
        ..slow_timing()
    };
    let r = rig(samples(1), timing);
    r.prober.set(|_| timeout_error());
    r.manager.start(connect(1, "profile-1")).await.unwrap();
    let degraded = r.manager.check_health(Slot::DEFAULT).await;
    assert_eq!(
        (degraded.health, degraded.consecutive_failures),
        (Health::Degraded, 1)
    );
    for _ in 0..20 {
        r.launch
            .engine(0)
            .say("ERROR dial tcp: context deadline exceeded");
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(r.prober.total(), 1);
    // The cooldown itself still runs the next probe.
    assert!(eventually(|| r.prober.total() == 2).await);
}

/// Spec external-proxy §7.6: failures back off without restarting the engine; the next probe
/// time is published.
#[tokio::test]
async fn exponential_cooldown_without_restart() {
    let r = rig(samples(1), slow_timing());
    r.prober.set(|_| timeout_error());
    r.manager.start(connect(1, "profile-1")).await.unwrap();
    for _ in 0..3 {
        r.manager.check_health(Slot::DEFAULT).await;
    }
    let status = r.manager.status(Slot::DEFAULT).await.instance;
    assert!(status.process_running);
    assert_eq!(
        (status.health, status.consecutive_failures),
        (Health::Degraded, 3)
    );
    assert!(status.next_check_at.is_some());
    let wire = serde_json::to_value(&status).unwrap();
    assert!(
        wire["nextCheckAt"]
            .as_str()
            .is_some_and(|s| s.ends_with('Z'))
    );
    assert_eq!(r.launch.starts(), 1);
}

/// Spec external-proxy §7.6: the fourth consecutive transport failure stops the slot (never a
/// restart); it stays listed as auto-disabled with its profile and the probe's error.
#[tokio::test]
async fn failure_budget_disables_without_restart() {
    let r = rig(samples(1), slow_timing());
    r.prober.set(|_| Err(ProbeError::Transport("EOF".into())));
    r.manager.start(connect(1, "profile-1")).await.unwrap();
    for _ in 0..4 {
        r.manager.check_health(Slot::DEFAULT).await;
    }
    let m = r.manager.clone();
    let mut rx = m.snapshot();
    let disabled = rx
        .wait_for(|s| {
            s.instances
                .first()
                .is_some_and(|i| i.auto_disabled && !i.process_running)
        })
        .await
        .unwrap()
        .instances[0]
        .clone();
    assert!(!disabled.running);
    assert_eq!(disabled.health, Health::Failed);
    assert_eq!(disabled.profile_id.as_deref(), Some("profile-1"));
    assert_eq!((disabled.port, disabled.proxy_url.clone()), (None, None));
    assert!(disabled.last_error.unwrap().contains("EOF"));
    assert_eq!(
        disabled.degradation_reason,
        Some(Degradation::HealthFailureBudgetExhausted)
    );
    assert_eq!(r.launch.starts(), 1);
    // Rotating it restarts the slot on the next profile after the preserved one.
    *r.source.profiles.lock() = samples(2);
    r.prober.set(|_| egress("198.51.100.5"));
    let rotated = r
        .manager
        .rotate(Slot::DEFAULT, None)
        .await
        .unwrap()
        .instance;
    assert_eq!(rotated.profile_id.as_deref(), Some("profile-2"));
    assert!(rotated.process_running && !rotated.auto_disabled);
}

/// B-29 / spec 3.12: an engine that dies is noticed at once and fails the slot (no restart);
/// the profile is free again for the picker (B-8) and the slot keeps its port until a stop.
#[tokio::test]
async fn crashed_engine_fails_the_slot() {
    let r = rig(samples(1), slow_timing());
    r.manager.start(connect(1, "profile-1")).await.unwrap();
    r.launch.engine(0).crash(-1);
    let mut rx = r.manager.snapshot();
    let failed = rx
        .wait_for(|s| s.instances.first().is_some_and(|i| !i.process_running))
        .await
        .unwrap()
        .instances[0]
        .clone();
    assert_eq!(
        (failed.health, failed.state),
        (Health::Failed, Lifecycle::Failed)
    );
    assert_eq!(failed.degradation_reason, Some(Degradation::ProcessFailed));
    assert_eq!(
        failed.last_error.as_deref(),
        Some("External proxy instance exited (-1)")
    );
    assert_eq!(failed.port, Some(17990));
    assert_eq!(failed.pid, None);
    let rows = r.manager.list(None).await;
    assert!(!rows[0].active);
    assert_eq!(r.launch.starts(), 1);
    // The Servers page starting that profile again restarts its dead slot (no second slot).
    let batch = r.manager.start_profiles(vec!["profile-1".into()]).await;
    assert_eq!(batch.started.len(), 1);
    assert_eq!(batch.started[0].slot, Slot::DEFAULT);
    assert!(batch.started[0].process_running);
    r.launch.engine(1).crash(1);
    let m = r.manager.clone();
    assert!(eventually(|| !m.inner.instance(Slot::DEFAULT).process_running).await);
    // A start of the configured failed slot restarts it.
    let restarted = r
        .manager
        .start(connect(1, "profile-1"))
        .await
        .unwrap()
        .instance;
    assert!(restarted.process_running);
    assert_eq!(r.launch.starts(), 3);
    assert_eq!(r.manager.instances().await.instances.len(), 1);
}

/// Spec external-proxy §7.7: one proxy per chosen usable profile on the lowest free slots,
/// never the main VPN's profile.
#[tokio::test]
async fn batch_start_leaves_the_vpn_profile_alone() {
    let r = rig(samples(3), slow_timing());
    *r.source.active_vpn.lock() = Some("profile-1".into());
    let ids = ["profile-1", "profile-2", "profile-3", " profile-2 ", ""].map(String::from);
    let result = r.manager.start_profiles(ids.to_vec()).await;
    assert_eq!(result.requested, 3);
    let started: Vec<_> = result
        .started
        .iter()
        .map(|i| (i.slot.get(), i.profile_id.clone().unwrap(), i.port.unwrap()))
        .collect();
    assert_eq!(
        started,
        [
            (1, "profile-2".into(), 17990),
            (2, "profile-3".into(), 17991)
        ]
    );
    let skip = BatchSkip {
        profile_id: "profile-1".into(),
        reason: BatchSkipReason::ActiveVpn,
    };
    assert_eq!(result.skipped, [skip]);
    assert!(result.failed.is_empty() && result.already_running_profile_ids.is_empty());
    assert_ne!(result.started[0].pid, result.started[1].pid);
    let ports: Vec<u64> = r.launch.configs.lock().iter().map(listen_port).collect();
    assert_eq!(ports, [17990, 17991]);
    // Again: both run already; an unknown id is unavailable.
    let again = r
        .manager
        .start_profiles(vec!["profile-2".into(), "nope".into()])
        .await;
    assert_eq!(again.already_running_profile_ids, ["profile-2"]);
    assert_eq!(again.skipped[0].reason, BatchSkipReason::Unavailable);
    assert_eq!(r.launch.starts(), 2);
}

/// Spec external-proxy §7.7: stop all ends every slot in one operation.
#[tokio::test]
async fn stop_all_stops_every_slot() {
    let r = rig(samples(3), slow_timing());
    let ids = (1..=3).map(|n| format!("profile-{n}")).collect();
    assert_eq!(r.manager.start_profiles(ids).await.started.len(), 3);
    let status = r
        .manager
        .stop_all(StopScope::Unleased, StopReason::Ui)
        .await;
    assert!(status.instances.is_empty() && !status.instance.running);
    assert!(r.manager.instances().await.instances.is_empty());
}

/// Spec external-proxy §7.7: 30 routes with distinct fresh egress IPs make prewarm ready, and
/// 30 concurrent clients lease 30 distinct routes.
#[tokio::test]
async fn capacity_of_thirty_distinct_routes() {
    let r = rig(samples(30), slow_timing());
    r.prober
        .set(|port| egress(&format!("198.51.100.{}", port - 17989)));
    let warm = r.manager.prewarm(30, None).await.unwrap();
    assert!(warm.ready);
    assert_eq!(warm.started.len(), 30);
    let expected = Aggregate {
        total: 30,
        running: 30,
        ready: 30,
        healthy: 30,
        unique_egress: 30,
        duplicate_egress: 0,
        starting: 0,
        degraded: 0,
        quarantined: 0,
    };
    assert_eq!(warm.aggregate, expected);
    let urls: HashSet<_> = warm.instances.iter().map(|i| i.proxy_url.clone()).collect();
    let ips: HashSet<_> = warm.instances.iter().map(|i| i.egress_ip).collect();
    assert_eq!((urls.len(), ips.len()), (30, 30));
    assert!(
        warm.instances
            .iter()
            .all(|i| i.ready && i.health == Health::Healthy && i.egress_checked_at.is_some())
    );

    let asks = (1..=30).map(|i| {
        let mut req = ReserveRequest::new(format!("buyer-worker-{i}"));
        req.ttl_secs = Some(120.0);
        r.manager.reserve(req)
    });
    let leases: Vec<Reservation> = join_all(asks)
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect();
    let slots: HashSet<_> = leases.iter().map(|l| l.slot).collect();
    let tokens: HashSet<_> = leases.iter().map(|l| l.lease_token.clone()).collect();
    assert_eq!((slots.len(), tokens.len()), (30, 30));
    for lease in leases {
        assert!(r.manager.release(lease.lease_token).await.unwrap().released);
    }
    // Prewarm tops up: 30 instances exist, so nothing more starts.
    let again = r.manager.prewarm(30, None).await.unwrap();
    assert!(again.started.is_empty() && again.ready);
    assert_eq!(r.launch.starts(), 30);
}

/// Spec external-proxy §7.9 phase 1: the second slot on an IP is quarantined, the first stays
/// ready, and the aggregate reports the collision.
#[tokio::test]
async fn duplicate_egress_is_quarantined() {
    let r = rig(samples(2), slow_timing());
    r.prober.set(|_| egress("198.51.100.10"));
    r.manager.start(connect(1, "profile-1")).await.unwrap();
    r.manager.start(connect(2, "profile-2")).await.unwrap();
    assert!(r.manager.check_health(slot(1)).await.ready);
    let second = r.manager.check_health(slot(2)).await;
    assert!(!second.ready);
    assert_eq!(
        (second.health, second.state),
        (Health::Quarantined, Lifecycle::Quarantined)
    );
    assert_eq!(
        second.degradation_reason,
        Some(Degradation::DuplicateEgressIp)
    );
    assert_eq!(
        second.last_error.as_deref(),
        Some("Duplicate egress IP 198.51.100.10 already belongs to slot 1")
    );
    let agg = r.manager.instances().await.aggregate;
    assert_eq!(
        (
            agg.ready,
            agg.unique_egress,
            agg.duplicate_egress,
            agg.quarantined
        ),
        (1, 1, 1, 1)
    );
}

/// Spec external-proxy §7.9 phase 2: rotating one slot leaves the other untouched, reports
/// its reason, and a retried request with the same key does not rotate twice.
#[tokio::test]
async fn rotation_is_isolated_and_idempotent() {
    let r = rig(samples(3), slow_timing());
    let mut answers: HashMap<u16, Vec<&str>> = HashMap::from([
        (17990, vec!["198.51.100.21", "198.51.100.23"]),
        (17991, vec!["198.51.100.22"]),
    ]);
    r.prober.set(move |port| {
        let list = answers.get_mut(&port).unwrap();
        let ip = if list.len() > 1 {
            list.remove(0)
        } else {
            list[0]
        };
        egress(ip)
    });
    r.manager.start(connect(1, "profile-1")).await.unwrap();
    r.manager.start(connect(2, "profile-2")).await.unwrap();
    r.manager.check_health(slot(1)).await;
    let before = r.manager.check_health(slot(2)).await;
    let req = StartRequest {
        slot: Some(slot(1)),
        action: Action::Rotate,
        idempotency_key: Some("rotation-1".into()),
        rotate_reason: Some("test".into()),
        ..StartRequest::default()
    };
    let rotated = r.manager.start(req.clone()).await.unwrap().instance;
    assert!(rotated.ready);
    assert_eq!(rotated.health, Health::Healthy);
    assert_eq!(rotated.egress_ip, Some("198.51.100.23".parse().unwrap()));
    assert_eq!(rotated.last_rotate_reason.as_deref(), Some("test"));
    assert_eq!(rotated.profile_id.as_deref(), Some("profile-3"));
    assert!(rotated.generation > 1);
    let after = r.manager.status(slot(2)).await.instance;
    let key = |i: &InstanceStatus| {
        let shape = (i.proxy_url.clone(), i.egress_ip, i.generation);
        (shape, i.profile_id.clone(), i.pid)
    };
    assert_eq!(key(&after), key(&before));
    let starts = r.launch.starts();
    let retry = StartRequest {
        rotate_reason: Some("ignored".into()),
        ..req
    };
    let again = r.manager.start(retry).await.unwrap().instance;
    assert_eq!(
        (again.generation, r.launch.starts()),
        (rotated.generation, starts)
    );
    assert_eq!(again.last_rotate_reason.as_deref(), Some("test"));
}

/// Three ready slots exiting through `198.51.100.1/2/3`.
async fn three_ready_routes() -> Rig {
    let r = rig(samples(3), slow_timing());
    r.prober
        .set(|port| egress(&format!("198.51.100.{}", port - 17989)));
    assert!(r.manager.prewarm(3, None).await.unwrap().ready);
    r
}

fn ask(owner: &str) -> ReserveRequest {
    ReserveRequest {
        ttl_secs: Some(120.0),
        ..ReserveRequest::new(owner)
    }
}

/// Spec external-proxy §7.8: a client falls back from an occupied egress IP, a leased route
/// cannot be rotated or stopped, tokens are enforced, and a returning owner gets its route.
#[tokio::test]
async fn leases_guard_routes() {
    let r = three_ready_routes().await;
    let ip2 = "198.51.100.2".parse().unwrap();
    let first = r
        .manager
        .reserve(ReserveRequest {
            preferred_egress_ip: Some(ip2),
            ..ask("buyer-worker-1")
        })
        .await
        .unwrap();
    assert_eq!(first.instance.egress_ip, Some(ip2));
    let leased = first.slot;
    let rotate = StartRequest {
        slot: Some(leased),
        action: Action::Rotate,
        idempotency_key: Some("leased-rotation".into()),
        ..StartRequest::default()
    };
    let err = r.manager.start(rotate).await.unwrap_err();
    assert_eq!(err.http_status(), 409);
    let now = r.manager.status(leased).await.instance;
    assert_eq!(
        (now.generation, now.proxy_url.clone(), now.egress_ip),
        (first.generation, first.proxy_url.clone(), Some(ip2))
    );
    let err = r.manager.stop(leased, StopReason::Api).await.unwrap_err();
    let text = format!("Slot {leased} cannot stop while a Buyer Search lease is active");
    assert_eq!(err, ProxyError::Conflict(text));

    let other = r
        .manager
        .reserve(ReserveRequest {
            preferred_egress_ip: Some(ip2),
            preferred_slot: Some(leased),
            ..ask("buyer-worker-2")
        })
        .await
        .unwrap();
    assert_ne!(other.slot, leased);
    assert_ne!(other.instance.egress_ip, Some(ip2));
    let strict = ReserveRequest {
        slot: Some(leased),
        allow_fallback: false,
        ..ask("buyer-worker-3")
    };
    assert_eq!(
        r.manager.reserve(strict).await.unwrap_err().http_status(),
        409
    );
    let wrong = r.manager.release("wrong-token".into()).await.unwrap_err();
    assert_eq!(wrong.http_status(), 403);
    let renewed = r
        .manager
        .renew(first.lease_token.clone(), Some(120.0))
        .await
        .unwrap();
    assert_eq!(renewed.lease_token, first.lease_token);

    // UI "stop all" and a main VPN disconnect keep the leased routes (B-9).
    r.manager
        .stop_all(StopScope::Unleased, StopReason::VpnStop)
        .await;
    let left: Vec<Slot> = r
        .manager
        .instances()
        .await
        .instances
        .iter()
        .map(|i| i.slot)
        .collect();
    let mut kept = vec![leased, other.slot];
    kept.sort();
    assert_eq!(left, kept);
    r.manager.release(first.lease_token).await.unwrap();
    let back = r.manager.reserve(ask("buyer-worker-1")).await.unwrap();
    assert_eq!(back.slot, leased);
}

/// Spec external-proxy §7.8: an expired lease is freed before the next reservation.
#[tokio::test]
async fn expired_lease_is_freed() {
    let r = rig(samples(1), slow_timing());
    r.prober.set(|_| egress("198.51.100.50"));
    r.manager.start(connect(1, "profile-1")).await.unwrap();
    assert!(r.manager.check_health(Slot::DEFAULT).await.ready);
    let short = ReserveRequest {
        slot: Some(Slot::DEFAULT),
        ttl_secs: Some(1.0),
        allow_fallback: false,
        ..ReserveRequest::new("expiry-owner")
    };
    r.manager.reserve(short).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1_050)).await;
    let next = ReserveRequest {
        slot: Some(Slot::DEFAULT),
        allow_fallback: false,
        ..ask("next-owner")
    };
    assert_eq!(r.manager.reserve(next).await.unwrap().slot, Slot::DEFAULT);
}

/// B-31: a leased route whose engine died cannot be renewed; the lease is dropped, so the slot
/// can be stopped or restarted again.
#[tokio::test]
async fn dead_leased_route_cannot_be_renewed() {
    let r = three_ready_routes().await;
    let lease = r.manager.reserve(ask("buyer-worker-1")).await.unwrap();
    let index = usize::from(lease.slot.get()) - 1;
    r.launch.engine(index).crash(1);
    let m = r.manager.clone();
    assert!(eventually(|| !m.inner.instance(lease.slot).process_running).await);
    let err = r.manager.renew(lease.lease_token, None).await.unwrap_err();
    assert_eq!(err, ProxyError::Conflict("Leased route is down".into()));
    assert!(r.manager.stop(lease.slot, StopReason::Api).await.is_ok());
}

/// Spec external-proxy §3.17: when a leased route meets a duplicate, the unleased peer is
/// quarantined and the leased one stays ready.
#[tokio::test]
async fn duplicate_quarantines_the_unleased_peer() {
    let r = three_ready_routes().await;
    let lease = r
        .manager
        .reserve(ReserveRequest {
            slot: Some(slot(3)),
            ..ask("buyer-worker-1")
        })
        .await
        .unwrap();
    assert_eq!(lease.slot, slot(3));
    // Slot 3's exit moves to the IP of slot 1 after a failed probe (no drift check then).
    r.prober.set(|_| timeout_error());
    r.manager.check_health(slot(3)).await;
    r.prober.set(|_| egress("198.51.100.1"));
    let leased = r.manager.check_health(slot(3)).await;
    assert!(leased.ready);
    let peer = r.manager.status(slot(1)).await.instance;
    assert_eq!(peer.health, Health::Quarantined);
    assert_eq!(
        peer.last_error.as_deref(),
        Some("Duplicate egress IP 198.51.100.1 also reported by slot 3")
    );
}

/// Spec external-proxy §3.16: a spent failure budget never stops a leased route; it stays
/// degraded (recovery blocked) with the probe's error and keeps running.
#[tokio::test]
async fn leased_route_is_not_auto_disabled() {
    let r = three_ready_routes().await;
    let lease = r.manager.reserve(ask("buyer-worker-1")).await.unwrap();
    r.prober.set(|_| Err(ProbeError::Transport("EOF".into())));
    for _ in 0..4 {
        r.manager.check_health(lease.slot).await;
    }
    let m = r.manager.clone();
    let blocked =
        |i: &InstanceStatus| i.degradation_reason == Some(Degradation::LeasedRouteRecoveryBlocked);
    assert!(eventually(|| blocked(&m.inner.instance(lease.slot))).await);
    let status = r.manager.status(lease.slot).await.instance;
    assert!(status.process_running && !status.auto_disabled);
    assert_eq!(status.health, Health::Degraded);
    assert_eq!(status.last_error.as_deref(), Some("EOF"));
}

/// Spec external-proxy §2.13 and B-3 / B-12: port conflicts, a busy port, `connect` without a
/// profile and an empty country are rejected before anything starts; a start of a running
/// slot is idempotent.
#[tokio::test]
async fn start_validation() {
    let r = rig(samples(2), slow_timing());
    r.manager.set_control_port(17990);
    let err = r.manager.start(connect(1, "profile-1")).await.unwrap_err();
    let reserved = "Port 17990 is reserved for the external proxy Control API";
    assert_eq!(err, ProxyError::Conflict(reserved.into()));
    r.manager.set_control_port(17873);
    r.launch.busy_ports.lock().insert(17991);
    let err = r.manager.start(connect(2, "profile-2")).await.unwrap_err();
    assert_eq!(
        err,
        ProxyError::Conflict("Port 17991 is unavailable: in use".into())
    );
    r.manager.start(connect(1, "profile-1")).await.unwrap();
    let on_same_port = StartRequest {
        port: Some(17990),
        ..connect(2, "profile-2")
    };
    let err = r.manager.start(on_same_port).await.unwrap_err();
    let used = "Port 17990 is already used by external proxy slot 1";
    assert_eq!(err, ProxyError::Conflict(used.into()));
    let bare = StartRequest {
        action: Action::Connect,
        ..StartRequest::default()
    };
    let err = r.manager.start(bare).await.unwrap_err();
    assert_eq!(err.http_status(), 400);
    let zero = StartRequest {
        port: Some(0),
        ..connect(3, "profile-2")
    };
    let err = r.manager.start(zero).await.unwrap_err();
    assert_eq!(err, ProxyError::BadRequest("invalid port".into()));
    assert!(r.manager.status(slot(3)).await.instance.port.is_none());
    let elsewhere = StartRequest {
        slot: Some(slot(3)),
        country: Some("jp".into()),
        ..StartRequest::default()
    };
    let err = r.manager.start(elsewhere).await.unwrap_err();
    assert_eq!(err.detail(), "No VPN profiles found for country: jp");
    assert_eq!(r.launch.starts(), 1);
    // A plain start of the running slot returns it as it is, even with other options.
    let again = StartRequest {
        slot: Some(Slot::DEFAULT),
        profile_id: Some("profile-2".into()),
        ..StartRequest::default()
    };
    let same = r.manager.start(again).await.unwrap().instance;
    assert_eq!(same.profile_id.as_deref(), Some("profile-1"));
    assert_eq!(r.launch.starts(), 1);
    // A failed engine start leaves the slot configured and failed with the reason.
    *r.launch.fail_next.lock() = Some(ProxyError::Engine("sing-box exited".into()));
    let err = r.manager.start(connect(4, "profile-2")).await.unwrap_err();
    assert_eq!(err.detail(), "sing-box exited");
    let failed = r.manager.status(slot(4)).await.instance;
    assert_eq!((failed.health, failed.port), (Health::Failed, Some(17993)));
    assert_eq!(failed.last_error.as_deref(), Some("sing-box exited"));
}

/// B-19 / spec 7.11: the UI "+" lets the backend pick the slot (a failed slot keeps its
/// number); statuses report the control API port actually bound.
#[tokio::test]
async fn add_allocates_and_reports_the_control_url() {
    let r = rig(samples(3), slow_timing());
    r.manager.set_control_port(49_152);
    *r.launch.fail_next.lock() = Some(ProxyError::Engine("boom".into()));
    assert!(r.manager.add("profile-1".into()).await.is_err());
    let added = r.manager.add("profile-2".into()).await.unwrap();
    assert_eq!(added.instance.slot, slot(2));
    assert_eq!(added.control_port, Some(49_152));
    assert_eq!(added.control_url.as_deref(), Some("http://127.0.0.1:49152"));
    assert_eq!(
        r.manager.snapshot().borrow().control_url.as_deref(),
        Some("http://127.0.0.1:49152")
    );
    let err = r.manager.add("missing".into()).await.unwrap_err();
    assert_eq!(err.detail(), "VPN profile not found or unusable: missing");
}

/// B-9 / spec 3.28: app exit stops every slot, leases notwithstanding, and refuses new starts.
#[tokio::test]
async fn shutdown_stops_everything() {
    let r = three_ready_routes().await;
    r.manager.reserve(ask("buyer-worker-1")).await.unwrap();
    r.manager.shutdown().await;
    assert!(r.manager.instances().await.instances.is_empty());
    let err = r.manager.start(connect(1, "profile-1")).await.unwrap_err();
    assert_eq!(err.http_status(), 503);
    let engines = r.launch.engines.lock().clone();
    assert!(engines.iter().all(|e| e.exit.borrow().is_some()));
}

/// AT-00-004 (spec external-proxy §7.1): a failed group health check keeps its category as the
/// status and never the cause.
#[tokio::test]
async fn group_health_errors_map_to_statuses() {
    let r = rig(samples(1), slow_timing());
    assert!(r.manager.check_group_health("g".into()).await.unwrap().ok);
    for (kind, status) in [
        (ErrorKind::Conflict, 409),
        (ErrorKind::Permission, 403),
        (ErrorKind::Validation, 404),
    ] {
        *r.source.group_health.lock() = Some(kind);
        let err = r.manager.check_group_health("g".into()).await.unwrap_err();
        assert_eq!(err.http_status(), status);
    }
}

/// Spec external-proxy §3.19: while healthy, an engine-log timeout pulls the next probe in.
#[tokio::test]
async fn transport_hint_pulls_the_probe_in() {
    let timing = Timing {
        hint_delay: Duration::from_millis(50),
        ..slow_timing()
    };
    let r = rig(samples(1), timing);
    r.manager.start(connect(1, "profile-1")).await.unwrap();
    r.manager.check_health(Slot::DEFAULT).await;
    assert_eq!(r.prober.total(), 1);
    r.launch.engine(0).say("ERROR connection: i/o timeout");
    assert!(eventually(|| r.prober.total() == 2).await);
}

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");

/// A SOCKS5 server (no auth) that plays the Internet: every CONNECT is answered by the stub
/// itself, `trace.test` with a Cloudflare-style trace naming `198.51.100.9`.
async fn fake_internet() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = serve_socks(&mut sock).await;
            });
        }
    });
    port
}

async fn serve_socks(sock: &mut TcpStream) -> std::io::Result<()> {
    let mut greeting = [0u8; 2];
    sock.read_exact(&mut greeting).await?;
    let mut methods = vec![0u8; usize::from(greeting[1])];
    sock.read_exact(&mut methods).await?;
    sock.write_all(&[5, 0]).await?;
    let mut request = [0u8; 4];
    sock.read_exact(&mut request).await?;
    let host = match request[3] {
        1 => {
            let mut addr = [0u8; 4];
            sock.read_exact(&mut addr).await?;
            Ipv4Addr::from(addr).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; usize::from(len[0])];
            sock.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        _ => return Ok(()),
    };
    let mut port = [0u8; 2];
    sock.read_exact(&mut port).await?;
    sock.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&chunk[..n]);
    }
    let body = if host == "trace.test" {
        "fl=1\nip=198.51.100.9\n"
    } else {
        "{}"
    };
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(reply.as_bytes()).await
}

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

/// AT-02-008 / spec external-proxy §7.5 with the real engine: a slot whose profile is a plain
/// SOCKS5 upstream on loopback runs as a real sing-box child, turns healthy through a probe
/// that travels its listener, the engine and the upstream, and its process ends on stop.
/// Skipped quietly without the bundled engine.
#[tokio::test]
async fn real_engine_slot_end_to_end() {
    let resources = Path::new(RESOURCES);
    if !resources.join("sing-box.exe").exists() {
        return;
    }
    let upstream = fake_internet().await;
    let socks = Profile {
        port: upstream,
        kind: Kind::Socks {
            username: None,
            password: None,
        },
        tls: None,
        ..vless("127.0.0.1")
    };
    let source = Arc::new(FakeSource::default());
    *source.profiles.lock() = vec![ProxyProfile {
        profile: socks,
        ..sample(1)
    }];
    let engines = Arc::new(Engines::new(resources));
    let prober = Arc::new(crate::probe::tests::test_config());
    let manager = ProxyManager::with_parts(source, engines, prober, slow_timing());
    let port = free_port();
    let req = StartRequest {
        port: Some(port),
        ..connect(1, "profile-1")
    };
    let started = manager.start(req).await.unwrap().instance;
    assert!(started.process_running && started.pid.is_some());
    assert_eq!(started.proxy_url, Some(format!("http://127.0.0.1:{port}")));
    let healthy = manager.check_health(Slot::DEFAULT).await;
    assert_eq!(healthy.health, Health::Healthy, "{:?}", healthy.last_error);
    assert!(healthy.ready && healthy.running);
    assert_eq!(healthy.egress_ip, Some("198.51.100.9".parse().unwrap()));
    manager.stop(Slot::DEFAULT, StopReason::Api).await.unwrap();
    assert!(!manager.status(Slot::DEFAULT).await.instance.process_running);
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    assert!(std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_err());
    manager.shutdown().await;
}

/// Spec external-proxy §6.3 NOTE / B-30: the pushed snapshot shows a confirmed route as ready,
/// and re-deriving it later (the UI tick) lets a route whose probes stalled go stale.
#[tokio::test]
async fn snapshot_readiness_follows_the_clock() {
    let r = rig(samples(1), slow_timing());
    let rx = r.manager.snapshot();
    r.manager.start(connect(1, "profile-1")).await.unwrap();
    assert!(rx.borrow().instances[0].process_running);
    r.manager.check_health(Slot::DEFAULT).await;
    let snapshot = rx.borrow().clone();
    assert!(snapshot.instances[0].ready && snapshot.aggregate.ready == 1);
    let later = snapshot.refreshed(snapshot.at + crate::model::FRESH_WINDOW_MS);
    assert!(!later.instances[0].ready && later.aggregate.ready == 0);
    assert_eq!(
        later.instances[0].egress_ip,
        snapshot.instances[0].egress_ip
    );
}

/// AT-09-011 (ru/en parity): the fragment is valid JSON with the same keys in both languages,
/// and every key the manager hands out exists in it.
#[test]
fn locale_fragments_cover_every_key() {
    fn leaves(prefix: &str, v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                for (k, v) in map {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    leaves(&key, v, out);
                }
            }
            other => {
                assert!(other.as_str().is_some_and(|s| !s.is_empty()), "{prefix}");
                out.push(prefix.to_owned());
            }
        }
    }
    let keys = |text: &str| {
        let mut out = Vec::new();
        leaves("", &serde_json::from_str(text).unwrap(), &mut out);
        out.sort();
        out
    };
    let ru = keys(include_str!("../../locales/proxies-manager.ru.json"));
    let en = keys(include_str!("../../locales/proxies-manager.en.json"));
    assert_eq!(ru, en);
    let degradations = [
        Degradation::ProcessFailed,
        Degradation::LeasedRouteRecoveryBlocked,
        Degradation::HealthFailureBudgetExhausted,
        Degradation::EgressIpChangedWithoutRotation,
        Degradation::RotationDidNotChangeEgressIp,
        Degradation::DuplicateEgressIp,
        Degradation::EgressProbeFailed,
    ];
    let healths = [
        Health::Stopped,
        Health::Starting,
        Health::Healthy,
        Health::Degraded,
        Health::Rotating,
        Health::Quarantined,
        Health::Failed,
    ];
    let used: Vec<String> = degradations
        .map(|d| super::degradation_msg(d).key.into_owned())
        .into_iter()
        .chain(healths.map(|h| super::health_msg(h).key.into_owned()))
        .collect();
    assert_eq!(used.len(), ru.len());
    for key in used {
        assert!(ru.contains(&key), "{key}");
    }
}
