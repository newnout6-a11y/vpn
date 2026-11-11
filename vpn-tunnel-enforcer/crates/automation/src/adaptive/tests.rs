//! Adaptive bypass: capability matrix, chain, siblings and the task against fakes.
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::types::{AdaptiveMode, Engine, OutboundFault, Owner};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;

use super::identity::IdentityRow;
use super::window::Timing;
use super::*;
use crate::coordinator::testing::FakeCoordinator;
use crate::coordinator::{LifecycleEvent, OpError, RuntimeId, StopCause};
use crate::test_support::TempDir;

const FAST: Timing = Timing {
    settle: Duration::from_millis(5),
    gap: Duration::from_millis(1),
};

// ---------- fakes ----------

struct FakeHost {
    profiles: Mutex<HashMap<String, ProfileView>>,
    siblings: Mutex<Vec<Sibling>>,
    /// Probe outcomes in call order; an exhausted script fails.
    probes: Mutex<VecDeque<bool>>,
    probe_calls: AtomicUsize,
    identity: Mutex<Option<NetworkSnapshot>>,
    identity_calls: AtomicUsize,
    /// The identity read number `n` (1-based) waits for this gate.
    gate: Mutex<Option<(usize, Arc<Notify>)>>,
    /// Identity returned from read number `n` on.
    switch_identity: Mutex<Option<(usize, Option<NetworkSnapshot>)>>,
    selected: Mutex<Vec<String>>,
    abandoned: AtomicUsize,
    coord: Arc<FakeCoordinator>,
}

impl FakeHost {
    fn new(coord: Arc<FakeCoordinator>) -> Arc<Self> {
        Arc::new(Self {
            profiles: Mutex::new(HashMap::new()),
            siblings: Mutex::new(Vec::new()),
            probes: Mutex::new(VecDeque::new()),
            probe_calls: AtomicUsize::new(0),
            identity: Mutex::new(Some(net("192.168.1.1"))),
            identity_calls: AtomicUsize::new(0),
            gate: Mutex::new(None),
            switch_identity: Mutex::new(None),
            selected: Mutex::new(Vec::new()),
            abandoned: AtomicUsize::new(0),
            coord,
        })
    }

    fn script(&self, outcomes: &[bool]) {
        self.probes.lock().extend(outcomes.iter().copied());
    }

    fn probes(&self) -> usize {
        self.probe_calls.load(Ordering::SeqCst)
    }
}

impl AdaptiveHost for FakeHost {
    fn profile(&self, id: &str) -> Option<ProfileView> {
        self.profiles.lock().get(id).cloned()
    }
    fn siblings(&self, _: &str) -> Vec<Sibling> {
        self.siblings.lock().clone()
    }
    async fn probe(&self, _: CancellationToken) -> Option<Duration> {
        self.probe_calls.fetch_add(1, Ordering::SeqCst);
        let ok = self.probes.lock().pop_front().unwrap_or(false);
        ok.then_some(Duration::from_millis(10))
    }
    fn select(&self, id: &str) -> AppResult<()> {
        self.selected.lock().push(id.to_owned());
        Ok(())
    }
    async fn abandon(&self) {
        self.abandoned.fetch_add(1, Ordering::SeqCst);
        self.coord.stop(StopCause::Fault);
    }
    async fn network_identity(&self) -> Option<NetworkSnapshot> {
        let n = self.identity_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let gate = self.gate.lock().clone().filter(|(at, _)| *at == n);
        if let Some((_, gate)) = gate {
            gate.notified().await;
        }
        match self.switch_identity.lock().clone() {
            Some((from, id)) if n >= from => id,
            _ => self.identity.lock().clone(),
        }
    }
}

fn net(gateway: &str) -> NetworkSnapshot {
    NetworkSnapshot::from_rows(vec![IdentityRow {
        guid: "1".repeat(32),
        mac: "102030405060".into(),
        prefixes: vec!["192.168.1.0/24".into()],
        gateways: vec![gateway.into()],
    }])
    .unwrap()
}

fn profile(id: &str, outbound: Value) -> ProfileView {
    ProfileView {
        id: id.into(),
        outbound,
        client_device: None,
        client_fingerprint: None,
        engine: Engine::SingBox,
    }
}

fn reality(id: &str) -> ProfileView {
    let o = json!({"type": "vless", "server": "r.example.test", "server_port": 443,
        "tls": {"enabled": true, "reality": {"enabled": true, "public_key": "PK_PLACEHOLDER"}}});
    profile(id, o)
}

fn tls_ws(id: &str) -> ProfileView {
    let o = json!({"type": "trojan", "server": "t.example.test", "server_port": 443,
        "password": "PASSWORD_PLACEHOLDER", "tls": {"enabled": true}, "transport": {"type": "ws"}});
    profile(id, o)
}

fn hy2(id: &str) -> ProfileView {
    let o = json!({"type": "hysteria2", "server": "h.example.test", "server_port": 443,
        "password": "PASSWORD_PLACEHOLDER", "tls": {"enabled": true}});
    profile(id, o)
}

struct Harness {
    coord: Arc<FakeCoordinator>,
    host: Arc<FakeHost>,
    settings: Arc<Store<Settings>>,
    docs: Arc<Store<AdaptiveDoc>>,
    adaptive: Arc<Adaptive<FakeCoordinator, FakeHost>>,
    status: watch::Receiver<AdaptiveStatus>,
    cancel: CancellationToken,
    _dir: TempDir,
}

impl Harness {
    fn new() -> Self {
        Self::with_timing(FAST)
    }

    fn with_timing(timing: Timing) -> Self {
        let dir = TempDir::new("adaptive-task");
        let coord = FakeCoordinator::new();
        let host = FakeHost::new(coord.clone());
        let settings = Arc::new(Store::<Settings>::open(dir.path()));
        let docs = Arc::new(Store::<AdaptiveDoc>::open(dir.path()));
        let adaptive = Arc::new(Adaptive::with_timing(
            coord.clone(),
            host.clone(),
            settings.clone(),
            docs.clone(),
            timing,
        ));
        let cancel = CancellationToken::new();
        tokio::spawn({
            let (a, c) = (adaptive.clone(), cancel.clone());
            async move { a.run(c).await }
        });
        let status = adaptive.status();
        Self {
            coord,
            host,
            settings,
            docs,
            adaptive,
            status,
            cancel,
            _dir: dir,
        }
    }

    /// Waits until the task listens (events sent before that would be lost, as in production).
    async fn ready(self) -> Self {
        while self.coord.events.receiver_count() == 0 {
            tokio::task::yield_now().await;
        }
        self
    }

    fn add(&self, view: &ProfileView) {
        self.host
            .profiles
            .lock()
            .insert(view.id.clone(), view.clone());
    }

    /// The app's connect path: `begin`, then the coordinator starts in the returned mode.
    async fn connect(&self, view: &ProfileView) -> AdaptiveMode {
        self.add(view);
        let mode = self
            .adaptive
            .begin(SessionKind::Direct, Some(view.clone()))
            .await;
        self.coord.start(SessionKind::Direct, Some(&view.id), mode);
        mode
    }

    /// Waits for a terminal phase (connected / failed / idle) and returns the status.
    async fn done(&mut self) -> AdaptiveStatus {
        let terminal = |s: &AdaptiveStatus| matches!(s.phase, Phase::Connected | Phase::Failed);
        let waited = tokio::time::timeout(Duration::from_secs(5), self.status.wait_for(terminal));
        waited
            .await
            .expect("verification finished")
            .unwrap()
            .clone()
    }

    fn learned(&self) -> Vec<AdaptiveMode> {
        self.docs
            .read(|d| d.learning.values().map(|r| r.mode).collect())
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

// ---------- pure parts ----------

/// `adaptiveBypass.test.ts` capability matrix plus A2 (Xray: no TLS knob) and A7 (`enabled: false`).
#[test]
fn capability_matrix_and_chain() {
    use AdaptiveMode::*;
    let local = capabilities(SessionKind::LocalProxyHard, None);
    assert!(local.external && !local.tls && !local.mtu);
    assert_eq!(next_mode(Baseline, &local), None);

    let tls = capabilities(
        SessionKind::Direct,
        Some(&profile("a", json!({"tls": {"enabled": true}}))),
    );
    assert!(tls.tls && tls.mtu && !tls.external && tls.reason.is_none());
    assert_eq!(next_mode(Baseline, &tls), Some(TlsCompatibility));
    assert_eq!(next_mode(TlsCompatibility, &tls), Some(MtuCompatibility));
    assert_eq!(next_mode(MtuCompatibility, &tls), None);

    let real = capabilities(SessionKind::Direct, Some(&reality("r")));
    assert!(!real.tls && real.mtu);
    assert_eq!(
        real.reason.as_ref().unwrap().key,
        "automation.adaptive.reason.reality"
    );
    assert_eq!(next_mode(Baseline, &real), Some(MtuCompatibility));

    let mut xray = tls_ws("x");
    xray.engine = Engine::Xray;
    let xray = capabilities(SessionKind::Direct, Some(&xray));
    assert!(!xray.tls && xray.mtu);
    assert_eq!(next_mode(Baseline, &xray), Some(MtuCompatibility));

    let plain = profile("p", json!({"type": "vless", "tls": {"enabled": false}}));
    assert!(!capabilities(SessionKind::Direct, Some(&plain)).tls);
    assert!(!capabilities(SessionKind::Direct, None).tls);
}

/// A5: another protocol family first, then the lowest latency, then store order.
#[test]
fn sibling_order_prefers_another_family_then_latency() {
    let active = tls_ws("active");
    let sib = |view: ProfileView, latency: Option<u32>| Sibling {
        profile: view,
        latency_ms: latency,
    };
    let ordered = order_siblings(
        &active,
        vec![
            sib(tls_ws("same-fast"), Some(5)),
            sib(tls_ws("active"), Some(1)),
            sib(reality("reality-slow"), Some(300)),
            sib(hy2("hy2-unknown"), None),
            sib(hy2("hy2-fast"), Some(40)),
        ],
    );
    let ids: Vec<&str> = ordered.iter().map(|s| s.profile.id.as_str()).collect();
    assert_eq!(
        ids,
        ["hy2-fast", "reality-slow", "hy2-unknown", "same-fast"]
    );
    assert_eq!(family(&reality("r").outbound), "vless/reality/");
    assert_eq!(family(&tls_ws("t").outbound), "trojan//ws");
}

// ---------- the task ----------

/// Baseline passes: connected in standard mode, nothing restarted, nothing learned.
#[tokio::test]
async fn baseline_that_works_is_connected() {
    let mut h = Harness::new().ready().await;
    h.host.script(&[true, true, false]);
    assert_eq!(h.connect(&tls_ws("p1")).await, AdaptiveMode::Baseline);
    let status = h.done().await;
    assert_eq!(status.phase, Phase::Connected);
    assert_eq!(
        status.message.key,
        "automation.adaptive.status.connectedBaseline"
    );
    assert!(h.coord.restarts().is_empty() && h.learned().is_empty());
    assert_eq!(h.host.probes(), 3);
}

/// Learning: MTU learned on a Reality server; the next begin starts in MTU; a hotspot with the
/// same subnet (another gateway MAC) starts in baseline; back home → MTU again; an unknown
/// identity → baseline and the store unchanged.
#[tokio::test]
async fn learning_round_trip() {
    let mut h = Harness::new().ready().await;
    let server = reality("r1");
    h.host.script(&[false, false, false, true, true, true]);
    assert_eq!(h.connect(&server).await, AdaptiveMode::Baseline);
    let status = h.done().await;
    assert_eq!(
        status.message.key,
        "automation.adaptive.status.connectedCompatibility"
    );
    assert_eq!(
        h.coord.restarts(),
        vec![(AdaptiveMode::MtuCompatibility, None)]
    );
    assert_eq!(h.learned(), vec![AdaptiveMode::MtuCompatibility]);

    assert_eq!(
        h.adaptive
            .begin(SessionKind::Direct, Some(server.clone()))
            .await,
        AdaptiveMode::MtuCompatibility
    );
    *h.host.identity.lock() = Some(net("192.168.1.1@0011223344ff"));
    assert_eq!(
        h.adaptive
            .begin(SessionKind::Direct, Some(server.clone()))
            .await,
        AdaptiveMode::Baseline
    );
    *h.host.identity.lock() = Some(net("192.168.1.1"));
    assert_eq!(
        h.adaptive
            .begin(SessionKind::Direct, Some(server.clone()))
            .await,
        AdaptiveMode::MtuCompatibility
    );
    *h.host.identity.lock() = None;
    let before = h.docs.snapshot();
    assert_eq!(
        h.adaptive.begin(SessionKind::Direct, Some(server)).await,
        AdaptiveMode::Baseline
    );
    assert_eq!(h.docs.snapshot().learning.len(), before.learning.len());
}

/// Fix A3: adaptive off → baseline start, no probes, nothing learned; restarts drop to baseline.
#[tokio::test]
async fn disabled_adaptive_starts_baseline_without_probes() {
    let mut h = Harness::new().ready().await;
    h.settings.update(|s| s.adaptive_bypass = false).unwrap();
    assert_eq!(h.connect(&tls_ws("p1")).await, AdaptiveMode::Baseline);
    assert_eq!(h.done().await.phase, Phase::Connected);
    assert_eq!(h.host.probes(), 0);
    assert!(h.learned().is_empty());
    assert_eq!(
        h.adaptive.restart_mode(AdaptiveMode::MtuCompatibility),
        AdaptiveMode::Baseline
    );
    h.settings.update(|s| s.adaptive_bypass = true).unwrap();
    assert_eq!(
        h.adaptive.restart_mode(AdaptiveMode::MtuCompatibility),
        AdaptiveMode::MtuCompatibility
    );
}

/// Fix A1: a reused learned MTU mode that fails is forgotten and retried once from baseline; the
/// chain then skips MTU (it just failed) and ends without a sibling.
#[tokio::test]
async fn stale_learned_mode_is_forgotten() {
    let mut h = Harness::new().ready().await;
    h.settings
        .update(|s| s.adaptive_bypass_server_fallback = false)
        .unwrap();
    let server = reality("r1");
    h.host.script(&[false, false, false, true, true, true]);
    h.connect(&server).await;
    h.done().await;
    assert_eq!(h.learned(), vec![AdaptiveMode::MtuCompatibility]);
    h.coord.stop(StopCause::Requested(Owner::Manual));

    h.host.script(&[false, false, false, false, false, false]);
    assert_eq!(h.connect(&server).await, AdaptiveMode::MtuCompatibility);
    let status = h.done().await;
    assert_eq!(status.phase, Phase::Failed);
    assert_eq!(
        status.reason.unwrap().key,
        "automation.adaptive.reason.probeFailed"
    );
    assert!(h.learned().is_empty(), "the stale record is removed");
    let restarts = h.coord.restarts();
    assert_eq!(restarts[1..], [(AdaptiveMode::Baseline, None)]);
    assert_eq!(h.coord.notices.lock().len(), 1);
}

/// An outbound fault: MTU / TLS cannot fix it, so no compatibility restart; without siblings the
/// fault text is the reason.
#[tokio::test]
async fn outbound_fault_skips_the_chain() {
    let mut h = Harness::new().ready().await;
    let server = tls_ws("t1");
    h.connect(&server).await;
    let runtime = h.coord.runtime();
    let _ = h.coord.events.send(LifecycleEvent::Fault {
        runtime_id: runtime,
        fault: OutboundFault::RealityKeyMismatch,
    });
    let status = h.done().await;
    assert_eq!(status.phase, Phase::Failed);
    assert_eq!(
        status.reason.unwrap().key,
        "automation.adaptive.reason.realityKeyMismatch"
    );
    assert!(h.coord.restarts().is_empty());
}

/// AT-10-004: the whole budget — baseline → TLS → MTU, then two siblings (another family first),
/// each started in the mode the chain reached; none verifies → the provisional sibling is
/// abandoned once, the failure stays visible and is announced once.
#[tokio::test]
async fn full_budget_then_abandon() {
    let mut h = Harness::new().ready().await;
    let server = tls_ws("t1");
    *h.host.siblings.lock() = vec![
        Sibling {
            profile: tls_ws("t2"),
            latency_ms: Some(1),
        },
        Sibling {
            profile: hy2("h1"),
            latency_ms: Some(90),
        },
        Sibling {
            profile: reality("r1"),
            latency_ms: None,
        },
    ];
    h.connect(&server).await;
    let status = h.done().await;
    assert_eq!(status.phase, Phase::Failed);
    assert_eq!(
        status.reason.as_ref().unwrap().key,
        "automation.adaptive.reason.siblingFailed"
    );
    use AdaptiveMode::*;
    assert_eq!(
        h.coord.restarts(),
        vec![
            (TlsCompatibility, None),
            (MtuCompatibility, None),
            (MtuCompatibility, Some("h1".to_owned())),
            (MtuCompatibility, Some("r1".to_owned())),
        ]
    );
    assert_eq!(status.attempts, 4);
    assert_eq!(h.host.probes(), 15);
    assert_eq!(h.host.abandoned.load(Ordering::SeqCst), 1);
    assert!(h.host.selected.lock().is_empty());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        h.status.borrow().phase,
        Phase::Failed,
        "the fault stop keeps the failure"
    );
    assert_eq!(h.coord.notices.lock().len(), 1);
}

/// AT-10-003: a sibling whose window gives `[10, null, 20]` is committed once.
#[tokio::test]
async fn verified_sibling_is_committed() {
    let mut h = Harness::new().ready().await;
    h.add(&reality("r1"));
    *h.host.siblings.lock() = vec![Sibling {
        profile: hy2("h1"),
        latency_ms: None,
    }];
    // Reality: baseline fails, MTU fails, the sibling passes 2 of 3.
    h.host
        .script(&[false, false, false, false, false, false, true, false, true]);
    h.connect(&reality("r1")).await;
    let status = h.done().await;
    assert_eq!(status.phase, Phase::Connected);
    assert_eq!(*h.host.selected.lock(), vec!["h1".to_owned()]);
    assert_eq!(h.host.abandoned.load(Ordering::SeqCst), 0);
    assert!(
        h.learned().is_empty(),
        "a sibling never learns for the original key"
    );
}

/// No fresh egress proof for the sibling (the coordinator's restart fails and ends the session):
/// no probe on it, failure shown.
#[tokio::test]
async fn sibling_without_egress_proof_is_not_probed() {
    let mut h = Harness::new().ready().await;
    *h.host.siblings.lock() = vec![Sibling {
        profile: hy2("h1"),
        latency_ms: None,
    }];
    let server = reality("r1");
    h.coord
        .restart_results
        .lock()
        .extend([Ok(()), Err(OpError::Timeout)]);
    h.coord.end_on_error.store(true, Ordering::SeqCst);
    h.connect(&server).await;
    let status = h.done().await;
    assert_eq!(status.phase, Phase::Failed);
    let reason = status.reason.unwrap();
    assert_eq!(reason.key, "automation.adaptive.reason.siblingStartFailed");
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(h.status.borrow().phase, Phase::Failed);
    assert_eq!(h.host.probes(), 6, "baseline and MTU windows only");
    assert!(h.host.selected.lock().is_empty());
}

/// AT-10-006: a manual switch during our restart wins — the late restart success is not ours to
/// verify, nothing is selected or abandoned, and the switched runtime is verified instead.
#[tokio::test]
async fn foreign_start_during_a_restart_supersedes_it() {
    let mut h = Harness::new().ready().await;
    h.add(&tls_ws("t9"));
    *h.coord.during_restart.lock() = Some(LifecycleEvent::Started {
        owner: Owner::Manual,
        runtime_id: RuntimeId(7),
        kind: SessionKind::Direct,
        profile_id: Some("t9".into()),
        mode: AdaptiveMode::Baseline,
    });
    h.host.script(&[false, false, false, true, true, true]);
    h.connect(&tls_ws("t1")).await;
    let status = h.done().await;
    assert_eq!(status.phase, Phase::Connected);
    assert_eq!(
        h.coord.restarts().len(),
        1,
        "only the TLS restart was asked for"
    );
    assert!(h.host.selected.lock().is_empty());
    assert_eq!(h.host.abandoned.load(Ordering::SeqCst), 0);
    assert!(
        h.learned().is_empty(),
        "the adopted runtime has no learning key"
    );
}

/// AT-10-006: a manual switch in the middle of a sibling window: no stop, no select.
#[tokio::test]
async fn manual_switch_during_a_sibling_window() {
    let mut h = Harness::new().ready().await;
    h.add(&tls_ws("manual"));
    *h.host.siblings.lock() = vec![Sibling {
        profile: hy2("h1"),
        latency_ms: None,
    }];
    h.host.script(&[false; 9]);
    h.connect(&tls_ws("t1")).await;
    while h.coord.restarts().len() < 3 || h.status.borrow().phase != Phase::Verifying {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    h.host.script(&[true; 3]);
    let manual = h
        .coord
        .start(SessionKind::Direct, Some("manual"), AdaptiveMode::Baseline);
    let status = h.done().await;
    assert_eq!(status.phase, Phase::Connected);
    assert_eq!(h.coord.runtime(), manual);
    assert!(h.host.selected.lock().is_empty());
    assert_eq!(h.host.abandoned.load(Ordering::SeqCst), 0);
}

/// Adoption (fix A9): a start nobody prepared is verified in the mode it reports and never
/// learns; a local-proxy session is external-managed without probes.
#[tokio::test]
async fn adopted_starts_use_their_reported_mode() {
    let mut h = Harness::new().ready().await;
    h.add(&reality("r1"));
    h.host.script(&[true; 3]);
    h.coord.start(
        SessionKind::Direct,
        Some("r1"),
        AdaptiveMode::MtuCompatibility,
    );
    let status = h.done().await;
    assert_eq!(status.mode, AdaptiveMode::MtuCompatibility);
    assert_eq!(
        status.message.key,
        "automation.adaptive.status.connectedCompatibility"
    );
    assert!(h.learned().is_empty());

    h.coord.stop(StopCause::Requested(Owner::Manual));
    let idle = h.status.wait_for(|s| s.phase == Phase::Idle);
    tokio::time::timeout(Duration::from_secs(5), idle)
        .await
        .unwrap()
        .unwrap();
    let probes = h.host.probes();
    h.coord
        .start(SessionKind::LocalProxyHard, None, AdaptiveMode::Baseline);
    let status = h.done().await;
    assert!(status.external);
    assert_eq!(
        status.message.key,
        "automation.adaptive.status.externalManaged"
    );
    assert_eq!(h.host.probes(), probes);
}

/// A network change during the window restarts it and fences learning for this runtime.
#[tokio::test]
async fn network_change_restarts_the_window_without_learning() {
    let mut h = Harness::with_timing(Timing {
        settle: Duration::from_millis(150),
        gap: Duration::from_millis(1),
    })
    .ready()
    .await;
    h.host.script(&[false, false, false]);
    h.connect(&reality("r1")).await;
    while h.coord.restarts().is_empty() || h.status.borrow().phase != Phase::Verifying {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    h.host.script(&[true; 3]);
    let _ = h.coord.events.send(LifecycleEvent::NetworkChanged);
    let status = h.done().await;
    assert_eq!(status.phase, Phase::Connected);
    assert_eq!(status.mode, AdaptiveMode::MtuCompatibility);
    assert!(h.learned().is_empty());
}

/// Network identity changed between begin and the re-read after the window: nothing stored,
/// still connected.
#[tokio::test]
async fn identity_change_during_the_window_is_not_learned() {
    let mut h = Harness::new().ready().await;
    *h.host.switch_identity.lock() = Some((2, Some(net("10.0.0.1"))));
    h.host.script(&[false, false, false, true, true, true]);
    h.connect(&reality("r1")).await;
    assert_eq!(h.done().await.phase, Phase::Connected);
    assert!(h.learned().is_empty());
}

/// A newer begin while the learning re-read is pending: the stale run stores nothing and does
/// not overwrite the new start's «connecting».
#[tokio::test]
async fn stale_publication_after_a_newer_begin() {
    let h = Harness::new().ready().await;
    let gate = Arc::new(Notify::new());
    *h.host.gate.lock() = Some((2, gate.clone()));
    h.host.script(&[false, false, false, true, true, true]);
    h.connect(&reality("r1")).await;
    while h.host.identity_calls.load(Ordering::SeqCst) < 2 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    h.adaptive
        .begin(SessionKind::Direct, Some(tls_ws("t1")))
        .await;
    gate.notify_one();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(h.learned().is_empty());
    assert_eq!(h.status.borrow().phase, Phase::Connecting);
}

/// A start by someone else while the learning re-read is pending: nothing is stored.
#[tokio::test]
async fn invalidation_during_a_pending_learn() {
    let mut h = Harness::new().ready().await;
    h.add(&tls_ws("manual"));
    let gate = Arc::new(Notify::new());
    *h.host.gate.lock() = Some((2, gate.clone()));
    h.host
        .script(&[false, false, false, true, true, true, true, true, true]);
    h.connect(&reality("r1")).await;
    while h.host.identity_calls.load(Ordering::SeqCst) < 2 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    h.coord
        .start(SessionKind::Direct, Some("manual"), AdaptiveMode::Baseline);
    gate.notify_one();
    assert_eq!(h.done().await.phase, Phase::Connected);
    assert!(h.learned().is_empty());
}

/// A failed compatibility restart passes the coordinator's own reason through untouched.
#[tokio::test]
async fn native_restart_failure_is_passed_through() {
    let mut h = Harness::new().ready().await;
    let native = vpnte_base::AppError::validation(vpnte_base::Msg::new("tunnel.example.reason"));
    h.coord
        .restart_results
        .lock()
        .push_back(Err(OpError::Failed(native)));
    h.connect(&tls_ws("t1")).await;
    let status = h.done().await;
    assert_eq!(status.phase, Phase::Failed);
    assert_eq!(status.reason.unwrap().key, "tunnel.example.reason");
    assert_eq!(h.coord.restarts().len(), 1);
}

/// `start_failed`: the start error is shown; a cancelled start returns to idle.
#[tokio::test]
async fn failed_and_cancelled_starts() {
    let h = Harness::new().ready().await;
    h.adaptive
        .begin(SessionKind::Direct, Some(tls_ws("t1")))
        .await;
    h.adaptive
        .start_failed(Some(vpnte_base::Msg::new("tunnel.example.startError")));
    let status = h.status.borrow().clone();
    assert_eq!(
        (status.phase, status.reason.unwrap().key.as_ref()),
        (Phase::Failed, "tunnel.example.startError")
    );
    h.adaptive
        .begin(SessionKind::Direct, Some(tls_ws("t1")))
        .await;
    h.adaptive.start_failed(None);
    assert_eq!(h.status.borrow().phase, Phase::Idle);
    assert!(!h.adaptive.retry(), "no tunnel runs");
}
