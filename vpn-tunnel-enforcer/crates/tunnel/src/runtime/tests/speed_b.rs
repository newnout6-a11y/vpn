//! speed3 Lane B budget tests: recovery and the switch in virtual time (S3-00 harness,
//! `start_paused`). `± 5 ms` covers the actor's own hops, which take no virtual time.
use std::sync::atomic::Ordering;

use serde_json::json;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::EnginePref;
use vpnte_engine::xray_process::XrayEvent;

use super::*;
use crate::api::{
    Mode, NameHint, Origin, OwnerCheck, Runtime, ServerFacts, SwitchReceipt, TunStatusKind,
    VpnProfile,
};
use crate::runtime::TunnelHandle;

fn near(got: u64, want: u64) -> bool {
    got.abs_diff(want) <= 5
}

/// Positions of every log entry that starts with `prefix`.
fn all(w: &World, prefix: &str) -> Vec<usize> {
    let log = w.log();
    (0..log.len())
        .filter(|&i| log[i].starts_with(prefix))
        .collect()
}

/// A runtime with the shipped crash backoff (the harness shortens it to 20/40/60 ms).
fn shipped(w: &Arc<World>) -> TunnelHandle {
    let mut d = deps(w);
    d.timings.backoff = Timings::default().backoff;
    TunnelHandle::spawn(d)
}

/// Waits (up to a virtual minute: the backoff reaches 10 s, past `until`'s cap) for the start
/// of native generation `n` to finish well.
async fn started(events: &mut broadcast::Receiver<TunnelEvent>, n: u64) {
    let done = TunnelEvent::StartFinished {
        generation: n,
        ok: true,
    };
    let wait = async {
        loop {
            match events.recv().await {
                Ok(e) if e == done => return,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => panic!("the runtime ended"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(60), wait)
        .await
        .expect("the start finished");
}

/// speed3 S3-01 (lab live-9 / live-10: «restarting:1/3» -> «capture prepared» took 2016 ms of a
/// 2 s backoff): the first restart after a crash spawns the core within 5 ms of the exit.
#[tokio::test(start_paused = true)]
async fn the_first_restart_after_a_crash_comes_at_once() {
    let w = World::new();
    let h = shipped(&w);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    let crashed = w.now_ms();
    w.core(0).crash();
    started(&mut events, 2).await;
    let spawn = w.ms("spawn:4101");
    assert!(near(spawn, crashed), "spawn {spawn} vs crash {crashed}");
}

/// speed3 S3-01, AT-02-003: four crashes in one window restart at 0, 5 and 15 s after the
/// first, then the spent budget keeps the kill switch's pause (never a silent release).
#[tokio::test(start_paused = true)]
async fn four_crashes_restart_at_0_5_and_15_s_then_hold() {
    let w = World::new();
    let h = shipped(&w);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    let first = w.now_ms();
    for n in 0..3u64 {
        w.core(usize::try_from(n).unwrap()).crash();
        started(&mut events, n + 2).await;
    }
    let at = |pid: u32| w.ms(&format!("spawn:{pid}")) - first;
    let spawns = [at(4101), at(4102), at(4103)];
    let want = [0, 5_000, 15_000];
    assert!(
        spawns.iter().zip(want).all(|(g, w)| near(*g, w)),
        "{spawns:?}"
    );
    w.core(3).crash();
    let held = TunnelEvent::Status(TunStatusKind::KillSwitchActive);
    until(&mut events, |e| *e == held).await;
    assert_eq!(w.count("release"), 0, "the pause holds");
    assert_eq!(w.cores.lock().len(), 4, "no fourth restart");
}

/// speed3 S3-01 (Sec rule 1): a TUN restart gives the dead adapter its moment (here it leaves
/// after 200 ms of the ≤ 300 ms wait) and then goes on; under Standard the protection reads
/// `lost`, the new `begin`, the new `ready` (tun_up) and never `release` in between.
#[tokio::test(start_paused = true)]
async fn a_tun_restart_waits_for_the_dead_adapter_with_the_block_armed() {
    let w = World::new();
    *w.guard.lock() = KillSwitchLevel::Standard;
    let h = shipped(&w);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    w.slow_gone.store(true, Ordering::SeqCst);
    let crashed = w.now_ms();
    w.core(0).crash();
    started(&mut events, 2).await;
    let spawn = w.ms("spawn:4101");
    assert!(
        near(spawn, crashed + 200),
        "spawn {spawn} vs crash {crashed}"
    );
    let (lost, gone) = (w.at("lost"), w.at("wait-gone"));
    let (begins, readies) = (all(&w, "begin:"), all(&w, "ready"));
    assert!(
        lost < gone && gone < begins[1] && begins[1] < readies[1],
        "{:?}",
        w.log()
    );
    assert_eq!(w.count("release"), 0, "{:?}", w.log());
}

/// speed3 S3-01: a lingering adapter never holds the restart back (best effort, the next run
/// takes another alias) and never releases the block.
#[tokio::test(start_paused = true)]
async fn a_lingering_adapter_does_not_hold_the_restart() {
    let w = World::new();
    let h = shipped(&w);
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .unwrap();
    w.gone.store(false, Ordering::SeqCst);
    let crashed = w.now_ms();
    w.core(0).crash();
    started(&mut events, 2).await;
    assert!(w.ms("spawn:4101") <= crashed + 300);
    assert_eq!(w.count("release"), 0);
}

/// speed3 S3-01: an xray-only crash restarts the active slot at once (no proof: sing-box and
/// the TUN stay), so traffic is back as soon as Xray accepts.
#[tokio::test(start_paused = true)]
async fn an_xray_only_crash_restarts_the_slot_at_once() {
    let w = World::new();
    let h = shipped(&w);
    let mut events = h.subscribe();
    let req = vpn_req(XRAY_KEY, EnginePref::Xray);
    h.start(req, CancellationToken::new()).await.unwrap();
    drain(&mut events);
    let tx = w.xray_events.lock().clone().expect("slot events");
    w.running.lock()[0] = false;
    let exited = w.now_ms();
    tx.send(XrayEvent::Exited {
        slot: Slot::A,
        pid: 1,
        code: Some(2),
        expected: false,
        graceful: false,
        tail: String::new(),
    })
    .await
    .unwrap();
    until(&mut events, |e| {
        *e == TunnelEvent::Status(TunStatusKind::Running)
    })
    .await;
    let restart = w.ms("xray-restart:a");
    assert!(near(restart, exited), "restart {restart} vs exit {exited}");
}

/// The app's evidence for every server (`Failover::fresh`), as `svc_auto` gives it in-process.
struct Evidence(bool);

#[async_trait]
impl crate::runtime::Failover for Evidence {
    async fn next_live_sibling(&self, _cancel: &CancellationToken) -> Option<VpnProfile> {
        None
    }
    fn commit(&self, _profile_id: &str) {}
    fn fresh(&self, _profile_id: &str) -> bool {
        self.0
    }
}

/// A running Xray-slot session on `XRAY_KEY` whose switch steps then take the plan's virtual
/// times: slot 100 ms, the probe through the slot 300 ms, the echo through the tunnel 300 ms.
async fn switching(fresh: bool) -> (Arc<World>, TunnelHandle) {
    let w = World::new();
    let mut d = deps(&w);
    d.failover = Some(Arc::new(Evidence(fresh)));
    let h = TunnelHandle::spawn(d);
    let req = vpn_req(XRAY_KEY, EnginePref::Xray);
    h.start(req, CancellationToken::new()).await.unwrap();
    w.slot_ready_ms.store(100, Ordering::SeqCst);
    w.proof_ms.store(300, Ordering::SeqCst);
    w.egress_ms.store(300, Ordering::SeqCst);
    (w, h)
}

/// Switches to `XRAY_KEY_2` with `origin`; the receipt and the virtual ms it took.
async fn switch(w: &World, h: &TunnelHandle, origin: Origin) -> (SwitchReceipt, u64) {
    let next = StartRequest {
        origin,
        ..vpn_req(XRAY_KEY_2, EnginePref::Xray)
    };
    let owner: OwnerCheck = Arc::new(|| true);
    let began = w.now_ms();
    let receipt = h
        .switch_upstream(next, CancellationToken::new(), owner)
        .await;
    (receipt.expect("switched in place"), w.now_ms() - began)
}

/// speed3 S3-07 (owner default 1; lab live-10: click -> new exit 1.6-2.0 s): a user's switch to
/// a server with fresh evidence selects as soon as slot B is ready and proves once by the echo
/// through the tunnel: success at 400 ms where probe-first takes 700, one handshake fewer.
#[tokio::test(start_paused = true)]
async fn a_fresh_user_switch_selects_at_slot_ready() {
    let (w, h) = switching(true).await;
    let began = w.now_ms();
    let (receipt, took) = switch(&w, &h, Origin::User).await;
    assert!(receipt.verified(), "{receipt:?}");
    assert!(near(w.ms("select:b") - began, 100), "{:?}", w.log());
    assert!(near(took, 400), "{took}");
    assert_eq!(
        all(&w, "egress-via").len(),
        1,
        "the start's proof only: {:?}",
        w.log()
    );
}

/// speed3 S3-07: without fresh evidence, and for every switch but the user's (rotation here),
/// the candidate keeps its probe before the select (700 ms in this world).
#[tokio::test(start_paused = true)]
async fn other_switches_keep_their_probe_first() {
    for (fresh, origin) in [(false, Origin::User), (true, Origin::Rotation)] {
        let (w, h) = switching(fresh).await;
        let began = w.now_ms();
        let (receipt, took) = switch(&w, &h, origin).await;
        assert!(receipt.verified(), "{receipt:?}");
        assert!(
            near(w.ms("select:b") - began, 400),
            "{origin:?}: {:?}",
            w.log()
        );
        assert!(near(took, 700), "{origin:?}: {took}");
    }
}

/// speed3 S3-07: the candidate's own downloads prove it first (here 150 ms after the select),
/// before its echo answers.
#[tokio::test(start_paused = true)]
async fn a_fresh_switch_is_proven_by_its_own_traffic_first() {
    let (w, h) = switching(true).await;
    let began = w.now_ms();
    let traffic = w.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        traffic.slot_traffic.lock()[1] = 4096;
    });
    let (receipt, took) = switch(&w, &h, Origin::User).await;
    assert!(receipt.verified(), "{receipt:?}");
    assert!(near(w.ms("select:b") - began, 100));
    assert!(near(took, 250), "{took}");
}

/// speed3 S3-07 (Sec): a fresh candidate that carries nothing within the 2 s budget fails the
/// switch: the previous slot is selected again, the candidate stopped and slot A proven again.
#[tokio::test(start_paused = true)]
async fn a_silent_fresh_candidate_restores_the_previous_slot() {
    let (w, h) = switching(true).await;
    w.egress_silent.store(true, Ordering::SeqCst);
    let healed = w.clone();
    tokio::spawn(async move {
        // B's 2 s budget runs out at 2.1 s; slot A answers again for its re-proof.
        tokio::time::sleep(Duration::from_millis(2_050)).await;
        healed.egress_silent.store(false, Ordering::SeqCst);
    });
    let (receipt, took) = switch(&w, &h, Origin::User).await;
    assert!(
        !receipt.committed && receipt.previous_preserved,
        "{receipt:?}"
    );
    assert!(took >= 2_100, "{took}");
    let (b, stop_b) = (w.at("select:b"), w.at("xray-stop:b"));
    let back = all(&w, "select:a").into_iter().find(|&a| a > b);
    assert!(back.is_some_and(|a| a < stop_b), "{:?}", w.log());
}

/// speed3 S3-07: with the name's handshake budget spent the switch still selects first, and
/// the candidate's traffic proves it (no echo, no probe).
#[tokio::test(start_paused = true)]
async fn a_spent_budget_still_proves_by_traffic() {
    let (w, h) = switching(true).await;
    w.budget_spent.store(true, Ordering::SeqCst);
    let traffic = w.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        traffic.slot_traffic.lock()[1] = 4096;
    });
    let (receipt, _) = switch(&w, &h, Origin::User).await;
    assert!(receipt.verified(), "{receipt:?}");
    let after = w.at("select:b");
    assert!(
        w.log()[after..].iter().all(|l| !l.starts_with("egress")),
        "{:?}",
        w.log()
    );
}

/// A key whose server is a name (the plain test keys dial address literals).
const HOSTED_KEY: &str = "vless://00000000-0000-4000-8000-000000000002@b.example.com:443?security=tls&sni=example.com&type=tcp#Fake%20H";

/// The helper service's inputs as `SharedInputs` gives them: the harness's, plus the facts the
/// request in flight carried about server `Fake H` (handed out once).
struct Sent(FakeInputs, parking_lot::Mutex<Option<ServerFacts>>);

#[async_trait]
impl InputsSource for Sent {
    async fn snapshot(&self) -> AppResult<UserInputs> {
        self.0.snapshot().await
    }
    fn server_facts(&self, profile_id: &str) -> ServerFacts {
        let mine = profile_id == "Fake H";
        mine.then(|| self.1.lock().take())
            .flatten()
            .unwrap_or_default()
    }
}

/// Switches to `HOSTED_KEY` with `facts` sent along; the resolve paths the switch used.
async fn hinted_switch(addrs: Vec<IpAddr>) -> (Arc<World>, Vec<ResolvePath>) {
    let w = World::new();
    let mut d = deps(&w);
    let hints = vec![NameHint {
        name: "b.example.com".into(),
        addrs,
    }];
    let facts = ServerFacts {
        fresh: false,
        hints,
    };
    d.inputs = Arc::new(Sent(
        FakeInputs(w.clone()),
        parking_lot::Mutex::new(Some(facts)),
    ));
    let h = TunnelHandle::spawn(d);
    h.start(
        vpn_req(XRAY_KEY, EnginePref::Xray),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let before = w.resolve_paths.lock().len();
    let next = vpn_req(HOSTED_KEY, EnginePref::Xray);
    let owner: OwnerCheck = Arc::new(|| true);
    let receipt = h
        .switch_upstream(next, CancellationToken::new(), owner)
        .await;
    assert!(receipt.expect("in place").verified());
    let paths = w.resolve_paths.lock()[before..].to_vec();
    (w, paths)
}

/// speed3 S3-10 (b) (lab live-10: R -> «xray-b spawned» 343-587 ms, a cold direct DoH of the
/// candidate's names inside it): a usable hint for the candidate's name skips the bootstrap
/// lookup and is what slot B dials; a hint no lookup could have answered (loopback) is refused
/// and the name is asked as before.
#[tokio::test(start_paused = true)]
async fn a_hinted_candidate_skips_the_bootstrap_lookup() {
    let (w, paths) = hinted_switch(vec!["203.0.113.77".parse().unwrap()]).await;
    assert!(paths.is_empty(), "{paths:?}");
    let dialled = w.xray_configs.lock().last().map(ToString::to_string);
    assert!(dialled.is_some_and(|c| c.contains("203.0.113.77")));
    let (_, paths) = hinted_switch(vec!["127.0.0.1".parse().unwrap()]).await;
    assert!(
        matches!(paths[..], [ResolvePath::ViaSingBox(_)]),
        "{paths:?}"
    );
}

/// A provider's balanced graph as a switch's candidate: two REALITY members behind a
/// `leastPing` balancer whose observatory judges them (Xray's 5 s ping timeout: settle 5.5 s).
fn balanced_req() -> StartRequest {
    let member = |tag: &str, ip: &str| {
        json!({ "tag": tag, "protocol": "vless",
            "settings": { "vnext": [{ "address": ip, "port": 443,
                "users": [{ "id": "00000000-0000-4000-8000-000000000003", "flow": "xtls-rprx-vision" }] }] },
            "streamSettings": { "network": "tcp", "security": "reality",
                "realitySettings": { "serverName": "front.example.com", "publicKey": "PBK-FAKE",
                                     "shortId": "1234", "fingerprint": "firefox" } } })
    };
    let doc = json!({ "remarks": "Fake balanced",
        "outbounds": [member("proxy-1", "203.0.113.21"), member("proxy-2", "203.0.113.22")],
        "routing": { "balancers": [{ "tag": "l1", "selector": ["proxy-"], "strategy": { "type": "leastPing" } }],
                     "rules": [{ "type": "field", "network": "tcp,udp", "balancerTag": "l1" }] },
        "observatory": { "subjectSelector": ["proxy-"], "probeUrl": "https://www.google.com/generate_204" } });
    let found = vpnte_profiles::json::parse_json(&doc);
    let profile = found.profiles.into_iter().next().expect("a provider graph");
    assert!(profile.native_xray.is_some(), "the balancer is kept");
    let profile = VpnProfile {
        id: profile.name.clone(),
        profile: Arc::new(profile),
        device: None,
        engine: EnginePref::Auto,
    };
    StartRequest {
        mode: Mode::DirectVpn { profile },
        engine: EnginePref::Xray,
        ..local_req()
    }
}

/// The harness's engines behind a balancer whose first pick is silent (lab L11-3): an echo
/// through the core answers only with a request at the balancer's settle point (`egress_ms`
/// after it); any echo without one hears nothing for its whole budget. Records every echo
/// through the core as `(port, with credentials, settle)`.
struct Balancer {
    fake: FakeEngines,
    echoes: Mutex<Vec<(u16, bool, Option<Duration>)>>,
}

impl Balancer {
    async fn silent(limit: Duration, cancel: &CancellationToken) -> AppResult<IpAddr> {
        tokio::select! {
            () = cancel.cancelled() => Err(AppError::cancelled()),
            () = tokio::time::sleep(limit.saturating_mul(2)) => Err(echo_failed(EchoFailure::NoReply)),
        }
    }
}

#[async_trait]
impl Engines for Balancer {
    fn spawn_core(&self, config: &[u8]) -> std::io::Result<Arc<dyn CoreProc>> {
        self.fake.spawn_core(config)
    }
    fn slots(&self, events: mpsc::Sender<XrayEvent>) -> Box<dyn Slots> {
        self.fake.slots(events)
    }
    fn singbox_exe(&self) -> PathBuf {
        self.fake.singbox_exe()
    }
    fn xray_exe(&self) -> PathBuf {
        self.fake.xray_exe()
    }
    fn log_files(&self, slots: bool) -> Vec<PathBuf> {
        self.fake.log_files(slots)
    }
    async fn select(&self, clash: &ClashEndpoint, slot: Slot) -> AppResult<()> {
        self.fake.select(clash, slot).await
    }
    async fn upstream_downloads(&self, clash: &ClashEndpoint) -> AppResult<Vec<(String, u64)>> {
        self.fake.upstream_downloads(clash).await
    }
    async fn slot_downloads(
        &self,
        clash: &ClashEndpoint,
        slot: Slot,
    ) -> AppResult<Vec<(String, u64)>> {
        self.fake.slot_downloads(clash, slot).await
    }
    fn handshake_ready(&self, server: &Profile) -> bool {
        self.fake.handshake_ready(server)
    }
    async fn resolve(
        &self,
        hosts: &[String],
        path: ResolvePath,
        cancel: &CancellationToken,
    ) -> Result<Resolved, ResolveFault> {
        self.fake.resolve(hosts, path, cancel).await
    }
    async fn egress_via(
        &self,
        server: &Profile,
        port: u16,
        creds: &Creds,
        settle: Option<Duration>,
        cancel: &CancellationToken,
    ) -> AppResult<IpAddr> {
        self.fake
            .egress_via(server, port, creds, settle, cancel)
            .await
    }
    /// The capture's own route reaches the balancer's silent first pick as well.
    async fn egress(
        &self,
        via: Option<u16>,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> AppResult<IpAddr> {
        self.fake.0.note(match via {
            Some(port) => format!("egress:{port}"),
            None => "egress".to_owned(),
        });
        Self::silent(timeout, cancel).await
    }
    async fn egress_core(
        &self,
        port: u16,
        creds: Option<&Creds>,
        limit: Duration,
        settle: Option<Duration>,
        cancel: &CancellationToken,
    ) -> AppResult<IpAddr> {
        self.echoes.lock().push((port, creds.is_some(), settle));
        let Some(at) = settle else {
            return Self::silent(limit, cancel).await;
        };
        let w = &self.fake.0;
        tokio::select! {
            () = cancel.cancelled() => return Err(AppError::cancelled()),
            () = tokio::time::sleep(at) => {}
        }
        w.take(&w.egress_ms).await;
        Ok(*w.tunnel_ip.lock())
    }
    async fn local_proxy(&self, addr: &HostPort, limit: Duration) -> AppResult<Option<PathBuf>> {
        self.fake.local_proxy(addr, limit).await
    }
    async fn physical_dns(&self) -> Vec<Ipv4Addr> {
        self.fake.physical_dns().await
    }
    async fn warm_dns(&self, clash: &ClashEndpoint) {
        self.fake.warm_dns(clash).await;
    }
    #[cfg(feature = "lab")]
    async fn start_mihomo(
        &self,
        config: &vpnte_engine::mihomo_config::Compiled,
        socks: SlotEndpoint,
        controller: ClashEndpoint,
        cancel: &CancellationToken,
    ) -> AppResult<Arc<dyn CoreProc>> {
        self.fake
            .start_mihomo(config, socks, controller, cancel)
            .await
    }
}

/// A Tunnel session on `XRAY_KEY` over [`Balancer`], its switch steps timed as in
/// [`switching`]: slot 100 ms, the probe through the slot 300 ms, an answered echo 300 ms.
async fn balanced_switching(fresh: bool) -> (Arc<World>, Arc<Balancer>, TunnelHandle) {
    let w = World::new();
    let engines = Arc::new(Balancer {
        fake: FakeEngines(w.clone()),
        echoes: Mutex::default(),
    });
    let mut d = deps(&w);
    d.engines = engines.clone();
    d.failover = Some(Arc::new(Evidence(fresh)));
    let h = TunnelHandle::spawn(d);
    let req = vpn_req(XRAY_KEY, EnginePref::Xray);
    h.start(req, CancellationToken::new()).await.unwrap();
    w.slot_ready_ms.store(100, Ordering::SeqCst);
    w.proof_ms.store(300, Ordering::SeqCst);
    w.egress_ms.store(300, Ordering::SeqCst);
    (w, engines, h)
}

/// The user's switch to the balanced candidate; the receipt and the virtual ms it took.
async fn switch_to_balanced(w: &World, h: &TunnelHandle) -> (SwitchReceipt, u64) {
    let owner: OwnerCheck = Arc::new(|| true);
    let began = w.now_ms();
    let receipt = h
        .switch_upstream(balanced_req(), CancellationToken::new(), owner)
        .await;
    (receipt.expect("switched in place"), w.now_ms() - began)
}

/// The port of the core's probe inbound (`live-check-in`) in the session's sing-box config.
fn probe_in(w: &World) -> u16 {
    let config = w.configs.lock()[0].clone();
    let inbounds = config["inbounds"].as_array().cloned().unwrap_or_default();
    let probe = inbounds.iter().find(|i| i["tag"] == "live-check-in");
    let port = probe.and_then(|p| p["listen_port"].as_u64());
    u16::try_from(port.expect("a probe inbound")).expect("a port")
}

/// Lab L11-3 (live-11: a Tunnel switch rolled back at its Confirm after 4 s while the new server
/// already carried the lab's traffic). Probe first: the candidate's balancer has not judged its
/// members, its first pick is silent. The confirm goes through the core's probe inbound (with its
/// credentials, never through the capture's own route), asks again at the settle point (5.5 s
/// after the slot accepted) and commits on that answer.
#[tokio::test(start_paused = true)]
async fn a_balanced_candidate_settles_before_its_confirm_probe_first() {
    let (w, engines, h) = balanced_switching(false).await;
    let began = w.now_ms();
    let (receipt, took) = switch_to_balanced(&w, &h).await;
    assert!(receipt.committed && receipt.verified(), "{receipt:?}");
    assert!(near(w.ms("select:b") - began, 400), "{:?}", w.log());
    assert!(near(took, 100 + 5_500 + 300), "{took}");
    let echoes = engines.echoes.lock().clone();
    let settle = Some(Duration::from_millis(5_200));
    assert_eq!(echoes, [(probe_in(&w), true, settle)]);
    assert_eq!(w.count("egress"), 0, "{:?}", w.log());
}

/// Lab L11-3, select first (S3-07, a server with fresh evidence): the one proof after the
/// select outlasts the 2 s budget for an unjudged balancer and commits on the answer after its
/// settle point instead of rolling back on the silent first pick.
#[tokio::test(start_paused = true)]
async fn a_balanced_candidate_settles_before_its_confirm_select_first() {
    let (w, engines, h) = balanced_switching(true).await;
    let began = w.now_ms();
    let (receipt, took) = switch_to_balanced(&w, &h).await;
    assert!(receipt.committed && receipt.verified(), "{receipt:?}");
    assert!(near(w.ms("select:b") - began, 100), "{:?}", w.log());
    assert!(near(took, 100 + 5_500 + 300), "{took}");
    let echoes = engines.echoes.lock().clone();
    let settle = Some(Duration::from_millis(5_500));
    assert_eq!(echoes, [(probe_in(&w), true, settle)]);
    assert_eq!(all(&w, "egress-via").len(), 1, "the start's proof only");
}

/// Lab L11-3: the candidate's own downloads prove it as soon as they show (1 s after the select
/// here), long before its balancer settles; the switch never waits for the echo.
#[tokio::test(start_paused = true)]
async fn a_candidates_own_traffic_proves_it_before_its_echo() {
    for fresh in [false, true] {
        let (w, _, h) = balanced_switching(fresh).await;
        let select = if fresh { 100 } else { 400 };
        let traffic = w.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(select + 1_000)).await;
            traffic.slot_traffic.lock()[1] = 4096;
        });
        let (receipt, took) = switch_to_balanced(&w, &h).await;
        assert!(receipt.committed && receipt.verified(), "{receipt:?}");
        // The downloads are read every 50 ms.
        assert!(
            (select + 1_000..=select + 1_055).contains(&took),
            "{fresh}: {took}"
        );
    }
}

/// A balanced candidate's longer wait reads its downloads every 250 ms after the first 2 s:
/// traffic 3 s after the select still proves it, within one such read.
#[tokio::test(start_paused = true)]
async fn late_traffic_still_proves_a_balanced_candidate() {
    let (w, _, h) = balanced_switching(false).await;
    let traffic = w.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400 + 3_000)).await;
        traffic.slot_traffic.lock()[1] = 4096;
    });
    let (receipt, took) = switch_to_balanced(&w, &h).await;
    assert!(receipt.committed && receipt.verified(), "{receipt:?}");
    assert!((3_400..=3_655).contains(&took), "{took}");
}

/// A plain candidate whose echo through the core stays silent still rolls back after the
/// confirm's 4 s (probe first): the settle wait is a balancer's only; slot A is selected again
/// before the candidate stops.
#[tokio::test(start_paused = true)]
async fn a_silent_plain_candidate_still_rolls_back() {
    let (w, h) = switching(false).await;
    w.egress_silent.store(true, Ordering::SeqCst);
    let healed = w.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(4_350)).await;
        healed.egress_silent.store(false, Ordering::SeqCst);
    });
    let (receipt, took) = switch(&w, &h, Origin::User).await;
    assert!(
        !receipt.committed && receipt.previous_preserved,
        "{receipt:?}"
    );
    assert!(took >= 4_400, "{took}");
    let (b, stop_b) = (w.at("select:b"), w.at("xray-stop:b"));
    let back = all(&w, "select:a").into_iter().find(|&a| a > b);
    assert!(back.is_some_and(|a| a < stop_b), "{:?}", w.log());
    // Both proofs after a select (the candidate's, slot A's again) went through the core's
    // probe inbound, never through the TUN's own route.
    let through_core = format!("egress:{}", probe_in(&w));
    assert_eq!(w.count(&through_core), 2, "{:?}", w.log());
    assert_eq!(w.count("egress"), 0, "{:?}", w.log());
}

/// A Tunnel session on `XRAY_KEY` switched to a key whose server is the name `host` (no hints);
/// the world, the resolve paths the switch used and its receipt. `silent_probe`: the candidate's
/// probe gets nothing back.
async fn named_switch(
    host: &str,
    silent_probe: bool,
) -> (Arc<World>, Vec<ResolvePath>, SwitchReceipt) {
    let w = World::new();
    let h = TunnelHandle::spawn(deps(&w));
    let req = vpn_req(XRAY_KEY, EnginePref::Xray);
    h.start(req, CancellationToken::new()).await.unwrap();
    if silent_probe {
        w.proofs_silent.store(1, Ordering::SeqCst);
    }
    let before = w.resolve_paths.lock().len();
    let key = HOSTED_KEY.replace("b.example.com", host);
    let owner: OwnerCheck = Arc::new(|| true);
    let receipt = h
        .switch_upstream(
            vpn_req(&key, EnginePref::Xray),
            CancellationToken::new(),
            owner,
        )
        .await
        .expect("in place");
    let paths = w.resolve_paths.lock()[before..].to_vec();
    (w, paths, receipt)
}

/// Lab L11-4 (live-11: «candidate resolved ms=336-370» inside every switch): a candidate whose
/// name this process resolved ahead (the app's likely picks, remembered for 10 min) is dialled
/// at that address with no lookup in the switch; a remembered answer no lookup could give
/// (loopback) is refused and the name asked as before.
#[tokio::test(start_paused = true)]
async fn a_name_resolved_ahead_skips_the_switchs_lookup() {
    // (name, the remembered answer, lookups in the switch, the address slot B dials: the
    // harness's bootstrap answers 203.0.113.10)
    let cases = [
        ("ahead-b.l11-4.example", "203.0.113.78", 0, "203.0.113.78"),
        ("loop-b.l11-4.example", "127.0.0.1", 1, "203.0.113.10"),
    ];
    for (host, remembered, asked, dialled) in cases {
        vpnte_core::resolve::remember(host, vec![remembered.parse().expect("ip")]);
        let (w, paths, receipt) = named_switch(host, false).await;
        assert!(receipt.verified(), "{receipt:?}");
        assert_eq!(paths.len(), asked, "{host}: {paths:?}");
        let config = w.xray_configs.lock().last().map(ToString::to_string);
        assert!(config.is_some_and(|c| c.contains(dialled)), "{host}");
        vpnte_core::resolve::drop_names(&[host.to_owned()]);
    }
}

/// S3-09 (e) for L11-4: a switch that dialled a remembered answer and failed forgets it, so the
/// next try asks the resolvers.
#[tokio::test(start_paused = true)]
async fn a_failed_switch_forgets_its_recalled_name() {
    let host = "stale-b.l11-4.example";
    vpnte_core::resolve::remember(host, vec!["203.0.113.79".parse().expect("ip")]);
    let (_, paths, receipt) = named_switch(host, true).await;
    assert!(
        !receipt.committed && receipt.previous_preserved,
        "{receipt:?}"
    );
    assert!(paths.is_empty(), "{paths:?}");
    assert!(!vpnte_core::resolve::remembers(host));
}
