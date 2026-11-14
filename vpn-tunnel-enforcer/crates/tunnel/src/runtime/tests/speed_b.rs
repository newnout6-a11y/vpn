//! speed3 Lane B budget tests: recovery and the switch in virtual time (S3-00 harness,
//! `start_paused`). `± 5 ms` covers the actor's own hops, which take no virtual time.
use std::sync::atomic::Ordering;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::EnginePref;
use vpnte_engine::xray_process::XrayEvent;

use super::*;
use crate::api::{
    NameHint, Origin, OwnerCheck, Runtime, ServerFacts, SwitchReceipt, TunStatusKind, VpnProfile,
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
