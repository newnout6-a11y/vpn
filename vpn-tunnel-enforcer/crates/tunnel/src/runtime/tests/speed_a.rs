//! speed3 Lane A budget tests: the start path in virtual time (S3-00 harness, `start_paused`).
//! Each test sets the steps' delays on the `World` and reads where `running` and each effect
//! landed; `± 5 ms` covers the actor's own hops, which take no virtual time.
use std::sync::atomic::Ordering;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::EnginePref;

use super::*;
use crate::api::Runtime;
use crate::runtime::TunnelHandle;

/// Step delays of a start, in virtual ms.
struct Steps {
    resolve: u32,
    slot: u32,
    proof: u32,
    core: u32,
    capture: u32,
}

impl Steps {
    fn on(&self, w: &World) {
        w.resolve_ms.store(self.resolve, Ordering::SeqCst);
        w.slot_ready_ms.store(self.slot, Ordering::SeqCst);
        w.proof_ms.store(self.proof, Ordering::SeqCst);
        w.core_ready_ms.store(self.core, Ordering::SeqCst);
        w.capture_ready_ms.store(self.capture, Ordering::SeqCst);
    }
}

/// An Xray key that dials a name (the fake lookup answers 203.0.113.10 for every name).
const NAMED_KEY: &str = "vless://00000000-0000-4000-8000-000000000005@vpn.example:443?security=tls&sni=example.com&type=tcp#Fake%20N";

/// An Xray-slot start of [`NAMED_KEY`] in `capture` mode.
fn slot_req(capture: CaptureKind) -> StartRequest {
    StartRequest {
        capture,
        ..vpn_req(NAMED_KEY, EnginePref::Xray)
    }
}

/// Starts `req` and returns the virtual ms at which the start returned (`running`).
async fn running_at(w: &Arc<World>, h: &TunnelHandle, req: StartRequest) -> u64 {
    h.start(req, CancellationToken::new()).await.expect("start");
    assert!(h.status().borrow().running);
    w.now_ms()
}

fn near(got: u64, want: u64) -> bool {
    got.abs_diff(want) <= 5
}

/// S3-00 self-test: a TUN first start under the Standard kill switch keeps the serial order
/// (resolve, slot A, its proof, then the core), so `running` lands at the sum of the steps.
#[tokio::test(start_paused = true)]
async fn a_serial_start_reaches_running_at_the_sum_of_its_steps() {
    let w = World::new();
    let steps = Steps {
        resolve: 100,
        slot: 350,
        proof: 300,
        core: 150,
        capture: 0,
    };
    steps.on(&w);
    let h = TunnelHandle::spawn(budget_deps(&w));
    let at = running_at(&w, &h, slot_req(CaptureKind::Tun)).await;
    assert!(near(at, 900), "running at {at}");
    assert!(near(w.ms("proof-done"), 750), "{}", w.ms("proof-done"));
    assert!(w.ms("proof-done") <= w.ms("spawn:4100"));
}

/// speed3 S3-03 (lab live-9/live-10: sing-box 136-155 ms after the proof): a Proxy start runs
/// the core beside slot A's exit proof; `running` = resolve + slot + max(proof, core).
#[tokio::test(start_paused = true)]
async fn a_proxy_start_runs_the_core_beside_the_proof() {
    let w = World::new();
    let steps = Steps {
        resolve: 100,
        slot: 100,
        proof: 300,
        core: 150,
        capture: 0,
    };
    steps.on(&w);
    let h = TunnelHandle::spawn(budget_deps(&w));
    let at = running_at(&w, &h, slot_req(CaptureKind::Proxy)).await;
    assert!(near(at, 500), "running at {at} (serial: 650)");
    assert!(w.ms("spawn:4100") < w.ms("proof-done"));
    // The start returns only after the proof: the system proxy (written after the start
    // returns) never points anyone at an unproven server.
    assert!(w.ms("proof-done") <= at);
}

/// S3-03: a Proxy start whose proof fails beside the core is compensated: the core it started
/// is stopped, nothing is selected, nothing runs.
#[tokio::test(start_paused = true)]
async fn a_failed_proof_beside_the_core_leaves_nothing_running() {
    let w = World::new();
    w.proofs_silent.store(1, Ordering::SeqCst);
    let h = TunnelHandle::spawn(budget_deps(&w));
    let req = slot_req(CaptureKind::Proxy);
    let err = h.start(req, CancellationToken::new()).await.unwrap_err();
    assert_eq!(err.user_msg().key, "tunnel.runtime.exitSilent");
    assert_eq!(w.count("terminate:4100"), 1, "{:?}", w.log());
    assert_eq!(w.count("select:a"), 0);
    assert!(!h.status().borrow().running);
}

/// S3-00 self-test for the S3-03 ordering fix (feasibility review): inputs that come 300 ms
/// after slot A accepts no longer hold the proof beside the core; the proof ends at slot + 300
/// and `running` at slot + 450 (the old order: the proof only after the inputs, slot + 600).
#[tokio::test(start_paused = true)]
async fn late_inputs_do_not_hold_a_proof_beside_the_core() {
    let w = World::new();
    let steps = Steps {
        resolve: 0,
        slot: 100,
        proof: 300,
        core: 150,
        capture: 0,
    };
    steps.on(&w);
    w.inputs_ms.store(400, Ordering::SeqCst);
    let h = TunnelHandle::spawn(budget_deps(&w));
    let at = running_at(&w, &h, slot_req(CaptureKind::Proxy)).await;
    assert!(near(w.ms("proof-done"), 400), "{}", w.ms("proof-done"));
    assert!(near(at, 550), "running at {at}");
}

/// The lab's steps of a Proxy recovery (live-10c, run 20261114-132449): upstream planned 174 ms,
/// slot A accepts after 376 ms, sing-box ready after 182 ms, one echo 316 ms.
fn lab_steps() -> Steps {
    Steps {
        resolve: 170,
        slot: 370,
        proof: 316,
        core: 180,
        capture: 0,
    }
}

/// The handshake budget's name of the fake keys (`sni=example.com`, both of them).
fn endpoint() -> vpnte_probes::discipline::Endpoint {
    let profile = vpnte_profiles::uri::parse_uri(XRAY_KEY).expect("fake key parses");
    vpnte_probes::discipline::Endpoint::of(&profile).expect("a network server")
}

/// One handshake of another check (a key check, the adaptive window's probe) on the budget.
async fn check_takes_a_slot(gate: &RealGate) {
    let wait = vpnte_probes::discipline::WINDOW + Duration::from_secs(5);
    let token = CancellationToken::new();
    gate.0
        .acquire(&endpoint(), wait, &token)
        .await
        .expect("slot");
}

/// The adaptive stability window after a (re)connect: 20 s on, three probes 2.5 s apart, each
/// behind the budget (`svc_auto` host `probe`); each waits for its slot in its own task.
fn adaptive_window(gate: &Arc<RealGate>) {
    for i in 0..3_u64 {
        let gate = gate.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20_000 + 2_500 * i)).await;
            check_takes_a_slot(&gate).await;
        });
    }
}

/// Crashes core `n` and returns the virtual ms from the crash to the recovery's success.
async fn crash_to_running(
    w: &Arc<World>,
    events: &mut tokio::sync::broadcast::Receiver<TunnelEvent>,
    n: usize,
) -> u64 {
    drain(events);
    let crashed = w.now_ms();
    w.core(n).crash();
    // Virtual time: a recovery that waits for a handshake slot may take a minute.
    let ok = async {
        while let Ok(e) = events.recv().await {
            if matches!(e, TunnelEvent::StartFinished { ok: true, .. }) {
                return;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(120), ok)
        .await
        .expect("the recovery finished");
    w.now_ms() - crashed
}

fn proofs(w: &World) -> usize {
    w.log()
        .iter()
        .filter(|l| l.starts_with("egress-via:"))
        .count()
}

/// Lab live-10 L10-2 (runs 20261114-125150 / -132449): a Proxy crash recovery waited 8.7 s and
/// 17.3 s for its proof's handshake slot (target with S3-01 and S3-03: traffic back <= 1.5 s). The name's budget (3 handshakes a minute) was full:
/// the connect's proof, the switch's probe and the adaptive window's three probes after every
/// (re)connect. Replayed on the real budget: both recoveries see no free slot, and the traffic
/// the programs send through slot A proves the server without waiting or a handshake.
#[tokio::test(start_paused = true)]
async fn a_recovery_without_a_free_slot_is_proven_by_its_traffic() {
    let w = World::new();
    lab_steps().on(&w);
    let gate = Arc::new(RealGate::default());
    *w.gate.lock() = Some(gate.clone());
    // A group key check before: three handshakes to the name, then a minute of rest.
    for _ in 0..3 {
        check_takes_a_slot(&gate).await;
    }
    tokio::time::sleep(Duration::from_secs(61)).await;
    // The shipped crash backoff (S3-01, Lane B: the first restart at once).
    let mut d = budget_deps(&w);
    d.timings.backoff = Timings::default().backoff;
    let h = TunnelHandle::spawn(d);
    let mut events = h.subscribe();
    running_at(&w, &h, slot_req(CaptureKind::Proxy)).await;
    tokio::time::sleep(Duration::from_secs(10)).await;
    let owner: crate::api::OwnerCheck = Arc::new(|| true);
    let next = StartRequest {
        capture: CaptureKind::Proxy,
        ..vpn_req(XRAY_KEY_2, EnginePref::Xray)
    };
    let sw = h.switch_upstream(next, CancellationToken::new(), owner);
    let sw = sw.await.expect("in place");
    assert_eq!(sw.outcome, crate::api::SwitchOutcome::Success, "{sw:?}");
    adaptive_window(&gate);
    tokio::time::sleep(Duration::from_secs(21)).await;
    // The first kill, ~25 s after the switch: no slot until a minute after the connect.
    let server = vpnte_profiles::uri::parse_uri(XRAY_KEY_2).expect("fake key parses");
    assert!(!gate.ready_now(&server));
    w.slot_traffic.lock()[0] = 4096;
    let before = proofs(&w);
    let took = crash_to_running(&w, &mut events, 0).await;
    assert!(took <= 1_500, "recovery took {took} ms");
    assert_eq!(proofs(&w), before, "{:?}", w.log());
    // The second kill ~69 s later (the lab's «rested» case): the recovery's own adaptive window
    // queued its probes into the full budget, so again no slot is free.
    adaptive_window(&gate);
    tokio::time::sleep(Duration::from_secs(69)).await;
    let wait = gate.0.wait_for(&endpoint());
    assert!(
        wait >= Duration::from_secs(8),
        "the echo would wait {wait:?}"
    );
    let took = crash_to_running(&w, &mut events, 1).await;
    assert!(took <= 1_500, "recovery took {took} ms");
    assert_eq!(proofs(&w), before, "{:?}", w.log());
    assert!(h.status().borrow().running);
}

/// L10-2, the other side: a recovery whose programs send nothing gets its traffic window
/// (3 s), then waits for the handshake slot and proves by echo as before; «Подключено» only
/// after that proof.
#[tokio::test(start_paused = true)]
async fn an_idle_recovery_waits_for_the_slot_after_its_traffic_window() {
    let w = World::new();
    lab_steps().on(&w);
    let gate = Arc::new(RealGate::default());
    *w.gate.lock() = Some(gate.clone());
    let h = TunnelHandle::spawn(budget_deps(&w));
    let mut events = h.subscribe();
    running_at(&w, &h, slot_req(CaptureKind::Proxy)).await;
    // Two more checks fill the name's minute: the next slot is a minute after the connect's.
    check_takes_a_slot(&gate).await;
    check_takes_a_slot(&gate).await;
    let free_at = w.ms("slot-admitted") + 60_000;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let before = proofs(&w);
    let took = crash_to_running(&w, &mut events, 0).await;
    let crashed = w.now_ms() - took;
    assert_eq!(proofs(&w), before + 1, "{:?}", w.log());
    // The echo goes out at the free slot (never before the traffic window) and its answer
    // comes before «running».
    let sent = free_at.max(crashed + 3_000);
    assert!(
        w.now_ms() >= sent + 316,
        "running at {} (slot {sent})",
        w.now_ms()
    );
    assert!(
        w.now_ms() <= sent + 316 + 1_000,
        "running at {}",
        w.now_ms()
    );
}

/// L10-2: a fresh connect keeps the gated echo. Nobody is routed into its server before the
/// start returns (the system proxy is written after it), so it waits for the slot even when
/// the counters would show traffic.
#[tokio::test(start_paused = true)]
async fn a_fresh_connect_keeps_the_gated_echo() {
    let w = World::new();
    lab_steps().on(&w);
    let gate = Arc::new(RealGate::default());
    *w.gate.lock() = Some(gate.clone());
    for _ in 0..3 {
        check_takes_a_slot(&gate).await;
    }
    w.slot_traffic.lock()[0] = 4096;
    let h = TunnelHandle::spawn(budget_deps(&w));
    let at = running_at(&w, &h, slot_req(CaptureKind::Proxy)).await;
    assert_eq!(proofs(&w), 1);
    assert!(at >= 60_000 + 316, "running at {at}");
}

/// The address the slot config dials (the first Xray config's first outbound address found).
fn dialled(w: &World) -> String {
    let configs = w.xray_configs.lock();
    let config = configs.last().expect("an Xray config").to_string();
    ["203.0.113.10", "203.0.113.50", "203.0.113.99"]
        .into_iter()
        .find(|ip| config.contains(ip))
        .unwrap_or("none")
        .to_owned()
}

fn hint(name: &str, addrs: &[&str]) -> crate::api::ServerFacts {
    crate::api::ServerFacts {
        fresh: false,
        hints: vec![crate::api::NameHint {
            name: name.to_owned(),
            addrs: addrs.iter().map(|a| a.parse().expect("ip")).collect(),
        }],
    }
}

/// speed3 S3-09 (b): a fresh hint the app sent for the server's name skips the lookup
/// (`resolve_ms`) and is what the slot dials.
#[tokio::test(start_paused = true)]
async fn a_fresh_hint_skips_the_lookup() {
    let w = World::new();
    let steps = Steps {
        resolve: 100,
        slot: 100,
        proof: 300,
        core: 150,
        capture: 0,
    };
    steps.on(&w);
    *w.facts.lock() = Some(hint("VPN.example", &["2001:db8::50", "203.0.113.50"]));
    let h = TunnelHandle::spawn(budget_deps(&w));
    let at = running_at(&w, &h, slot_req(CaptureKind::Proxy)).await;
    assert!(near(at, 400), "running at {at} (looked up: 500)");
    assert!(w.resolve_paths.lock().is_empty());
    assert_eq!(dialled(&w), "203.0.113.50");
}

/// S3-09 (Sec): a hint is filtered like a looked-up answer: loopback, unspecified, link-local
/// and our TUN's own addresses are refused and the name is looked up; a hint never replaces a
/// profile's IP literal.
#[tokio::test]
async fn bad_hints_are_refused() {
    let w = World::new();
    let bad = ["127.0.0.1", "0.0.0.0", "169.254.1.1", "192.168.250.254"];
    *w.facts.lock() = Some(hint("vpn.example", &bad));
    let h = TunnelHandle::spawn(budget_deps(&w));
    h.start(slot_req(CaptureKind::Proxy), CancellationToken::new())
        .await
        .expect("start");
    assert_eq!(w.resolve_paths.lock().len(), 1);
    assert_eq!(dialled(&w), "203.0.113.10");
    h.stop(crate::api::StopOptions::default()).await;
    *w.facts.lock() = Some(hint("203.0.113.10", &["203.0.113.99"]));
    let literal = StartRequest {
        capture: CaptureKind::Proxy,
        ..vpn_req(XRAY_KEY, EnginePref::Xray)
    };
    h.start(literal, CancellationToken::new())
        .await
        .expect("start");
    assert_eq!(dialled(&w), "203.0.113.10");
}

/// S3-09 (e): a start that fails after a remembered answer drops it from the resolver's memory,
/// so the next start asks the resolvers (feasibility review: no such safety net existed).
#[tokio::test]
async fn a_failed_start_forgets_its_remembered_name() {
    let w = World::new();
    let name = "stale-a.s3-09.example";
    let key = NAMED_KEY.replace("vpn.example", name);
    vpnte_core::resolve::remember(name, vec!["203.0.113.30".parse().expect("ip")]);
    assert!(vpnte_core::resolve::remembers(name));
    w.proofs_silent.store(1, Ordering::SeqCst);
    let h = TunnelHandle::spawn(budget_deps(&w));
    let req = StartRequest {
        capture: CaptureKind::Proxy,
        ..vpn_req(&key, EnginePref::Xray)
    };
    h.start(req, CancellationToken::new()).await.unwrap_err();
    assert!(!vpnte_core::resolve::remembers(name));
}

/// speed3 S3-08, first commit (lead decision: «Строгий» only): a TUN first start under «Строгий»
/// brings the TUN up beside slot A's proof; `running` = resolve + slot + max(proof, core +
/// capture), and the protection sees exactly today's calls.
#[tokio::test(start_paused = true)]
async fn a_strict_tun_start_brings_the_tun_up_beside_the_proof() {
    let w = World::new();
    *w.guard.lock() = KillSwitchLevel::Strict;
    let steps = Steps {
        resolve: 50,
        slot: 100,
        proof: 300,
        core: 430,
        capture: 10,
    };
    steps.on(&w);
    let h = TunnelHandle::spawn(budget_deps(&w));
    let req = StartRequest {
        kill_switch: KillSwitchLevel::Strict,
        ..slot_req(CaptureKind::Tun)
    };
    let at = running_at(&w, &h, req).await;
    assert!(near(at, 590), "running at {at} (serial: 890)");
    let protection: Vec<String> = (w.log().into_iter())
        .filter(|l| l.starts_with("begin") || l == "ready" || l == "release" || l == "lost")
        .collect();
    assert_eq!(protection, ["begin:0", "ready"]);
}

/// S3-08 under «Стандартный» keeps today's order (the owner's decision of 12.11 stands until
/// question 32 is answered): the proof before the core.
#[tokio::test(start_paused = true)]
async fn a_standard_tun_start_keeps_the_proof_first() {
    let w = World::new();
    let steps = Steps {
        resolve: 50,
        slot: 100,
        proof: 300,
        core: 430,
        capture: 10,
    };
    steps.on(&w);
    let h = TunnelHandle::spawn(budget_deps(&w));
    let at = running_at(&w, &h, slot_req(CaptureKind::Tun)).await;
    assert!(near(at, 890), "running at {at}");
    assert!(w.ms("proof-done") <= w.ms("spawn:4100"));
}

/// S3-08 under «Строгий»: a dead server is compensated as before: the core it started is
/// stopped, nothing is selected, the start fails.
#[tokio::test(start_paused = true)]
async fn a_strict_tun_start_on_a_dead_server_leaves_nothing_running() {
    let w = World::new();
    *w.guard.lock() = KillSwitchLevel::Strict;
    w.proofs_silent.store(1, Ordering::SeqCst);
    let h = TunnelHandle::spawn(budget_deps(&w));
    let req = StartRequest {
        kill_switch: KillSwitchLevel::Strict,
        ..slot_req(CaptureKind::Tun)
    };
    h.start(req, CancellationToken::new()).await.unwrap_err();
    assert_eq!(w.count("terminate:4100"), 1, "{:?}", w.log());
    assert_eq!(w.count("select:a"), 0);
    assert!(!h.status().borrow().running);
}

/// speed3 S3-05: one DoH warm-up per TUN start, right after sing-box is ready (its Clash API
/// opens last); none for a Proxy start; a warm-up that never answers changes nothing of the
/// start (option W off).
#[tokio::test(start_paused = true)]
async fn a_tun_start_warms_its_doh_once_and_never_waits_for_it() {
    let w = World::new();
    w.core_ready_ms.store(430, Ordering::SeqCst);
    w.capture_ready_ms.store(10, Ordering::SeqCst);
    w.warm_hangs.store(true, Ordering::SeqCst);
    let h = TunnelHandle::spawn(budget_deps(&w));
    let at = running_at(&w, &h, slot_req(CaptureKind::Tun)).await;
    tokio::task::yield_now().await;
    assert_eq!(w.warms.load(Ordering::SeqCst), 1);
    assert!(w.ms("core-ready:4100") <= w.ms("warm-dns"));
    assert!(near(at, w.ms("core-ready:4100") + 10), "running at {at}");
    h.stop(crate::api::StopOptions::default()).await;
    running_at(&w, &h, slot_req(CaptureKind::Proxy)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        w.warms.load(Ordering::SeqCst),
        1,
        "no warm-up for a Proxy start"
    );
}

/// S3-05 (security review condition 1): the warm-up asks only when the session's DNS rules
/// leave its name on the tunnel's DoH; a direct rule that names it (a user's «Не через прокси»)
/// or a rule this cannot read keeps it from asking.
#[test]
fn the_warm_up_skips_a_name_that_goes_direct() {
    use super::super::start::warms_through_tunnel;
    use serde_json::json;
    let remote = json!({ "domain_suffix": ["msftconnecttest.com"], "server": "dns-remote" });
    let other = json!({ "domain_suffix": [".ru"], "server": "dns-direct" });
    assert!(warms_through_tunnel(&[remote, other]));
    for direct in [
        json!({ "domain_suffix": [".msftconnecttest.com"], "server": "dns-direct" }),
        json!({ "domain_suffix": ["msftconnecttest.com"], "server": "dns-direct" }),
        json!({ "domain": ["WWW.msftconnecttest.com"], "server": "dns-direct" }),
        json!({ "domain_keyword": ["msftconnect"], "server": "dns-direct" }),
        json!({ "domain_regex": ["^.*$"], "server": "dns-direct" }),
    ] {
        assert!(
            !warms_through_tunnel(std::slice::from_ref(&direct)),
            "{direct}"
        );
    }
}
