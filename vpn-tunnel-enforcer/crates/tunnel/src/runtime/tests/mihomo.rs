//! WP-12 lab: AmneziaWG sessions on mihomo, chained behind sing-box (fakes; the real engines run
//! in the engine crate's tests). The lab gate is opened once for this test process.
use std::sync::atomic::Ordering;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Engine, EnginePref};

use super::*;
use crate::api::{CaptureKind, Mode, Runtime, StopOptions, VpnProfile};
use crate::runtime::TunnelHandle;

/// Obvious fakes: keys of 0x01 / 0x02 bytes, a documentation-style name.
const AWG_CONF: &str = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.8.1.2/32\nJc = 4\nJmin = 40\nJmax = 70\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = awg.example.net:51820\n";

fn open_gate() {
    let dir = std::env::temp_dir().join(format!("vpnte-tunnel-lab-{}", uuid::Uuid::new_v4()));
    let path = vpnte_engine::lab::record_path(&dir);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let record = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "passed": vpnte_engine::lab::REQUIRED,
        "by": "tunnel tests",
    });
    std::fs::write(&path, record.to_string()).unwrap();
    vpnte_engine::lab::activate(&dir).expect("complete record");
    let _ = std::fs::remove_dir_all(&dir);
}

fn awg_req(capture: CaptureKind) -> StartRequest {
    let profile = vpnte_profiles::wg_ini::parse_wg_ini(AWG_CONF)
        .expect("a .conf")
        .expect("valid");
    StartRequest {
        mode: Mode::DirectVpn {
            profile: VpnProfile {
                id: "awg".into(),
                profile: Arc::new(profile),
                device: None,
                engine: EnginePref::Auto,
            },
        },
        capture,
        engine: EnginePref::Auto,
        ..local_req()
    }
}

/// The `proxy-out` outbound of a generated sing-box config.
fn proxy_out(config: &Value) -> Value {
    let outbounds = config["outbounds"].as_array().expect("outbounds");
    outbounds
        .iter()
        .find(|o| o["tag"] == "proxy-out")
        .cloned()
        .expect("proxy-out")
}

/// D3 / AT-12-003 step 2: mihomo starts first, the tunnel is proven by an answer through its
/// listener, then sing-box (the proxy capture, routing, DNS, stats) dials the run's keyed hop
/// (audit mihomo-a5: UDP over TCP inside it, never mihomo's SOCKS5 UDP relay); the endpoint name
/// was resolved by the app; a stop ends both engines.
#[tokio::test]
async fn amneziawg_runs_on_mihomo_behind_sing_box() {
    open_gate();
    let w = World::new();
    let h = TunnelHandle::spawn(deps(&w));
    let receipt = h
        .start(awg_req(CaptureKind::Proxy), CancellationToken::new())
        .await
        .expect("AmneziaWG start");
    assert_eq!(receipt.engine.kind, Engine::Mihomo);
    assert!(w.at("mihomo-start:5100") < w.at("egress-via:awg.example.net"));
    assert!(w.at("egress-via:awg.example.net") < w.at("spawn:4101"));
    assert_eq!(*w.resolve_paths.lock(), [ResolvePath::Direct]);
    let out = proxy_out(&w.configs.lock()[0]);
    let hop = (*w.mihomo_hop.lock()).expect("mihomo started");
    assert_ne!(Some(hop), *w.mihomo_port.lock(), "not the SOCKS5 listener");
    assert_eq!(out["type"], "shadowsocks");
    assert_eq!(out["server"], "127.0.0.1");
    assert_eq!(out["server_port"], hop);
    assert_eq!(out["method"], vpnte_engine::mihomo_config::HOP_METHOD);
    assert!(out["password"].as_str().is_some_and(|k| k.len() == 24));
    assert_eq!(out["udp_over_tcp"]["enabled"], true);
    let status = h.status().borrow().clone();
    assert_eq!(status.engine.map(|e| e.kind), Some(Engine::Mihomo));
    let stop = h.stop(StopOptions::default()).await;
    assert!(stop.ok && stop.runtime_stopped);
    // The stop and the chain's watcher may both ask: a stop is idempotent.
    assert!(w.count("terminate:4101") >= 1, "sing-box stopped");
    assert!(w.count("terminate:5100") >= 1, "mihomo stopped");
}

/// AT-12-003 step 2: a server that never answers (or answers too late for the probe) is an
/// honest failure, never "connected"; the started mihomo is stopped, sing-box never runs.
#[tokio::test]
async fn a_silent_amneziawg_server_is_never_connected() {
    open_gate();
    let w = World::new();
    *w.egress_via.lock() = EgressVia::NoReply;
    let h = TunnelHandle::spawn(deps(&w));
    let err = h
        .start(awg_req(CaptureKind::Proxy), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.user_msg().key, "tunnel.runtime.mihomo.noTraffic");
    assert_eq!(err.kind(), ErrorKind::Network);
    assert_eq!(w.count("terminate:5100"), 1, "mihomo stopped");
    assert!(w.log().iter().all(|l| !l.starts_with("spawn:")));
    assert!(!h.status().borrow().running);
}

/// D4: no TUN chain for mihomo yet (capability), so Tunnel mode refuses AmneziaWG before any
/// effect instead of sending the hop's traffic around the kill switch.
#[tokio::test]
async fn tunnel_mode_refuses_amneziawg_before_any_effect() {
    open_gate();
    let w = World::new();
    let h = TunnelHandle::spawn(deps(&w));
    let err = h
        .start(awg_req(CaptureKind::Tun), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.user_msg().key, "tunnel.runtime.mihomo.tunUnavailable");
    assert_eq!(err.kind(), ErrorKind::Validation);
    assert!(
        w.log()
            .iter()
            .all(|l| !l.starts_with("mihomo-start") && !l.starts_with("prepare"))
    );
}

/// Either half of the chain dying is the session's crash: mihomo's crash ends sing-box too and
/// the actor's crash policy takes over.
#[tokio::test]
async fn a_mihomo_crash_is_a_session_crash() {
    open_gate();
    let w = World::new();
    w.auto_restart.store(false, Ordering::SeqCst);
    let h = TunnelHandle::spawn(deps(&w));
    h.start(awg_req(CaptureKind::Proxy), CancellationToken::new())
        .await
        .expect("AmneziaWG start");
    w.core(0).crash();
    let mut status = h.status();
    tokio::time::timeout(Duration::from_secs(5), status.wait_for(|s| !s.running))
        .await
        .expect("the session ended")
        .unwrap();
    assert!(w.count("terminate:4101") >= 1, "the chain stopped sing-box");
}

/// Audit mihomo-a1: sing-box dying on a port race is retried with fresh ports behind the same,
/// untouched mihomo run; the session then runs on the second sing-box and stays up.
#[tokio::test]
async fn a_bind_failure_retry_keeps_the_mihomo_run() {
    open_gate();
    let w = World::new();
    w.ready.lock().push_back(Ready::BindFail);
    let h = TunnelHandle::spawn(deps(&w));
    h.start(awg_req(CaptureKind::Proxy), CancellationToken::new())
        .await
        .expect("the retry starts");
    assert_eq!(w.configs.lock().len(), 2, "one retry");
    assert_eq!(w.count("mihomo-start:5100"), 1, "the same run");
    // A watcher of the failed first pair would stop the run the retry chained.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(w.count("terminate:5100"), 0, "{:?}", w.log());
    let status = h.status().borrow().clone();
    assert!(status.running);
    assert_eq!(status.pid, Some(4102));
    let stop = h.stop(StopOptions::default()).await;
    assert!(stop.ok && stop.runtime_stopped);
    assert!(
        w.count("terminate:5100") >= 1,
        "mihomo stopped with the session"
    );
}

/// Audit mihomo-a1: mihomo dying while sing-box gets ready fails the start with mihomo's own
/// message, not a sing-box one, and sing-box is stopped by the compensation.
#[tokio::test]
async fn mihomo_dying_during_sing_box_readiness_is_named() {
    open_gate();
    let w = World::new();
    w.ready.lock().push_back(Ready::Hold);
    let h = TunnelHandle::spawn(deps(&w));
    let start = {
        let h = h.clone();
        tokio::spawn(async move {
            h.start(awg_req(CaptureKind::Proxy), CancellationToken::new())
                .await
        })
    };
    while !w.log().iter().any(|l| l.starts_with("spawn:")) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    w.core(0).crash();
    let err = start.await.expect("join").unwrap_err();
    assert_eq!(err.user_msg().key, "engine.lab.process.exited");
    assert!(!h.status().borrow().running);
}

/// Audit mihomo-b3: an echo service's error page that came back through the tunnel proves
/// traffic: the session connects (the address is just unknown), never "the server did not
/// answer".
#[tokio::test]
async fn an_answer_without_an_address_is_still_traffic() {
    open_gate();
    let w = World::new();
    *w.egress_via.lock() = EgressVia::NoAddress;
    let h = TunnelHandle::spawn(deps(&w));
    h.start(awg_req(CaptureKind::Proxy), CancellationToken::new())
        .await
        .expect("answers came back through the tunnel");
    assert!(h.status().borrow().running);
    assert!(w.at("egress-via:awg.example.net") < w.at("spawn:4101"));
}

/// Audit mihomo-b3: a probe the handshake budget deferred dialled nothing, so it says so (its
/// own message), never that the server did not answer; mihomo is stopped again.
#[tokio::test]
async fn a_deferred_probe_does_not_blame_the_server() {
    open_gate();
    let w = World::new();
    *w.egress_via.lock() = EgressVia::Deferred;
    let h = TunnelHandle::spawn(deps(&w));
    let err = h
        .start(awg_req(CaptureKind::Proxy), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.user_msg().key, "probes.discipline.deferred");
    assert_eq!(w.count("terminate:5100"), 1, "mihomo stopped");
}

/// Audit mihomo-b3: mihomo dying during the probe is named as mihomo's exit, not as a silent
/// AmneziaWG server.
#[tokio::test]
async fn mihomo_dying_during_the_probe_is_named() {
    open_gate();
    let w = World::new();
    *w.egress_via.lock() = EgressVia::NoReply;
    w.crash_mihomo_on_probe.store(true, Ordering::SeqCst);
    let h = TunnelHandle::spawn(deps(&w));
    let err = h
        .start(awg_req(CaptureKind::Proxy), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.user_msg().key, "engine.lab.process.exited");
}
