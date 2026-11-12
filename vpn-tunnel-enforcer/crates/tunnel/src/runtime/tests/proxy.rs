//! Proxy capture in the actor (NOADMIN.md §2): the real [`ProxyCapture`] over fake engines whose
//! cores bind the `proxy-in` port of their config, and the strategy choice per start.
use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;
use vpnte_base::types::KillSwitchLevel;

use super::*;
use crate::api::{CaptureKind, RestartOptions, Runtime, StopOptions, TunStatusKind};
use crate::runtime::TunnelHandle;

fn proxy_req() -> StartRequest {
    StartRequest {
        capture: CaptureKind::Proxy,
        ..local_req()
    }
}

/// The `proxy-in` port of a generated config.
fn proxy_in(config: &Value) -> Option<u16> {
    let inbounds = config["inbounds"].as_array()?;
    let inbound = inbounds.iter().find(|i| i["tag"] == "proxy-in")?;
    u16::try_from(inbound["listen_port"].as_u64()?).ok()
}

fn config(w: &World, n: usize) -> Value {
    w.configs.lock()[n].clone()
}

fn free(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

/// NOADMIN.md §2: a proxy start runs the engine behind a loopback mixed inbound with no TUN
/// and no protection step; the status names the capture and the port; a stop frees the port.
#[tokio::test]
async fn proxy_start_needs_no_protection_and_publishes_the_port() {
    let w = World::new();
    let h = TunnelHandle::spawn(deps(&w));
    h.start(proxy_req(), CancellationToken::new())
        .await
        .expect("proxy start");
    let cfg = config(&w, 0);
    let port = proxy_in(&cfg).expect("proxy-in inbound");
    let inbounds = cfg["inbounds"].as_array().expect("inbounds");
    assert!(inbounds.iter().all(|i| i["type"] != "tun"));
    let status = h.status().borrow().clone();
    assert_eq!(status.capture, Some(CaptureKind::Proxy));
    let session = status.session.expect("session endpoints");
    assert_eq!((session.proxy_port, session.tun_luid), (Some(port), None));
    assert_eq!(w.core(0).proxy_port(), Some(port));
    // The TUN fake was never asked: no prepare, no WFP begin.
    assert!(
        w.log()
            .iter()
            .all(|l| !l.starts_with("prepare") && !l.starts_with("begin"))
    );
    let receipt = h.stop(StopOptions::default()).await;
    assert!(receipt.ok && receipt.runtime_stopped);
    assert!(free(port), "the mixed port is free after the stop");
    assert_eq!(h.status().borrow().capture, None);
}

/// NOADMIN.md §0 / §2: a TUN start in a host that supplied no TUN capture (not elevated)
/// answers `Permission` before anything runs; the proxy strategy still works.
#[tokio::test]
async fn tun_without_a_tun_capture_answers_permission() {
    let w = World::new();
    let mut d = deps(&w);
    d.tun = None;
    let h = TunnelHandle::spawn(d);
    let err = h
        .start(local_req(), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Permission);
    assert_eq!(err.user_msg().key, "tunnel.runtime.tunUnavailable");
    assert!(w.cores.lock().is_empty(), "nothing spawned");
    h.start(proxy_req(), CancellationToken::new())
        .await
        .expect("proxy start");
}

/// The `Permission` refusal comes before anything runs (review): a TUN start refused in a
/// TUN-less host leaves a pending crash restart of the proxy session alone.
#[tokio::test]
async fn a_refused_tun_start_keeps_the_pending_crash_restart() {
    let w = World::new();
    let mut d = deps(&w);
    d.tun = None;
    d.timings.backoff = [Duration::from_millis(300); 3];
    let h = TunnelHandle::spawn(d);
    let mut events = h.subscribe();
    h.start(proxy_req(), CancellationToken::new())
        .await
        .expect("proxy start");
    w.core(0).crash();
    until(&mut events, |e| {
        matches!(e, TunnelEvent::Status(TunStatusKind::Restarting { .. }))
    })
    .await;
    let err = h
        .start(local_req(), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Permission);
    until(&mut events, |e| {
        matches!(
            e,
            TunnelEvent::StartFinished {
                generation: 2,
                ok: true
            }
        )
    })
    .await;
    assert_eq!(h.status().borrow().capture, Some(CaptureKind::Proxy));
}

/// NOADMIN.md §2: the strict kill switch needs WFP; the proxy capture refuses it before any
/// engine runs.
#[tokio::test]
async fn strict_is_refused_by_the_proxy_capture() {
    let w = World::new();
    let h = TunnelHandle::spawn(deps(&w));
    let req = StartRequest {
        kill_switch: KillSwitchLevel::Strict,
        ..proxy_req()
    };
    let err = h.start(req, CancellationToken::new()).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Validation);
    assert_eq!(err.user_msg().key, "tunnel.runtime.proxy.strictUnavailable");
    assert!(w.cores.lock().is_empty(), "nothing spawned");
}

/// NOADMIN.md §2: the mixed port belongs to the session: a crash restart and a protected
/// restart keep it (the system proxy keeps pointing at it).
#[tokio::test]
async fn the_port_survives_crash_and_protected_restarts() {
    let w = World::new();
    let h = TunnelHandle::spawn(deps(&w));
    let mut events = h.subscribe();
    h.start(proxy_req(), CancellationToken::new())
        .await
        .expect("proxy start");
    let port = proxy_in(&config(&w, 0)).expect("port");
    w.core(0).crash();
    until(&mut events, |e| {
        matches!(
            e,
            TunnelEvent::StartFinished {
                generation: 2,
                ok: true
            }
        )
    })
    .await;
    assert_eq!(proxy_in(&config(&w, 1)), Some(port), "crash restart");
    let next = proxy_req();
    h.restart_protected("test".into(), next, RestartOptions::default())
        .await
        .expect("protected restart");
    assert_eq!(proxy_in(&config(&w, 2)), Some(port), "protected restart");
    assert_eq!(w.core(2).proxy_port(), Some(port));
    assert_eq!(h.status().borrow().capture, Some(CaptureKind::Proxy));
}

/// NOADMIN.md §2: an engine that runs but no longer accepts on its mixed port has lost the
/// capture: the core is ended and the crash policy restarts it.
#[tokio::test]
async fn a_deaf_inbound_is_ended_as_a_crash() {
    let w = World::new();
    let mut d = deps(&w);
    d.timings.capture_watch = Duration::from_millis(30);
    let h = TunnelHandle::spawn(d);
    let mut events = h.subscribe();
    h.start(proxy_req(), CancellationToken::new())
        .await
        .expect("proxy start");
    w.core(0).deafen();
    until(&mut events, |e| {
        matches!(
            e,
            TunnelEvent::StartFinished {
                generation: 2,
                ok: true
            }
        )
    })
    .await;
    assert_eq!(w.count("terminate:4100"), 1, "{:?}", w.log());
    assert!(h.status().borrow().running);
}

/// A start with the other strategy first releases what the previous one still holds (here a
/// TUN session's blocking crash outcome); a failed release refuses the start, nothing runs.
#[tokio::test]
async fn a_strategy_change_releases_the_previous_protection() {
    let w = World::new();
    w.auto_restart.store(false, Ordering::SeqCst);
    let h = TunnelHandle::spawn(deps(&w));
    let mut events = h.subscribe();
    h.start(local_req(), CancellationToken::new())
        .await
        .expect("tun start");
    w.core(0).crash();
    until(&mut events, |e| {
        matches!(e, TunnelEvent::Status(TunStatusKind::KillSwitchActive))
    })
    .await;
    assert_eq!(w.count("release"), 0, "standard keeps blocking");
    w.release_fail.store(true, Ordering::SeqCst);
    let err = h
        .start(proxy_req(), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.user_msg().key, "tunnel.runtime.cleanup.protection");
    assert_eq!(w.cores.lock().len(), 1, "no proxy engine ran");
    w.release_fail.store(false, Ordering::SeqCst);
    h.start(proxy_req(), CancellationToken::new())
        .await
        .expect("proxy start after the release");
    assert!(w.at("release") < w.at("spawn:4101"), "{:?}", w.log());
    assert_eq!(h.status().borrow().capture, Some(CaptureKind::Proxy));
}

/// The outbound of the route rule whose `process_path_regex` lists the bundled `exe` image.
fn engine_rule(config: &Value, exe: &str) -> Option<String> {
    let path = format!(r"C:\Program Files\VPN Tunnel Enforcer\resources\{exe}");
    let regex = vpnte_engine::routing::process::AppPath::parse(&path)
        .expect("bundled path parses")
        .regex();
    config["route"]["rules"]
        .as_array()?
        .iter()
        .find(|r| {
            r["process_path_regex"]
                .as_array()
                .is_some_and(|list| list.iter().any(|v| *v == *regex))
        })
        .and_then(|r| r["outbound"].as_str().map(str::to_owned))
}

/// Spec external-proxy §3.28 (decision 5): under the TUN the bundled sing-box and Xray images
/// (external proxy slots, probe engines) leave through `direct-out`, so slot traffic does not
/// loop through the tunnel; the proxy capture captures nothing and needs no such rule.
#[tokio::test]
async fn bundled_engines_go_direct_only_under_the_tun() {
    let w = World::new();
    let h = TunnelHandle::spawn(deps(&w));
    h.start(local_req(), CancellationToken::new())
        .await
        .expect("tun start");
    let tun = config(&w, 0);
    for exe in ["sing-box.exe", "xray.exe"] {
        assert_eq!(
            engine_rule(&tun, exe).as_deref(),
            Some("direct-out"),
            "{exe}"
        );
    }
    assert!(h.stop(StopOptions::default()).await.ok);
    h.start(proxy_req(), CancellationToken::new())
        .await
        .expect("proxy start");
    let proxy = config(&w, 1);
    for exe in ["sing-box.exe", "xray.exe"] {
        assert_eq!(engine_rule(&proxy, exe), None, "{exe}");
    }
}

/// NOADMIN.md §2 (review): under the proxy capture the app's own requests never use the system
/// proxy, so the default route shows the real address. The in-place switch therefore reads the
/// tunnel egress through the session's mixed inbound; through the default route it could never
/// match the slot's address and every Soft server switch on Xray would fail.
#[tokio::test]
async fn proxy_switch_reads_the_egress_through_the_mixed_inbound() {
    use vpnte_base::types::EnginePref;
    let w = World::new();
    let h = TunnelHandle::spawn(deps(&w));
    let soft = |key| StartRequest {
        capture: CaptureKind::Proxy,
        ..vpn_req(key, EnginePref::Xray)
    };
    h.start(soft(XRAY_KEY), CancellationToken::new())
        .await
        .expect("proxy slot start");
    let port = proxy_in(&config(&w, 0)).expect("port");
    let owner: crate::api::OwnerCheck = Arc::new(|| true);
    let sw = h
        .switch_upstream(soft(XRAY_KEY_2), CancellationToken::new(), owner)
        .await
        .expect("in place");
    assert!(sw.verified(), "{sw:?}");
    assert!(w.count(&format!("egress:{port}")) >= 1, "{:?}", w.log());
    assert_eq!(
        w.count("egress"),
        0,
        "never the default route: {:?}",
        w.log()
    );
}
