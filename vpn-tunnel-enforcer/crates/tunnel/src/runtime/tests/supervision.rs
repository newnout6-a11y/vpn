//! Watchdogs (§7.20) and the real engine check of every generated config (CONTRACT §4.10).
use std::path::Path;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{EnginePref, ProxyKind};

use super::*;
use crate::api::{Mode, Runtime, StopOptions, TunStatusKind, TunnelEvent};
use crate::runtime::{Confirmations, TunnelHandle};

fn is_down(e: &TunnelEvent) -> bool {
    matches!(e, TunnelEvent::Status(TunStatusKind::ProxyDown { .. }))
}

/// Local proxy: the watchdog marks the upstream down after three failed connects (the tunnel
/// stays up and holds the traffic) and up again once the proxy answers.
#[tokio::test]
async fn local_proxy_watchdog_down_and_up() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let w = World::new();
    let mut d = deps(&w);
    d.timings.proxy_watch = Duration::from_millis(20);
    d.timings.proxy_probe = Duration::from_millis(200);
    let h = TunnelHandle::spawn(d);
    let mut events = h.subscribe();
    let req = StartRequest {
        mode: Mode::LocalProxy {
            addr: addr.to_string(),
            kind: ProxyKind::Socks5,
        },
        ..local_req()
    };
    h.start(req, CancellationToken::new()).await.unwrap();
    drain(&mut events);
    drop(listener);
    until(&mut events, is_down).await;
    let status = h.status().borrow().clone();
    assert!(status.running && !status.proxy_reachable);
    let warning = status.warning.expect("reason");
    assert_eq!(warning.key, "tunnel.runtime.watchdog.proxyDown");
    assert_eq!(warning.args[0].1, addr.to_string());
    assert_eq!(
        w.count("terminate:4100"),
        0,
        "the watchdog never stops the tunnel"
    );
    let _again = tokio::net::TcpListener::bind(addr).await.unwrap();
    until(&mut events, |e| {
        *e == TunnelEvent::Status(TunStatusKind::Running)
    })
    .await;
    assert!(h.status().borrow().proxy_reachable);
}

struct Always;

impl Confirmations for Always {
    fn confirmed_within(&self, _age: Duration) -> bool {
        true
    }
}

/// Direct VPN: no traffic and no outside evidence = upstream down, named by the CURRENT
/// profile; recent outside evidence keeps it up.
#[tokio::test]
async fn direct_vpn_watchdog_needs_evidence() {
    let w = World::new();
    let mut d = deps(&w);
    d.timings.egress_watch = Duration::from_millis(20);
    let h = TunnelHandle::spawn(d);
    let mut events = h.subscribe();
    let req = vpn_req(NATIVE_KEY, EnginePref::SingBox);
    h.start(req, CancellationToken::new()).await.unwrap();
    until(&mut events, is_down).await;
    let warning = h.status().borrow().warning.clone().expect("reason");
    assert_eq!(warning.key, "tunnel.runtime.watchdog.upstreamDown");
    assert_eq!(warning.args[0].1, "Fake C");

    let w = World::new();
    let mut d = deps(&w);
    d.timings.egress_watch = Duration::from_millis(20);
    d.confirmations = Some(Arc::new(Always));
    let h = TunnelHandle::spawn(d);
    let mut events = h.subscribe();
    let req = vpn_req(NATIVE_KEY, EnginePref::SingBox);
    h.start(req, CancellationToken::new()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!drain(&mut events).iter().any(is_down));
    assert!(h.status().borrow().proxy_reachable);
}

/// Every config shape the runtime generates (local proxy, native sing-box, Xray slots; WFP
/// guard on and off) passes the bundled `sing-box check` (no elevation needed); skipped when
/// the engine is not there.
#[tokio::test]
async fn generated_configs_pass_the_engine_check() {
    let exe = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../resources/sing-box.exe"
    ));
    if !exe.is_file() {
        eprintln!("skipped: no sing-box under resources/");
        return;
    }
    let cases = [
        (local_req(), KillSwitchLevel::Standard),
        (
            vpn_req(NATIVE_KEY, EnginePref::SingBox),
            KillSwitchLevel::Off,
        ),
        // Pinned server address, the name kept as TLS server name and WebSocket host.
        (
            vpn_req(NATIVE_BY_NAME_KEY, EnginePref::SingBox),
            KillSwitchLevel::Standard,
        ),
        (vpn_req(XRAY_KEY, EnginePref::Xray), KillSwitchLevel::Strict),
    ];
    for (req, guard) in cases {
        let w = World::new();
        *w.guard.lock() = guard;
        let h = TunnelHandle::spawn(deps(&w));
        h.start(req, CancellationToken::new()).await.expect("start");
        let config = w.configs.lock()[0].to_string();
        let checked = vpnte_engine::singbox_process::check_config(exe, config.as_bytes()).await;
        assert!(checked.is_ok(), "{guard:?}: {checked:?}");
        let _ = h.stop(StopOptions::default()).await;
    }
}
