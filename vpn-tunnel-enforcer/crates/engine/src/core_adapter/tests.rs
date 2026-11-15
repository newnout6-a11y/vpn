//! AT-12-001: one conformance set (config compile, start, health, statistics, stop, system state)
//! run on sing-box, the reference, and on the lab engine mihomo. Every difference between them is
//! a declared capability; nothing else may differ.
use std::collections::HashMap;
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::path::Path;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::Engine;

use super::*;
use crate::clash_api::{ClashApi, ClashEndpoint};
use crate::mihomo_config::{Listen, translate};
use crate::mihomo_process::{self, MihomoProcess};
use crate::singbox_process::{self, ExitInfo, SingBoxProcess, testkit};
use crate::test_support::awg_samples::V1_0;
use crate::test_support::{
    TempDir, awg_profile, mihomo_endpoints, mihomo_exe, open_lab_gate, singbox_exe,
};
use crate::{ports, slot::SlotEndpoint};

enum Running {
    SingBox(SingBoxProcess),
    Mihomo(MihomoProcess),
}

/// One engine under test: its run, its loopback listener and its controller.
struct Subject {
    run: Running,
    listener: u16,
    controller: ClashEndpoint,
}

impl Subject {
    fn pid(&self) -> u32 {
        match &self.run {
            Running::SingBox(p) => p.pid(),
            Running::Mihomo(p) => p.pid(),
        }
    }

    async fn ready(&self) -> Result<(), String> {
        let cancel = CancellationToken::new();
        match &self.run {
            Running::SingBox(p) => p.wait_ready(singbox_process::READY_TIMEOUT, &cancel).await,
            Running::Mihomo(p) => {
                return (p.wait_ready(mihomo_process::READY_TIMEOUT, &cancel).await)
                    .map_err(|e| e.to_string());
            }
        }
        .map_err(|e| e.to_string())
    }

    async fn stop(&self) -> ExitInfo {
        match &self.run {
            Running::SingBox(p) => p.terminate(singbox_process::STOP_TIMEOUT).await,
            Running::Mihomo(p) => p.terminate(mihomo_process::STOP_TIMEOUT).await,
        }
        .expect("exit proven")
    }
}

/// Starts `engine` with a harmless loopback config (`None` without its binary), after checking
/// that the same config compiles.
async fn start(engine: Engine, runs: &Path, peer: u16) -> Option<Subject> {
    match engine {
        Engine::SingBox => {
            let exe = singbox_exe()?;
            let controller = ClashEndpoint::allocate(&[]).unwrap();
            let listener = ports::alloc_port(false, &[controller.port]).unwrap();
            let config = testkit::singbox_config(listener, &ports::creds(), Some(&controller));
            singbox_process::check_config(&exe, &config).await.unwrap();
            let run = Running::SingBox(SingBoxProcess::spawn(&exe, &config, None).unwrap());
            Some(Subject {
                run,
                listener,
                controller,
            })
        }
        Engine::Mihomo => {
            let exe = mihomo_exe()?;
            let (socks, hop, controller): (SlotEndpoint, _, ClashEndpoint) = mihomo_endpoints();
            let profile = awg_profile(V1_0, &format!("127.0.0.1:{peer}"));
            let listen = Listen {
                socks: &socks,
                hop: &hop,
                controller: &controller,
            };
            let config = translate(&profile, &HashMap::new(), &listen).unwrap();
            mihomo_process::check_config(&exe, runs, &config)
                .await
                .unwrap();
            let listener = socks.port();
            let run = MihomoProcess::spawn(&exe, runs, &config, socks, controller.clone(), None);
            Some(Subject {
                run: Running::Mihomo(run.unwrap()),
                listener,
                controller,
            })
        }
        Engine::Xray => None,
    }
}

/// The per-user system proxy and the process's sockets: what an engine must leave alone.
fn system_proxy() -> vpnte_winnet::sysproxy::ProxyConfig {
    vpnte_winnet::sysproxy::read().expect("system proxy readable")
}

fn assert_loopback_only(pid: u32) {
    let rows = vpnte_winnet::process::socket_table().unwrap();
    for row in rows.iter().filter(|r| r.pid == pid) {
        let listening =
            row.remote.is_none() || row.state == Some(vpnte_winnet::process::TcpState::Listen);
        assert!(!listening || row.local.ip().is_loopback(), "{row:?}");
    }
}

/// AT-12-001: the same lifecycle on both engines; system state untouched after every call.
#[tokio::test]
async fn the_same_lifecycle_holds_for_sing_box_and_mihomo() {
    open_lab_gate();
    let runs = TempDir::new("conformance");
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let peer_port = peer.local_addr().unwrap().port();
    for engine in [Engine::SingBox, Engine::Mihomo] {
        let caps = capabilities(engine);
        let before = system_proxy();
        let Some(subject) = start(engine, runs.path(), peer_port).await else {
            eprintln!("skipped {engine:?}: binary absent");
            continue;
        };
        assert!(caps.config_check && caps.stdin_config, "{engine:?}");
        subject.ready().await.unwrap();
        assert_eq!(system_proxy(), before, "{engine:?}: start");
        assert_loopback_only(subject.pid());
        if caps.controller {
            let api = ClashApi::new(&subject.controller).unwrap();
            assert!(api.version().await.is_ok(), "{engine:?}: health");
            assert!(api.connections().await.is_ok(), "{engine:?}: connections");
            assert!(api.traffic().await.is_ok(), "{engine:?}: traffic");
        }
        let info = subject.stop().await;
        assert!(info.user_initiated, "{engine:?}: {info:?}");
        assert!(
            TcpListener::bind((Ipv4Addr::LOCALHOST, subject.listener)).is_ok(),
            "{engine:?}: listener released"
        );
        assert_eq!(system_proxy(), before, "{engine:?}: stop");
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        std::fs::read_dir(runs.path()).unwrap().count(),
        0,
        "run dirs removed"
    );
}

/// The declared deviations of the lab engine (the tunnel handles each one).
#[test]
fn mihomo_deviations_are_declared() {
    let (sing_box, mihomo) = (capabilities(Engine::SingBox), capabilities(Engine::Mihomo));
    assert!(sing_box.session_owner && sing_box.tun_capture && !sing_box.amneziawg);
    assert!(mihomo.amneziawg && !mihomo.other_kinds);
    assert!(
        !mihomo.tun_capture,
        "no TUN chain: Tunnel mode refuses AmneziaWG"
    );
    assert!(!mihomo.session_owner, "chained behind sing-box");
    assert!(
        !mihomo.selector_switch,
        "a server change restarts the session"
    );
    assert_eq!(mihomo.readiness, Readiness::SocksAndController);
    let same = Capabilities {
        amneziawg: sing_box.amneziawg,
        other_kinds: sing_box.other_kinds,
        tun_capture: sing_box.tun_capture,
        session_owner: sing_box.session_owner,
        readiness: sing_box.readiness,
        ..mihomo
    };
    assert_eq!(same, sing_box, "no undeclared difference");
}
