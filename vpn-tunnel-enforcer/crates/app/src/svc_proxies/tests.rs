//! The proxies service over a throw-away server list: rows as slot candidates, the engine choice,
//! the control API on loopback, a real slot from a list row (bundled sing-box; skipped quietly
//! without it) and the stops of the VPN lifecycle and of the app exit. Every listener is on
//! 127.0.0.1 and the fake upstream answers every request itself: nothing leaves this PC.
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use vpnte_base::AppError;
use vpnte_base::types::{ClientDevice, EnginePref};
use vpnte_core::ops::OperationRegistry;
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_probes::key_health::{HealthError, ProbeCtx};
use vpnte_probes::ping::NetPath;
use vpnte_proxies::control::{ControlConfig, ENDPOINT_FILE, client};
use vpnte_proxies::manager::{EngineChoice, ProfileSource};
use vpnte_proxies::model::{Action, ProxyError, ServerStatus, StartRequest};
use vpnte_proxies::slot::Slot;
use vpnte_servers::model::ProfileId;
use vpnte_servers::store::{AddTarget, SelectBy, Servers};

use super::*;

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");
const KEY_A: &str = "vless://00000000-0000-4000-8000-00000000000a@203.0.113.20:443?security=tls&sni=example.com&type=tcp#Fake%20A";
const KEY_B: &str = "vless://00000000-0000-4000-8000-00000000000b@203.0.113.21:443?security=tls&sni=example.com&type=tcp#Fake%20B";

/// A throw-away data dir under %TEMP%, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("vpnte-wire-proxies-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Rig {
    dir: TempDir,
    servers: Arc<Servers>,
    settings: Arc<Store<Settings>>,
    source: Arc<ServerProfiles>,
}

fn rig(name: &str) -> Rig {
    let dir = TempDir::new(name);
    let servers = Arc::new(Servers::open(&dir.0));
    let settings = Arc::new(Store::<Settings>::open(&dir.0));
    let probe_ctx: ProbeCtxFn = Arc::new(|device| ProbeCtx {
        singbox_exe: Path::new(RESOURCES).join("sing-box.exe"),
        xray_exe: Path::new(RESOURCES).join("xray.exe"),
        engine_pref: EnginePref::Auto,
        device,
        net: NetPath { tun_direct: None },
        dns_bootstrap_in: None,
    });
    let source = Arc::new(ServerProfiles {
        servers: servers.clone(),
        settings: settings.clone(),
        ops: OperationRegistry::new(),
        probe_ctx,
    });
    Rig {
        dir,
        servers,
        settings,
        source,
    }
}

fn add(servers: &Servers, uri: &str, device: ClientDevice) -> ProfileId {
    let profile = vpnte_profiles::uri::parse_uri(uri).unwrap();
    let target = AddTarget::Keys {
        group: None,
        device,
    };
    servers.add(vec![profile], target).unwrap().added[0].clone()
}

/// A control server on an ephemeral loopback port, its files in the rig's dir.
fn control(r: &Rig) -> ControlConfig {
    ControlConfig {
        dir: r.dir.0.clone(),
        port: 0,
        fallback: false,
    }
}

/// Server list rows in list order; a key the user removed is not offered; key health or the
/// ping decides the status.
#[test]
fn rows_become_slot_candidates() {
    let r = rig("rows");
    let a = add(&r.servers, KEY_A, ClientDevice::default());
    let b = add(&r.servers, KEY_B, ClientDevice::default());
    let gone = add(
        &r.servers,
        KEY_A.replace("0a@", "0c@").as_str(),
        ClientDevice::default(),
    );
    r.servers.remove(&gone).unwrap();
    r.servers.record_ping(&a, Some(42));
    let rows = r.source.profiles();
    let ids: Vec<&str> = rows.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, [a.as_str(), b.as_str()]);
    assert_eq!(
        (rows[0].status, rows[0].ping_ms),
        (ServerStatus::Online, Some(42))
    );
    assert_eq!(
        (rows[1].status, rows[1].ping_ms),
        (ServerStatus::Unknown, None)
    );
    assert!(rows.iter().all(|p| p.usable() && p.group_id.is_some()));
    assert_eq!(rows[1].name, "Fake B");
}

/// The VPN's server is the list's selection; new slots take the engine setting and that
/// server's device (`EngineChoice` has one device for every start).
#[test]
fn the_vpn_server_steers_new_slots() {
    let r = rig("choice");
    add(&r.servers, KEY_A, ClientDevice::default());
    let b = add(&r.servers, KEY_B, ClientDevice::Android);
    r.servers.select(&b, SelectBy::User).unwrap();
    r.settings
        .update(|s| s.proxy_engine = EnginePref::SingBox)
        .unwrap();
    assert_eq!(
        r.source.active_vpn_profile_id().as_deref(),
        Some(b.as_str())
    );
    assert_eq!(
        r.source.engine_choice(),
        EngineChoice {
            pref: EnginePref::SingBox,
            device: ClientDevice::Android,
        }
    );
}

/// An unknown group is the key check's "not found or empty" (the control API answers 404).
#[tokio::test]
async fn an_unknown_group_is_not_found() {
    let r = rig("group");
    let err = r
        .source
        .check_group_health("no-such-group")
        .await
        .unwrap_err();
    assert_eq!(
        err.kind,
        AppError::from(HealthError::GroupNotFoundOrEmpty).kind
    );
}
/// Waits (≤ 5 s) for the control server's endpoint file and returns its port.
async fn control_port(dir: &Path) -> u16 {
    for _ in 0..100 {
        if let Some(url) = client::discover(&dir.join(ENDPOINT_FILE)) {
            return url.port();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no control endpoint file");
}

fn accepts(port: u16) -> bool {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok()
}

/// Spec external-proxy §3.28: the control API runs while the app runs, on 127.0.0.1 only; the
/// exit stop closes it and refuses later starts.
#[tokio::test]
async fn the_control_api_lives_until_the_exit_stop() {
    let r = rig("control");
    let id = add(&r.servers, KEY_A, ClientDevice::default());
    let shutdown = CancellationToken::new();
    let proxies = Proxies::start(
        r.source.clone(),
        Path::new(RESOURCES),
        control(&r),
        &shutdown,
    );
    let port = control_port(&r.dir.0).await;
    assert!(accepts(port), "control API on 127.0.0.1:{port}");
    let slots = proxies.slots();
    assert!(slots.state.borrow().instances.is_empty());
    proxies.shutdown().await;
    assert!(!accepts(port), "closed at exit");
    let late = slots.ops.add(id.0).await.unwrap_err();
    assert!(matches!(late, ProxyError::Unavailable(_)), "{late:?}");
    proxies.shutdown().await;
}

/// A SOCKS5 upstream (no auth) that plays the Internet on loopback: every CONNECT is answered
/// by the stub itself, so a slot's probes never leave this PC.
async fn fake_upstream() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                // Greeting -> no auth; request -> success; then hold until the client goes.
                if sock.read(&mut buf).await.is_ok_and(|n| n > 0) {
                    let _ = sock.write_all(&[5, 0]).await;
                }
                if sock.read(&mut buf).await.is_ok_and(|n| n > 0) {
                    let _ = sock.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                }
                while sock.read(&mut buf).await.is_ok_and(|n| n > 0) {}
            });
        }
    });
    port
}

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    probe.local_addr().unwrap().port()
}

/// A server of the list runs as a real slot (bundled sing-box) on a loopback port and shows in
/// the pushed state; a VPN stop ends the slot. Skipped quietly without the engine.
#[tokio::test]
async fn a_list_row_runs_as_a_slot_until_the_vpn_stops() {
    if !Path::new(RESOURCES).join("sing-box.exe").exists() {
        return;
    }
    let r = rig("slot");
    let upstream = fake_upstream().await;
    let id = add(
        &r.servers,
        &format!("socks5://127.0.0.1:{upstream}#Fake%20Socks"),
        ClientDevice::default(),
    );
    let shutdown = CancellationToken::new();
    let proxies = Proxies::start(
        r.source.clone(),
        Path::new(RESOURCES),
        control(&r),
        &shutdown,
    );
    let slots = proxies.slots();
    let port = free_port();
    let req = StartRequest {
        slot: Some(Slot::DEFAULT),
        profile_id: Some(id.0.clone()),
        port: Some(port),
        action: Action::Start,
        ..StartRequest::default()
    };
    let started = slots.ops.start(req).await.unwrap().instance;
    assert!(
        started.process_running && started.pid.is_some(),
        "{started:?}"
    );
    assert_eq!(started.proxy_url, Some(format!("http://127.0.0.1:{port}")));
    assert!(accepts(port));
    let mut state = slots.state.clone();
    let listed = state.wait_for(|s| s.instances.iter().any(|i| i.process_running));
    tokio::time::timeout(Duration::from_secs(5), listed)
        .await
        .expect("pushed")
        .expect("manager alive");
    proxies.vpn_stopped().await;
    let after = slots.ops.status(Slot::DEFAULT).await.instance;
    assert!(!after.process_running, "{after:?}");
    assert!(!accepts(port), "the slot port is closed");
    proxies.shutdown().await;
}
