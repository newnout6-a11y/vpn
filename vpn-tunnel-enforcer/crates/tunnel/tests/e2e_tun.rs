//! End-to-end TUN path (needs an elevated process; CI runners are elevated): a helper sing-box
//! serves as the local upstream proxy, the runtime starts a TUN against it with the kill switch
//! at `standard`, and the machine is checked before and after the stop. No secrets, no VPN
//! server. Skips quietly when not elevated or the engines are missing. A guard restores the
//! machine (full stop, dynamic WFP session closed, helper killed) even when an assertion fails.
#![cfg(feature = "tunnel-runtime")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::types::{AdaptiveMode, EnginePref, KillSwitchLevel, ProxyKind};
use vpnte_core::net::{Route, client_for};
use vpnte_engine::singbox_process::SingBoxProcess;
use vpnte_tunnel::api::{Mode, Origin, Runtime, StartRequest, StopOptions};
use vpnte_tunnel::runtime::{
    InputsSource, RealEngines, RuntimeDeps, Timings, TunCapture, TunnelHandle, UserInputs,
};
use vpnte_winnet::adapters;
use vpnte_winnet::wfp::{EnginePaths, KillSwitchState, Protection, ProtectionSettings};

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");
const PROBE_URL: &str = "https://www.gstatic.com/generate_204";
const OUTSIDE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);

/// Canonical path without the `\\?\` prefix: WFP app ids match the image path processes run from.
fn canonical(p: &Path) -> Option<PathBuf> {
    let full = std::fs::canonicalize(p).ok()?;
    let text = full.to_string_lossy();
    Some(PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text)))
}

struct NoStores;

#[async_trait]
impl InputsSource for NoStores {
    async fn snapshot(&self) -> AppResult<UserInputs> {
        Ok(UserInputs {
            kill_switch: KillSwitchLevel::Standard,
            ..UserInputs::default()
        })
    }
}

/// Restores the machine whatever happened: full stop, dynamic WFP session closed, helper gone.
struct Guard {
    runtime: Option<TunnelHandle>,
    protection: Arc<Protection>,
    helper: Option<SingBoxProcess>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let receipt = runtime.stop(StopOptions::default()).await;
                    eprintln!("guard stop: ok={}", receipt.ok);
                });
            });
        }
        // Closing the dynamic session makes BFE drop every filter of a standard session.
        self.protection.shutdown();
        drop(self.helper.take());
    }
}

/// A TCP connect to the outside from a socket bound to a physical adapter's address (strong
/// host send: it can only leave through that adapter, i.e. around the tunnel).
async fn connect_around_the_tunnel(source: Ipv4Addr) -> std::io::Result<()> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.bind(SocketAddr::new(IpAddr::V4(source), 0))?;
    match tokio::time::timeout(Duration::from_secs(5), socket.connect(OUTSIDE)).await {
        Ok(stream) => stream.map(drop),
        Err(_) => Err(std::io::ErrorKind::TimedOut.into()),
    }
}

async fn https_get() -> bool {
    let Ok(client) = client_for(&Route::Direct, Duration::from_secs(15)) else {
        return false;
    };
    client
        .get(PROBE_URL)
        .send()
        .await
        .is_ok_and(|r| r.status().is_success())
}

/// The helper upstream: a plain sing-box mixed proxy on loopback, straight out.
fn helper_config(port: u16) -> Vec<u8> {
    serde_json::json!({
        "log": { "level": "warn" },
        "inbounds": [{ "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    })
    .to_string()
    .into_bytes()
}

/// The whole TUN path against a local helper proxy (see the module doc).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs elevation"]
async fn elevated_tun_session_end_to_end() {
    if !vpnte_winnet::elevation::is_elevated() {
        eprintln!("skipped: the process is not elevated");
        return;
    }
    let (Some(singbox), Some(xray)) = (
        canonical(&Path::new(RESOURCES).join("sing-box.exe")),
        canonical(&Path::new(RESOURCES).join("xray.exe")),
    ) else {
        eprintln!("skipped: engine binaries missing under {RESOURCES}");
        return;
    };
    vpnte_base::http::init_tls();
    let Some(physical) = adapters::physical_adapters()
        .ok()
        .and_then(|list| list.iter().find_map(|a| a.source_v4().first().copied()))
    else {
        eprintln!("skipped: no physical IPv4 adapter");
        return;
    };
    let logs = std::env::temp_dir().join(format!("vpnte-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&logs).expect("log dir");
    let engines = EnginePaths {
        singbox: singbox.clone(),
        xray: Some(xray.clone()),
        external_proxy: None,
    };
    let settings = ProtectionSettings {
        level: KillSwitchLevel::Standard,
        ..ProtectionSettings::default()
    };
    // The test process stands in for every other program in the kill-switch check below, so it
    // must not get the app's own (all-interface) permit: an engine, permitted anyway, is named
    // as "our exe" instead.
    let protection = Arc::new(Protection::new(engines, singbox.clone(), settings));
    protection.startup().expect("WFP startup");
    let mut guard = Guard {
        runtime: None,
        protection: protection.clone(),
        helper: None,
    };

    // 1. The helper proxy.
    let port = vpnte_engine::ports::alloc_port(false, &[]).expect("free port");
    let helper = SingBoxProcess::spawn(&singbox, &helper_config(port), None).expect("helper");
    helper
        .wait_ready(Duration::from_secs(20), &CancellationToken::new())
        .await
        .expect("helper ready");
    guard.helper = Some(helper);

    // 2. The runtime in local-proxy mode, kill switch standard.
    let deps = RuntimeDeps {
        engines: Arc::new(RealEngines::new(singbox, xray, Some(logs.clone()))),
        capture: Arc::new(TunCapture::new(protection.clone())),
        inputs: Arc::new(NoStores),
        failover: None,
        confirmations: None,
        timings: Timings::default(),
    };
    let runtime = TunnelHandle::spawn(deps);
    guard.runtime = Some(runtime.clone());
    let req = StartRequest {
        mode: Mode::LocalProxy {
            addr: format!("127.0.0.1:{port}"),
            kind: ProxyKind::Socks5,
        },
        kill_switch: KillSwitchLevel::Standard,
        public_wifi: false,
        stealth: false,
        adaptive: AdaptiveMode::Baseline,
        engine: EnginePref::Auto,
        origin: Origin::User,
    };
    let receipt = runtime
        .start(req, CancellationToken::new())
        .await
        .expect("TUN start");
    let session = runtime.status().borrow().session.clone().expect("session");
    let alias = session.tun_alias.clone().expect("alias");

    // 3. Adapter with our addresses (standard = dual-stack), routes, traffic, kill switch.
    let tun = adapters::wait_owned_tun(
        &alias,
        adapters::TUN_V4,
        Some(adapters::TUN_V6),
        Duration::from_secs(2),
        &CancellationToken::new(),
    )
    .await
    .expect("our TUN with our addresses");
    assert_eq!(Some(tun.luid), session.tun_luid);
    assert!(
        adapters::route_proof(&tun).unwrap_or(false),
        "routes go through the TUN"
    );
    assert!(https_get().await, "HTTPS through the tunnel");
    assert!(
        connect_around_the_tunnel(physical).await.is_err(),
        "a socket bound to the physical adapter must be blocked"
    );
    let status = protection.status();
    assert_eq!(status.kill_switch, KillSwitchState::Engaged);
    assert!(
        status.dynamic_filters.unwrap_or(0) > 0,
        "our WFP filters are present"
    );

    // 4. Stop: engines gone, adapter gone, dynamic filters gone, plain traffic works again.
    let stop = runtime.stop(StopOptions::default()).await;
    guard.runtime = None;
    assert!(stop.confirms_cleanup(), "{stop:?}");
    assert!(stop.adapter_gone, "adapter gone after the stop");
    assert!(!adapters::adapter_present(tun.luid).unwrap_or(true));
    assert_eq!(runtime.last_exit().map(|e| e.user_initiated), Some(true));
    let after = protection.status();
    assert_eq!(
        after.dynamic_filters.unwrap_or(0),
        0,
        "dynamic filters removed"
    );
    assert!(
        connect_around_the_tunnel(physical).await.is_ok(),
        "plain traffic works"
    );
    assert!(https_get().await, "HTTPS without the tunnel");
    eprintln!(
        "e2e ok: generation {}, pid {}",
        receipt.generation, receipt.pid
    );
    let _ = std::fs::remove_dir_all(&logs);
}
