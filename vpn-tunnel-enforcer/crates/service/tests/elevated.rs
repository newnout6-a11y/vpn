//! Elevated end-to-end (CI's disposable elevated runner: `-- --ignored elevated_`): installs the
//! service from this build, talks to it over the real pipe, runs a TUN session against a loopback
//! upstream (a helper sing-box mixed proxy, as `crates/tunnel/tests/e2e_tun.rs`), stops it and
//! uninstalls, checking that nothing is left: no service, no folders, no WFP filter of ours.
//! A guard uninstalls even when an assertion fails. Skips quietly when not elevated.
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, EnginePref, KillSwitchLevel, ProxyKind};
use vpnte_engine::singbox_process::SingBoxProcess;
use vpnte_service::paths;
use vpnte_service::pipe::client::{CallError, Client, ServerCheck};
use vpnte_service::pipe::{Listener, PipeConfig};
use vpnte_service::proto::{
    ErrorCode, Reply, Request, RoutingInputs, StopTunnel, TunnelStart, Upstream,
};
use vpnte_service::scm::manage;
use vpnte_tunnel::api::Origin;
use vpnte_winnet::adapters;
use vpnte_winnet::wfp::ProtectionSettings;

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");
const BUILT: &str = env!("CARGO_BIN_EXE_vpnte-service");

fn verb(exe: &Path, args: &[&str]) -> bool {
    let out = Command::new(exe)
        .args(args)
        .output()
        .expect("run vpnte-service");
    eprintln!(
        "vpnte-service {args:?}: {} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
    out.status.success()
}

/// Uninstalls whatever happened (the built exe runs the same verb), kills the helper.
struct Guard {
    helper: Option<SingBoxProcess>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        drop(self.helper.take());
        let _ = verb(Path::new(BUILT), &["uninstall"]);
    }
}

fn helper_config(port: u16) -> Vec<u8> {
    serde_json::json!({
        "log": { "level": "info" },
        "inbounds": [{ "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    })
    .to_string()
    .into_bytes()
}

fn start_request(port: u16) -> Request {
    Request::Start(Box::new(TunnelStart {
        upstream: Upstream::LocalProxy {
            addr: format!("127.0.0.1:{port}").parse().expect("addr"),
            kind: ProxyKind::Socks5,
        },
        routing: RoutingInputs::default(),
        protection: ProtectionSettings {
            level: KillSwitchLevel::Standard,
            ..ProtectionSettings::default()
        },
        adaptive: AdaptiveMode::Baseline,
        engine: EnginePref::Auto,
        origin: Origin::User,
    }))
}

/// The installed service exe, as the SCM knows it.
fn installed() -> PathBuf {
    manage::installed_binary()
        .expect("SCM readable")
        .expect("service installed")
}

fn our_filters() -> usize {
    vpnte_winnet::wfp::Engine::open_dynamic()
        .and_then(|e| e.owned_filters())
        .map(|f| f.len())
        .unwrap_or(usize::MAX)
}

fn canonical(p: &Path) -> PathBuf {
    let full = std::fs::canonicalize(p).expect("canonical");
    let text = full.to_string_lossy().into_owned();
    PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text))
}

async fn connect(exe: &Path) -> Client {
    Client::connect(
        vpnte_service::sddl::PIPE_NAME,
        &ServerCheck::Image(exe.to_owned()),
        Duration::from_secs(10),
    )
    .await
    .expect("connect to the installed service")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs elevation"]
async fn elevated_install_tun_session_and_uninstall_leave_nothing() {
    if !vpnte_winnet::elevation::is_elevated() {
        eprintln!("skipped: the process is not elevated");
        return;
    }
    let resources = canonical(Path::new(RESOURCES));
    if !resources.join("sing-box.exe").exists() {
        eprintln!("skipped: engine binaries missing under {RESOURCES}");
        return;
    }
    let mut guard = Guard { helper: None };

    // 1. Install from a temp copy of this build, laid out like the app (exe + resources).
    let app = std::env::temp_dir().join(format!("vpnte-svc-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&app).expect("temp app dir");
    let exe = app.join("vpnte-service.exe");
    std::fs::copy(BUILT, &exe).expect("copy the build");
    let resources_arg = resources.to_string_lossy().into_owned();
    assert!(
        verb(&exe, &["install", "--resources", &resources_arg]),
        "install"
    );
    let service_exe = installed();
    assert_eq!(
        service_exe,
        paths::install_dir().expect("dir").join(paths::EXE_NAME)
    );
    assert!(vpnte_service::sddl::path_admin_only(
        service_exe.parent().expect("dir")
    ));

    // 2. The pipe is the service's: nobody else gets the first instance; one controller.
    assert!(
        Listener::bind(&PipeConfig::production()).is_err(),
        "the service holds the first instance"
    );
    let mut client = connect(&service_exe).await;
    let (protocol, _) = client.hello("e2e").await.expect("hello");
    assert_eq!(protocol, vpnte_service::proto::PROTOCOL);
    let mut second = connect(&service_exe).await;
    match second.hello("e2e").await {
        Err(CallError::Service(e)) => assert_eq!(e.code, ErrorCode::Busy),
        other => panic!("second client: {other:?}"),
    }
    drop(second);

    // 3. TUN session against a loopback helper proxy, kill switch standard.
    let port = vpnte_engine::ports::alloc_port(false, &[]).expect("free port");
    let helper = SingBoxProcess::spawn(&resources.join("sing-box.exe"), &helper_config(port), None)
        .expect("helper");
    helper
        .wait_ready(Duration::from_secs(20), &CancellationToken::new())
        .await
        .expect("helper ready");
    guard.helper = Some(helper);
    let started = client.call(start_request(port)).await.expect("TUN start");
    assert!(matches!(started, Reply::Started(Some(_))), "{started:?}");
    let Reply::Status(status) = client.call(Request::Status).await.expect("status") else {
        panic!("status reply");
    };
    let session = status.tunnel.session.clone().expect("session endpoints");
    let alias = session.tun_alias.clone().expect("TUN alias");
    let tun = adapters::wait_owned_tun(
        &alias,
        adapters::TUN_V4,
        Some(adapters::TUN_V6),
        Duration::from_secs(5),
        &CancellationToken::new(),
    )
    .await
    .expect("our TUN with our addresses");
    assert!(
        adapters::route_proof(&tun).unwrap_or(false),
        "routes via the TUN"
    );
    assert!(
        status.protection.dynamic_filters.unwrap_or(0) > 0,
        "kill switch filters present"
    );

    // 4. Stop: engines ended by themselves (the service has no console), protection released.
    let Reply::Stopped(receipt) = client
        .call(Request::Stop(StopTunnel::default()))
        .await
        .expect("stop")
    else {
        panic!("stop reply");
    };
    assert!(receipt.ok && receipt.runtime_stopped, "{receipt:?}");
    assert_eq!(receipt.protection_released, Some(true), "{receipt:?}");
    assert!(receipt.adapter_gone, "{receipt:?}");
    assert!(!receipt.forced, "sing-box had to be killed: {receipt:?}");
    drop(client);
    drop(guard.helper.take());

    // 5. Uninstall leaves no service, no folder, no filter of ours.
    assert!(verb(&exe, &["uninstall"]), "uninstall");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while manage::installed_binary().expect("SCM readable").is_some() {
        assert!(
            std::time::Instant::now() < deadline,
            "service still registered"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        !paths::install_dir().expect("dir").exists(),
        "program folder left"
    );
    assert!(
        !paths::data_dir().expect("dir").exists(),
        "data folder left"
    );
    assert_eq!(our_filters(), 0, "WFP filters left");
    let _ = std::fs::remove_dir_all(&app);
}
