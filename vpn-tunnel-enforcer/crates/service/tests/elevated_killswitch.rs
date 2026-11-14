//! ks-d, elevated (CI's disposable elevated runner: `-- --ignored elevated_`): the kill switch
//! through the installed service, with the real SCM, engines and WFP (research killswitch §3.1,
//! §5.4, §5.7, §9 package D). A guard uninstalls whatever happened. Skips quietly when not
//! elevated. Not provable without a reboot (recorded in `progress/ks-d.md`): that static filters
//! are gone after one, and that BFE leaves "Always" out at boot once the service is disabled or
//! gone; what the API shows of both is checked here.
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, EnginePref, KillSwitchLevel, ProxyKind};
use vpnte_engine::singbox_process::SingBoxProcess;
use vpnte_service::paths;
use vpnte_service::pipe::client::{Client, ServerCheck};
use vpnte_service::proto::{Reply, Request, RoutingInputs, StopTunnel, TunnelStart, Upstream};
use vpnte_service::scm::manage;
use vpnte_tunnel::api::Origin;
use vpnte_winnet::wfp::{
    Engine, FilterInfo, Layer, PROVIDER_KEY, ProtectionSettings, ProviderInfo,
};

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");
const BUILT: &str = env!("CARGO_BIN_EXE_vpnte-service");

fn verb(exe: &Path, args: &[&str]) -> i32 {
    let out = Command::new(exe)
        .args(args)
        .output()
        .expect("run vpnte-service");
    eprintln!(
        "vpnte-service {args:?}: {} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
    out.status.code().unwrap_or(-1)
}

/// Uninstalls whatever happened, ends the helper proxy.
struct Guard(Option<SingBoxProcess>);

impl Drop for Guard {
    fn drop(&mut self) {
        drop(self.0.take());
        let _ = manage::set_enabled(true);
        let _ = verb(Path::new(BUILT), &["uninstall"]);
    }
}

/// Elevated and with the engines in place, else `None` (skipped).
fn ready() -> Option<PathBuf> {
    if !vpnte_winnet::elevation::is_elevated() {
        eprintln!("skipped: the process is not elevated");
        return None;
    }
    let full = std::fs::canonicalize(RESOURCES).ok()?;
    let text = full.to_string_lossy().into_owned();
    let resources = PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text));
    if !resources.join("sing-box.exe").exists() {
        eprintln!("skipped: engine binaries missing under {RESOURCES}");
        return None;
    }
    Some(resources)
}

/// Installs from a temp copy of this build, laid out like the app.
fn install(tag: &str, resources: &Path) {
    let app = std::env::temp_dir().join(format!("vpnte-ksd-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&app).expect("temp app dir");
    let exe = app.join("vpnte-service.exe");
    std::fs::copy(BUILT, &exe).expect("copy the build");
    let resources = resources.to_string_lossy().into_owned();
    assert_eq!(
        verb(&exe, &["install", "--resources", &resources]),
        0,
        "install"
    );
}

/// A loopback mixed proxy the TUN session uses as its upstream.
async fn helper(resources: &Path) -> (SingBoxProcess, u16) {
    let port = vpnte_engine::ports::alloc_port(false, &[]).expect("free port");
    let config = serde_json::json!({
        "log": { "level": "info" },
        "inbounds": [{ "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    });
    let exe = resources.join("sing-box.exe");
    let helper = SingBoxProcess::spawn(&exe, config.to_string().as_bytes(), None).expect("helper");
    let cancel = CancellationToken::new();
    let ready = helper.wait_ready(Duration::from_secs(20), &cancel);
    ready.await.expect("helper ready");
    (helper, port)
}

fn start(port: u16, level: KillSwitchLevel) -> Request {
    Request::Start(Box::new(TunnelStart {
        upstream: Upstream::LocalProxy {
            addr: format!("127.0.0.1:{port}").parse().expect("addr"),
            kind: ProxyKind::Socks5,
        },
        routing: RoutingInputs::default(),
        protection: ProtectionSettings {
            level,
            ..ProtectionSettings::default()
        },
        adaptive: AdaptiveMode::Baseline,
        engine: EnginePref::Auto,
        origin: Origin::User,
    }))
}

/// Connects and says hello, retrying while the service (re)starts.
async fn connect() -> Client {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let exe = manage::installed_binary().expect("SCM").expect("installed");
        let check = ServerCheck::Image(exe);
        let pipe = vpnte_service::sddl::PIPE_NAME;
        if let Ok(mut c) = Client::connect(pipe, &check, Duration::from_secs(5)).await
            && c.hello("ks-d").await.is_ok()
        {
            return c;
        }
        assert!(Instant::now() < deadline, "the service answers");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn ours() -> Vec<FilterInfo> {
    Engine::open_persistent()
        .and_then(|e| e.owned_filters())
        .expect("WFP readable")
}

/// `FWP_ACTION_BLOCK` (`FWP_ACTION_FLAG_TERMINATING | 1`).
const BLOCK: u32 = 0x1001;

/// "If the VPN drops": the IPv4 block-all of the session set (static in the service).
fn static_block() -> bool {
    ours().iter().any(|f| {
        let block_all = f.action == BLOCK && f.weight == Some(0);
        !f.is_persistent() && f.layer == Layer::Connect4.key() && block_all
    })
}

fn provider() -> Option<ProviderInfo> {
    Engine::open_persistent()
        .and_then(|e| e.provider(&PROVIDER_KEY))
        .expect("WFP readable")
}

/// Ends a process the test started (through the service) the hard way.
fn kill(pid: u32) {
    let out = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .output();
    assert!(out.is_ok_and(|o| o.status.success()), "taskkill {pid}");
}

/// AT-03-001 through the service: the engine dies under a TUN session with "If the VPN drops";
/// the static block-all holds (nothing persistent), a stop removes everything of ours.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs elevation"]
async fn elevated_at_03_001_the_engine_dies_and_the_static_block_holds() {
    let Some(resources) = ready() else { return };
    let mut guard = Guard(None);
    install("at001", &resources);
    let (proxy, port) = helper(&resources).await;
    guard.0 = Some(proxy);
    let mut client = connect().await;
    let started = client.call(start(port, KillSwitchLevel::Standard)).await;
    assert!(
        matches!(started, Ok(Reply::Started(Some(_)))),
        "{started:?}"
    );
    let Ok(Reply::Status(status)) = client.call(Request::Status).await else {
        panic!("status");
    };
    assert!(static_block(), "armed after the tunnel came up");
    kill(status.tunnel.pid.expect("engine pid"));
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(static_block(), "the block holds after the drop");
    assert!(
        ours().iter().all(|f| !f.is_persistent()),
        "nothing persistent"
    );
    let stopped = client.call(Request::Stop(StopTunnel::default())).await;
    assert!(matches!(stopped, Ok(Reply::Stopped(_))), "{stopped:?}");
    assert!(ours().is_empty(), "a stop removes every filter of ours");
}

/// AT-03-002 through the service: the service itself is killed with the drop armed. Its static
/// block survives the crash; Windows restarts it, it takes the block over and starts the session
/// again for this user; a stop leaves nothing. (After a reboot nothing static exists at all:
/// WFP's documented lifetime, not provable here.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs elevation"]
async fn elevated_at_03_002_a_killed_service_keeps_its_block_and_resumes() {
    let Some(resources) = ready() else { return };
    let mut guard = Guard(None);
    install("at002", &resources);
    let (proxy, port) = helper(&resources).await;
    guard.0 = Some(proxy);
    let mut client = connect().await;
    let started = client.call(start(port, KillSwitchLevel::Standard)).await;
    assert!(
        matches!(started, Ok(Reply::Started(Some(_)))),
        "{started:?}"
    );
    let pid = manage::process_id().expect("SCM").expect("running");
    kill(pid);
    drop(client);
    assert!(static_block(), "the block survives the service's crash");
    let deadline = Instant::now() + Duration::from_secs(90);
    while manage::process_id().expect("SCM").is_none_or(|p| p == pid) {
        assert!(Instant::now() < deadline, "Windows restarts the service");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let mut client = connect().await;
    let deadline = Instant::now() + Duration::from_secs(60);
    let kept = loop {
        let Ok(Reply::Status(status)) = client.call(Request::Status).await else {
            panic!("status");
        };
        if let Some(kept) = status.kept {
            break kept;
        }
        assert!(Instant::now() < deadline, "the session started again");
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(kept.local_proxy.map(|a| a.port()), Some(port));
    assert!(static_block(), "held through the restart");
    let stopped = client.call(Request::Stop(StopTunnel::default())).await;
    assert!(matches!(stopped, Ok(Reply::Stopped(_))), "{stopped:?}");
    assert!(ours().is_empty(), "nothing of ours after the stop");
}

/// "Always" belongs to the service: persistent filters under a provider registered with the
/// service's name — what lets BFE leave them out at boot once the service is disabled or gone,
/// even after a failed cleanup. With `VPNTE_BFE_RESTART_TESTS` set, BFE is restarted with the
/// service disabled: the provider reads disabled and no persistent filter of ours is active (the
/// valve itself); enabled again, the next BFE start brings "Always" back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs elevation"]
async fn elevated_always_belongs_to_the_service_provider() {
    let Some(resources) = ready() else { return };
    let _guard = Guard(None);
    install("always", &resources);
    let mut client = connect().await;
    let strict = ProtectionSettings {
        level: KillSwitchLevel::Strict,
        ..ProtectionSettings::default()
    };
    let reply = client.call(Request::KillSwitch(Box::new(strict))).await;
    assert!(matches!(reply, Ok(Reply::Done { .. })), "{reply:?}");
    assert!(
        ours().iter().any(|f| f.is_persistent()),
        "Always is persistent"
    );
    let p = provider().expect("our provider");
    assert_eq!(p.service_name.as_deref(), Some(paths::SERVICE_NAME));
    assert!(!p.disabled(), "flags {:#x}", p.flags);
    drop(client);
    if std::env::var_os("VPNTE_BFE_RESTART_TESTS").is_none() {
        eprintln!("BFE restart part skipped (VPNTE_BFE_RESTART_TESTS not set)");
        return;
    }
    manage::set_enabled(false).expect("disable the service");
    restart_bfe();
    let p = provider().expect("our provider");
    eprintln!(
        "after a BFE start with the service disabled: provider flags {:#x}",
        p.flags
    );
    assert!(
        p.disabled(),
        "BFE disabled our provider: Always is not enforced"
    );
    let persistent = ours().iter().filter(|f| f.is_persistent()).count();
    assert_eq!(persistent, 0, "no persistent filter of ours is active");
    manage::set_enabled(true).expect("enable the service");
    restart_bfe();
    assert!(!provider().expect("our provider").disabled());
    assert!(ours().iter().any(|f| f.is_persistent()), "Always is back");
}

/// Restarts the Base Filtering Engine (and the services that depend on it).
fn restart_bfe() {
    let script = "Restart-Service -Name BFE -Force";
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output();
    assert!(out.is_ok_and(|o| o.status.success()), "BFE restarted");
}
