//! p-svc-recheck, elevated (CI's disposable elevated runner: `-- --ignored elevated_`): the
//! installed service runs the leak self-test of its TUN session while the kill switch is on and
//! sends the result with its status (protocol 2), so the app shows it as its own runs. A guard
//! uninstalls whatever happened; skips quietly when not elevated. Not provable here: a real wake
//! (the SCM's power event) and a real network change; their handling is tested with fakes
//! (`service::recheck::tests`).
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, EnginePref, KillSwitchLevel, ProxyKind};
use vpnte_engine::singbox_process::SingBoxProcess;
use vpnte_probes::leak::{SelfTestVerdict, verdict};
use vpnte_service::pipe::client::{Client, ServerCheck};
use vpnte_service::proto::{
    Event, PROTOCOL, Reply, Request, RoutingInputs, StopTunnel, TunnelStart, Upstream,
};
use vpnte_service::scm::manage;
use vpnte_tunnel::api::Origin;
use vpnte_winnet::wfp::ProtectionSettings;

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");
const BUILT: &str = env!("CARGO_BIN_EXE_vpnte-service");

fn verb(exe: &Path, args: &[&str]) -> i32 {
    let out = Command::new(exe)
        .args(args)
        .output()
        .expect("run vpnte-service");
    eprintln!("vpnte-service {args:?}: {}", out.status);
    out.status.code().unwrap_or(-1)
}

/// Uninstalls whatever happened, ends the helper proxy.
struct Guard(Option<SingBoxProcess>);

impl Drop for Guard {
    fn drop(&mut self) {
        drop(self.0.take());
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
    resources.join("sing-box.exe").exists().then_some(resources)
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

async fn connect() -> Client {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let exe = manage::installed_binary().expect("SCM").expect("installed");
        let pipe = vpnte_service::sddl::PIPE_NAME;
        if let Ok(mut c) =
            Client::connect(pipe, &ServerCheck::Image(exe), Duration::from_secs(5)).await
            && c.hello("recheck").await.is_ok_and(|(p, _)| p == PROTOCOL)
        {
            return c;
        }
        assert!(Instant::now() < deadline, "the service answers");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// RU audit item 11: a TUN session under "If the VPN drops" gets the service's periodic
/// self-test (the first after a full 30 s period); the filters keep the adapter-bound probes in,
/// so it never reads as a leak, and the answer to `Status` carries the same run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs elevation"]
async fn elevated_the_service_self_tests_its_tun_session() {
    let Some(resources) = ready() else {
        return;
    };
    let app = std::env::temp_dir().join(format!("vpnte-recheck-{}", std::process::id()));
    std::fs::create_dir_all(&app).expect("temp app dir");
    let exe = app.join("vpnte-service.exe");
    std::fs::copy(BUILT, &exe).expect("copy the build");
    let mut guard = Guard(None);
    let dir = resources.to_string_lossy().into_owned();
    assert_eq!(verb(&exe, &["install", "--resources", &dir]), 0, "install");
    let (proxy, port) = helper(&resources).await;
    guard.0 = Some(proxy);
    let mut c = connect().await;
    let start = Request::Start(Box::new(TunnelStart {
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
    }));
    assert!(matches!(c.call(start).await, Ok(Reply::Started(Some(_)))));
    let deadline = Instant::now() + Duration::from_secs(90);
    let pushed = loop {
        assert!(Instant::now() < deadline, "a self-test within 90 s");
        let next = tokio::time::timeout(Duration::from_secs(5), c.next_event()).await;
        if let Ok(Ok(Event::Status(status))) = next
            && let Some(result) = status.self_test
        {
            break result;
        }
    };
    eprintln!("self-test: {:?}, {:?}", verdict(&pushed), pushed.probes);
    assert_ne!(
        verdict(&pushed),
        SelfTestVerdict::Leak,
        "the filters hold the probes"
    );
    match c.call(Request::Status).await {
        Ok(Reply::Status(status)) => assert!(status.tunnel.self_test.is_some()),
        other => panic!("status: {other:?}"),
    }
    let stopped = c.call(Request::Stop(StopTunnel::default())).await;
    assert!(matches!(stopped, Ok(Reply::Stopped(r)) if r.ok));
    drop(c);
    drop(guard);
    let _ = std::fs::remove_dir_all(&app);
}
