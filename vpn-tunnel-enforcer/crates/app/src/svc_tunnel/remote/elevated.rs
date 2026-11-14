//! Elevated end to end (CI's disposable elevated runner: `-- --ignored elevated_remote`): the
//! app's remote runtime starts a TUN session through the installed helper service against a
//! loopback upstream (a helper sing-box mixed proxy), stops it, and the service is uninstalled.
//! The service exe comes from this build's target folder (CI builds it in the step before); skips
//! quietly when not elevated or when the exe or the engines are missing.
//!
//! The second test runs the session from an UNELEVATED child (this test binary again, with the
//! LUA token of `tests/common`), as the app runs on the owner's PC: the elevated session alone
//! could never see that an unelevated app could not check the pipe's server (13.11.2026).
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, EnginePref, KillSwitchLevel, ProxyKind};
use vpnte_core::store::Store;
use vpnte_engine::singbox_process::SingBoxProcess;
use vpnte_tunnel::api::{CaptureKind, Mode, Origin, Runtime, StartRequest, StopOptions};

use super::Remote;
use super::tests::NoInputs;
use crate::api_settings::test_support::TempDir;
use crate::boot::service::RealService;
use crate::svc_core::docs::ProtectionDoc;

#[path = "../../../tests/common/mod.rs"]
mod common;

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");
/// Set only in the child: the helper proxy's port, and where it writes what happened.
const CHILD_PORT: &str = "VPNTE_E2E_CHILD_PORT";
const CHILD_REPORT: &str = "VPNTE_E2E_CHILD_REPORT";
/// The child's test (no `elevated_` in it: CI's filter must not run it on its own).
const CHILD_TEST: &str = "svc_tunnel::remote::elevated::lua_child_tunnel_session";

/// `target/<profile>/vpnte-service.exe` next to this test binary's `deps` folder.
fn built_service() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let built = exe.parent()?.parent()?.join("vpnte-service.exe");
    built.is_file().then_some(built)
}

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

/// Uninstalls whatever happened.
struct Uninstall(PathBuf);

impl Drop for Uninstall {
    fn drop(&mut self) {
        let _ = verb(&self.0, &["uninstall"]);
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

/// The installed service and a loopback upstream; dropped (fields in this order), the upstream
/// stops, the service is uninstalled with the exe still in `app`, then the folder goes.
struct Bench {
    _helper: SingBoxProcess,
    _uninstall: Uninstall,
    _real: RealService,
    app: TempDir,
    port: u16,
}

/// Installs this build's service and starts the upstream; `None` (said why) when the test
/// cannot run here.
async fn bench(name: &str) -> Option<Bench> {
    if !vpnte_winnet::elevation::is_elevated() {
        eprintln!("skipped: the process is not elevated");
        return None;
    }
    let (Some(built), Ok(resources)) = (built_service(), std::fs::canonicalize(RESOURCES)) else {
        eprintln!("skipped: vpnte-service.exe or the resources are missing");
        return None;
    };
    let text = resources.to_string_lossy().into_owned();
    let resources = PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text));
    if !resources.join("sing-box.exe").exists() {
        eprintln!("skipped: engine binaries missing under {RESOURCES}");
        return None;
    }
    let app = TempDir::new(name);
    let exe = app.0.join("vpnte-service.exe");
    std::fs::copy(&built, &exe).expect("copy the service build");
    let uninstall = Uninstall(exe.clone());
    // The service this test installs is the one it may reach (tests see none otherwise).
    let real = RealService::allow();
    let resources_arg = resources.to_string_lossy().into_owned();
    assert!(
        verb(&exe, &["install", "--resources", &resources_arg]),
        "install"
    );
    let port = vpnte_engine::ports::alloc_port(false, &[]).expect("free port");
    let helper = SingBoxProcess::spawn(&resources.join("sing-box.exe"), &helper_config(port), None)
        .expect("helper");
    helper
        .wait_ready(Duration::from_secs(20), &CancellationToken::new())
        .await
        .expect("helper ready");
    Some(Bench {
        _helper: helper,
        _uninstall: uninstall,
        _real: real,
        app,
        port,
    })
}

fn request(port: u16) -> StartRequest {
    StartRequest {
        mode: Mode::LocalProxy {
            addr: format!("127.0.0.1:{port}"),
            kind: ProxyKind::Socks5,
        },
        capture: CaptureKind::Tun,
        kill_switch: KillSwitchLevel::Standard,
        public_wifi: false,
        stealth: false,
        adaptive: AdaptiveMode::Baseline,
        engine: EnginePref::Auto,
        origin: Origin::User,
    }
}

/// A TUN session through the installed service, as the app's remote runtime runs it: started,
/// seen running with its endpoints, stopped. The panic message says which step failed.
async fn tun_session(dir: &Path, port: u16) {
    let protection = Arc::new(Store::<ProtectionDoc>::open(dir));
    let remote = Remote::new(Arc::new(NoInputs), protection, CancellationToken::new());
    assert!(remote.installed(), "the SCM knows the service");
    let receipt = remote
        .start(request(port), CancellationToken::new())
        .await
        .expect("TUN session through the service");
    let status = remote.status().borrow().clone();
    assert!(status.running, "{status:?}");
    assert_eq!(status.capture, Some(CaptureKind::Tun));
    assert!(receipt.generation >= 1);
    let session = status.session.expect("session endpoints for the app");
    assert!(session.clash_port > 0 && !session.clash_secret.is_empty());
    assert!(!remote.starting(), "linked: no longer starting");
    let stopped = remote.stop(StopOptions::default()).await;
    assert!(stopped.ok && stopped.runtime_stopped, "{stopped:?}");
    assert!(!remote.status().borrow().running);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs elevation"]
async fn elevated_remote_tun_session_through_the_installed_service() {
    let Some(bench) = bench("remote-e2e").await else {
        return;
    };
    tun_session(&bench.app.0, bench.port).await;
}

/// p-live-fix 3b: the same session from an unelevated app, the owner's case. This test binary
/// runs [`lua_child_tunnel_session`] under the LUA token (`tests/common`) and reports back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs elevation"]
async fn elevated_remote_tun_session_from_an_unelevated_app() {
    let Some(bench) = bench("remote-e2e-lua").await else {
        return;
    };
    let report = bench.app.0.join("child-report.txt");
    let exe = std::env::current_exe().expect("this test binary");
    let port = bench.port.to_string();
    let envs = [
        (CHILD_PORT, std::ffi::OsStr::new(&port)),
        (CHILD_REPORT, report.as_os_str()),
    ];
    let args = [CHILD_TEST, "--exact", "--ignored", "--test-threads=1"];
    let mut child = common::Child::spawn(&exe, &args, &envs);
    let code = tokio::task::spawn_blocking(move || child.exit_within(Duration::from_secs(180)))
        .await
        .expect("wait for the child");
    let said = std::fs::read_to_string(&report).unwrap_or_default();
    eprintln!("unelevated child: exit {code:?}, report: {said}");
    assert_eq!(code, Some(0), "the unelevated app's session: {said}");
    assert!(
        said.starts_with("ok") || said.starts_with("skipped"),
        "{said}"
    );
}

/// Not a test on its own: the unelevated app of `…_from_an_unelevated_app` (without its port it
/// does nothing, so a run of every ignored test passes it by).
#[test]
#[ignore = "child process of the unelevated end-to-end test"]
fn lua_child_tunnel_session() {
    let (Ok(port), Ok(report)) = (std::env::var(CHILD_PORT), std::env::var(CHILD_REPORT)) else {
        return;
    };
    let write = |text: &str| {
        let _ = std::fs::write(&report, text);
    };
    write("started");
    assert!(
        !vpnte_winnet::elevation::is_elevated(),
        "the child runs unelevated"
    );
    if !interactive() {
        write(
            "skipped: this logon is not interactive; the service's pipe admits interactive users",
        );
        return;
    }
    // SAFETY: this process runs this one test (`--exact`, one test thread) and nothing of ours
    // reads the environment yet; `tests/common` hides the service from every child app.
    unsafe { std::env::remove_var(crate::boot::service::ENV_NO_SERVICE) };
    let _real = RealService::allow();
    let dir = TempDir::new("remote-e2e-child");
    let port: u16 = port.parse().expect("the helper's port");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let session = std::panic::AssertUnwindSafe(|| runtime.block_on(tun_session(&dir.0, port)));
    match std::panic::catch_unwind(session) {
        Ok(()) => write("ok"),
        Err(panic) => {
            let text = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("panic");
            write(&format!("failed: {text}"));
            std::panic::resume_unwind(panic);
        }
    }
}

/// This process's token has the INTERACTIVE group enabled (the pipe's DACL admits interactive
/// users; a CI runner's service logon may not be one).
fn interactive() -> bool {
    use windows::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, PSID, SECURITY_MAX_SID_SIZE, WinInteractiveSid,
    };
    let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = SECURITY_MAX_SID_SIZE;
    let psid = PSID(sid.as_mut_ptr().cast());
    let mut member = windows::core::BOOL(0);
    // SAFETY: a buffer of the maximum SID size with its size, then that SID and an out flag; no
    // token handle: the thread's own token is checked.
    let checked = unsafe {
        CreateWellKnownSid(WinInteractiveSid, None, Some(psid), &mut len).is_ok()
            && CheckTokenMembership(None, psid, &mut member).is_ok()
    };
    checked && member.as_bool()
}
