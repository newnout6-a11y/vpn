//! Elevated end to end (CI's disposable elevated runner: `-- --ignored elevated_`): the app's
//! remote runtime starts a TUN session through the installed helper service against a loopback
//! upstream (a helper sing-box mixed proxy), stops it, and the service is uninstalled. The
//! service exe comes from this build's target folder (CI builds it in the step before); skips
//! quietly when not elevated or when the exe or the engines are missing.
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
use crate::svc_core::docs::ProtectionDoc;

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs elevation"]
async fn elevated_remote_tun_session_through_the_installed_service() {
    if !vpnte_winnet::elevation::is_elevated() {
        eprintln!("skipped: the process is not elevated");
        return;
    }
    let (Some(built), Ok(resources)) = (built_service(), std::fs::canonicalize(RESOURCES)) else {
        eprintln!("skipped: vpnte-service.exe or the resources are missing");
        return;
    };
    let text = resources.to_string_lossy().into_owned();
    let resources = PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text));
    if !resources.join("sing-box.exe").exists() {
        eprintln!("skipped: engine binaries missing under {RESOURCES}");
        return;
    }
    let app = TempDir::new("remote-e2e");
    let exe = app.0.join("vpnte-service.exe");
    std::fs::copy(&built, &exe).expect("copy the service build");
    let _uninstall = Uninstall(exe.clone());
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

    let protection = Arc::new(Store::<ProtectionDoc>::open(&app.0));
    let remote = Remote::new(Arc::new(NoInputs), protection, CancellationToken::new());
    assert!(remote.installed(), "the SCM knows the service");
    let request = StartRequest {
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
    };
    let receipt = remote
        .start(request, CancellationToken::new())
        .await
        .expect("TUN session through the service");
    let status = remote.status().borrow().clone();
    assert!(status.running, "{status:?}");
    assert_eq!(status.capture, Some(CaptureKind::Tun));
    assert!(receipt.generation >= 1);
    let session = status.session.expect("session endpoints for the app");
    assert!(session.clash_port > 0 && !session.clash_secret.is_empty());
    let stopped = remote.stop(StopOptions::default()).await;
    assert!(stopped.ok && stopped.runtime_stopped, "{stopped:?}");
    assert!(!remote.status().borrow().running);
    drop(helper);
}
