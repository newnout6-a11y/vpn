//! Elevated checks of reviews 4555679947 and 4555679938 (CI's disposable elevated runner:
//! `-- --ignored elevated_`), with the real SCM, files and WFP:
//! - an upgrade that fails after stopping the old service starts it again;
//! - "Always" filters go before the service: by the elevated `uninstall`, and by the last user's
//!   `ForgetMe` (removed before the answer; the service then removes itself).
//!
//! The decision logic itself (which step follows which failure) is unit-tested with fakes in
//! `install::flow::tests` and `host::tests`. Skips quietly when not elevated.
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use vpnte_base::types::KillSwitchLevel;
use vpnte_service::paths;
use vpnte_service::pipe::client::{Client, ServerCheck};
use vpnte_service::proto::{Reply, Request};
use vpnte_service::scm::manage;
use vpnte_winnet::wfp::ProtectionSettings;

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");
const BUILT: &str = env!("CARGO_BIN_EXE_vpnte-service");

/// Runs a verb; its exit code.
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

/// Uninstalls whatever happened.
struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = verb(Path::new(BUILT), &["uninstall"]);
    }
}

/// Elevated and with the engines in place, else `None` (skipped).
fn ready() -> Option<PathBuf> {
    if !vpnte_winnet::elevation::is_elevated() {
        eprintln!("skipped: the process is not elevated");
        return None;
    }
    let resources = std::fs::canonicalize(RESOURCES).ok()?;
    let text = resources.to_string_lossy().into_owned();
    let resources = PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text));
    if !resources.join("sing-box.exe").exists() {
        eprintln!("skipped: engine binaries missing under {RESOURCES}");
        return None;
    }
    Some(resources)
}

/// Installs from a temp copy of this build, laid out like the app.
fn install(tag: &str, resources: &Path) -> PathBuf {
    let app = std::env::temp_dir().join(format!("vpnte-svc-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&app).expect("temp app dir");
    let exe = app.join("vpnte-service.exe");
    std::fs::copy(BUILT, &exe).expect("copy the build");
    let resources = resources.to_string_lossy().into_owned();
    assert_eq!(
        verb(&exe, &["install", "--resources", &resources]),
        0,
        "install"
    );
    exe
}

async fn connect() -> Client {
    let exe = manage::installed_binary()
        .expect("SCM readable")
        .expect("service installed");
    let mut client = Client::connect(
        vpnte_service::sddl::PIPE_NAME,
        &ServerCheck::Image(exe),
        Duration::from_secs(10),
    )
    .await
    .expect("connect to the installed service");
    client.hello("2.0.0-test").await.expect("hello");
    client
}

fn our_filters() -> usize {
    vpnte_winnet::wfp::Engine::open_dynamic()
        .and_then(|e| e.owned_filters())
        .map(|f| f.len())
        .unwrap_or(usize::MAX)
}

async fn always(client: &mut Client) {
    let strict = ProtectionSettings {
        level: KillSwitchLevel::Strict,
        ..ProtectionSettings::default()
    };
    let reply = client.call(Request::KillSwitch(Box::new(strict))).await;
    assert!(matches!(reply, Ok(Reply::Done { .. })), "{reply:?}");
    assert!(our_filters() > 0, "\"Always\" holds filters of ours");
}

/// Review 4555679947: an engine file held open makes the upgrade fail after the old service
/// stopped; the service runs and answers again afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs elevation"]
async fn elevated_a_failed_upgrade_starts_the_service_again() {
    let Some(resources) = ready() else { return };
    let _guard = Guard;
    let exe = install("upgrade", &resources);
    drop(connect().await);
    let held = paths::install_dir().expect("install dir").join("xray.exe");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&held)
        .expect("hold xray.exe");
    let resources = resources.to_string_lossy().into_owned();
    let code = verb(&exe, &["install", "--resources", &resources]);
    drop(lock);
    assert_eq!(code, 1, "the original error, the service started again");
    let mut client = connect().await;
    assert!(matches!(
        client.call(Request::Status).await,
        Ok(Reply::Status(_))
    ));
}

/// Review 4555679938: the elevated uninstall removes "Always" filters, then the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs elevation"]
async fn elevated_uninstall_removes_always_filters_then_the_service() {
    let Some(resources) = ready() else { return };
    let _guard = Guard;
    let exe = install("filters", &resources);
    always(&mut connect().await).await;
    assert_eq!(verb(&exe, &["uninstall"]), 0, "uninstall");
    assert_eq!(our_filters(), 0, "no filter of ours left");
    assert!(manage::installed_binary().expect("SCM").is_none());
}

/// The last user's `ForgetMe` removes "Always" filters before its answer, then the service
/// removes itself. CI's runner may count a second (installing) user: then only the filters stay
/// checked as untouched and the removal part is reported as skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs elevation"]
async fn elevated_the_last_leave_removes_filters_and_the_service() {
    let Some(resources) = ready() else { return };
    let _guard = Guard;
    install("leave", &resources);
    let mut client = connect().await;
    always(&mut client).await;
    drop(client);
    let removing = vpnte_service::per_user::forget_me()
        .await
        .expect("forget-me");
    if removing != Some(true) {
        eprintln!("skipped: another user is recorded ({removing:?})");
        return;
    }
    assert_eq!(our_filters(), 0, "filters removed before the answer");
    let deadline = Instant::now() + Duration::from_secs(30);
    while manage::installed_binary().expect("SCM").is_some() {
        assert!(Instant::now() < deadline, "the service removed itself");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
