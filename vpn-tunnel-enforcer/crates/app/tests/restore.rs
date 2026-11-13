//! The logon restore as shipped: the real exe started with `--restore-proxy`, as Windows starts
//! it from the `RunOnce` value at sign-in, on a throw-away data dir (`VPNTE_DATA_DIR`, which
//! also keeps it away from the real `RunOnce` key). `restore_exits_at_once_*` touches nothing of
//! the user's. `system_*` points the real per-user system proxy at a dead port, as a session a
//! power loss ended would leave it, and checks the restore puts it back
//! (`#[ignore = "changes system state"]`; CI runs it).
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vpnte_automation::hardening;
use vpnte_automation::tweaks::journal::TweakDoc;
use vpnte_automation::tweaks::{DevTargets, Feature, Journal, Soft, SoftSystem, Writer};
use vpnte_base::types::ProxyKind;
use vpnte_core::net::HostPort;
use vpnte_core::store::Store;
use windows::Win32::Foundation::HANDLE;

const APP: &str = env!("CARGO_BIN_EXE_vpn-tunnel-enforcer");

/// A throw-away data dir path, removed on drop (created only by what the test does).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let id = uuid::Uuid::new_v4().simple();
        Self(std::env::temp_dir().join(format!("vpnte-app-{tag}-{id}")))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs the real exe as Windows does at sign-in; the exit status within `limit` (killed after).
fn restore(data: &Path, limit: Duration) -> Option<ExitStatus> {
    let mut child = Command::new(APP)
        .arg("--restore-proxy")
        .env("VPNTE_DATA_DIR", data)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// RU-2026 14c: the process Windows starts at sign-in returns before any window, mutex or log,
/// and on a data dir without a journal (the app removed, nothing ever journalled) it creates
/// nothing.
#[test]
fn restore_exits_at_once_and_creates_nothing() {
    let data = TempDir::new("restore");
    let status = restore(&data.0, Duration::from_secs(15));
    assert_eq!(status.and_then(|s| s.code()), Some(0));
    assert!(!data.0.exists(), "no data dir created");
}

/// Rolls the test's own session back on drop: the machine never stays on the dead port, even
/// when an assertion fails before the restore did its work.
struct Undo(Soft);

impl Drop for Undo {
    fn drop(&mut self) {
        let _ = self.0.rollback_blocking();
    }
}

/// A process that has exited: the app a power loss ended.
fn gone_writer() -> Writer {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "no-such-test", "--quiet"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child.wait().unwrap();
    Writer::of_process(child.id(), HANDLE(child.as_raw_handle())).unwrap()
}

/// RU-2026 14c: the session of an app a power loss ended (its tweaks on the real per-user
/// system proxy and variables, its process gone) is rolled back by the sign-in restore.
#[test]
#[ignore = "changes system state"]
fn system_restore_puts_the_proxy_back_after_a_power_loss() {
    let data = TempDir::new("restore-system");
    let proxy_before = vpnte_winnet::sysproxy::read().unwrap();
    let env = vpnte_winnet::env::UserEnv::current_user();
    let http_before = env.get("HTTP_PROXY").unwrap();
    let journal = Arc::new(Journal::open(&data.0, hardening::admit));
    let soft = Soft::new(journal, SoftSystem::current_user());
    let _undo = Undo(soft.clone());
    let dead_port = HostPort::parse("127.0.0.1:9").unwrap();
    soft.apply_blocking(&dead_port, ProxyKind::Http, DevTargets::default())
        .unwrap();
    assert_ne!(vpnte_winnet::sysproxy::read().unwrap(), proxy_before);
    let gone = gone_writer();
    Store::<TweakDoc>::open(&data.0)
        .update(|d| d.writer = Some(gone))
        .unwrap();

    let status = restore(&data.0, Duration::from_secs(30));
    assert_eq!(status.and_then(|s| s.code()), Some(0));
    assert_eq!(vpnte_winnet::sysproxy::read().unwrap(), proxy_before);
    assert_eq!(env.get("HTTP_PROXY").unwrap(), http_before);
    let left = Journal::open(&data.0, hardening::admit);
    assert!(!left.is_applied(Feature::SoftProxy) && !left.is_applied(Feature::SoftEnv));
}
