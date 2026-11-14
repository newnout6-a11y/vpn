//! The crash watcher as shipped: the real exe started with `--crash-watch <pid>` over a
//! throw-away child (this test binary, re-run as a sleeper) and a throw-away data dir.
//! `watcher_waits_cheaply_*` touches nothing of the user's: its journal stays empty.
//! `system_*` points the real per-user system proxy at a dead port and checks the watcher puts it
//! back after the child is killed (`#[ignore = "changes system state"]`; CI runs it).
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use vpnte_automation::hardening;
use vpnte_automation::tweaks::journal::TweakDoc;
use vpnte_automation::tweaks::{DevTargets, Feature, Journal, Soft, SoftSystem, Writer};
use vpnte_base::types::ProxyKind;
use vpnte_core::net::HostPort;
use vpnte_core::store::Store;
use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};

mod common;

const APP: &str = env!("CARGO_BIN_EXE_vpn-tunnel-enforcer");

/// Not a test: the throw-away child the watcher watches (`sleeper --exact --ignored`).
#[test]
#[ignore = "child process of the crash-watch tests"]
fn sleeper() {
    std::thread::sleep(Duration::from_secs(120));
}

/// A started process, unelevated as the app's main mode (`common::Child`: CI runs the tests
/// elevated, and an elevated process ignores `VPNTE_DATA_DIR`), ended on drop if still running.
struct Proc(common::Child);

impl Proc {
    fn sleeper() -> Self {
        let exe = std::env::current_exe().unwrap();
        Self(common::Child::spawn(
            &exe,
            &["sleeper", "--exact", "--ignored", "--quiet"],
            &[],
        ))
    }

    fn watcher(of: &Proc, data: &Path) -> Self {
        let pid = of.0.id().to_string();
        Self(common::Child::spawn(
            Path::new(APP),
            &["--crash-watch", &pid],
            &[("VPNTE_DATA_DIR", data.as_os_str())],
        ))
    }

    /// The exit code within `limit`, `None` while it still runs.
    fn exit_within(&mut self, limit: Duration) -> Option<i32> {
        self.0.exit_within(limit)
    }

    /// (working set, private bytes) in KiB.
    fn memory_kib(&self) -> (usize, usize) {
        let mut c = PROCESS_MEMORY_COUNTERS_EX::default();
        let size = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
        // SAFETY: our own child's handle and a sized out-buffer of the EX layout.
        let ok = unsafe { K32GetProcessMemoryInfo(self.0.handle(), (&raw mut c).cast(), size) };
        assert!(ok.as_bool(), "memory counters");
        (c.WorkingSetSize / 1024, c.PrivateUsage / 1024)
    }
}

/// A throw-away data dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let id = uuid::Uuid::new_v4().simple();
        let dir = std::env::temp_dir().join(format!("vpnte-app-{tag}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// research killswitch §6 item 6: the watcher only waits (no CPU, a small working set) and
/// leaves quietly once its app is gone and the journal holds nothing of it.
#[test]
fn watcher_waits_cheaply_and_leaves_with_its_app() {
    let data = TempDir::new("crash-watch");
    let mut app = Proc::sleeper();
    let mut watcher = Proc::watcher(&app, &data.0);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        watcher.exit_within(Duration::ZERO),
        None,
        "waits while the app lives"
    );
    let (ws, private) = watcher.memory_kib();
    eprintln!("crash watcher while waiting: working set {ws} KiB, private {private} KiB");
    assert!(ws < 32 * 1024, "working set {ws} KiB");

    app.0.kill();
    assert_eq!(watcher.exit_within(Duration::from_secs(15)), Some(0));
}

/// Rolls the test's own session back on drop: the machine never stays on the dead port, even
/// when an assertion fails before the watcher did its work.
struct Restore(Soft);

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = self.0.rollback_blocking();
    }
}

/// ks-b (research killswitch §5.5): an app killed while its proxy session holds the per-user
/// system proxy and the proxy variables: its watcher puts both back.
#[test]
#[ignore = "changes system state"]
fn system_watcher_rolls_back_after_a_kill() {
    let data = TempDir::new("crash-watch-system");
    let proxy_before = vpnte_winnet::sysproxy::read().unwrap();
    let env = vpnte_winnet::env::UserEnv::current_user();
    let http_before = env.get("HTTP_PROXY").unwrap();
    let mut app = Proc::sleeper();
    let journal = Arc::new(Journal::open(&data.0, hardening::admit));
    let soft = Soft::new(journal, SoftSystem::current_user());
    let _restore = Restore(soft.clone());
    let dead_port = HostPort::parse("127.0.0.1:9").unwrap();
    soft.apply_blocking(&dead_port, ProxyKind::Http, DevTargets::default())
        .unwrap();
    assert_ne!(vpnte_winnet::sysproxy::read().unwrap(), proxy_before);
    // The child stands for the app: the journal is its, as the app's own apply would leave it.
    let writer = Writer::of_process(app.0.id(), app.0.handle()).unwrap();
    Store::<TweakDoc>::open(&data.0)
        .update(|d| d.writer = Some(writer))
        .unwrap();

    let mut watcher = Proc::watcher(&app, &data.0);
    std::thread::sleep(Duration::from_millis(500));
    app.0.kill();
    assert_eq!(watcher.exit_within(Duration::from_secs(30)), Some(0));
    assert_eq!(vpnte_winnet::sysproxy::read().unwrap(), proxy_before);
    assert_eq!(env.get("HTTP_PROXY").unwrap(), http_before);
    let left = Journal::open(&data.0, hardening::admit);
    assert!(!left.is_applied(Feature::SoftProxy) && !left.is_applied(Feature::SoftEnv));
}
