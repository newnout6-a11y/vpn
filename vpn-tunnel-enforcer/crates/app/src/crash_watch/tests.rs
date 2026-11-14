//! The crash guardian on throw-away places: a re-run of this test binary as the child, an
//! in-memory system proxy and an `HKCU\Software\VPNTE-Test-*` key instead of the user's
//! environment. Nothing here touches the real system proxy or the real data dir.
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use vpnte_automation::hardening;
use vpnte_automation::tweaks::{
    DevTargets, Journal, Soft, SoftSystem, SystemProxy, Writer, journal::TweakDoc,
};
use vpnte_base::types::ProxyKind;
use vpnte_core::net::HostPort;
use vpnte_core::store::Store;
use vpnte_winnet::env::UserEnv;
use vpnte_winnet::registry::{self, Access, Hive, Key, View};
use vpnte_winnet::sysproxy::ProxyConfig;

use super::*;
use crate::restore::{self, LogonValue};

/// Not a test: the child the spawn tests start (`--exact … --ignored`); it only waits.
#[test]
#[ignore = "child process of the spawn tests"]
fn sleeper() {
    std::thread::sleep(Duration::from_secs(120));
}

const SLEEPER: &str = "--exact crash_watch::tests::sleeper --ignored --quiet";

/// The watcher's process start: it runs until the app stops it.
#[test]
fn a_started_child_runs_until_stopped() {
    let exe = std::env::current_exe().unwrap();
    let child = spawn(&exe, SLEEPER).unwrap();
    assert!(child.running());
    child.stop();
    assert!(!child.running(), "gone after stop");
    assert!(child.wait(0));
}

/// The child of a process that is gone, or of a PID that was never ours, is not watched.
#[test]
fn only_a_running_older_process_is_watched() {
    assert!(watch::open_app(u32::MAX).is_none());
    assert_eq!(watch::watch(u32::MAX), EXIT_NOT_WATCHED);
    // Our own process started before the check: as for a real app and its watcher.
    assert!(watch::open_app(std::process::id()).is_some());
}

#[derive(Debug, Default)]
struct MemProxy(Mutex<ProxyConfig>);

impl SystemProxy for MemProxy {
    fn read(&self) -> io::Result<ProxyConfig> {
        Ok(self.0.lock().clone())
    }
    fn write(&self, config: &ProxyConfig) -> io::Result<()> {
        *self.0.lock() = config.clone();
        Ok(())
    }
}

/// A throw-away data dir and registry root, removed on drop.
struct Place {
    dir: PathBuf,
    key: String,
}

impl Place {
    fn new() -> Self {
        let id = uuid::Uuid::new_v4().simple();
        let dir = std::env::temp_dir().join(format!("vpnte-app-crash-watch-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            dir,
            key: format!(r"Software\VPNTE-Test-crash-watch-{id}"),
        }
    }

    fn system(&self, proxy: &Arc<MemProxy>) -> SoftSystem {
        SoftSystem {
            proxy: proxy.clone(),
            env: UserEnv::under(self.key.clone()),
            git: None,
            gradle_home: None,
            studio_root: None,
            broadcast: false,
            check_user: false,
        }
    }
}

impl Place {
    /// The logon value under this place's key instead of the real `RunOnce`.
    fn logon(&self) -> LogonValue {
        LogonValue::under(&self.run_once(), &std::env::current_exe().unwrap()).unwrap()
    }

    fn run_once(&self) -> String {
        format!(r"{}\RunOnce", self.key)
    }

    /// The command the logon value holds now (`None`: absent).
    fn logon_command(&self) -> Option<String> {
        Key::open(
            Hive::CurrentUser,
            &self.run_once(),
            Access::Read,
            View::Native,
        )
        .unwrap()
        .and_then(|key| key.string(restore::VALUE).unwrap())
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let _ = registry::delete_tree(Hive::CurrentUser, &self.key, View::Native);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn users_proxy() -> ProxyConfig {
    ProxyConfig {
        use_proxy: true,
        server: "proxy.example:3128".into(),
        bypass: "<local>".into(),
        ..ProxyConfig::default()
    }
}

/// A Soft session applied by "the app" `app` under `place` (the journal claims it for `app`).
fn session(place: &Place, proxy: &Arc<MemProxy>, app: Writer) {
    let journal = Arc::new(Journal::open(&place.dir, hardening::admit));
    let soft = Soft::new(journal, place.system(proxy));
    let addr = HostPort::parse("127.0.0.1:20809").unwrap();
    soft.apply_blocking(&addr, ProxyKind::Http, DevTargets::default())
        .unwrap();
    Store::<TweakDoc>::open(&place.dir)
        .update(|d| d.writer = Some(app))
        .unwrap();
}

const APP: Writer = Writer {
    pid: 5100,
    started: 7,
};

/// After its app died, the watcher puts the user's own proxy and variables back, and the logon
/// restore has nothing left to do: its value goes too (RU-2026 14c).
#[test]
fn the_watcher_rolls_back_what_its_app_left() {
    let place = Place::new();
    let proxy = Arc::new(MemProxy(Mutex::new(users_proxy())));
    session(&place, &proxy, APP);
    assert_ne!(proxy.read().unwrap(), users_proxy());
    let logon = place.logon();
    logon.set().unwrap();

    let report = watch::roll_back(&place.dir, place.system(&proxy), APP, Some(&logon));
    assert!(report.is_some_and(|r| r.is_complete()));
    assert_eq!(place.logon_command(), None);
    assert_eq!(proxy.read().unwrap(), users_proxy());
    assert_eq!(
        UserEnv::under(place.key.clone()).get("HTTP_PROXY").unwrap(),
        None
    );
}

/// A watcher whose app is not the journal's last writer touches nothing.
#[test]
fn the_watcher_leaves_another_app_s_journal_alone() {
    let place = Place::new();
    let proxy = Arc::new(MemProxy(Mutex::new(users_proxy())));
    session(&place, &proxy, APP);
    let other = Writer { pid: 5200, ..APP };
    let logon = place.logon();
    logon.set().unwrap();

    assert_eq!(
        watch::roll_back(&place.dir, place.system(&proxy), other, Some(&logon)),
        None
    );
    assert_ne!(proxy.read().unwrap(), users_proxy());
    let exe = std::env::current_exe().unwrap();
    let expected = format!("\"{}\" --restore-proxy", exe.display());
    assert_eq!(
        place.logon_command(),
        Some(expected),
        "the journal's owner keeps it"
    );
}
