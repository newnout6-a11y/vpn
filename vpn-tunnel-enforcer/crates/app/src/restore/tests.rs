//! The logon restore on throw-away places: an in-memory system proxy, an
//! `HKCU\Software\VPNTE-Test-*` key for the variables and the `RunOnce` value, a temp data dir.
//! Nothing here touches the real system proxy, the real `RunOnce` key or the real data dir.
use std::ffi::c_void;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc as std_mpsc;

use parking_lot::Mutex;
use vpnte_automation::tweaks::{
    DevTargets, Journal, RollbackReport, SoftSystem, SystemProxy, Target, Writer,
};
use vpnte_base::types::ProxyKind;
use vpnte_core::net::HostPort;
use vpnte_core::store::Store;
use vpnte_winnet::env::UserEnv;
use vpnte_winnet::registry::{self, Access, Hive, Key, View};
use vpnte_winnet::sysproxy::ProxyConfig;
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    IsWindow, SendMessageW, WM_CLOSE, WM_ENDSESSION, WM_QUERYENDSESSION,
};

use super::*;

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

fn users_proxy() -> ProxyConfig {
    ProxyConfig {
        use_proxy: true,
        server: "proxy.example:3128".into(),
        bypass: "<local>".into(),
        ..ProxyConfig::default()
    }
}

/// A throw-away data dir, registry key and system proxy, removed on drop.
struct Place {
    dir: PathBuf,
    key: String,
    proxy: Arc<MemProxy>,
    logon: LogonValue,
}

impl Place {
    fn new() -> Self {
        let id = uuid::Uuid::new_v4().simple();
        let dir = std::env::temp_dir().join(format!("vpnte-app-restore-{id}"));
        let key = format!(r"Software\VPNTE-Test-restore-{id}");
        let exe = std::env::current_exe().unwrap();
        Self {
            logon: LogonValue::under(&format!(r"{key}\RunOnce"), &exe).unwrap(),
            dir,
            key,
            proxy: Arc::new(MemProxy(Mutex::new(users_proxy()))),
        }
    }

    fn system(&self) -> SoftSystem {
        SoftSystem {
            proxy: self.proxy.clone(),
            env: UserEnv::under(self.key.clone()),
            git: None,
            gradle_home: None,
            studio_root: None,
            broadcast: false,
            check_user: false,
        }
    }

    /// A Soft session applied by this process (the journal records it as the writer).
    fn session(&self) {
        let journal = Arc::new(Journal::open(&self.dir, hardening::admit));
        let addr = HostPort::parse("127.0.0.1:20809").unwrap();
        Soft::new(journal, self.system())
            .apply_blocking(&addr, ProxyKind::Http, DevTargets::default())
            .unwrap();
        assert_ne!(self.proxy.read().unwrap(), users_proxy());
    }

    /// The process that applied the session is gone (a logoff or a power loss ended it).
    fn writer_gone(&self) {
        let gone = Writer {
            pid: u32::MAX - 3,
            started: 1,
        };
        Store::<TweakDoc>::open(&self.dir)
            .update(|d| d.writer = Some(gone))
            .unwrap();
    }

    /// The command the logon value holds now (`None`: absent).
    fn logon_command(&self) -> Option<String> {
        let path = format!(r"{}\RunOnce", self.key);
        Key::open(Hive::CurrentUser, &path, Access::Read, View::Native)
            .unwrap()
            .and_then(|key| key.string(VALUE).unwrap())
    }

    fn http_proxy(&self) -> Option<String> {
        UserEnv::under(self.key.clone())
            .get("HTTP_PROXY")
            .unwrap()
            .map(|v| v.text().to_owned())
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let _ = registry::delete_tree(Hive::CurrentUser, &self.key, View::Native);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn expected_command() -> String {
    let exe = std::env::current_exe().unwrap();
    format!("\"{}\" --restore-proxy", exe.display())
}

/// The value runs this exe with `--restore-proxy`; writing it again and removing an absent one
/// are both fine.
#[test]
fn the_value_runs_the_exe_with_the_flag_and_goes_away() {
    let place = Place::new();
    place.logon.clear().unwrap();
    place.logon.set().unwrap();
    place.logon.set().unwrap();
    assert_eq!(place.logon_command(), Some(expected_command()));
    place.logon.clear().unwrap();
    assert_eq!(place.logon_command(), None);
    place.logon.clear().unwrap();
    let too_long = std::env::temp_dir().join("d".repeat(250)).join("app.exe");
    assert_eq!(
        LogonValue::under(&place.key, &too_long),
        None,
        "Windows would not run it"
    );
}

/// It follows a rollback: gone once complete, kept while a value waits for a retry.
#[test]
fn the_value_follows_the_rollback() {
    let place = Place::new();
    let failed = RollbackReport {
        failed: vec![Target::SystemProxy],
        ..RollbackReport::default()
    };
    place.logon.follow(&failed);
    assert_eq!(place.logon_command(), Some(expected_command()));
    place.logon.follow(&RollbackReport::default());
    assert_eq!(place.logon_command(), None);
}

/// RU-2026 14c: at sign-in, a session whose app still runs (autostart started it) stays; the
/// session of an app a power loss ended goes back. Without a journal nothing is created.
#[test]
fn the_logon_restore_undoes_only_a_session_whose_app_is_gone() {
    let place = Place::new();
    assert_eq!(roll_back_orphaned(&place.dir, place.system()), None);
    assert!(!place.dir.exists(), "nothing created without a journal");

    place.session();
    let live = roll_back_orphaned(&place.dir, place.system());
    assert_eq!(live, None, "this process wrote it and still runs");
    assert_ne!(place.proxy.read().unwrap(), users_proxy());

    place.writer_gone();
    let report = roll_back_orphaned(&place.dir, place.system());
    assert!(report.is_some_and(|r| r.is_complete()));
    assert_eq!(place.proxy.read().unwrap(), users_proxy());
    assert_eq!(place.http_proxy(), None);
}

/// At logoff the whole session goes back, as at the app's own exit; with nothing journalled
/// the value is left alone.
#[test]
fn the_session_end_rolls_back_every_soft_value() {
    let place = Place::new();
    place.session();
    place.logon.set().unwrap();

    let report = roll_back_at_end(&place.dir, place.system(), Some(&place.logon));
    assert!(report.is_complete() && !report.restored.is_empty());
    assert_eq!(place.proxy.read().unwrap(), users_proxy());
    assert_eq!(place.http_proxy(), None);
    assert_eq!(place.logon_command(), None);

    place.logon.set().unwrap();
    let again = roll_back_at_end(&place.dir, place.system(), Some(&place.logon));
    assert_eq!(again, RollbackReport::default());
    assert_eq!(place.logon_command(), Some(expected_command()));
}

/// The real window: the rollback runs on WM_ENDSESSION only when the session really ends; the
/// logoff itself is allowed, and WM_CLOSE (`taskkill` without /f) does not remove the guard.
#[test]
fn the_window_rolls_back_only_when_the_session_really_ends() {
    let (tx, rx) = std_mpsc::channel();
    let hwnd = session_end::start(move || {
        let _ = tx.send(());
    })
    .unwrap();
    let hwnd = HWND(hwnd as *mut c_void);
    let send = |msg: u32, wparam: usize| {
        // SAFETY: our own live window, pumped by its thread; SendMessageW waits for it.
        unsafe { SendMessageW(hwnd, msg, Some(WPARAM(wparam)), Some(LPARAM(0))) }.0
    };
    assert_ne!(send(WM_QUERYENDSESSION, 0), 0, "the logoff may go on");
    send(WM_ENDSESSION, 0);
    assert!(rx.try_recv().is_err(), "a refused logoff keeps the session");
    send(WM_ENDSESSION, 1);
    assert!(rx.try_recv().is_ok());
    send(WM_CLOSE, 0);
    // SAFETY: a plain query on a window handle.
    assert!(unsafe { IsWindow(Some(hwnd)) }.as_bool());
}
