//! The real registry API, sandboxed below a throw-away `HKCU\Software\VPNTE-Test-hardening-*`
//! key (no elevation needed); the one `HKLM` test is ignored unless elevated.
use std::sync::Arc;

use vpnte_winnet::registry::{self, Access, Hive, Key, Value};

use super::*;
use crate::hardening::admit;
use crate::hardening::browser::{Browser, BrowserDirs, BrowserState, Browsers};
use crate::hardening::fake::reg;
use crate::hardening::location::{self, Location};
use crate::test_support::{TempDir, TestKey};
use crate::tweaks::journal::{Journal, TweakState};

fn exists(root: &TestKey, path: &str) -> bool {
    let path = format!(r"{}\{path}", root.0);
    Key::open(Hive::CurrentUser, &path, Access::Read, View::Native)
        .unwrap()
        .is_some()
}

/// Write / read-back keeps the type, `Absent` deletes the value, and pruning removes the keys
/// our write created (parents included) but never the first two levels or a non-empty key.
#[test]
fn values_round_trip_and_created_keys_are_pruned() {
    let root = TestKey::new("hardening");
    let sys = WinSystem::under(root.0.clone());
    let brave = reg(
        RegHive::Hklm,
        r"SOFTWARE\Policies\BraveSoftware\Brave",
        "DnsOverHttpsMode",
    );
    assert_eq!(sys.read(&brave).unwrap(), Val::Absent);
    assert!(sys.write(&brave, &Val::Sz("off".into())).unwrap());
    assert!(!sys.write(&brave, &Val::Sz("secure".into())).unwrap());
    assert_eq!(sys.read(&brave).unwrap(), Val::Sz("secure".into()));
    let expand = reg(RegHive::Hkcu, r"Software\X\Y", "E");
    sys.write(&expand, &Val::ExpandSz("%TEMP%\\x".into()))
        .unwrap();
    assert_eq!(
        sys.read(&expand).unwrap(),
        Val::ExpandSz("%TEMP%\\x".into())
    );
    let dword = reg(RegHive::Hklm, location::POLICY_KEY, "DisableLocation");
    sys.write(&dword, &Val::Dword(1)).unwrap();
    assert_eq!(sys.read(&dword).unwrap(), Val::Dword(1));

    // A value of someone else keeps the key.
    let other = reg(
        RegHive::Hklm,
        r"SOFTWARE\Policies\BraveSoftware\Brave",
        "Other",
    );
    sys.write(&other, &Val::Dword(5)).unwrap();
    sys.write(&brave, &Val::Absent).unwrap();
    assert_eq!(sys.read(&brave).unwrap(), Val::Absent);
    sys.prune(&brave).unwrap();
    assert!(exists(&root, r"HKLM\SOFTWARE\Policies\BraveSoftware\Brave"));

    sys.write(&other, &Val::Absent).unwrap();
    sys.prune(&brave).unwrap();
    assert!(!exists(&root, r"HKLM\SOFTWARE\Policies\BraveSoftware"));
    assert!(exists(&root, r"HKLM\SOFTWARE\Policies"));
    // Deleting an absent value or pruning an absent key is fine.
    sys.write(&brave, &Val::Absent).unwrap();
    sys.prune(&brave).unwrap();
}

/// A type the journal cannot hold is unreadable (apply must abort), never "absent".
#[test]
fn unsupported_type_is_unreadable() {
    let root = TestKey::new("hardening");
    let sys = WinSystem::under(root.0.clone());
    let path = format!(r"{}\HKLM\{}", root.0, location::POLICY_KEY);
    let (key, _) = Key::create(Hive::CurrentUser, &path, View::Native).unwrap();
    let raw = Value::Raw {
        kind: 3,
        data: vec![1, 2],
    };
    key.set("DisableLocation", &raw).unwrap();
    let target = reg(RegHive::Hklm, location::POLICY_KEY, "DisableLocation");
    let err = sys.read(&target).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    let text = Target::Git {
        key: crate::tweaks::journal::GitKey::HttpProxy,
    };
    assert_eq!(
        sys.read(&text).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
}

/// The whole browser path on the real registry API: detection through `App Paths`, apply,
/// read-back, rollback, and the keys we created are gone again.
#[test]
fn browsers_on_the_registry_api() {
    let root = TestKey::new("hardening");
    let sys: Arc<dyn System> = Arc::new(WinSystem::under(root.0.clone()));
    let app = reg(
        RegHive::Hklm,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
        "",
    );
    let exe = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
    sys.write(&app, &Val::Sz(exe.into())).unwrap();
    let dir = TempDir::new("hardening");
    let journal = Arc::new(Journal::open(&dir.0, admit));
    let browsers = Browsers::new(journal, sys.clone(), BrowserDirs::default());
    let report = browsers.apply_blocking().unwrap();
    let edge = report.browsers.iter().find(|e| e.browser == Browser::Edge);
    assert_eq!(edge.unwrap().state, BrowserState::Protected);
    let policy = reg(
        RegHive::Hklm,
        r"SOFTWARE\Policies\Microsoft\Edge",
        "WebRtcIPHandlingPolicy",
    );
    let ours = Val::Sz("disable_non_proxied_udp".into());
    assert_eq!(sys.read(&policy).unwrap(), ours);
    assert!(exists(&root, r"HKLM\SOFTWARE\Policies\Microsoft\Edge"));

    assert!(browsers.rollback_blocking().unwrap().success);
    assert_eq!(sys.read(&policy).unwrap(), Val::Absent);
    assert!(!exists(&root, r"HKLM\SOFTWARE\Policies\Microsoft"));
    assert!(exists(&root, r"HKLM\SOFTWARE\Policies"));
}

/// Location privacy on the real registry API: an unrelated value in the policy key survives.
#[test]
fn location_on_the_registry_api() {
    let root = TestKey::new("hardening");
    let sys: Arc<dyn System> = Arc::new(WinSystem::under(root.0.clone()));
    let unrelated = reg(RegHive::Hklm, location::POLICY_KEY, "Unrelated");
    sys.write(&unrelated, &Val::Dword(7)).unwrap();
    let dir = TempDir::new("hardening");
    let journal = Arc::new(Journal::open(&dir.0, admit));
    let location = Location::new(journal, sys.clone());
    let status = location.apply_blocking().unwrap();
    assert_eq!(status.ours, TweakState::On);
    assert_eq!(status.os_denied(), Some(true));
    assert!(location.rollback_blocking().is_complete());
    let status = location.status_blocking();
    assert_eq!(status.ours, TweakState::Off);
    assert_eq!(status.os_denied(), Some(false));
    assert_eq!(sys.read(&unrelated).unwrap(), Val::Dword(7));
}

/// Machine hive: write, read back, delete and prune under a throw-away
/// `HKLM\SOFTWARE\VPNTE-Test-hardening-*` key, removed afterwards.
#[test]
#[ignore = "needs elevation"]
fn elevated_machine_hive_write_and_prune() {
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = registry::delete_tree(Hive::LocalMachine, &self.0, View::Native);
        }
    }
    let base = Cleanup(format!(
        r"SOFTWARE\VPNTE-Test-hardening-{}",
        uuid::Uuid::new_v4()
    ));
    let sys = WinSystem::new();
    assert!(sys.elevated());
    let target = reg(RegHive::Hklm, &format!(r"{}\Policies\X", base.0), "V");
    assert!(sys.write(&target, &Val::Sz("x".into())).unwrap());
    assert_eq!(sys.read(&target).unwrap(), Val::Sz("x".into()));
    sys.write(&target, &Val::Absent).unwrap();
    sys.prune(&target).unwrap();
    let left = Key::open(Hive::LocalMachine, &base.0, Access::Read, View::Native).unwrap();
    assert!(left.unwrap().is_empty().unwrap());
}
