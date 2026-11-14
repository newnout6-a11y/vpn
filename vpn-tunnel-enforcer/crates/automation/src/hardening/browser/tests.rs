use std::path::PathBuf;
use std::sync::Arc;

use vpnte_base::{ErrorKind, Msg};

use super::*;
use crate::hardening::admit;
use crate::hardening::fake::{Fake, reg};
use crate::test_support::{TempDir, ru};
use crate::tweaks::journal::{Feature, Journal, Record, RegHive, Target, Val};

const CHROME: &str = r"SOFTWARE\Policies\Google\Chrome";
const EDGE: &str = r"SOFTWARE\Policies\Microsoft\Edge";
const CHROME_EXE: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
const EDGE_EXE: &str = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
const LOCAL: &str = r"C:\Users\u\AppData\Local";
const ROAMING: &str = r"C:\Users\u\AppData\Roaming";

struct Setup {
    _dir: TempDir,
    fake: Arc<Fake>,
    journal: Arc<Journal>,
    browsers: Browsers,
}

fn setup(fake: Fake) -> Setup {
    let dir = TempDir::new("hardening");
    let fake = Arc::new(fake);
    let journal = Arc::new(Journal::open(&dir.0, admit));
    let dirs = BrowserDirs {
        local: Some(PathBuf::from(LOCAL)),
        roaming: Some(PathBuf::from(ROAMING)),
    };
    let browsers = Browsers::new(journal.clone(), fake.clone(), dirs);
    Setup {
        _dir: dir,
        fake,
        journal,
        browsers,
    }
}

fn with_chrome() -> Fake {
    let fake = Fake::default();
    fake.app_path("chrome.exe", CHROME_EXE);
    fake
}

fn webrtc(key: &str) -> Target {
    reg(RegHive::Hklm, key, "WebRtcIPHandlingPolicy")
}

fn doh(key: &str) -> Target {
    reg(RegHive::Hklm, key, "DnsOverHttpsMode")
}

fn ours() -> Val {
    Val::Sz("disable_non_proxied_udp".into())
}

fn state(report: &BrowserReport, browser: Browser) -> BrowserState {
    let entry = report.browsers.iter().find(|e| e.browser == browser);
    entry.unwrap().state.clone()
}

/// AT-09-005 (`browserHardening.test.ts`): no browsers → success, nothing changed, «не найдены».
#[test]
fn no_browsers_found() {
    let s = setup(Fake::default());
    let r = s.browsers.apply_blocking().unwrap();
    assert!(r.success && !r.restart_required);
    assert_eq!(r.message, Some(Msg::new(NONE_FOUND)));
    assert!(ru(NONE_FOUND).contains("не найдены"));
    assert!(
        r.browsers
            .iter()
            .all(|e| e.state == BrowserState::NotInstalled)
    );
    assert_eq!(s.fake.write_count(), 0);
}

/// AT-09-005: Chrome installed → HKLM `SOFTWARE\Policies\Google\Chrome` gets the WebRTC and DoH
/// policies, status Protected; a second apply writes nothing; HKCU is never touched.
#[test]
fn chrome_gets_machine_policies() {
    let s = setup(with_chrome());
    let r = s.browsers.apply_blocking().unwrap();
    assert_eq!(s.fake.get(&webrtc(CHROME)), ours());
    assert_eq!(s.fake.get(&doh(CHROME)), Val::Sz("off".into()));
    assert_eq!(state(&r, Browser::Chrome), BrowserState::Protected);
    assert_eq!(state(&r, Browser::Edge), BrowserState::NotInstalled);
    assert!(r.success && r.restart_required);
    assert_eq!(r.message, Some(Msg::new(APPLIED)));
    assert!(r.notes.contains(&Msg::new(MANAGED)));
    let writes = s.fake.writes.lock().clone();
    assert!(writes.iter().all(|(t, _)| matches!(
        t,
        Target::Reg {
            hive: RegHive::Hklm,
            ..
        }
    )));
    assert!(s.browsers.is_applied());

    let r = s.browsers.apply_blocking().unwrap();
    assert_eq!(s.fake.write_count(), writes.len());
    assert_eq!(r.message, Some(Msg::new(ALREADY)));
    assert!(!r.restart_required);
    let status = s.browsers.status_blocking();
    assert_eq!(state(&status, Browser::Chrome), BrowserState::Protected);
}

/// AT-09-005: a read-back mismatch fails that browser with «не была подтверждена при обратном
/// чтении» and leaves nothing behind.
#[test]
fn read_back_mismatch_fails_and_undoes() {
    let fake = with_chrome();
    fake.garble.lock().insert(doh(CHROME));
    let s = setup(fake);
    let r = s.browsers.apply_blocking().unwrap();
    let reason = Msg::new(NOT_CONFIRMED);
    assert_eq!(state(&r, Browser::Chrome), BrowserState::Failed { reason });
    assert_eq!(r.message, Some(Msg::new(NOT_CONFIRMED)));
    assert!(ru(NOT_CONFIRMED).contains("не была подтверждена при обратном чтении"));
    assert!(!r.success);
    assert_eq!(s.fake.get(&webrtc(CHROME)), Val::Absent);
    assert_eq!(s.fake.get(&doh(CHROME)), Val::Absent);
    assert!(!s.browsers.is_applied());
}

/// AT-09-001 / B2: rollback restores a value only while it is still ours; one an administrator
/// changed since is kept and reported.
#[test]
fn rollback_restores_only_still_ours() {
    let s = setup(with_chrome());
    s.browsers.apply_blocking().unwrap();
    s.fake.set(&webrtc(CHROME), Val::Sz("default".into()));
    let r = s.browsers.rollback_blocking().unwrap();
    assert_eq!(s.fake.get(&webrtc(CHROME)), Val::Sz("default".into()));
    assert_eq!(s.fake.get(&doh(CHROME)), Val::Absent);
    assert_eq!(r.message, Some(Msg::new(ROLLED_BACK)));
    assert!(r.success && r.restart_required);
    let kept = Msg::new("automation.tweaks.keptUserValue").arg("count", 1);
    assert_eq!(r.notes, vec![kept]);
    assert!(!s.browsers.is_applied());
    assert_eq!(state(&r, Browser::Chrome), BrowserState::Off);
}

/// Owner decision 10.2-B: Vivaldi, Opera, Chromium and Firefox are detected, shown as not
/// checked, and nothing is written for them.
#[test]
fn unverified_browsers_are_never_touched() {
    let fake = Fake::default();
    let local = r"C:\Users\u\AppData\Local";
    fake.app_path(
        "vivaldi.exe",
        &format!(r"{local}\Vivaldi\Application\vivaldi.exe"),
    );
    // Chromium registers `chrome.exe` too: its path tells it apart from Chrome.
    fake.app_path(
        "chrome.exe",
        &format!(r"{local}\Chromium\Application\chrome.exe"),
    );
    for dir in [r"Opera Software\Opera Stable", r"Mozilla\Firefox\Profiles"] {
        fake.dirs.lock().insert(PathBuf::from(ROAMING).join(dir));
    }
    let s = setup(fake);
    let r = s.browsers.apply_blocking().unwrap();
    for b in [
        Browser::Vivaldi,
        Browser::Chromium,
        Browser::Opera,
        Browser::Firefox,
    ] {
        assert_eq!(state(&r, b), BrowserState::NotVerified, "{b:?}");
        assert!(!b.verified());
    }
    assert_eq!(state(&r, Browser::Chrome), BrowserState::NotInstalled);
    assert_eq!(s.fake.write_count(), 0);
    assert_eq!(r.message, Some(Msg::new(NONE_FOUND)));
}

/// `--no-elevate`: machine policies are refused with a Permission error before any write.
#[test]
fn unelevated_apply_is_refused() {
    let fake = with_chrome();
    let s = setup(Fake {
        unelevated: true,
        ..fake
    });
    let err = s.browsers.apply_blocking().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Permission);
    assert_eq!(err.user_msg(), Msg::new("automation.hardening.needsAdmin"));
    assert_eq!(s.fake.write_count(), 0);
}

/// Yandex reads both policy roots: both get the two values (§3.7).
#[test]
fn yandex_gets_both_policy_roots() {
    let fake = Fake::default();
    fake.dirs
        .lock()
        .insert(PathBuf::from(LOCAL).join(r"Yandex\YandexBrowser\User Data"));
    let s = setup(fake);
    let r = s.browsers.apply_blocking().unwrap();
    assert_eq!(state(&r, Browser::Yandex), BrowserState::Protected);
    for key in [
        r"SOFTWARE\Policies\YandexBrowser",
        r"SOFTWARE\Policies\Yandex\YandexBrowser",
    ] {
        assert_eq!(s.fake.get(&webrtc(key)), ours());
        assert_eq!(s.fake.get(&doh(key)), Val::Sz("off".into()));
    }
}

/// A policy value of a type the journal may not record (it would be dropped at the next start
/// and our value would stay forever) leaves that browser untouched.
#[test]
fn foreign_value_type_leaves_the_browser_alone() {
    let fake = with_chrome();
    fake.set(&webrtc(CHROME), Val::Dword(1));
    let s = setup(fake);
    let r = s.browsers.apply_blocking().unwrap();
    let reason = Msg::new(FOREIGN);
    assert_eq!(state(&r, Browser::Chrome), BrowserState::Failed { reason });
    assert_eq!(r.message, Some(Msg::new(FAILED)));
    assert_eq!(s.fake.write_count(), 0);
    assert_eq!(s.fake.get(&webrtc(CHROME)), Val::Dword(1));
}

/// Each browser is its own unit: a failing Edge write undoes Edge only, Chrome stays protected.
#[test]
fn one_failing_browser_keeps_the_others() {
    let fake = with_chrome();
    fake.app_path("msedge.exe", EDGE_EXE);
    fake.fail_write.lock().insert(doh(EDGE));
    let s = setup(fake);
    let r = s.browsers.apply_blocking().unwrap();
    assert_eq!(state(&r, Browser::Chrome), BrowserState::Protected);
    let reason = Msg::new(FAILED);
    assert_eq!(state(&r, Browser::Edge), BrowserState::Failed { reason });
    assert!(!r.success);
    assert_eq!(s.fake.get(&webrtc(EDGE)), Val::Absent);
    assert_eq!(s.fake.get(&doh(CHROME)), Val::Sz("off".into()));
    assert_eq!(s.journal.records(Feature::BrowserWebRtc).len(), 2);
}

/// Spec §8.11: the old app's values outside today's scope (its HKCU keys) go back on the next
/// apply, and a verified key keeps the old baseline through the re-apply.
#[test]
fn old_values_are_cleaned_on_the_next_apply() {
    let fake = with_chrome();
    let hkcu = reg(RegHive::Hkcu, CHROME, "WebRtcIPHandlingPolicy");
    fake.set(&hkcu, ours());
    fake.set(&webrtc(CHROME), ours());
    let s = setup(fake);
    let adopted = |target: &Target, baseline: Val| Record {
        feature: Feature::BrowserWebRtc,
        target: target.clone(),
        baseline,
        applied: ours(),
        created: false,
    };
    let legacy = vec![
        adopted(&webrtc(CHROME), Val::Sz("default".into())),
        adopted(&hkcu, Val::Absent),
    ];
    assert_eq!(s.journal.adopt_legacy(legacy).unwrap(), 2);

    let r = s.browsers.apply_blocking().unwrap();
    assert!(r.success && r.restart_required);
    assert_eq!(s.fake.get(&hkcu), Val::Absent);
    assert_eq!(s.fake.get(&webrtc(CHROME)), ours());
    assert_eq!(s.fake.get(&doh(CHROME)), Val::Sz("off".into()));

    s.browsers.rollback_blocking().unwrap();
    assert_eq!(s.fake.get(&webrtc(CHROME)), Val::Sz("default".into()));
    assert_eq!(s.fake.get(&doh(CHROME)), Val::Absent);
    assert!(!s.browsers.is_applied());
}

/// Nothing journalled: rollback is a no-op that says so.
#[test]
fn rollback_without_records_writes_nothing() {
    let s = setup(with_chrome());
    let r = s.browsers.rollback_blocking().unwrap();
    assert_eq!(r.message, Some(Msg::new(NOT_APPLIED)));
    assert!(r.success);
    assert_eq!(s.fake.write_count(), 0);
    assert_eq!(state(&r, Browser::Chrome), BrowserState::Off);
}

/// A failed restore keeps its record: the report says partial, a later rollback finishes.
#[test]
fn failed_rollback_keeps_the_record_for_a_retry() {
    let s = setup(with_chrome());
    s.browsers.apply_blocking().unwrap();
    s.fake.fail_write.lock().insert(doh(CHROME));
    let r = s.browsers.rollback_blocking().unwrap();
    assert!(!r.success);
    assert_eq!(r.message, Some(Msg::new(ROLLBACK_PARTIAL)));
    assert_eq!(s.journal.records(Feature::BrowserWebRtc).len(), 1);
    s.fake.fail_write.lock().clear();
    let r = s.browsers.rollback_blocking().unwrap();
    assert!(r.success);
    assert_eq!(s.fake.get(&doh(CHROME)), Val::Absent);
    assert!(!s.browsers.is_applied());
}

/// Status: Off before, Drifted after someone changed our value, Unknown when unreadable.
#[test]
fn status_reads_our_values_back() {
    let s = setup(with_chrome());
    let status = s.browsers.status_blocking();
    assert_eq!(state(&status, Browser::Chrome), BrowserState::Off);
    assert_eq!(state(&status, Browser::Firefox), BrowserState::NotInstalled);
    s.browsers.apply_blocking().unwrap();
    s.fake.set(&doh(CHROME), Val::Sz("secure".into()));
    let status = s.browsers.status_blocking();
    assert_eq!(state(&status, Browser::Chrome), BrowserState::Drifted);
    s.fake.fail_read.lock().insert(doh(CHROME));
    let status = s.browsers.status_blocking();
    assert_eq!(state(&status, Browser::Chrome), BrowserState::Unknown);
}

/// The async API runs on the blocking pool.
#[tokio::test]
async fn async_api() {
    let s = setup(with_chrome());
    let r = s.browsers.apply().await.unwrap();
    assert_eq!(state(&r, Browser::Chrome), BrowserState::Protected);
    let status = s.browsers.status().await.unwrap();
    assert_eq!(state(&status, Browser::Chrome), BrowserState::Protected);
    let r = s.browsers.rollback().await.unwrap();
    assert!(r.success);
    assert_eq!(s.fake.get(&webrtc(CHROME)), Val::Absent);
}
