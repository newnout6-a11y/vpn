//! Instant preferences: autostart (fake `Run` value), kill switch, notifications, language and
//! theme.
use vpnte_base::ErrorKind;
use vpnte_base::i18n::Lang;
use vpnte_base::types::KillSwitchLevel;
use vpnte_core::settings::NotifyMethod;
use vpnte_ui::settings::{self as ui, SettingsApi};

use super::super::super::SettingsService;
use super::super::super::actions;
use super::super::super::test_support::FakeAutostart;
use super::{setup, until};

/// The toggle writes the per-user value, reads it back and persists the setting; the page shows
/// what Windows reports.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn autostart_reads_back_windows() {
    let (shared, _, os, _dir) = setup("autostart", false, FakeAutostart::default());
    let api = SettingsService(shared.clone());
    assert!(api.set_autostart(true).await.expect("on"));
    assert!(*os.present.lock());
    assert!(shared.backend.settings.read(|s| s.autostart));
    until(&api.state(), |s| s.autostart).await;
    assert!(!api.set_autostart(false).await.expect("off"));
    assert!(!shared.backend.settings.read(|s| s.autostart));
    until(&api.state(), |s| !s.autostart).await;
}

/// Switched off in Task Manager: the app's part is done, the error says where the switch is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn autostart_switched_off_by_the_user_is_explained() {
    let fake = FakeAutostart {
        user_off: true,
        ..FakeAutostart::default()
    };
    let (shared, _, _, _dir) = setup("autostart-off", false, fake);
    let err = SettingsService(shared)
        .set_autostart(true)
        .await
        .expect_err("not effective");
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert_eq!(err.user_msg().key, "winnet.autostart.disabledByUser");
}

/// Windows refusing the write leaves the setting as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn autostart_refused_by_windows_changes_nothing() {
    let fake = FakeAutostart {
        fail: true,
        ..FakeAutostart::default()
    };
    let (shared, _, _, _dir) = setup("autostart-fail", false, fake);
    let err = actions::set_autostart(&shared, true)
        .await
        .expect_err("denied");
    assert_eq!(err.kind, ErrorKind::Permission);
    assert!(!shared.backend.settings.read(|s| s.autostart));
}

/// The level goes through the tunnel and the section is re-read; strict without WFP is
/// refused and the level stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_switch_level_goes_through_the_tunnel() {
    let (shared, fake, _, _dir) = setup("kill", false, FakeAutostart::default());
    let api = SettingsService(shared);
    api.set_kill_switch_level(KillSwitchLevel::Standard)
        .await
        .expect("standard");
    let view = until(&api.kill_switch(), |k| k.level == KillSwitchLevel::Standard).await;
    assert_eq!(view.status, ui::ProtectionStatus::Armed);
    let err = api
        .set_kill_switch_level(KillSwitchLevel::Strict)
        .await
        .expect_err("needs admin");
    assert_eq!(err.kind, ErrorKind::Permission);
    assert_eq!(*fake.level.lock(), KillSwitchLevel::Standard);
    let add = api
        .add_exception(ui::ExceptionKind::Ip, "192.0.2.1".into(), "Lab".into())
        .await
        .expect_err("needs admin");
    assert_eq!(add.kind, ErrorKind::Permission);
}

/// One notification control per call, stored at once and shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notification_changes_are_stored() {
    let (shared, _, _, _dir) = setup("notify", false, FakeAutostart::default());
    let api = SettingsService(shared.clone());
    for change in [
        ui::NotificationChange::Event(ui::NotifyEvent::LeakDetected, false),
        ui::NotificationChange::Method(ui::NotifyMethod::Both),
        ui::NotificationChange::Sound(false),
        ui::NotificationChange::Enabled(false),
    ] {
        api.set_notification(change).await.expect("stored");
    }
    let s = shared.backend.settings.snapshot();
    assert!(!s.notifications.leak_detected && s.notifications.vpn_connect);
    assert_eq!(s.notifications.method, NotifyMethod::Both);
    assert!(!s.notifications.sound && !s.desktop_notifications);
    until(&api.notifications(), |n| !n.enabled && !n.sound).await;
}

/// The language is stored; a theme id must name a theme.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn language_and_theme_are_stored() {
    let (shared, _, _, _dir) = setup("lang", false, FakeAutostart::default());
    let api = SettingsService(shared.clone());
    api.set_language(Lang::En).await.expect("stored");
    assert_eq!(shared.backend.settings.read(|s| s.locale), Some(Lang::En));
    actions::set_theme(&shared, "builtin-dark".into())
        .await
        .expect("theme");
    assert_eq!(
        shared.backend.settings.read(|s| s.active_theme_id.clone()),
        "builtin-dark"
    );
    let err = actions::set_theme(&shared, "deleted".into())
        .await
        .expect_err("unknown");
    assert_eq!(err.kind, ErrorKind::Validation);
    until(&api.state(), |s| s.active_theme_id == "builtin-dark").await;
}

/// Features this build does not wire answer honestly, never with a fake result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unwired_features_report_unavailable() {
    let (shared, _, _, _dir) = setup("unwired", false, FakeAutostart::default());
    let api = SettingsService(shared);
    let conflict = |r: vpnte_base::AppResult<()>| r.expect_err("unavailable").kind;
    assert_eq!(
        conflict(api.set_location_privacy(true).await.map(drop)),
        ErrorKind::Conflict
    );
    assert_eq!(
        conflict(api.apply_browser_protection().await.map(drop)),
        ErrorKind::Conflict
    );
    assert_eq!(
        conflict(api.rotate_now().await.map(drop)),
        ErrorKind::Conflict
    );
    assert_eq!(
        conflict(api.export_config(ui::ExportMode::Redacted).await),
        ErrorKind::Conflict
    );
    assert_eq!(
        conflict(api.export_diagnostics().await.map(drop)),
        ErrorKind::Conflict
    );
    assert_eq!(conflict(api.clear_captures().await), ErrorKind::Conflict);
    assert_eq!(
        conflict(api.retry_adaptive().await.map(drop)),
        ErrorKind::Conflict
    );
    let state = api.state().borrow().clone();
    assert!(!state.location_privacy && state.browser.browsers.is_empty());
    assert_eq!(
        state.adaptive.message, None,
        "status unavailable, not idle-and-fine"
    );
}
