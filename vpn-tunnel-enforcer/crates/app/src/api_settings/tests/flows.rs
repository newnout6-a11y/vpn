//! Flows over a throw-away backend and a fake unelevated tunnel: what each action writes, what
//! it refuses before writing, and what the page is shown.
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use vpnte_base::ErrorKind;
use vpnte_core::settings::RoutingMode;
use vpnte_ui::settings::{self as ui, SettingsApi, SettingsPatch};

use super::super::test_support::{FakeAutostart, FakeTunnel, Restart, TempDir, backend};
use super::super::{SettingsService, Shared};

mod lists;
mod prefs;
mod wizard;

/// A started settings service over a fake tunnel (`tun`: TUN capture available).
pub(super) fn setup(
    name: &str,
    tun: bool,
    autostart: FakeAutostart,
) -> (Arc<Shared>, Arc<FakeTunnel>, Arc<FakeAutostart>, TempDir) {
    let dir = TempDir::new(name);
    let fake = FakeTunnel::new(tun);
    let autostart = Arc::new(autostart);
    let shared = Shared::start(backend(&dir, fake.clone()), autostart.clone(), None);
    (shared, fake, autostart, dir)
}

/// Waits (bounded) until the published value satisfies `pred`.
pub(super) async fn until<T: Clone>(rx: &watch::Receiver<T>, pred: impl Fn(&T) -> bool) -> T {
    let mut rx = rx.clone();
    let wait = rx.wait_for(|v| pred(v));
    let value = tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .expect("timed out")
        .expect("channel open");
    value.clone()
}

/// A save writes settings and Soft targets, hands old / new to the tunnel and says which
/// changes wait for the next connect; the page sees the new values.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn save_writes_and_reports_next_connect() {
    let (shared, fake, _, _dir) = setup("save", false, FakeAutostart::default());
    let api = SettingsService(shared.clone());
    let report = api
        .save(SettingsPatch {
            routing_mode: Some(ui::RoutingMode::Soft),
            soft_git: Some(true),
            smart_ru_split: Some(true),
            minimize_to_tray: Some(false),
            ..SettingsPatch::default()
        })
        .await
        .expect("saved");
    assert!(report.next_connect);
    assert_eq!(report.restart, None, "no session: nothing restarted");
    assert_eq!(report.settings.routing_mode, ui::RoutingMode::Soft);
    let stored = shared.backend.settings.snapshot();
    assert_eq!(stored.routing_mode, RoutingMode::Soft);
    assert!(stored.smart_ru_split && !stored.minimize_to_tray);
    assert!(shared.backend.soft.read(|d| d.dev_targets.git));
    let applied = fake.applied.lock().clone();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].0.routing_mode, RoutingMode::Hard);
    assert_eq!(applied[0].1.routing_mode, RoutingMode::Soft);
    until(&api.state(), |s| {
        s.settings.soft_git && s.settings.smart_ru_split
    })
    .await;
    until(&api.domains(), |d| d.smart_ru).await;
}

/// Refusals come before any write: Hard without TUN, leak protection without WFP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_saves_write_nothing() {
    let (shared, fake, _, _dir) = setup("refused", false, FakeAutostart::default());
    shared
        .backend
        .settings
        .update(|s| s.routing_mode = RoutingMode::Soft)
        .expect("soft");
    let api = SettingsService(shared.clone());
    let hard = api
        .save(SettingsPatch {
            routing_mode: Some(ui::RoutingMode::Hard),
            minimize_to_tray: Some(false),
            ..SettingsPatch::default()
        })
        .await
        .expect_err("needs admin");
    assert_eq!(hard.kind, ErrorKind::Permission);
    let leak = api
        .save(SettingsPatch {
            leak_protection: Some(false),
            minimize_to_tray: Some(false),
            ..SettingsPatch::default()
        })
        .await
        .expect_err("needs admin");
    assert_eq!(leak.kind, ErrorKind::Permission);
    let stored = shared.backend.settings.snapshot();
    assert_eq!(stored.routing_mode, RoutingMode::Soft);
    assert!(stored.minimize_to_tray, "nothing was written");
    assert!(fake.applied.lock().is_empty());
}

/// An edit equal to the live value is no change: nothing is written or applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unchanged_patch_is_a_no_op() {
    let (shared, fake, _, _dir) = setup("noop", false, FakeAutostart::default());
    let report = SettingsService(shared)
        .save(SettingsPatch {
            minimize_to_tray: Some(true),
            ..SettingsPatch::default()
        })
        .await
        .expect("saved");
    assert!(!report.next_connect);
    assert!(fake.applied.lock().is_empty());
}

/// A restart is reported only when it was observed (the engine generation moved on); a failed
/// one only while a session is open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_is_reported_only_when_observed() {
    let (shared, fake, _, _dir) = setup("restart", false, FakeAutostart::default());
    let api = SettingsService(shared);
    fake.open_session(1);
    *fake.restart.lock() = Restart::Restarts;
    let patch = |on: bool| SettingsPatch {
        stealth_mode: Some(on),
        ..SettingsPatch::default()
    };
    assert_eq!(
        api.save(patch(true)).await.expect("saved").restart,
        Some(Ok(()))
    );
    *fake.restart.lock() = Restart::Keeps;
    assert_eq!(api.save(patch(false)).await.expect("saved").restart, None);
    *fake.restart.lock() = Restart::Fails;
    let failed = api.save(patch(true)).await.expect("saved").restart;
    assert_eq!(
        failed.and_then(Result::err).map(|m| m.key.into_owned()),
        Some("test.restartFailed".to_owned())
    );
}
