//! The first-run wizard: what finish and skip persist, the no-admin routing rule, the undo of a
//! failed finish, and the key check that imports nothing.
use vpnte_base::ErrorKind;
use vpnte_base::i18n::Lang;
use vpnte_base::types::KillSwitchLevel;
use vpnte_core::settings::{ConnectionMode, RoutingMode};
use vpnte_ui::wizard::{Connection, KeyText, Routing, WizardApi, WizardChoices};

use super::super::super::WizardService;
use super::super::super::test_support::FakeAutostart;
use super::super::super::wizard;
use super::{setup, until};

fn choices(connection: Connection, routing: Routing) -> WizardChoices {
    WizardChoices {
        lang: Lang::En,
        connection,
        routing,
        key: None,
        kill_switch: KillSwitchLevel::Off,
        autostart: false,
    }
}

/// A fresh install opens the wizard with Soft preselected when the TUN is unavailable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_start_opens_with_soft_defaults() {
    let (shared, _, _, _dir) = setup("wizard-open", false, FakeAutostart::default());
    let api = WizardService(shared);
    let state = until(&api.state(), |w| w.open).await;
    assert_eq!(state.current.routing, Routing::Soft);
    assert_eq!(state.current.servers, 0);
    assert!(!state.current.autostart);
}

/// Without TUN capture a key is stored as Soft (the page offers no Soft with a key), with the
/// language, the connection mode and the completion flag; the wizard closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_with_a_key_without_tun_stores_soft() {
    let (shared, _, _, _dir) = setup("wizard-key", false, FakeAutostart::default());
    let api = WizardService(shared.clone());
    until(&api.state(), |w| w.open).await;
    api.finish(choices(Connection::Key, Routing::Hard))
        .await
        .expect("finished");
    let s = shared.backend.settings.snapshot();
    assert_eq!(s.routing_mode, RoutingMode::Soft);
    assert_eq!(s.connection_mode, ConnectionMode::DirectVpn);
    assert_eq!(s.locale, Some(Lang::En));
    assert!(s.first_run_complete);
    assert!(!api.state().borrow().open);
}

/// Hard chosen over Soft with a local proxy and no TUN: refused, nothing written, still open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_hard_over_local_proxy_is_refused() {
    let (shared, _, _, _dir) = setup("wizard-hard", false, FakeAutostart::default());
    let api = WizardService(shared.clone());
    until(&api.state(), |w| w.open).await;
    let err = api
        .finish(choices(Connection::LocalProxy, Routing::Hard))
        .await
        .expect_err("needs admin");
    assert_eq!(err.kind, ErrorKind::Permission);
    assert!(!shared.backend.settings.read(|s| s.first_run_complete));
    assert!(api.state().borrow().open);
}

/// A failed key import undoes the kill switch and autostart changes made before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_finish_undoes_autostart_and_kill_switch() {
    let (shared, fake, os, _dir) = setup("wizard-undo", false, FakeAutostart::default());
    let api = WizardService(shared.clone());
    let mut bad = choices(Connection::Key, Routing::Soft);
    bad.key = Some(KeyText("this is not a key".into()));
    bad.autostart = true;
    bad.kill_switch = KillSwitchLevel::Standard;
    let err = api.finish(bad).await.expect_err("import fails");
    assert_eq!(err.kind, ErrorKind::Validation);
    assert!(!*os.present.lock(), "autostart restored");
    assert!(!shared.backend.settings.read(|s| s.autostart));
    assert_eq!(*fake.level.lock(), KillSwitchLevel::Off, "level restored");
    assert!(!shared.backend.settings.read(|s| s.first_run_complete));
}

/// ks-a: the wizard itself refuses nothing about the kill switch any more ("Always" is not a
/// first-run choice); a picked "Always" is the tunnel's call, which without the helper service
/// says so in one line, and nothing stays applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn always_without_the_service_is_refused_by_the_tunnel() {
    let (shared, fake, _, _dir) = setup("wizard-strict", true, FakeAutostart::default());
    let mut strict = choices(Connection::LocalProxy, Routing::Soft);
    strict.kill_switch = KillSwitchLevel::Strict;
    let err = WizardService(shared)
        .finish(strict)
        .await
        .expect_err("refused");
    assert_eq!(err.kind, ErrorKind::Permission);
    assert_eq!(err.user_msg().key, "app.tunnel.alwaysNeedsService");
    assert_eq!(*fake.level.lock(), KillSwitchLevel::Off);
}

/// «Пропустить» stores the language and the flag only; «Пройти мастер заново» reopens it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn skip_then_reopen() {
    let (shared, _, _, _dir) = setup("wizard-skip", false, FakeAutostart::default());
    let api = WizardService(shared.clone());
    until(&api.state(), |w| w.open).await;
    api.skip(Lang::Ru).await.expect("skipped");
    let s = shared.backend.settings.snapshot();
    assert!(s.first_run_complete);
    assert_eq!(s.locale, Some(Lang::Ru));
    assert_eq!(s.routing_mode, RoutingMode::Hard, "nothing else written");
    assert!(!api.state().borrow().open);
    wizard::open(&shared).await;
    assert!(api.state().borrow().open);
}

/// A key is parsed without importing anything; text without a key says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_key_imports_nothing() {
    let (shared, _, _, _dir) = setup("wizard-check", false, FakeAutostart::default());
    let api = WizardService(shared.clone());
    let key =
        "vless://00000000-0000-4000-8000-000000000000@203.0.113.10:443?security=none&type=tcp#Fake";
    let token = tokio_util::sync::CancellationToken::new();
    let check = api
        .check_key(key.into(), token.clone())
        .await
        .expect("parsed");
    assert_eq!(check.servers, 1);
    assert!(!check.subscription);
    assert_eq!(shared.backend.servers.read(|d| d.profiles.len()), 0);
    let err = api
        .check_key("hello".into(), token)
        .await
        .expect_err("no key");
    assert_eq!(err.kind, ErrorKind::Validation);
}
