//! The first-run wizard: what finish and skip persist, the no-admin routing rule, the undo of a
//! failed finish, and the key check that imports nothing.
use vpnte_base::ErrorKind;
use vpnte_base::i18n::Lang;
use vpnte_base::types::KillSwitchLevel;
use vpnte_core::settings::{ConnectionMode, RoutingMode, RuleSetMode};
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
        smart_ru: true,
        key: None,
        kill_switch: KillSwitchLevel::Off,
        autostart: false,
    }
}

/// A fresh install opens the wizard with Soft preselected when the TUN is unavailable, and
/// Smart RU preselected on (owner answer 18).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_start_opens_with_soft_defaults() {
    let (shared, _, _, _dir) = setup("wizard-open", false, FakeAutostart::default());
    let api = WizardService(shared);
    let state = until(&api.state(), |w| w.open).await;
    assert_eq!(state.current.routing, Routing::Soft);
    assert_eq!(state.current.servers, 0);
    assert!(!state.current.autostart);
    assert!(state.current.smart_ru);
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
    assert!(s.smart_ru_split);
    assert!(s.first_run_complete);
    assert!(!api.state().borrow().open);
    // A re-run starts from the stored Smart RU choice and stores a change of it.
    wizard::open(&shared).await;
    assert!(api.state().borrow().current.smart_ru);
    let mut off = choices(Connection::Key, Routing::Soft);
    off.smart_ru = false;
    api.finish(off).await.expect("finished again");
    assert!(!shared.backend.settings.read(|s| s.smart_ru_split));
}

/// Re-check item 12a: Smart RU turned on in the wizard turns managed list updates on (24 h); a
/// re-run with Smart RU already on keeps the update choice made in Settings since.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smart_ru_on_turns_list_updates_on() {
    let (shared, _, _, _dir) = setup("wizard-lists", false, FakeAutostart::default());
    let settings = &shared.backend.settings;
    settings
        .update(|s| {
            s.smart_ru_rule_set_mode = RuleSetMode::Bundled;
            s.smart_ru_rule_set_auto_update = false;
            s.smart_ru_rule_set_update_hours = 72;
        })
        .expect("saved");
    let api = WizardService(shared.clone());
    until(&api.state(), |w| w.open).await;
    api.finish(choices(Connection::Key, Routing::Soft))
        .await
        .expect("finished");
    let s = settings.snapshot();
    assert!(s.smart_ru_split);
    assert_eq!(
        (
            s.smart_ru_rule_set_mode,
            s.smart_ru_rule_set_auto_update,
            s.smart_ru_rule_set_update_hours
        ),
        (RuleSetMode::Managed, true, 24)
    );
    settings
        .update(|s| s.smart_ru_rule_set_mode = RuleSetMode::Bundled)
        .expect("saved");
    wizard::open(&shared).await;
    api.finish(choices(Connection::Key, Routing::Soft))
        .await
        .expect("finished again");
    assert_eq!(
        settings.read(|s| s.smart_ru_rule_set_mode),
        RuleSetMode::Bundled
    );
}

/// psmart-b4: «Автообновлять списки» switched off on the Settings page stays off when a wizard
/// re-run turns Smart RU on again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_wizard_keeps_a_list_choice_made_in_settings() {
    let (shared, _, _, _dir) = setup("wizard-choice", false, FakeAutostart::default());
    let settings = &shared.backend.settings;
    let off = super::super::super::save::core_patch(&vpnte_ui::settings::SettingsPatch {
        smart_ru_auto_update: Some(false),
        ..Default::default()
    })
    .expect("patch");
    settings
        .update(|s| {
            s.apply(off);
            s.smart_ru_split = false;
        })
        .expect("saved");
    let api = WizardService(shared.clone());
    until(&api.state(), |w| w.open).await;
    api.finish(choices(Connection::Key, Routing::Soft))
        .await
        .expect("finished");
    let s = settings.snapshot();
    assert!(s.smart_ru_split);
    assert_eq!(
        (s.smart_ru_rule_set_mode, s.smart_ru_rule_set_auto_update),
        (RuleSetMode::Bundled, false)
    );
}

/// Tunnel mode over a local proxy where it cannot run (no helper service): stored as Proxy, as
/// the wizard's summary already showed with the service's install (p-noadmin-ui): «Завершить»
/// never fails for it, and the wizard closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_hard_over_local_proxy_without_tun_stores_soft() {
    let (shared, _, _, _dir) = setup("wizard-hard", false, FakeAutostart::default());
    let api = WizardService(shared.clone());
    until(&api.state(), |w| w.open).await;
    api.finish(choices(Connection::LocalProxy, Routing::Hard))
        .await
        .expect("finished");
    let s = shared.backend.settings.snapshot();
    assert_eq!(s.routing_mode, RoutingMode::Soft);
    assert!(s.first_run_complete);
    assert!(!api.state().borrow().open);
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

/// PR #137 review: a failed finish puts back the autostart Windows had before the step, not
/// the stored setting (here Windows starts the app while the setting says no).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_finish_restores_the_autostart_windows_had() {
    let on = FakeAutostart::default();
    *on.present.lock() = true;
    let (shared, _, os, _dir) = setup("wizard-undo-os", false, on);
    assert!(!shared.backend.settings.read(|s| s.autostart));
    let api = WizardService(shared.clone());
    let mut bad = choices(Connection::Key, Routing::Soft);
    bad.key = Some(KeyText("this is not a key".into()));
    api.finish(bad).await.expect_err("import fails");
    assert!(*os.present.lock(), "Windows starts the app again");
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
    assert!(
        !s.smart_ru_split,
        "a skipped wizard leaves Smart RU at its default"
    );
    assert!(!api.state().borrow().open);
    wizard::open(&shared).await;
    let reopened = api.state().borrow().clone();
    assert!(reopened.open);
    assert!(
        !reopened.current.smart_ru,
        "a re-run shows the stored choice"
    );
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
