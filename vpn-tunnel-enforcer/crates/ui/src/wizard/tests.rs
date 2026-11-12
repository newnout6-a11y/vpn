//! Ported vectors of `FirstRunWizard.test.tsx` (ui-servers §7.8) for the five-step wizard, plus the
//! spec's decided fixes (W-2, W-5/D-15, V-05, W-8, W-9/W-10) and the locale gate.
use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_base::types::KillSwitchLevel;

use super::model::{Detect, KeyStatus, Model, Step};
use super::*;

fn first_run() -> Model {
    Model::new(Lang::Ru, &WizardDefaults::default())
}

fn at(step: Step) -> Model {
    let mut m = first_run();
    while m.step != step {
        assert!(m.forward());
    }
    m
}

fn check(servers: usize) -> KeyCheck {
    KeyCheck {
        servers,
        subscription: false,
    }
}

/// AT-09-014 navigation: Next walks the screens in order and stops on the last one; Back stops
/// on the first.
#[test]
fn next_and_back_walk_the_steps_in_order() {
    let mut m = first_run();
    assert_eq!(m.step, Step::Welcome);
    assert!(!m.backward());
    for expected in [Step::Connect, Step::Routing, Step::Protection, Step::Done] {
        assert!(m.forward());
        assert_eq!(m.step, expected);
    }
    assert!(!m.forward());
    assert_eq!(m.step, Step::Done);
    assert!(m.backward());
    assert_eq!(m.step, Step::Protection);
    assert_eq!(Step::ALL.map(Step::index), [0, 1, 2, 3, 4]);
    assert_eq!(Step::Done.next(), None);
    assert_eq!(Step::Welcome.prev(), None);
}

/// AT-09-014 "imports a validated key and enables autostart on finish": the trimmed text is
/// checked once and handed to finish.
#[test]
fn a_checked_key_is_sent_trimmed() {
    let mut m = at(Step::Connect);
    m.connection = Connection::Key;
    m.edit_key(" vless://key ".into());
    let (seq, text) = m.begin_check().expect("check starts");
    assert_eq!(text, "vless://key");
    assert_eq!(m.key_status(), &KeyStatus::Checking);
    assert_eq!(m.begin_check(), None, "one check at a time");
    m.end_check(seq, Ok(check(1)));
    assert_eq!(m.key_status(), &KeyStatus::Valid(check(1)));
    m.autostart = true;
    let c = m.choices();
    assert_eq!(c.key, Some(KeyText("vless://key".into())));
    assert!(c.autostart);
    assert!(!m.key_left_unchecked());
}

/// AT-09-014 "does not keep a key the app rejected, and an edit drops a previous validation".
#[test]
fn an_edit_drops_the_validation_and_a_rejected_key_is_not_sent() {
    let mut m = at(Step::Connect);
    m.connection = Connection::Key;
    m.edit_key("vless://key".into());
    let (seq, _) = m.begin_check().unwrap();
    m.end_check(seq, Ok(check(2)));
    m.edit_key("garbage".into());
    assert_eq!(m.key_status(), &KeyStatus::Idle);
    let (seq, _) = m.begin_check().unwrap();
    m.end_check(seq, Ok(check(0)));
    assert_eq!(m.key_status(), &KeyStatus::Invalid);
    assert_eq!(m.choices().key, None);
    assert!(m.key_left_unchecked());
}

/// AT-09-014 "ignores an inspection result that arrives after the text was edited".
#[test]
fn a_result_for_an_older_text_is_ignored() {
    let mut m = at(Step::Connect);
    m.connection = Connection::Key;
    m.edit_key("vless://old".into());
    let (seq, _) = m.begin_check().unwrap();
    m.edit_key("vless://new".into());
    m.end_check(seq, Ok(check(1)));
    assert_eq!(m.key_status(), &KeyStatus::Idle);
    assert_eq!(m.choices().key, None);
}

/// A failed check (network) shows its message and keeps the key out; blank text never starts one.
#[test]
fn a_failed_check_keeps_the_key_out() {
    let mut m = at(Step::Connect);
    m.connection = Connection::Key;
    m.edit_key("   ".into());
    assert_eq!(m.begin_check(), None);
    m.edit_key("https://sub.example/x".into());
    let (seq, _) = m.begin_check().unwrap();
    m.end_check(seq, Err(Msg::new("errors.network")));
    assert_eq!(
        m.key_status(),
        &KeyStatus::Failed(Msg::new("errors.network"))
    );
    assert_eq!(m.choices().key, None);
}

/// W-9: the key belongs to the key connection; switching to a local proxy does not import it.
#[test]
fn a_key_is_only_sent_with_the_key_connection() {
    let mut m = at(Step::Connect);
    m.connection = Connection::Key;
    m.edit_key("vless://key".into());
    let (seq, _) = m.begin_check().unwrap();
    m.end_check(seq, Ok(check(1)));
    m.connection = Connection::LocalProxy;
    assert_eq!(m.choices().key, None);
    assert!(!m.key_left_unchecked());
}

/// AT-09-014 "shows the current autostart state and applies a change to it, not just enabling".
#[test]
fn autostart_starts_from_the_current_state() {
    let current = WizardDefaults {
        autostart: true,
        ..WizardDefaults::default()
    };
    let mut m = Model::new(Lang::En, &current);
    assert!(m.autostart);
    m.autostart = false;
    assert!(!m.choices().autostart);
}

/// AT-09-014 "skipping both optional steps changes nothing"; W-5 / D-15: the kill switch starts
/// Off on a first run and is only on after an explicit pick.
#[test]
fn walking_through_keeps_the_defaults() {
    let mut m = first_run();
    while m.forward() {}
    let c = m.choices();
    assert_eq!(c.key, None);
    assert!(!c.autostart);
    assert_eq!(c.kill_switch, KillSwitchLevel::Off);
    assert_eq!(c.connection, Connection::LocalProxy);
    assert_eq!(c.routing, Routing::Soft, "NOADMIN §0: Proxy mode unless elevated");
    assert_eq!(c.lang, Lang::Ru);
}

/// V-05: a «Строгий» pick is sent as the level itself (the old wizard saved only a boolean, so
/// strict became standard after a restart); a second run starts from the current level.
#[test]
fn the_kill_switch_level_is_sent_as_picked() {
    let mut m = at(Step::Protection);
    m.kill_switch = KillSwitchLevel::Strict;
    assert_eq!(m.choices().kill_switch, KillSwitchLevel::Strict);
    let current = WizardDefaults {
        kill_switch: KillSwitchLevel::Standard,
        ..WizardDefaults::default()
    };
    assert_eq!(
        Model::new(Lang::Ru, &current).choices().kill_switch,
        KillSwitchLevel::Standard
    );
}

/// NOADMIN §2: Proxy mode works with a key from the list as well as with a local proxy, so the
/// pick is sent as made whatever the connection (the old wizard forced Tunnel with a key).
#[test]
fn either_routing_goes_with_either_connection() {
    let mut m = at(Step::Routing);
    for connection in [Connection::Key, Connection::LocalProxy] {
        m.connection = connection;
        for routing in [Routing::Hard, Routing::Soft] {
            m.routing = routing;
            assert_eq!(m.choices().routing, routing, "{connection:?}");
        }
    }
}

/// W-8: detection runs once per wizard session (Back / Next does not rescan); «Искать снова»
/// runs it again; a second start while one runs is refused.
#[test]
fn detection_runs_once_per_session() {
    let mut m = first_run();
    assert!(!m.wants_detection(), "only on the Connect screen");
    m.forward();
    assert!(m.wants_detection());
    assert!(m.begin_detect());
    assert!(!m.begin_detect());
    let proxy = LocalProxy {
        host: "127.0.0.1".into(),
        port: 2080,
        kind: ProxyKind::Socks5,
    };
    m.end_detect(Ok(Some(proxy.clone())));
    assert_eq!(m.detect, Detect::Found(proxy));
    m.forward();
    m.backward();
    assert!(!m.wants_detection());
    assert!(m.begin_detect(), "retry");
    m.end_detect(Ok(None));
    assert_eq!(m.detect, Detect::NotFound);
}

/// Pasted keys never reach a log through `Debug`.
#[test]
fn key_text_is_not_printed() {
    let mut m = at(Step::Connect);
    m.connection = Connection::Key;
    m.edit_key("vless://uuid@host:443".into());
    let (seq, _) = m.begin_check().unwrap();
    m.end_check(seq, Ok(check(1)));
    let printed = format!("{m:?} {:?}", m.choices());
    assert!(!printed.contains("uuid@host"), "{printed}");
    assert!(printed.contains("KeyText(..)"));
}

/// Every key the screens use resolves in both languages (from this fragment or the old app's
/// strings), plural forms included.
#[test]
fn every_used_key_exists() {
    crate::test_locales::init_locales();
    let code = [
        include_str!("view.rs"),
        include_str!("steps.rs"),
        include_str!("demo.rs"),
        include_str!("model.rs"),
    ]
    .concat();
    let mut used: Vec<&str> = code
        .split('"')
        .filter(|s| {
            ["ui.wizard.", "onboarding.", "settings.", "common."]
                .iter()
                .any(|p| s.starts_with(p))
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.')
        })
        .collect();
    used.sort_unstable();
    used.dedup();
    assert!(used.len() > 40, "{used:?}");
    for lang in [Lang::Ru, Lang::En] {
        for key in &used {
            let text = vpnte_base::i18n::lookup(lang, key, &[("count", "2".into())], None);
            assert_ne!(&text, key, "{key} missing in {lang:?}");
        }
    }
}

fn strict_with_autostart() -> WizardChoices {
    WizardChoices {
        lang: Lang::Ru,
        connection: Connection::Key,
        routing: Routing::Hard,
        key: Some(KeyText("vless://a@b.example:443#x".into())),
        kill_switch: KillSwitchLevel::Strict,
        autostart: true,
    }
}

/// §6.7 apply order as the demo backend shows it to the app: key import first, the OS side
/// effects next, one settings write last; a failed write undoes the side effects in reverse
/// order and leaves the wizard open (AT-09-014 "restores the previous autostart when saving
/// onboarding completion fails afterwards").
#[tokio::test]
async fn demo_finish_undoes_side_effects_when_the_write_fails() {
    let api = DemoWizardApi::new(DemoScene::FinishFails);
    let err = api.finish(strict_with_autostart()).await.unwrap_err();
    assert_eq!(err.user_msg(), Msg::new("ui.wizard.demo.diskFull"));
    assert!(api.state().borrow().open, "onboarding stays incomplete");
    assert_eq!(
        *api.log().borrow(),
        [
            "import: 1 servers",
            "autostart: true",
            "kill switch: strict",
            "settings: write failed",
            "undo kill switch: off",
            "undo autostart: false",
        ]
    );
}

/// AT-09-014 "calls onComplete when saveSettings succeeds" / "skipping both optional steps
/// changes nothing": unchanged autostart and level are not touched; success closes the wizard
/// and the next opening starts from the saved values.
#[tokio::test]
async fn demo_finish_applies_only_changes_and_closes() {
    let api = DemoWizardApi::new(DemoScene::FirstRun);
    let choices = Model::new(Lang::En, &WizardDefaults::default()).choices();
    api.finish(choices).await.expect("finish");
    let state = api.state().borrow().clone();
    assert!(!state.open);
    assert_eq!(
        *api.log().borrow(),
        ["settings: lang=en connection=local-proxy routing=soft kill=off first_run_complete"]
    );
    api.reopen();
    assert!(api.state().borrow().open);
}
