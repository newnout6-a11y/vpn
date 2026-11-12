//! Tests of the Settings and wizard APIs: pure projections and patch mapping, then flows over a
//! throw-away backend and a fake unelevated tunnel (no real `Run` key, no network).
use vpnte_automation::tweaks::DevTargets;
use vpnte_base::ErrorKind;
use vpnte_base::types::ProxyKind;
use vpnte_core::settings::{RuleSetMode, Settings};
use vpnte_ui::settings::{self as ui, SettingsPatch};

use super::project::settings_view;
use super::save::{check, core_patch, next_connect};

mod flows;
mod locales;
mod views;

/// The draft fields mirror the stored settings; capture shows off whatever was imported.
#[test]
fn settings_view_mirrors_the_stored_fields() {
    let mut s = Settings {
        smart_ru_rule_set_mode: RuleSetMode::Managed,
        smart_ru_rule_set_auto_update: true,
        deep_inspection: true,
        ..Settings::default()
    };
    let mut patch = vpnte_core::settings::SettingsPatch::default();
    patch
        .set_proxy_override("socks5://user:secret@127.0.0.1:1080")
        .expect("proxy");
    s.apply(patch);
    let soft = DevTargets {
        git: true,
        gradle: false,
        android_studio: true,
    };
    let view = settings_view(&s, &soft, false);
    assert!(view.smart_ru_auto_update);
    assert!(!view.deep_inspection, "capture is not part of this build");
    assert_eq!(
        view.proxy_override, "127.0.0.1:1080",
        "never the credentials"
    );
    assert!(view.soft_git && !view.soft_gradle && view.soft_studio);
    assert!(!view.leak_protection);
    s.smart_ru_rule_set_auto_update = false;
    assert!(!settings_view(&s, &soft, true).smart_ru_auto_update);
}

/// «Автообновлять списки» selects managed lists, auto update, the bootstrap route and 24 h;
/// off returns to the bundled lists.
#[test]
fn auto_update_maps_to_the_rule_set_keys() {
    let on = core_patch(&SettingsPatch {
        smart_ru_auto_update: Some(true),
        ..SettingsPatch::default()
    })
    .expect("patch");
    assert_eq!(on.smart_ru_rule_set_mode, Some(RuleSetMode::Managed));
    assert_eq!(on.smart_ru_rule_set_auto_update, Some(true));
    assert_eq!(on.smart_ru_rule_set_use_proxy, Some(true));
    assert_eq!(on.smart_ru_rule_set_update_hours, Some(24));
    let off = core_patch(&SettingsPatch {
        smart_ru_auto_update: Some(false),
        ..SettingsPatch::default()
    })
    .expect("patch");
    assert_eq!(off.smart_ru_rule_set_mode, Some(RuleSetMode::Bundled));
    assert_eq!(off.smart_ru_rule_set_use_proxy, None);
}

/// The manual proxy is parsed (a bad one is a field error); the page's type wins over a typed
/// scheme, a scheme alone sets the type; "" clears.
#[test]
fn proxy_override_is_parsed_once() {
    let patch = |input: &str, kind: Option<ProxyKind>| SettingsPatch {
        proxy_override: Some(input.into()),
        proxy_type: kind,
        ..SettingsPatch::default()
    };
    let scheme = core_patch(&patch("http://127.0.0.1:8080", None)).expect("patch");
    assert_eq!(scheme.proxy_type, Some(ProxyKind::Http));
    let chosen = core_patch(&patch("http://127.0.0.1:8080", Some(ProxyKind::Socks5))).expect("p");
    assert_eq!(chosen.proxy_type, Some(ProxyKind::Socks5));
    let cleared = core_patch(&patch("", None)).expect("patch");
    assert_eq!(cleared.proxy_override, Some(None));
    let bad = core_patch(&patch("not a proxy", None)).expect_err("refused");
    assert_eq!(bad.kind, ErrorKind::Validation);
}

/// NOADMIN §0 / §2: Hard without TUN capture is refused before anything is written, with a
/// message that offers Soft; capture is not part of this build.
#[test]
fn checks_refuse_hard_without_tun_and_capture() {
    let hard = SettingsPatch {
        routing_mode: Some(ui::RoutingMode::Hard),
        ..SettingsPatch::default()
    };
    let err = check(&hard, false).expect_err("needs admin");
    assert_eq!(err.kind, ErrorKind::Permission);
    assert_eq!(err.user_msg().key, "app.settings.hardNeedsAdmin");
    assert!(check(&hard, true).is_ok());
    let soft = SettingsPatch {
        routing_mode: Some(ui::RoutingMode::Soft),
        ..SettingsPatch::default()
    };
    assert!(check(&soft, false).is_ok());
    for capture in [
        SettingsPatch {
            deep_inspection: Some(true),
            ..SettingsPatch::default()
        },
        SettingsPatch {
            capture_quota_mb: Some(2048),
            ..SettingsPatch::default()
        },
    ] {
        assert_eq!(
            check(&capture, true).expect_err("refused").kind,
            ErrorKind::Conflict
        );
    }
    let off = SettingsPatch {
        deep_inspection: Some(false),
        ..SettingsPatch::default()
    };
    assert!(check(&off, false).is_ok());
}

/// ui-pages §6.4: these changes apply at the next connect.
#[test]
fn next_connect_follows_the_spec_fields() {
    assert!(next_connect(&SettingsPatch {
        soft_gradle: Some(true),
        ..SettingsPatch::default()
    }));
    assert!(next_connect(&SettingsPatch {
        proxy_engine: Some(vpnte_base::types::EnginePref::Xray),
        ..SettingsPatch::default()
    }));
    assert!(!next_connect(&SettingsPatch {
        minimize_to_tray: Some(false),
        ..SettingsPatch::default()
    }));
}

/// Browser states never read as protected unless they are; unverified ones are «Не проверено»;
/// browsers that are not installed are left out of the list.
#[test]
fn browser_states_are_shown_honestly() {
    use vpnte_automation::hardening::{Browser, BrowserEntry, BrowserReport, BrowserState};
    let entry = |browser, state| BrowserEntry { browser, state };
    let report = BrowserReport {
        browsers: vec![
            entry(Browser::Chrome, BrowserState::Protected),
            entry(Browser::Edge, BrowserState::Drifted),
            entry(Browser::Firefox, BrowserState::NotVerified),
            entry(Browser::Opera, BrowserState::NotInstalled),
        ],
        restart_required: true,
        success: true,
        message: None,
        notes: Vec::new(),
    };
    let view = super::auto::browser_view(&report);
    let statuses: Vec<_> = view.browsers.iter().map(|b| b.status.clone()).collect();
    assert_eq!(
        statuses,
        [
            ui::BrowserStatus::Protected,
            ui::BrowserStatus::NotProtected,
            ui::BrowserStatus::NotChecked,
        ]
    );
    assert!(view.restart_required);
}

/// b7: «Ротировать сейчас» claims the previous server back only when the switch itself said
/// so; an attempt that never started or was cancelled midway shows just its reason.
#[test]
fn rotate_now_never_guesses_a_restore() {
    use vpnte_automation::rotation::RotationOutcome as Outcome;
    use vpnte_base::Msg;
    let reason = || Msg::new("automation.rotation.busy");
    for outcome in [
        Outcome::NotStarted { reason: reason() },
        Outcome::Aborted { reason: reason() },
    ] {
        let err = super::auto::page_outcome(outcome).expect_err("no outcome to show");
        assert_eq!(err.kind, ErrorKind::Conflict, "never hidden as cancelled");
        assert_eq!(err.user_msg().key, "automation.rotation.busy");
    }
    let failed = Outcome::Failed {
        profile_id: "b".into(),
        reason: reason(),
        restored_previous: false,
    };
    assert!(matches!(
        super::auto::page_outcome(failed),
        Ok(ui::RotationOutcome::Failed {
            restored_previous: false,
            ..
        })
    ));
}
