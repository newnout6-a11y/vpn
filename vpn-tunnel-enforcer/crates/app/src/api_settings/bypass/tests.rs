//! «Не через прокси» in the app (RU-2026 item 14 a-b): the page's text saved as the canonical
//! list, the view, and what the keeper hands to the system-proxy tweak. Nothing here sets the
//! process-wide list: other tests apply Soft sessions with fakes in this binary.
use vpnte_base::ErrorKind;
use vpnte_core::settings::{RoutingMode, RuleSetMode, Settings};
use vpnte_engine::routing::domain::{DomainAction, DomainPattern};
use vpnte_ui::settings as ui;

use super::*;
use crate::api_settings::project::settings_view;
use crate::api_settings::save::{core_patch, next_connect};
use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};

fn patch_with(text: &str) -> ui::SettingsPatch {
    ui::SettingsPatch {
        proxy_bypass: Some(text.to_owned()),
        ..ui::SettingsPatch::default()
    }
}

#[test]
fn the_page_text_is_saved_as_the_canonical_list() {
    let core = core_patch(&patch_with(
        "Example.com; 10.*\nhttps://x.example/a <local>",
    ))
    .unwrap();
    assert_eq!(
        core.proxy_bypass,
        Some(vec![
            "example.com".into(),
            "10.*".into(),
            "x.example".into()
        ])
    );
    assert_eq!(
        core_patch(&patch_with("")).unwrap().proxy_bypass,
        Some(vec![])
    );
    // A running session follows the list: no «at the next connection» note.
    assert!(!next_connect(&patch_with("")));
    let auto = ui::SettingsPatch {
        proxy_bypass_auto: Some(false),
        ..ui::SettingsPatch::default()
    };
    assert_eq!(core_patch(&auto).unwrap().proxy_bypass_auto, Some(false));
    assert!(!next_connect(&auto));
}

#[test]
fn a_bad_entry_is_refused_by_name_before_any_write() {
    let err = core_patch(&patch_with("good.example\n~ads")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Validation);
    let msg = err.msg.unwrap();
    assert_eq!(msg.key, "engine.routing.bypass.invalid");
    assert_eq!(msg.args[0].1, "~ads");
}

#[test]
fn the_view_shows_one_entry_per_line() {
    let s = Settings {
        proxy_bypass: vec!["corp.example".into(), "*.lan".into()],
        proxy_bypass_auto: false,
        ..Settings::default()
    };
    let view = settings_view(&s, &Default::default(), true);
    assert_eq!(view.proxy_bypass, "corp.example\n*.lan");
    assert!(!view.proxy_bypass_auto);
    assert!(Settings::default().proxy_bypass_auto);
}

#[test]
fn the_stored_entries_come_first_in_each_readers_syntax() {
    let s = Settings {
        proxy_bypass: vec!["corp.example".into(), "10.*".into()],
        ..Settings::default()
    };
    let auto = [bypass::BypassEntry::parse("*.bank.example").unwrap()];
    let list = lists(&s, &auto);
    assert_eq!(
        list.proxy_override,
        [
            "corp.example",
            "*.corp.example",
            "10.0.0.0/8",
            "*.bank.example"
        ]
    );
    assert_eq!(
        list.no_proxy,
        ["corp.example", ".corp.example", "10.0.0.0/8"]
    );
}

fn proxy_mode() -> Settings {
    Settings {
        routing_mode: RoutingMode::Soft,
        ..Settings::default()
    }
}

/// The automatic entries need Proxy mode and the switch; without Smart RU the user's Direct
/// rules alone decide, with Smart RU running but its lists unread nothing is certain.
#[tokio::test]
async fn automatic_entries_need_proxy_mode_and_the_switch() {
    let dir = TempDir::new("bypass-auto");
    let backend = backend(&dir, FakeTunnel::new(false));
    backend
        .rules
        .update(|d| {
            let site = DomainPattern::parse("bank.example").unwrap();
            d.add_domain_rule(site, DomainAction::Direct)
        })
        .unwrap()
        .unwrap();
    assert!(automatic_wanted(&proxy_mode()));
    assert!(!automatic_wanted(&Settings::default()), "Tunnel mode");
    let off = Settings {
        proxy_bypass_auto: false,
        ..proxy_mode()
    };
    assert!(!automatic_wanted(&off));
    assert_eq!(smart_dir(&backend, &proxy_mode()).await, None);
    let got = automatic(&backend, &proxy_mode(), false, None);
    assert_eq!(got, [BypassEntry::Site("bank.example".into())]);
    assert!(automatic(&backend, &proxy_mode(), true, None).is_empty());
}

/// With Smart RU on the keeper reads the active (here: bundled) rule sets through the engine;
/// skipped quietly where the bundled engine is missing.
#[tokio::test]
async fn smart_ru_adds_the_gov_list_of_the_active_rule_sets() {
    let dir = TempDir::new("bypass-smart");
    let backend = backend(&dir, FakeTunnel::new(false));
    if !backend.engines.singbox.exists() {
        return;
    }
    let s = Settings {
        smart_ru_split: true,
        smart_ru_rule_set_mode: RuleSetMode::Bundled,
        ..proxy_mode()
    };
    let active = smart_dir(&backend, &s).await.expect("the bundled lists");
    assert_eq!(active, backend.dirs.resources);
    let lists = read_lists(&backend.engines.singbox, &active).await.unwrap();
    let got = automatic(&backend, &s, true, Some(&lists));
    assert!(got.contains(&BypassEntry::Site("gosuslugi.ru".into())));
    assert!(
        !got.iter()
            .any(|e| ["ru", "su", "xn--p1ai"].contains(&e.to_string().trim_start_matches("*.")))
    );
    // psmart-b1: the same lists name Smart RU's VPN route for a site blocked in Russia.
    assert!(lists.blocked_covers("rutracker.org"));
}

/// fixlists-a2: a failed read of the Smart RU lists is not kept: the same directory is read
/// again (here its files appear in between) and a retry is due until then.
#[tokio::test]
async fn a_failed_read_of_the_lists_is_tried_again() {
    let real = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
    let exe = real.join("sing-box.exe");
    if !exe.exists() {
        return;
    }
    let dir = TempDir::new("bypass-reread");
    let mut reader = Reader::default();
    reader.read(&exe, &dir.0).await;
    assert!(reader.cache.is_none() && reader.stale(&dir.0));
    assert_eq!(reader.failures, 1);
    for (_, file, _) in vpnte_engine::routing::smart_ru::RULE_SETS {
        std::fs::copy(real.join(file), dir.0.join(file)).unwrap();
    }
    reader.read(&exe, &dir.0).await;
    assert!(reader.cache.is_some() && !reader.stale(&dir.0));
    assert_eq!(reader.failures, 0);
}

/// fixlists-a3: the Settings page wakes when the keeper holds other lists, not when it sends
/// the same ones again.
#[tokio::test]
async fn new_lists_wake_the_settings_page() {
    let out = watch::Sender::new(None);
    let mut rx = out.subscribe();
    let lists = Arc::new(SmartLists::default());
    publish(&out, Some(lists.clone()));
    assert!(rx.has_changed().unwrap());
    rx.borrow_and_update();
    publish(&out, Some(lists));
    assert!(!rx.has_changed().unwrap(), "the same lists");
    publish(&out, None);
    assert!(rx.has_changed().unwrap());
}
