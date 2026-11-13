use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::{Value, json};
use vpnte_base::types::KillSwitchLevel;
use vpnte_ui::theme::{Rgb, ThemeMode};

use super::*;

/// A throw-away data dir under %TEMP%, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("vpnte-app-base-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn keys(prefix: &str, v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                keys(&key, v, out);
            }
        }
        _ => {
            out.insert(prefix.to_owned());
        }
    }
}

fn flat(json: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    keys("", &serde_json::from_str(json).unwrap(), &mut out);
    out
}

#[test]
fn app_base_fragments_have_identical_keys_and_every_key_used() {
    let ru = flat(include_str!("../../locales/app-base.ru.json"));
    let en = flat(include_str!("../../locales/app-base.en.json"));
    assert_eq!(ru, en);
    for key in ["app.base.needsAdmin", "app.base.tunnelMissing"] {
        assert!(ru.contains(key), "{key}");
    }
    assert!(ru.iter().all(|k| k.starts_with("app.base.")));
}

#[test]
fn every_locale_layer_is_a_json_object() {
    let layers = locale_layers();
    assert!(layers.len() > 20);
    for (ru, en) in layers {
        for text in [ru, en] {
            assert!(serde_json::from_str::<Value>(text).unwrap().is_object());
        }
    }
}

#[test]
fn needs_admin_is_a_permission_error_with_its_message() {
    let err = needs_admin();
    assert_eq!(err.kind, ErrorKind::Permission);
    assert_eq!(err.user_msg().key, "app.base.needsAdmin");
}

#[test]
fn first_start_defaults_to_soft_unless_elevated() {
    for (fresh, elevated, expected) in [
        (true, false, RoutingMode::Soft),
        (true, true, RoutingMode::Hard),
        (false, false, RoutingMode::Hard),
    ] {
        let dir = TempDir::new("first-start");
        let settings = Store::<Settings>::open(&dir.0);
        first_start(&settings, fresh, elevated);
        let saved = Store::<Settings>::open(&dir.0).snapshot();
        assert_eq!(
            saved.routing_mode, expected,
            "fresh {fresh}, elevated {elevated}"
        );
        assert!(saved.log_key.is_some(), "the log key is persisted");
    }
}

#[test]
fn engines_resolve_canonically_or_keep_the_expected_path() {
    let missing = PathBuf::from(r"C:\nonexistent-vpnte\resources");
    let e = engines(&missing);
    assert_eq!(e.singbox, missing.join("sing-box.exe"));
    assert_eq!(e.xray, missing.join("xray.exe"));

    let bundled = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
    if bundled.join("sing-box.exe").is_file() {
        let e = engines(&bundled);
        let text = e.singbox.to_string_lossy().into_owned();
        assert!(
            e.singbox.is_file() && !text.contains("..") && !text.starts_with(r"\\?\"),
            "{text}"
        );
    }
}

#[test]
fn themes_resolve_builtins_custom_and_unknown_ids() {
    let doc = ThemesDoc::from_legacy(&json!({
        "activeThemeId": "custom-1",
        "customThemes": [
            {"id": "custom-1", "name": "Sea", "mode": "dark", "colors": {"accent": "#112233"}, "isCustom": true},
            {"id": "broken", "mode": 7},
            "junk"
        ]
    }));
    assert_eq!(doc.custom_themes.len(), 1, "invalid entries are dropped");
    let sea = doc.theme("custom-1");
    assert_eq!(sea.mode, ThemeMode::Dark);
    assert_eq!(sea.custom.map(|p| p.accent), Some(Rgb(0x11, 0x22, 0x33)));
    assert_eq!(doc.theme(docs::BUILTIN_LIGHT).mode, ThemeMode::Light);
    assert_eq!(doc.theme(docs::BUILTIN_DARK).custom, None);
    assert_eq!(
        doc.theme("deleted-id"),
        vpnte_ui::theme::Theme::builtin(ThemeMode::System)
    );
}

#[test]
fn protection_doc_round_trips_and_keeps_unknown_keys() {
    let dir = TempDir::new("protection");
    let file = dir.0.join(ProtectionDoc::FILE);
    std::fs::write(
        &file,
        r#"{"schemaVersion": 1, "level": "strict", "allowLan": true, "futureKey": [1, 2]}"#,
    )
    .unwrap();
    let store = Store::<ProtectionDoc>::open(&dir.0);
    let doc = store.snapshot();
    assert_eq!(doc.settings.level, KillSwitchLevel::Strict);
    assert!(
        doc.settings.leak_protection,
        "a missing field takes its default"
    );
    assert_eq!(doc.extra.get("futureKey"), Some(&json!([1, 2])));
    store.update(|d| d.settings.allow_lan = false).unwrap();
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(saved["allowLan"], json!(false));
    assert_eq!(saved["futureKey"], json!([1, 2]));
    assert_eq!(saved["schemaVersion"], json!(1));
    assert!(saved.get("settings").is_none() && saved.get("extra").is_none());
}

#[test]
fn soft_doc_defaults_to_no_dev_targets() {
    let doc: SoftDoc = serde_json::from_value(json!({"devTargets": {"git": true}})).unwrap();
    assert!(doc.dev_targets.git && !doc.dev_targets.gradle && !doc.dev_targets.android_studio);
    assert_eq!(SoftDoc::default().dev_targets, Default::default());
}

/// firewall-recovery §2 / storage A4: the old level wins when strict, else the old boolean;
/// exceptions are re-validated and invalid ones dropped and counted.
#[test]
fn protection_from_legacy_revalidates_exceptions() {
    let old = json!({
        "killSwitchLevel": "strict",
        "killSwitchExceptions": [
            {"id": "e1", "type": "ip", "value": "10.0.0.0/8", "label": "LAN"},
            {"id": "e2", "type": "ip", "value": "10.0.0.0/8", "label": "same network again"},
            {"id": "e3", "type": "ip", "value": "not an address", "label": "bad"},
            {"id": "e4", "type": "app", "value": r"C:\nonexistent-vpnte\gone.exe", "label": "gone"},
            {"type": "ip", "value": "192.168.1.1", "label": "no id"},
            {"id": "e6", "type": "bogus", "value": "x", "label": "y"}
        ]
    });
    let (doc, dropped) = ProtectionDoc::from_legacy(Some(&old), Some(false));
    assert_eq!(doc.settings.level, KillSwitchLevel::Strict);
    assert_eq!(doc.settings.exceptions.len(), 1);
    assert_eq!(doc.settings.exceptions[0].id, "e1");
    assert_eq!(dropped, 5);

    let (doc, dropped) = ProtectionDoc::from_legacy(None, Some(true));
    assert_eq!(
        (doc.settings.level, dropped),
        (KillSwitchLevel::Standard, 0)
    );
    let (doc, _) = ProtectionDoc::from_legacy(None, None);
    assert_eq!(doc, ProtectionDoc::default());
}

/// `Arc<Backend>` crosses threads (UI thread, tokio workers, the notifier thread).
#[test]
fn backend_is_shareable_across_threads() {
    fn shareable<T: Send + Sync + 'static>() {}
    shareable::<Backend>();
    shareable::<Notifier>();
}

/// The whole bootstrap against throw-away dirs: lock, log, stores, first-start default, paths.
/// The only test that builds the backend (it installs the process-wide log subscriber). It passes
/// the dirs to `build_in`: an elevated process ignores the environment overrides (p-left), and CI
/// runners are elevated.
#[test]
fn build_bootstraps_an_empty_data_dir() {
    let data = TempDir::new("build-data");
    let legacy = TempDir::new("build-legacy");
    let resources = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
    // SAFETY: the Windows environment block is guarded by the OS; no other test reads or
    // writes these variables. Code that reads them directly (the import's own-install check)
    // sees the same throw-away dirs.
    unsafe {
        std::env::set_var(vpnte_core::paths::ENV_DATA_DIR, &data.0);
        std::env::set_var(vpnte_core::paths::ENV_LEGACY_DIR, &legacy.0);
        std::env::set_var(vpnte_core::paths::ENV_RESOURCES_DIR, &resources);
    }
    let dirs = DataDirs::new(data.0.clone(), legacy.0.clone(), resources);
    let backend = build_in(&Args::default(), dirs).unwrap();
    assert_eq!(backend.dirs.root, data.0);
    assert!(backend.dirs.logs.is_dir() && backend.import.is_none());
    let expected = if backend.elevated {
        RoutingMode::Hard
    } else {
        RoutingMode::Soft
    };
    assert_eq!(backend.settings.read(|s| s.routing_mode), expected);
    assert!(
        data.0.join(Settings::FILE).is_file(),
        "first start saved settings"
    );
    assert!(
        backend.tunnel().is_err(),
        "no tunnel before svc_tunnel::build"
    );
    assert!(
        build(&Args::default()).is_err(),
        "a second backend cannot take the data lock"
    );
    assert!(backend.servers.view().servers.is_empty());
    drop(backend.log.lock().take());
    drop(backend);
}
