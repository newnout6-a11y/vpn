//! The locale fragment of the package: valid JSON, identical key sets in ru and en, and every
//! key the code uses present.
fn keys(prefix: &str, v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                keys(&format!("{prefix}{k}."), v, out);
            }
        }
        _ => out.push(prefix.trim_end_matches('.').to_owned()),
    }
}

fn flat(text: &str) -> Vec<String> {
    let value: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
    let mut out = Vec::new();
    keys("", &value, &mut out);
    out.sort();
    out
}

#[test]
fn fragments_match_and_cover_the_code() {
    let ru = flat(include_str!("../../../locales/app-settings.ru.json"));
    let en = flat(include_str!("../../../locales/app-settings.en.json"));
    assert_eq!(ru, en, "ru and en key sets differ");
    assert!(en.iter().all(|k| k.starts_with("app.")));
    let sources = [
        include_str!("../mod.rs"),
        include_str!("../service.rs"),
        include_str!("../project.rs"),
        include_str!("../save.rs"),
        include_str!("../actions.rs"),
        include_str!("../rules.rs"),
        include_str!("../wizard.rs"),
        include_str!("../dialog.rs"),
        include_str!("../../api_logs/mod.rs"),
        include_str!("../../services.rs"),
    ];
    for source in sources {
        for (i, _) in source.match_indices("\"app.") {
            let key: String = source[i + 1..].chars().take_while(|c| *c != '"').collect();
            if key.starts_with("app.settings.") || key.starts_with("app.logs.") {
                assert!(en.contains(&key), "missing locale key {key}");
            }
        }
    }
}

/// The fragment is one of the app's locale layers (compiled in with the feature).
#[test]
fn fragment_is_a_locale_layer() {
    let en = include_str!("../../../locales/app-settings.en.json");
    assert!(
        crate::svc_core::locale_layers()
            .iter()
            .any(|(_, layer_en)| *layer_en == en)
    );
}
