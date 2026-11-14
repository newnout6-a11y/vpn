//! AT-09-011 (ru / en parity). The package's locale fragment: valid JSON, identical key sets in
//! ru and en, placeholders equal, every `app.tools.*` key the code names present, the probes'
//! keys the code names present in their own fragments, and the fragment registered once.
use std::collections::BTreeMap;

fn flat(prefix: &str, v: &serde_json::Value, out: &mut BTreeMap<String, String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                flat(&format!("{prefix}{k}."), v, out);
            }
        }
        other => {
            let text = other.as_str().unwrap_or_default().to_owned();
            out.insert(prefix.trim_end_matches('.').to_owned(), text);
        }
    }
}

fn keys(text: &str) -> BTreeMap<String, String> {
    let value: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
    let mut out = BTreeMap::new();
    flat("", &value, &mut out);
    out
}

fn placeholders(text: &str) -> Vec<&str> {
    let mut found: Vec<&str> = text
        .match_indices("{{")
        .filter_map(|(i, _)| text[i + 2..].split("}}").next())
        .collect();
    found.sort_unstable();
    found
}

const RU: &str = include_str!("../../../locales/app-tools.ru.json");
const EN: &str = include_str!("../../../locales/app-tools.en.json");

const SOURCES: [&str; 5] = [
    include_str!("../mod.rs"),
    include_str!("../project.rs"),
    include_str!("../availability.rs"),
    include_str!("../routing.rs"),
    include_str!("../speed.rs"),
];

/// Every quoted key with `prefix` in the package's sources.
fn named(prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for source in SOURCES {
        for (i, _) in source.match_indices(&format!("\"{prefix}")) {
            out.push(source[i + 1..].chars().take_while(|c| *c != '"').collect());
        }
    }
    out
}

#[test]
fn fragments_match_and_cover_the_code() {
    let (ru, en) = (keys(RU), keys(EN));
    assert_eq!(
        ru.keys().collect::<Vec<_>>(),
        en.keys().collect::<Vec<_>>(),
        "ru and en key sets differ"
    );
    for (key, text) in &en {
        assert!(key.starts_with("app.tools."), "{key}");
        assert!(
            !text.trim().is_empty() && !ru[key].trim().is_empty(),
            "{key}"
        );
        assert_eq!(placeholders(text), placeholders(&ru[key]), "{key}");
        assert!(
            !text.chars().any(|c| matches!(c, 'а'..='я' | 'А'..='Я')),
            "{key}"
        );
    }
    let used = named("app.tools.");
    assert!(!used.is_empty());
    for key in used {
        assert!(en.contains_key(&key), "missing locale key {key}");
    }
}

/// The probes' keys this package returns itself exist in their fragments (ru and en).
#[test]
fn borrowed_keys_exist() {
    let layers = [
        (
            include_str!("../../../../probes/locales/probes-web.ru.json"),
            include_str!("../../../../probes/locales/probes-web.en.json"),
        ),
        (
            include_str!("../../../../probes/locales/probes-diag.ru.json"),
            include_str!("../../../../probes/locales/probes-diag.en.json"),
        ),
    ];
    let catalogs: Vec<_> = layers.iter().map(|(ru, en)| (keys(ru), keys(en))).collect();
    let used = named("probes.");
    assert!(!used.is_empty());
    for key in used {
        assert!(
            catalogs
                .iter()
                .any(|(ru, en)| ru.contains_key(&key) && en.contains_key(&key)),
            "{key}"
        );
    }
}

/// The fragment is part of the app's single locale registration (`svc_core::locale_layers`).
#[test]
fn fragment_is_a_locale_layer() {
    let layers = crate::svc_core::locale_layers();
    assert_eq!(layers.iter().filter(|pair| **pair == (RU, EN)).count(), 1);
}
