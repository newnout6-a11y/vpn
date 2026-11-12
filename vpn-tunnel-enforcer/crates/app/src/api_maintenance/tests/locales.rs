//! AT-09-011 (ru / en parity). The package's locale fragment: valid JSON, identical key sets
//! in ru and en, placeholders equal, and every `app.maintenance.*` key the code names present.
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

const RU: &str = include_str!("../../../locales/app-maintenance.ru.json");
const EN: &str = include_str!("../../../locales/app-maintenance.en.json");

#[test]
fn fragments_match_and_cover_the_code() {
    let (ru, en) = (keys(RU), keys(EN));
    assert_eq!(
        ru.keys().collect::<Vec<_>>(),
        en.keys().collect::<Vec<_>>(),
        "ru and en key sets differ"
    );
    for (key, text) in &en {
        assert!(key.starts_with("app.maintenance."), "{key}");
        assert!(
            !text.trim().is_empty() && !ru[key].trim().is_empty(),
            "{key}"
        );
        assert_eq!(placeholders(text), placeholders(&ru[key]), "{key}");
    }
    let sources = [
        include_str!("../mod.rs"),
        include_str!("../project.rs"),
        include_str!("../legacy.rs"),
        include_str!("../protection.rs"),
        include_str!("../repair.rs"),
        include_str!("../report.rs"),
        include_str!("../selftest.rs"),
        include_str!("../export.rs"),
    ];
    for source in sources {
        for (i, _) in source.match_indices("\"app.maintenance.") {
            let key: String = source[i + 1..].chars().take_while(|c| *c != '"').collect();
            assert!(en.contains_key(&key), "missing locale key {key}");
        }
    }
}

/// Keys of other layers this package returns exist in their own fragments (ru and en).
#[test]
fn borrowed_keys_exist() {
    let layers = [
        (
            include_str!("../../../../forensics/locales/forensics-export.ru.json"),
            include_str!("../../../../forensics/locales/forensics-export.en.json"),
            &["forensics.export.dialogTitle", "forensics.export.zipFilter"][..],
        ),
        (
            include_str!("../../../../cleanup/locales/cleanup-legacy.ru.json"),
            include_str!("../../../../cleanup/locales/cleanup-legacy.en.json"),
            &["cleanup.legacy.notice.summary"][..],
        ),
        (
            include_str!("../../../../probes/locales/probes-ip.ru.json"),
            include_str!("../../../../probes/locales/probes-ip.en.json"),
            &["probes.leak.selfTest.disagreement"][..],
        ),
        (
            include_str!("../../../../core/locales/core-ops.ru.json"),
            include_str!("../../../../core/locales/core-ops.en.json"),
            &["core.ops.busy"][..],
        ),
    ];
    for (ru, en, wanted) in layers {
        let (ru, en) = (keys(ru), keys(en));
        for key in wanted {
            assert!(ru.contains_key(*key) && en.contains_key(*key), "{key}");
        }
    }
}

/// The fragments of this package and of `app-clickjack` (its Save dialog) are part of the app's
/// single locale registration (`svc_core::locale_layers`).
#[test]
fn fragment_is_a_locale_layer() {
    let layers = crate::svc_core::locale_layers();
    let clickjack = (
        include_str!("../../../locales/app-clickjack.ru.json"),
        include_str!("../../../locales/app-clickjack.en.json"),
    );
    for pair in [clickjack, (RU, EN)] {
        assert_eq!(
            layers.iter().filter(|p| **p == pair).count(),
            1,
            "{}",
            pair.0.len()
        );
    }
}
