//! Locale checks: the fragments are valid JSON with the same keys and placeholders in ru and en,
//! [`crate::LOCALES`] equals the files, and every `service.*` key literal in the sources exists
//! while every fragment key is used by the sources.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::Value;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

fn flatten(json: &str) -> BTreeMap<String, String> {
    fn walk(prefix: &str, value: &Value, out: &mut BTreeMap<String, String>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    walk(&path, child, out);
                }
            }
            Value::String(text) => {
                out.insert(prefix.to_owned(), text.clone());
            }
            other => panic!("{prefix}: not a string: {other}"),
        }
    }
    let value: Value = serde_json::from_str(json).expect("fragment is valid JSON");
    let mut out = BTreeMap::new();
    walk("", &value, &mut out);
    out
}

fn placeholders(text: &str) -> BTreeSet<String> {
    text.split("{{")
        .skip(1)
        .filter_map(|rest| rest.split_once("}}").map(|(name, _)| name.to_owned()))
        .collect()
}

/// Every `"service.…"` string literal in `src/` (keys are always written out in full).
fn code_keys() -> BTreeSet<String> {
    fn scan(dir: &Path, out: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).expect("src dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs")
                && !path.ends_with("test_locales.rs")
            {
                let text = std::fs::read_to_string(&path).expect("source");
                for piece in text.split("\"service.").skip(1) {
                    // Keys have at least two segments (`service.pipe.busy`); `"service.log"`
                    // is a file name.
                    if let Some((key, _)) = piece.split_once('"')
                        && key.contains('.')
                        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '.')
                    {
                        out.insert(format!("service.{key}"));
                    }
                }
            }
        }
    }
    let mut out = BTreeSet::new();
    scan(&Path::new(ROOT).join("src"), &mut out);
    out
}

#[test]
fn fragments_match_each_other_the_code_and_locales_const() {
    let read = |lang: &str| {
        std::fs::read_to_string(Path::new(ROOT).join(format!("locales/svc-core.{lang}.json")))
            .expect("fragment")
    };
    let (ru, en) = (read("ru"), read("en"));
    assert_eq!(crate::LOCALES, &[(ru.as_str(), en.as_str())]);
    let (ru, en) = (flatten(&ru), flatten(&en));
    assert_eq!(
        ru.keys().collect::<Vec<_>>(),
        en.keys().collect::<Vec<_>>(),
        "ru and en keys differ"
    );
    for (key, text) in &ru {
        assert_eq!(placeholders(text), placeholders(&en[key]), "{key}");
        assert!(key.starts_with("service."), "{key}");
    }
    let used = code_keys();
    let missing: Vec<_> = used.iter().filter(|k| !ru.contains_key(*k)).collect();
    assert!(
        missing.is_empty(),
        "keys used in code but missing: {missing:?}"
    );
    let unused: Vec<_> = ru.keys().filter(|k| !used.contains(*k)).collect();
    assert!(unused.is_empty(), "fragment keys no code uses: {unused:?}");
}
