//! Locale checks shared by the package tests: the fragment files in `locales/`, [`crate::LOCALES`]
//! and every i18n key written in the sources.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use serde_json::Value;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Leaf keys of a fragment (`profiles.emit.echConfig`) with their text; panics on invalid JSON.
pub fn flatten(json: &str) -> BTreeMap<String, String> {
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

/// Fragment files on disk as `(package, ru, en)`, in file-name order.
pub fn fragments() -> Vec<(String, String, String)> {
    let dir = Path::new(ROOT).join("locales");
    let mut packages: Vec<String> = std::fs::read_dir(&dir)
        .expect("locales dir")
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|name| name.strip_suffix(".ru.json").map(str::to_owned))
        .collect();
    packages.sort();
    packages
        .into_iter()
        .map(|p| {
            let read = |lang: &str| {
                std::fs::read_to_string(dir.join(format!("{p}.{lang}.json"))).expect("fragment")
            };
            let (ru, en) = (read("ru"), read("en"));
            (p, ru, en)
        })
        .collect()
}

/// Leaf keys of one package's fragment (ru).
pub fn package_keys(package: &str) -> BTreeSet<String> {
    let (_, ru, _) = fragments()
        .into_iter()
        .find(|(p, _, _)| p == package)
        .unwrap_or_else(|| panic!("no fragment for {package}"));
    flatten(&ru).into_keys().collect()
}

/// Leaf keys of every registered fragment ([`crate::LOCALES`]), `[ru, en]`.
static CATALOG: LazyLock<[BTreeSet<String>; 2]> = LazyLock::new(|| {
    let (mut ru, mut en) = (BTreeSet::new(), BTreeSet::new());
    for (ru_json, en_json) in crate::LOCALES {
        ru.extend(flatten(ru_json).into_keys());
        en.extend(flatten(en_json).into_keys());
    }
    [ru, en]
});

/// Panics unless `key` (or its plural forms `key_one`, …) exists in both registered languages.
pub fn assert_localized(key: &str) {
    for (lang, keys) in ["ru", "en"].iter().zip(CATALOG.iter()) {
        let found = keys.iter().any(|k| {
            k == key
                || k.strip_prefix(key)
                    .is_some_and(|rest| rest.starts_with('_'))
        });
        assert!(found, "{key} is missing in {lang}");
    }
}

fn placeholders(text: &str) -> BTreeSet<&str> {
    text.split("{{")
        .skip(1)
        .filter_map(|rest| rest.split_once("}}").map(|(name, _)| name.trim()))
        .collect()
}

/// Every fragment: valid JSON, all keys under `profiles`, the same keys and placeholders in ru and
/// en, no key defined by two packages.
#[test]
fn fragments_are_valid_and_match() {
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    for (package, ru, en) in fragments() {
        let (ru, en) = (flatten(&ru), flatten(&en));
        assert!(ru.keys().eq(en.keys()), "{package}: ru and en keys differ");
        for (key, text) in &ru {
            assert!(
                key.starts_with("profiles."),
                "{package}: {key} is not under `profiles`"
            );
            assert_eq!(
                placeholders(text),
                placeholders(&en[key]),
                "{package}: {key}"
            );
            if let Some(other) = owner.insert(key.clone(), package.clone()) {
                panic!("{key} is defined by {other} and {package}");
            }
        }
    }
}

/// [`crate::LOCALES`] carries exactly the fragment files, in file-name order.
#[test]
fn locales_const_lists_every_fragment() {
    let on_disk: Vec<(String, String)> = fragments()
        .into_iter()
        .map(|(_, ru, en)| (ru, en))
        .collect();
    let registered: Vec<(String, String)> = crate::LOCALES
        .iter()
        .map(|&(ru, en)| (ru.to_owned(), en.to_owned()))
        .collect();
    assert_eq!(registered, on_disk);
}

/// Every i18n key literal in the sources (`"profiles.…"`) exists in both languages.
#[test]
fn every_key_in_the_sources_is_localized() {
    fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("src dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    rust_files(&Path::new(ROOT).join("src"), &mut files);
    let key = regex::Regex::new(r#""(profiles\.[A-Za-z0-9_.]*[A-Za-z0-9_])""#).expect("pattern");
    let mut seen = 0;
    for file in files.iter().filter(|f| !f.ends_with("test_locales.rs")) {
        let text = std::fs::read_to_string(file).expect("source");
        for found in key.captures_iter(&text) {
            assert_localized(&found[1]);
            seen += 1;
        }
    }
    assert!(seen > 50, "only {seen} keys found: is the scan broken?");
}
