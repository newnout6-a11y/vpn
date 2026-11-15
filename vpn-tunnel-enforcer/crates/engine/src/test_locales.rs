//! Locale checks for the whole crate: the fragment files in `locales/`, [`crate::LOCALES`] and
//! every i18n key the sources use (literal keys and `format!("engine.….{}")` families).
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde_json::Value;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Leaf keys of a fragment (`engine.process.xray.exited`) with their text; panics on invalid
/// JSON or a non-string leaf.
pub(crate) fn flatten(json: &str) -> BTreeMap<String, String> {
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
fn fragments() -> Vec<(String, String, String)> {
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

/// Every registered key with its text, `[ru, en]`.
static CATALOG: LazyLock<[BTreeMap<String, String>; 2]> = LazyLock::new(|| {
    let (mut ru, mut en) = (BTreeMap::new(), BTreeMap::new());
    for (ru_json, en_json) in crate::LOCALES {
        ru.extend(flatten(ru_json));
        en.extend(flatten(en_json));
    }
    [ru, en]
});

/// The registered text of `key` in `lang` (`"ru"` / `"en"`); panics when it is missing.
pub(crate) fn text(lang: &str, key: &str) -> String {
    let catalog = &CATALOG[usize::from(lang == "en")];
    catalog
        .get(key)
        .unwrap_or_else(|| panic!("missing locale key {key} ({lang})"))
        .clone()
}

/// Panics unless `key` (or its plural forms `key_one`, …) exists in both languages.
pub(crate) fn assert_localized(key: &str) {
    for (lang, keys) in ["ru", "en"].iter().zip(CATALOG.iter()) {
        let found = keys.keys().any(|k| {
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

/// Every `.rs` file under `src/` except this one.
fn sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("src dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&Path::new(ROOT).join("src"), &mut files);
    files
        .into_iter()
        .filter(|f| !f.ends_with("test_locales.rs"))
        .map(|f| {
            let text = std::fs::read_to_string(&f).expect("source");
            (f, text)
        })
        .collect()
}

/// Every fragment: valid JSON, one top-level key `engine`, the same keys and `{{placeholders}}`
/// in ru and en, no key defined by two packages.
#[test]
fn fragments_are_valid_and_match() {
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    for (package, ru_json, en_json) in fragments() {
        for json in [&ru_json, &en_json] {
            let doc: Value = serde_json::from_str(json).expect("valid JSON");
            let top: Vec<&String> = doc.as_object().expect("object").keys().collect();
            assert_eq!(top, ["engine"], "{package}: top-level keys");
        }
        let (ru, en) = (flatten(&ru_json), flatten(&en_json));
        assert!(ru.keys().eq(en.keys()), "{package}: ru and en keys differ");
        for (key, text) in &ru {
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
    assert!(
        owner.len() > 50,
        "only {} keys: is the walk broken?",
        owner.len()
    );
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

/// Every i18n key literal in the sources (`"engine.…"`) exists in both languages, and every
/// registered key is used: literally, or by a `format!("engine.….{…}")` family.
#[test]
fn keys_in_the_sources_match_the_fragments() {
    let literal = regex::Regex::new(r#""(engine\.[A-Za-z0-9_.]*[A-Za-z0-9_])""#).expect("pattern");
    let family = regex::Regex::new(r#""(engine\.[A-Za-z0-9_.]*\.)\{"#).expect("pattern");
    let (mut used, mut families) = (BTreeSet::new(), BTreeSet::new());
    for (_, text) in sources() {
        for found in literal.captures_iter(&text) {
            assert_localized(&found[1]);
            used.insert(found[1].to_owned());
        }
        families.extend(family.captures_iter(&text).map(|c| c[1].to_owned()));
    }
    assert!(
        used.len() > 50,
        "only {} keys found: is the scan broken?",
        used.len()
    );
    let plural = regex::Regex::new(r"_(zero|one|two|few|many|other)$").expect("pattern");
    for key in CATALOG[0].keys() {
        let base = plural.replace(key, "");
        let known = used.contains(base.as_ref()) || families.iter().any(|f| base.starts_with(f));
        assert!(known, "{key} is never used");
    }
}
