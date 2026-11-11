//! Locale checks for the whole crate: the fragment files in `locales/`, [`crate::LOCALES`] and
//! every i18n key written in the sources.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Leaf keys of a fragment (`servers.fetch.http`) with their text; panics on invalid JSON.
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

fn placeholders(text: &str) -> BTreeSet<&str> {
    text.split("{{")
        .skip(1)
        .filter_map(|rest| rest.split_once("}}").map(|(name, _)| name.trim()))
        .collect()
}

/// Every fragment: valid JSON, all keys under `servers`, the same keys and placeholders in ru and
/// en, no key defined by two packages, and an `en` file for every `ru` file.
#[test]
fn fragments_are_valid_and_match() {
    let files = std::fs::read_dir(Path::new(ROOT).join("locales")).expect("locales dir");
    let json_files = files
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|name| name.ends_with(".json"))
        .count();
    let fragments = fragments();
    assert_eq!(
        json_files,
        2 * fragments.len(),
        "one ru and one en file per package"
    );
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    for (package, ru, en) in fragments {
        let (ru, en) = (flatten(&ru), flatten(&en));
        assert!(ru.keys().eq(en.keys()), "{package}: ru and en keys differ");
        for (key, text) in &ru {
            assert!(
                key.starts_with("servers."),
                "{package}: {key} is not under `servers`"
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

/// Every `.rs` file under `src/` but this one, with whether it is a test file.
fn sources() -> Vec<(PathBuf, bool)> {
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
            let test = f.ends_with("tests.rs");
            (f, test)
        })
        .collect()
}

/// The i18n key literals (`"servers.…"`) of a source text.
fn key_literals(source: &str) -> impl Iterator<Item = &str> {
    source.match_indices("\"servers.").filter_map(|(at, _)| {
        let rest = &source[at + 1..];
        let key = &rest[..rest.find('"')?];
        let plain = key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_');
        (plain && !key.ends_with('.')).then_some(key)
    })
}

/// Every i18n key literal in the sources exists in both languages, and every key of the
/// fragments is used by non-test code (no dead text).
#[test]
fn keys_in_the_sources_match_the_fragments() {
    let (mut ru, mut en) = (BTreeSet::new(), BTreeSet::new());
    for (ru_json, en_json) in crate::LOCALES {
        ru.extend(flatten(ru_json).into_keys());
        en.extend(flatten(en_json).into_keys());
    }
    let mut used = BTreeSet::new();
    for (file, test) in sources() {
        let text = std::fs::read_to_string(&file).expect("source");
        for key in key_literals(&text) {
            assert!(
                ru.contains(key),
                "{key} ({}) is missing in ru",
                file.display()
            );
            assert!(
                en.contains(key),
                "{key} ({}) is missing in en",
                file.display()
            );
            if !test {
                used.insert(key.to_owned());
            }
        }
    }
    let unused: Vec<&String> = ru.difference(&used).collect();
    assert!(unused.is_empty(), "keys no code uses: {unused:?}");
}
