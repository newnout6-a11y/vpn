//! Locale checks for the whole crate: the fragment files in `locales/`, [`crate::LOCALES`] and
//! every i18n key the sources use (literal keys, `concat!` / `format!` prefixes and key-prefix
//! constants such as `tunnel.lifecycle.notice`). Also the one test-side catalog of the crate.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde_json::Value;
use vpnte_base::i18n::Lang;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Leaf keys of a fragment (`tunnel.runtime.tunSetup.adapter`) with their text; panics on invalid
/// JSON or a non-string leaf.
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

/// Every registered key with its text, `[ru, en]`.
static CATALOG: LazyLock<[BTreeMap<String, String>; 2]> = LazyLock::new(|| {
    let (mut ru, mut en) = (BTreeMap::new(), BTreeMap::new());
    for (ru_json, en_json) in crate::LOCALES {
        ru.extend(flatten(ru_json));
        en.extend(flatten(en_json));
    }
    [ru, en]
});

fn catalog(lang: Lang) -> &'static BTreeMap<String, String> {
    &CATALOG[usize::from(lang == Lang::En)]
}

/// The registered template of `key` in `lang` (the process-wide i18n catalogs are set once per
/// process and may belong to another test, so tests render against this one).
pub(crate) fn template(lang: Lang, key: &str) -> Option<&'static str> {
    catalog(lang).get(key).map(String::as_str)
}

/// `key` (or its plural forms `key_one`, …) exists in both languages.
pub(crate) fn has_key(key: &str) -> bool {
    [Lang::Ru, Lang::En].into_iter().all(|lang| {
        catalog(lang).keys().any(|k| {
            k == key
                || k.strip_prefix(key)
                    .is_some_and(|rest| rest.starts_with('_'))
        })
    })
}

fn placeholders(text: &str) -> BTreeSet<&str> {
    text.split("{{")
        .skip(1)
        .filter_map(|rest| rest.split_once("}}").map(|(name, _)| name.trim()))
        .collect()
}

/// Production code of every `.rs` file under `src/`: test files (`tests.rs`, `tests/`) are skipped
/// and an inline `#[cfg(test)] mod tests` block is cut off (tests use fake keys on purpose).
fn sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
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
        .filter(|f| {
            let test_file = f.ends_with("tests.rs") || f.ends_with("test_locales.rs");
            !test_file && !f.components().any(|c| c.as_os_str() == "tests")
        })
        .map(|f| {
            let text = std::fs::read_to_string(&f).expect("source");
            let code = text.split("#[cfg(test)]\nmod tests {").next();
            (f, code.unwrap_or_default().to_owned())
        })
        .collect()
}

/// One `"tunnel.…` string in a source: a whole literal key, or a prefix that code completes
/// (`concat!("tunnel.outcome.headline.", ..)`, `format!("tunnel.….{name}")`).
enum Found<'a> {
    Literal(&'a str),
    Prefix(&'a str),
}

fn scan(text: &str) -> Vec<Found<'_>> {
    let is_key = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.';
    let mut out = Vec::new();
    for (at, _) in text.match_indices("\"tunnel.") {
        let rest = &text[at + 1..];
        let end = rest.find(|c: char| !is_key(c)).unwrap_or(rest.len());
        let key = &rest[..end];
        match rest[end..].chars().next() {
            Some('"') if key.ends_with('.') => out.push(Found::Prefix(key)),
            Some('"') => out.push(Found::Literal(key)),
            Some('{') => out.push(Found::Prefix(key)),
            _ => {}
        }
    }
    out
}

/// Every fragment: valid JSON, one top-level key `tunnel`, the same keys and `{{placeholders}}`
/// in ru and en, no key defined by two packages.
#[test]
fn fragments_are_valid_and_match() {
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    for (package, ru_json, en_json) in fragments() {
        for json in [&ru_json, &en_json] {
            let doc: Value = serde_json::from_str(json).expect("valid JSON");
            let top: Vec<&String> = doc.as_object().expect("object").keys().collect();
            assert_eq!(top, ["tunnel"], "{package}: top-level keys");
        }
        let (ru, en) = (flatten(&ru_json), flatten(&en_json));
        assert!(ru.keys().eq(en.keys()), "{package}: ru and en keys differ");
        for (key, text) in &ru {
            assert!(!text.trim().is_empty(), "{package}: {key} is empty");
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
        owner.len() > 100,
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

/// Every key literal in the sources (`"tunnel.…"`) exists in both languages (or is the prefix of
/// a key family), and every registered key is used: literally or under a used prefix.
#[test]
fn keys_in_the_sources_match_the_fragments() {
    let keys = catalog(Lang::Ru);
    let (mut used, mut prefixes) = (BTreeSet::new(), BTreeSet::new());
    for (file, text) in sources() {
        for found in scan(&text) {
            match found {
                Found::Literal(key) if has_key(key) => {
                    used.insert(key.to_owned());
                }
                Found::Literal(key) => {
                    let family = format!("{key}.");
                    let known = keys.keys().any(|k| k.starts_with(&family));
                    assert!(known, "{}: {key} is not localized", file.display());
                    prefixes.insert(family);
                }
                Found::Prefix(prefix) => {
                    prefixes.insert(prefix.to_owned());
                }
            }
        }
    }
    assert!(
        used.len() > 50,
        "only {} keys found: is the scan broken?",
        used.len()
    );
    for key in keys.keys() {
        let base = ["_zero", "_one", "_two", "_few", "_many", "_other"]
            .iter()
            .find_map(|s| key.strip_suffix(s))
            .unwrap_or(key);
        let known = used.contains(base) || prefixes.iter().any(|p| base.starts_with(p.as_str()));
        assert!(known, "{key} is never used");
    }
}

/// p-follow3: the exit-check texts of a start or a server switch also show in Proxy mode,
/// where nothing is a tunnel: they never say so (like `exitSilent`).
#[test]
fn exit_check_texts_are_mode_neutral() {
    for key in ["egressUnknown", "exitSilent", "switchUnconfirmed"] {
        let key = format!("tunnel.runtime.{key}");
        let ru = template(Lang::Ru, &key).expect("ru").to_lowercase();
        let en = template(Lang::En, &key).expect("en").to_lowercase();
        assert!(
            !ru.contains("туннел") && !en.contains("tunnel"),
            "{key}: {ru} / {en}"
        );
    }
}
