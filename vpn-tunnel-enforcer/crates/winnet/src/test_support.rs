//! Test helpers shared by the modules: throw-away directories and the locale-fragment checks.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

/// A fresh directory under %TEMP% in its long form (no `\\?\`, no 8.3 names), removed on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("vpnte-test-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = std::fs::canonicalize(&dir).unwrap();
        let long = real.to_str().unwrap().trim_start_matches(r"\\?\");
        Self(PathBuf::from(long))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// Creates `name` with a minimal `MZ` header and returns its path.
    pub(crate) fn file(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, b"MZ").unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every fragment on disk: package id -> (ru, en) documents.
fn fragments() -> BTreeMap<String, (Value, Value)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("locales");
    let read = |path: PathBuf| -> Value {
        let text = std::fs::read_to_string(&path).unwrap();
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    };
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if let Some(package) = name.strip_suffix(".ru.json") {
            let en = dir.join(format!("{package}.en.json"));
            out.insert(package.to_owned(), (read(dir.join(&name)), read(en)));
        }
    }
    out
}

/// `a.b.c` key -> text of every leaf.
fn flatten(value: &Value) -> BTreeMap<String, String> {
    fn walk(prefix: &str, value: &Value, out: &mut BTreeMap<String, String>) {
        match value {
            Value::Object(map) => {
                for (k, v) in map {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    walk(&key, v, out);
                }
            }
            Value::String(s) => {
                out.insert(prefix.to_owned(), s.clone());
            }
            other => {
                out.insert(prefix.to_owned(), other.to_string());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk("", value, &mut out);
    out
}

/// `{{name}}` placeholders of a text.
fn placeholders(text: &str) -> BTreeSet<&str> {
    text.split("{{")
        .skip(1)
        .filter_map(|s| s.split_once("}}"))
        .map(|(name, _)| name)
        .collect()
}

/// The keys of one package's fragment (the en and ru key sets are checked equal elsewhere).
pub(crate) fn package_keys(package: &str) -> BTreeSet<String> {
    let fragments = fragments();
    let (_, en) = fragments
        .get(package)
        .unwrap_or_else(|| panic!("no fragment {package}"));
    flatten(en).into_keys().collect()
}

/// Every `"winnet.…"` string literal in the sources (a literal ending in `.` is a key prefix).
fn literal_keys() -> BTreeSet<String> {
    fn walk(dir: &Path, out: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                for rest in text.split("\"winnet.").skip(1) {
                    let key = &rest[..rest.find('"').unwrap_or(0)];
                    let plain = key.chars().all(|c| c.is_ascii_alphanumeric() || c == '.');
                    if plain && !key.is_empty() && !key.ends_with('.') {
                        out.insert(format!("winnet.{key}"));
                    }
                }
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out
}

/// Every key the code names literally exists in the fragments.
#[test]
fn literal_keys_exist() {
    let all: BTreeSet<String> = fragments()
        .values()
        .flat_map(|(_, en)| flatten(en).into_keys())
        .collect();
    let keys = literal_keys();
    assert!(keys.len() > 40, "the scan found the keys: {keys:?}");
    let missing: Vec<&String> = keys.iter().filter(|k| !all.contains(*k)).collect();
    assert!(missing.is_empty(), "missing locale keys: {missing:?}");
}

/// Every fragment is valid JSON with identical ru / en keys and placeholders, all under `winnet`;
/// no key is defined by two packages.
#[test]
fn fragments_are_consistent() {
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    for (package, (ru, en)) in fragments() {
        let (ru, en) = (flatten(&ru), flatten(&en));
        assert_eq!(
            ru.keys().collect::<Vec<_>>(),
            en.keys().collect::<Vec<_>>(),
            "{package}"
        );
        for (key, text) in &en {
            assert!(
                key.starts_with("winnet."),
                "{package}: {key} is not under `winnet`"
            );
            assert_eq!(
                placeholders(text),
                placeholders(&ru[key]),
                "{package}: {key}"
            );
            if let Some(other) = owner.insert(key.clone(), package.clone()) {
                panic!("{key} is defined by {other} and {package}");
            }
        }
    }
}

/// [`crate::LOCALES`] carries exactly the fragment files, in package order.
#[test]
fn locales_constant_matches_the_files() {
    let files: Vec<(Value, Value)> = fragments().into_values().collect();
    let registered: Vec<(Value, Value)> = crate::LOCALES
        .iter()
        .map(|(ru, en)| {
            (
                serde_json::from_str(ru).unwrap(),
                serde_json::from_str(en).unwrap(),
            )
        })
        .collect();
    assert_eq!(registered, files);
}
