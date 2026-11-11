//! Test helpers shared by the modules: throw-away directories and the locale-fragment checks.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

/// A fresh directory under `%TEMP%`, removed on drop (tests never touch the real data dirs).
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "vpnte-core-{tag}-{}-{n}-{:08x}",
            std::process::id(),
            fastrand::u32(..)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// Writes `name` (parents created) and returns its path.
    pub(crate) fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// Text of `name`, empty when it does not exist.
    pub(crate) fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.0.join(name)).unwrap_or_default()
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

/// `a.b.c` key -> text of every leaf (non-string leaves become their JSON text).
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

/// The keys of one package's fragment (ru and en are checked equal by `fragments_are_consistent`).
pub(crate) fn package_keys(package: &str) -> BTreeSet<String> {
    let fragments = fragments();
    let (_, en) = fragments
        .get(package)
        .unwrap_or_else(|| panic!("no fragment {package}"));
    flatten(en).into_keys().collect()
}

/// Every fragment is valid JSON with identical ru / en keys and placeholders, every leaf is a
/// string under `core`, and no key is defined by two packages.
#[test]
fn fragments_are_consistent() {
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    let all = fragments();
    assert_eq!(all.len(), 5, "one fragment pair per work package");
    for (package, (ru_doc, en_doc)) in all {
        for doc in [&ru_doc, &en_doc] {
            let top: Vec<&String> = doc.as_object().unwrap().keys().collect();
            assert_eq!(top, ["core"], "{package}: one top-level key `core`");
        }
        let (ru, en) = (flatten(&ru_doc), flatten(&en_doc));
        assert_eq!(
            ru.keys().collect::<Vec<_>>(),
            en.keys().collect::<Vec<_>>(),
            "{package}"
        );
        for (key, text) in &en {
            let leaf = en_doc.pointer(&format!("/{}", key.replace('.', "/")));
            assert!(leaf.is_some_and(Value::is_string), "{package}: {key}");
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

/// Every literal `core.*` key passed to `Msg::new` in the sources exists in the fragments.
#[test]
fn literal_message_keys_exist() {
    fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let known: BTreeSet<String> = fragments()
        .values()
        .flat_map(|(_, en)| flatten(en).into_keys())
        .collect();
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut seen = 0;
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        for part in text.split("Msg::new(\"core.").skip(1) {
            let key = format!("core.{}", part.split('"').next().unwrap());
            assert!(known.contains(&key), "{}: {key}", file.display());
            seen += 1;
        }
    }
    assert!(seen > 20, "the scan found the message keys ({seen})");
}
