//! Test helpers shared by the packages: a throw-away directory, a throw-away `HKCU` key, the
//! locale fragment lookups, and the crate-wide checks of `LOCALES`. Nothing here touches the
//! user's real data or settings.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use vpnte_winnet::registry::{self, Hive, View};

/// A fresh directory under `%TEMP%`, removed on drop (tests never touch the real data dirs).
pub(crate) struct TempDir(pub(crate) PathBuf);

impl TempDir {
    /// `%TEMP%\vpnte-automation-<tag>-<uuid>`.
    pub(crate) fn new(tag: &str) -> Self {
        let name = format!("vpnte-automation-{tag}-{}", uuid::Uuid::new_v4());
        let dir = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `HKCU\Software\VPNTE-Test-<tag>-<uuid>`, deleted with its contents on drop.
pub(crate) struct TestKey(pub(crate) String);

impl TestKey {
    pub(crate) fn new(tag: &str) -> Self {
        Self(format!(
            r"Software\VPNTE-Test-{tag}-{}",
            uuid::Uuid::new_v4()
        ))
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        let _ = registry::delete_tree(Hive::CurrentUser, &self.0, View::Native);
    }
}

/// The leaves of an i18next fragment by dotted key; panics on invalid JSON or a non-string leaf.
pub(crate) fn fragment(json: &str) -> BTreeMap<String, String> {
    fn walk(prefix: &str, value: &serde_json::Value, out: &mut BTreeMap<String, String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    walk(&path, value, out);
                }
            }
            serde_json::Value::String(text) => {
                out.insert(prefix.to_owned(), text.clone());
            }
            other => panic!("{prefix}: not a string: {other}"),
        }
    }
    let mut out = BTreeMap::new();
    walk("", &serde_json::from_str(json).unwrap(), &mut out);
    out
}

/// Every key of the crate's Russian fragments with its text.
fn russian() -> BTreeMap<String, String> {
    crate::LOCALES
        .iter()
        .flat_map(|(ru, _)| fragment(ru))
        .collect()
}

/// The Russian text of `key` from the crate's fragments; panics when it is missing.
pub(crate) fn ru(key: &str) -> String {
    russian()
        .remove(key)
        .unwrap_or_else(|| panic!("missing in the fragments: {key}"))
}

/// Whether the crate's fragments define `key` (a plural key counts by its `_other` form).
pub(crate) fn has_key(key: &str) -> bool {
    let all = russian();
    all.contains_key(key) || all.contains_key(&format!("{key}_other"))
}

mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use super::{fragment, has_key};
    use crate::LOCALES;

    const CRATE: &str = env!("CARGO_MANIFEST_DIR");

    /// `LOCALES` is exactly the fragments in `locales/`: one `(ru, en)` pair per package, in
    /// file-name order (the app registers this list, so a new fragment must be added to it).
    #[test]
    fn locales_are_the_fragment_files() {
        let mut names: Vec<String> = std::fs::read_dir(Path::new(CRATE).join("locales"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".json"))
            .collect();
        names.sort();
        let packages: BTreeSet<&str> = names
            .iter()
            .map(|n| n.rsplitn(3, '.').nth(2).unwrap())
            .collect();
        assert_eq!(
            names.len(),
            2 * packages.len(),
            "a ru / en pair each: {names:?}"
        );
        assert_eq!(LOCALES.len(), packages.len());
        let read =
            |name: String| std::fs::read_to_string(Path::new(CRATE).join("locales").join(name));
        for (package, (ru, en)) in packages.iter().zip(LOCALES) {
            assert_eq!(
                read(format!("{package}.ru.json")).unwrap(),
                *ru,
                "{package}"
            );
            assert_eq!(
                read(format!("{package}.en.json")).unwrap(),
                *en,
                "{package}"
            );
        }
    }

    /// Valid JSON with string leaves, everything under `automation.`, the same keys and
    /// placeholders in Russian and English, and no key defined by two packages.
    #[test]
    fn fragments_are_complete() {
        let vars = regex::Regex::new(r"\{\{(\w+)\}\}").unwrap();
        let names = |text: &str| -> BTreeSet<String> {
            vars.captures_iter(text).map(|c| c[1].to_owned()).collect()
        };
        let mut owner: BTreeMap<String, usize> = BTreeMap::new();
        for (index, (ru, en)) in LOCALES.iter().enumerate() {
            let (ru, en) = (fragment(ru), fragment(en));
            assert_eq!(ru.keys().collect::<Vec<_>>(), en.keys().collect::<Vec<_>>());
            for (key, text) in &ru {
                assert!(key.starts_with("automation."), "{key}");
                assert!(
                    !text.trim().is_empty() && !en[key].trim().is_empty(),
                    "{key}"
                );
                assert_eq!(names(text), names(&en[key]), "{key}");
                assert_eq!(
                    owner.insert(key.clone(), index),
                    None,
                    "{key} in two fragments"
                );
            }
        }
    }

    /// Every `"automation.…"` key literal in the crate's sources exists in the fragments
    /// (composed keys are checked next to the code that composes them).
    #[test]
    fn literal_keys_exist() {
        fn sources(dir: &Path, out: &mut Vec<(String, String)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    sources(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    out.push((path.display().to_string(), text));
                }
            }
        }
        let mut files = Vec::new();
        sources(&Path::new(CRATE).join("src"), &mut files);
        assert!(files.len() > 20, "the walk found the sources");
        let literal = regex::Regex::new(r#""(automation\.[A-Za-z0-9_.]*[A-Za-z0-9_])""#).unwrap();
        let mut checked = 0;
        for (file, text) in &files {
            for key in literal.captures_iter(text) {
                assert!(
                    has_key(&key[1]),
                    "{file}: missing in the fragments: {}",
                    &key[1]
                );
                checked += 1;
            }
        }
        assert!(checked > 100, "only {checked} keys found");
    }
}
