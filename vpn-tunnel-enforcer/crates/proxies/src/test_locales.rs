//! Locale checks for the whole crate (AT-09-011, ru/en parity): the fragment files in `locales/`,
//! [`crate::LOCALES`], every i18n key written in the sources and the placeholders the code fills.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Leaf keys of a fragment (`proxies.error.conflict`) with their text; panics on invalid JSON or
/// a leaf that is not a non-empty string.
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
            Value::String(text) if !text.trim().is_empty() => {
                out.insert(prefix.to_owned(), text.clone());
            }
            other => panic!("{prefix}: not a non-empty string: {other}"),
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

/// Every registered key with its text, `(ru, en)`.
fn catalog() -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let (mut ru, mut en) = (BTreeMap::new(), BTreeMap::new());
    for (ru_json, en_json) in crate::LOCALES {
        ru.extend(flatten(ru_json));
        en.extend(flatten(en_json));
    }
    (ru, en)
}

fn placeholders(text: &str) -> BTreeSet<&str> {
    text.split("{{")
        .skip(1)
        .filter_map(|rest| rest.split_once("}}").map(|(name, _)| name.trim()))
        .collect()
}

/// Every fragment: valid JSON, one top-level key `proxies`, the same keys and placeholders in ru
/// and en, no key defined by two packages, and an `en` file for every `ru` file.
#[test]
fn fragments_are_valid_and_match() {
    let json_files = std::fs::read_dir(Path::new(ROOT).join("locales"))
        .expect("locales dir")
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
    for (package, ru_json, en_json) in fragments {
        for json in [&ru_json, &en_json] {
            let doc: Value = serde_json::from_str(json).expect("valid JSON");
            let top: Vec<&String> = doc.as_object().expect("object").keys().collect();
            assert_eq!(top, ["proxies"], "{package}: top-level keys");
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
        owner.len() >= 10,
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
            let test = f.ends_with("tests.rs") || f.ends_with("check.rs");
            (f, test)
        })
        .collect()
}

/// The i18n key literals (`"proxies.…"`) of a source text.
fn key_literals(source: &str) -> impl Iterator<Item = &str> {
    source.match_indices("\"proxies.").filter_map(|(at, _)| {
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
    let (ru, en) = catalog();
    let mut used = BTreeSet::new();
    for (file, test) in sources() {
        let text = std::fs::read_to_string(&file).expect("source");
        for key in key_literals(&text) {
            let shown = file.display();
            assert!(ru.contains_key(key), "{key} ({shown}) is missing in ru");
            assert!(en.contains_key(key), "{key} ({shown}) is missing in en");
            if !test {
                used.insert(key.to_owned());
            }
        }
    }
    let unused: Vec<&String> = ru.keys().filter(|k| !used.contains(*k)).collect();
    assert!(unused.is_empty(), "keys no code uses: {unused:?}");
}

/// Panics unless `msg` names a registered key whose texts contain every argument it fills.
fn assert_renders(msg: &vpnte_base::Msg) {
    let (ru, en) = catalog();
    for (lang, catalog) in [("ru", &ru), ("en", &en)] {
        let key = msg.key.as_ref();
        let text = catalog
            .get(key)
            .unwrap_or_else(|| panic!("{key} is missing in {lang}"));
        let wanted: BTreeSet<&str> = msg.args.iter().map(|(name, _)| name.as_ref()).collect();
        assert_eq!(placeholders(text), wanted, "{lang} {key}");
    }
}

/// The messages the backend hands out fill exactly the placeholders of their texts.
#[test]
fn messages_fill_their_placeholders() {
    {
        use crate::model::ProxyError;
        let detail = || "detail".to_owned();
        for err in [
            ProxyError::BadRequest(detail()),
            ProxyError::Forbidden(detail()),
            ProxyError::NotFound(detail()),
            ProxyError::Conflict(detail()),
            ProxyError::Unavailable(detail()),
            ProxyError::Upstream(502, detail()),
            ProxyError::Engine(detail()),
        ] {
            assert_renders(&vpnte_base::AppError::from(err).user_msg());
        }
    }
    {
        use crate::manager::degradation_msg;
        use crate::model::Degradation;
        for reason in [
            Degradation::ProcessFailed,
            Degradation::LeasedRouteRecoveryBlocked,
            Degradation::HealthFailureBudgetExhausted,
            Degradation::EgressIpChangedWithoutRotation,
            Degradation::RotationDidNotChangeEgressIp,
            Degradation::DuplicateEgressIp,
            Degradation::EgressProbeFailed,
        ] {
            assert_renders(&degradation_msg(reason));
        }
    }
    {
        use crate::control::ServeError;
        let io = || std::io::Error::other("x");
        for err in [
            ServeError::Token(io()),
            ServeError::Bind {
                port: 17873,
                source: io(),
            },
        ] {
            assert_renders(&vpnte_base::AppError::from(err).user_msg());
        }
    }
}
