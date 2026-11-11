//! Test helpers over the locale files: the old app's UI strings (`crates/ui/assets/locales`) plus
//! every fragment of this crate (`locales/<package>.{ru,en}.json`), read the way
//! `vpnte_base::i18n` flattens them.
use std::collections::BTreeMap;
use std::path::Path;

/// A flattened i18next document: `a.b.c` -> template.
pub type Catalog = BTreeMap<String, String>;

/// Flattens an i18next document (nested objects become dotted keys); panics on invalid JSON.
pub fn flatten(json: &str) -> Catalog {
    fn walk(prefix: &str, v: &serde_json::Value, out: &mut Catalog) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    walk(&key, v, out);
                }
            }
            serde_json::Value::String(s) => {
                out.insert(prefix.to_owned(), s.clone());
            }
            other => {
                out.insert(prefix.to_owned(), other.to_string());
            }
        }
    }
    let value: serde_json::Value = serde_json::from_str(json).expect("locale file is valid JSON");
    let mut out = Catalog::new();
    walk("", &value, &mut out);
    out
}

/// This crate's fragments as `(package, ru json, en json)`, sorted by package.
pub fn fragments() -> Vec<(String, String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("locales");
    let mut pairs: BTreeMap<String, [String; 2]> = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).expect("locales dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let (stem, slot) = match (name.strip_suffix(".ru.json"), name.strip_suffix(".en.json")) {
            (Some(stem), _) => (stem, 0),
            (_, Some(stem)) => (stem, 1),
            _ => continue,
        };
        let text = std::fs::read_to_string(&path).expect("readable fragment");
        pairs.entry(stem.to_owned()).or_default()[slot] = text;
    }
    pairs
        .into_iter()
        .map(|(stem, [ru, en])| (stem, ru, en))
        .collect()
}

/// What the app registers for this crate, `[ru, en]`: UI strings, then [`crate::LOCALES`].
#[cfg(any(feature = "view-logic", feature = "view-mascot"))]
pub fn catalogs() -> [Catalog; 2] {
    let mut ru = flatten(include_str!("../../ui/assets/locales/ru.json"));
    let mut en = flatten(include_str!("../../ui/assets/locales/en.json"));
    for (ru_json, en_json) in crate::LOCALES {
        ru.extend(flatten(ru_json));
        en.extend(flatten(en_json));
    }
    [ru, en]
}

/// `msg` resolves in both languages and supplies every `{{placeholder}}` of its template.
#[cfg(any(feature = "view-logic", feature = "view-mascot"))]
pub fn assert_resolves(msg: &vpnte_base::Msg, catalogs: &[Catalog; 2]) {
    for (lang, cat) in ["ru", "en"].into_iter().zip(catalogs) {
        let template = cat
            .get(msg.key.as_ref())
            .unwrap_or_else(|| panic!("{lang}: missing key {}", msg.key));
        let mut rest = template.as_str();
        while let Some(start) = rest.find("{{") {
            let end = rest[start..].find("}}").expect("closed placeholder") + start;
            let name = rest[start + 2..end].trim();
            assert!(
                msg.args.iter().any(|(k, _)| k == name),
                "{lang}: {} needs {{{{{name}}}}}",
                msg.key
            );
            rest = &rest[end + 2..];
        }
    }
}

/// Every fragment is valid JSON, has both languages with identical keys, all under `view`.
#[test]
fn fragments_are_valid_with_identical_keys_under_view() {
    let all = fragments();
    assert!(!all.is_empty(), "no locale fragments found");
    for (package, ru, en) in all {
        assert!(
            !ru.is_empty() && !en.is_empty(),
            "{package}: a language is missing"
        );
        let (ru, en) = (flatten(&ru), flatten(&en));
        assert!(ru.keys().eq(en.keys()), "{package}: ru and en keys differ");
        for key in ru.keys() {
            assert!(
                key.starts_with("view."),
                "{package}: {key} is not under `view`"
            );
        }
    }
}

/// [`crate::LOCALES`] carries every fragment file, in package order.
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
