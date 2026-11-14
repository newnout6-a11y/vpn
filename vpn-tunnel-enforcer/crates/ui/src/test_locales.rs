//! Locale checks shared by the packages' tests: flattening, placeholders, the runtime catalogs and
//! the crate-wide fragment rules (valid JSON, equal ru/en keys and placeholders, allowed sections).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde_json::Value;
use vpnte_base::i18n::Lang;

/// `crates/base/locales/base.{ru,en}.json`: the canonical `errors.*` texts every page shows.
pub(crate) const BASE: (&str, &str) = (
    include_str!("../../base/locales/base.ru.json"),
    include_str!("../../base/locales/base.en.json"),
);

/// A caller layer for the layer-order test of `lang`: it overrides a UI key and adds a backend key.
pub(crate) const PROBE: (&str, &str) = (
    r#"{"ui":{"frame":{"demo":{"close":"Закрыть окно"}}},"tunnel":{"x":"икс"}}"#,
    r#"{"tunnel":{"x":"ex"}}"#,
);

/// Registers the process-wide catalog the same way for every test (the first registration wins
/// for the whole test binary): the UI layers, the canonical errors and [`PROBE`].
pub(crate) fn init_locales() {
    crate::lang::init_locales(&[BASE, PROBE]);
}

/// Leaf keys (`a.b.c`) of a locale document with their texts. Panics on invalid JSON and on
/// leaves that are not strings.
pub(crate) fn flatten(json: &str) -> BTreeMap<String, String> {
    fn walk(prefix: &str, value: &Value, out: &mut BTreeMap<String, String>) {
        match value {
            Value::Object(map) => {
                for (k, v) in map {
                    walk(&format!("{prefix}{k}."), v, out);
                }
            }
            Value::String(s) => {
                out.insert(prefix.trim_end_matches('.').to_owned(), s.clone());
            }
            other => panic!("{prefix}: not a string: {other}"),
        }
    }
    let value: Value = serde_json::from_str(json).expect("valid locale JSON");
    let mut out = BTreeMap::new();
    walk("", &value, &mut out);
    out
}

/// `key_one` / `key_few` / … → `key`: plural forms differ between the languages.
pub(crate) fn plural_stem(key: &str) -> &str {
    ["_zero", "_one", "_two", "_few", "_many", "_other"]
        .iter()
        .find_map(|suffix| key.strip_suffix(suffix))
        .unwrap_or(key)
}

/// `{{name}}` placeholders of a text, sorted and deduplicated.
pub(crate) fn placeholders(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .split("{{")
        .skip(1)
        .filter_map(|rest| {
            rest.split_once("}}")
                .map(|(name, _)| name.trim().to_owned())
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// What the app resolves at runtime, `[ru, en]`: the old app's catalog, the canonical errors of
/// `vpnte-base`, every UI fragment, then `extra` (for example `vpnte_view::LOCALES`).
pub(crate) fn catalogs(extra: &[(&str, &str)]) -> [BTreeMap<String, String>; 2] {
    let old = |path: &str| {
        let bytes = crate::assets::file(path).expect("embedded old catalog");
        std::str::from_utf8(bytes).expect("UTF-8").to_owned()
    };
    let (old_ru, old_en) = (old("locales/ru.json"), old("locales/en.json"));
    let mut layers = vec![(old_ru.as_str(), old_en.as_str()), BASE];
    layers.extend_from_slice(crate::LOCALES);
    layers.extend_from_slice(extra);
    let (mut ru, mut en) = (BTreeMap::new(), BTreeMap::new());
    for (r, e) in layers {
        ru.extend(flatten(r));
        en.extend(flatten(e));
    }
    [ru, en]
}

/// The text of `key` (or of any of its plural forms) in `catalog`.
pub(crate) fn lookup<'a>(catalog: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    catalog.get(key).map(String::as_str).or_else(|| {
        catalog
            .iter()
            .find(|(k, _)| k.len() > key.len() && plural_stem(k) == key)
            .map(|(_, v)| v.as_str())
    })
}

/// [`catalogs`] without extra layers for one language, parsed once per test binary.
pub(crate) fn catalog(lang: Lang) -> &'static BTreeMap<String, String> {
    static CATALOGS: OnceLock<[BTreeMap<String, String>; 2]> = OnceLock::new();
    let [ru, en] = CATALOGS.get_or_init(|| catalogs(&[]));
    match lang {
        Lang::Ru => ru,
        Lang::En => en,
    }
}

/// The text of `key` (or of one of its plural forms) in `lang` itself, without the English
/// fallback the runtime lookup has.
pub(crate) fn text(lang: Lang, key: &str) -> Option<String> {
    lookup(catalog(lang), key).map(str::to_owned)
}

/// Asserts that every key exists in both catalogs (plural keys through any form).
pub(crate) fn assert_resolve<'a>(
    catalogs: &[BTreeMap<String, String>; 2],
    keys: impl IntoIterator<Item = &'a str>,
) {
    let missing: Vec<String> = keys
        .into_iter()
        .flat_map(|key| {
            ["ru", "en"]
                .into_iter()
                .zip(catalogs)
                .filter(|(_, catalog)| lookup(catalog, key).is_none())
                .map(move |(lang, _)| format!("{lang}: {key}"))
        })
        .collect();
    assert!(missing.is_empty(), "missing locale keys: {missing:#?}");
}

/// Plural stems with the placeholders of all their forms.
fn stems(doc: &BTreeMap<String, String>) -> BTreeMap<&str, BTreeSet<String>> {
    let mut out: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (key, text) in doc {
        out.entry(plural_stem(key))
            .or_default()
            .extend(placeholders(text));
    }
    out
}

/// `LOCALES` lists every `locales/<fragment>.{ru,en}.json` pair, in file-name order.
#[test]
fn locales_list_every_fragment() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("locales");
    let mut fragments: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("locales dir") {
        let name = entry
            .expect("dir entry")
            .file_name()
            .to_string_lossy()
            .into_owned();
        if let Some(stem) = name
            .strip_suffix(".ru.json")
            .or(name.strip_suffix(".en.json"))
        {
            fragments.insert(stem.to_owned());
        }
    }
    let read = |name: String| std::fs::read_to_string(dir.join(name)).expect("fragment file");
    let on_disk: Vec<(String, String)> = fragments
        .iter()
        .map(|stem| {
            (
                read(format!("{stem}.ru.json")),
                read(format!("{stem}.en.json")),
            )
        })
        .collect();
    let listed: Vec<(String, String)> = crate::LOCALES
        .iter()
        .map(|(ru, en)| ((*ru).to_owned(), (*en).to_owned()))
        .collect();
    assert_eq!(
        listed.len(),
        on_disk.len(),
        "fragments on disk: {fragments:?}"
    );
    assert!(
        listed == on_disk,
        "LOCALES differs from locales/ (order or content)"
    );
}

/// Every fragment: valid JSON with string leaves, the same keys (plural forms collapsed) and
/// placeholders in ru and en, no Cyrillic in en, keys only under `ui` or a section of the old
/// app's catalog, and no key defined by two fragments.
#[test]
fn fragments_pair_up() {
    let old =
        flatten(std::str::from_utf8(crate::assets::file("locales/ru.json").unwrap()).unwrap());
    let sections: BTreeSet<&str> = old.keys().filter_map(|k| k.split('.').next()).collect();
    let mut owner: BTreeMap<String, usize> = BTreeMap::new();
    for (index, (ru, en)) in crate::LOCALES.iter().enumerate() {
        let (ru, en) = (flatten(ru), flatten(en));
        assert_eq!(
            stems(&ru),
            stems(&en),
            "fragment #{index}: keys or placeholders differ"
        );
        for (key, text) in &en {
            let cyrillic = text.chars().any(|c| ('\u{400}'..='\u{4ff}').contains(&c));
            assert!(!cyrillic, "fragment #{index}: Cyrillic in en text of {key}");
        }
        for key in ru.keys() {
            let section = key.split('.').next().unwrap_or_default();
            assert!(
                section == "ui" || sections.contains(section),
                "fragment #{index}: {key} is outside `ui` and the old catalog's sections"
            );
            if let Some(other) = owner.insert(key.clone(), index) {
                panic!("{key} is defined by fragments #{other} and #{index}");
            }
        }
    }
}
