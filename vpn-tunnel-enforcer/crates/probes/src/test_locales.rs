//! Locale checks for the whole crate: the fragment files in `locales/` and [`crate::LOCALES`].
//! Each package's own test pins that the keys its code emits exist and none is unused.
use std::collections::BTreeMap;
use std::path::Path;

use crate::test_support::{flatten, placeholders};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Fragment files on disk as `(package, ru, en)`, in file-name order (`probes-live-stages.*`
/// before `probes-live.*`: `-` sorts before `.`).
fn fragments() -> Vec<(String, String, String)> {
    let dir = Path::new(ROOT).join("locales");
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .expect("locales dir")
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|name| name.ends_with(".ru.json"))
        .collect();
    files.sort();
    files
        .iter()
        .filter_map(|name| name.strip_suffix(".ru.json"))
        .map(|p| {
            let read = |lang: &str| {
                std::fs::read_to_string(dir.join(format!("{p}.{lang}.json"))).expect("fragment")
            };
            let (ru, en) = (read("ru"), read("en"));
            (p.to_owned(), ru, en)
        })
        .collect()
}

/// Every fragment: valid JSON, all keys under `probes`, the same keys and placeholders in ru
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
    for (package, ru, en) in fragments {
        let (ru, en) = (flatten(&ru), flatten(&en));
        assert!(ru.keys().eq(en.keys()), "{package}: ru and en keys differ");
        for (key, text) in &ru {
            assert!(
                key.starts_with("probes."),
                "{package}: {key} is not under `probes`"
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

/// [`crate::LOCALES`] carries exactly the fragment files, in the order of [`fragments`] (a new
/// fragment needs its pair in `lib.rs`).
#[test]
fn locales_const_lists_every_fragment() {
    let on_disk: Vec<(String, String, String)> = fragments();
    let names: Vec<&str> = on_disk.iter().map(|(p, _, _)| p.as_str()).collect();
    assert_eq!(
        crate::LOCALES.len(),
        on_disk.len(),
        "LOCALES vs files {names:?}"
    );
    for ((package, ru, en), &(reg_ru, reg_en)) in on_disk.iter().zip(crate::LOCALES) {
        assert!(ru == reg_ru && en == reg_en, "LOCALES entry for {package}");
    }
}
