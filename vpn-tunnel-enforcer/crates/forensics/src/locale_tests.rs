//! The locale fragments: `LOCALES` lists every file of `locales/`, each fragment is valid JSON with
//! all keys under `forensics`, ru and en have the same keys and placeholders, no key is defined
//! twice, and every key the code names exists.
use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use super::LOCALES;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/locales");
const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");

/// Leaf key path → text; panics on a non-string leaf.
fn flatten(prefix: &str, v: &Value, out: &mut BTreeMap<String, String>) {
    match v {
        Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&path, v, out);
            }
        }
        Value::String(s) => {
            out.insert(prefix.to_string(), s.clone());
        }
        other => panic!("{prefix}: not a string: {other}"),
    }
}

fn parse(name: &str, text: &str) -> BTreeMap<String, String> {
    let v: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("{name}: {e}"));
    let top: Vec<&String> = v
        .as_object()
        .expect("fragment is an object")
        .keys()
        .collect();
    assert_eq!(top, ["forensics"], "{name}: top-level keys");
    let mut out = BTreeMap::new();
    flatten("", &v, &mut out);
    out
}

fn placeholders(text: &str) -> Vec<&str> {
    let mut out: Vec<&str> = text
        .match_indices("{{")
        .filter_map(|(at, _)| text[at..].find("}}").map(|end| &text[at..at + end + 2]))
        .collect();
    out.sort_unstable();
    out
}

#[test]
fn locales_list_every_fragment_in_file_name_order() {
    let mut names: Vec<String> = std::fs::read_dir(DIR)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    let stems: Vec<&str> = names
        .iter()
        .filter_map(|n| n.strip_suffix(".ru.json"))
        .collect();
    let expected: Vec<String> = stems
        .iter()
        .flat_map(|s| [format!("{s}.en.json"), format!("{s}.ru.json")])
        .collect();
    let mut sorted = expected.clone();
    sorted.sort();
    assert_eq!(names, sorted, "every fragment has a ru and an en file");
    assert_eq!(LOCALES.len(), stems.len());
    for ((ru, en), stem) in LOCALES.iter().zip(&stems) {
        let read = |lang: &str| {
            std::fs::read_to_string(Path::new(DIR).join(format!("{stem}.{lang}.json")))
        };
        assert_eq!(*ru, read("ru").unwrap(), "{stem}.ru.json");
        assert_eq!(*en, read("en").unwrap(), "{stem}.en.json");
    }
}

#[test]
fn fragments_agree_and_cover_every_key_in_the_code() {
    let mut all_ru = BTreeMap::new();
    let mut all_en = BTreeMap::new();
    for (i, (ru, en)) in LOCALES.iter().enumerate() {
        let (ru, en) = (
            parse(&format!("#{i} ru"), ru),
            parse(&format!("#{i} en"), en),
        );
        assert_eq!(
            ru.keys().collect::<Vec<_>>(),
            en.keys().collect::<Vec<_>>(),
            "#{i}"
        );
        for (key, text) in &ru {
            assert_eq!(placeholders(text), placeholders(&en[key]), "{key}");
            assert!(
                !text.trim().is_empty() && !en[key].trim().is_empty(),
                "{key}"
            );
        }
        for (key, text) in ru {
            assert!(
                all_ru.insert(key.clone(), text).is_none(),
                "{key} defined twice"
            );
        }
        all_en.extend(en);
    }
    let literal = regex::Regex::new(r#""(forensics\.[A-Za-z]+\.[A-Za-z0-9_.]+)""#).unwrap();
    let mut used = 0;
    let mut stack = vec![Path::new(SRC).to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for cap in literal.captures_iter(&text) {
                used += 1;
                let key = &cap[1];
                assert!(
                    all_ru.contains_key(key) && all_en.contains_key(key),
                    "{}: missing key {key}",
                    path.display()
                );
            }
        }
    }
    assert!(used >= 50, "{used}");
}
