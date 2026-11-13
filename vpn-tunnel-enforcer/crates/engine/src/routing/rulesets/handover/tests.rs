use serde_json::Value;

use super::*;
use crate::test_support::{TempDir, resources, singbox_exe};

fn bundled_set() -> RuleSetFiles {
    RuleSetFiles::read(&resources()).expect("the bundled rule sets")
}

/// The set as JSON, with `edit` applied to its files array (the wire form the app sends).
fn edited(edit: impl FnOnce(&mut Vec<Value>)) -> RuleSetFiles {
    let mut v = serde_json::to_value(bundled_set()).unwrap();
    edit(v["files"].as_array_mut().unwrap());
    serde_json::from_value(v).unwrap()
}

fn data(f: &[Value], name: &str) -> Value {
    f.iter().find(|x| x["name"] == name).unwrap()["data"].clone()
}

/// The hand-over carries every file in `RULE_SETS` order as base64, logs names and sizes only,
/// and is refused by `read` when a file is missing.
#[test]
fn a_set_is_read_in_order_and_travels_as_base64() {
    let set = bundled_set();
    let v = serde_json::to_value(&set).unwrap();
    let names: Vec<&str> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    let expected: Vec<&str> = RULE_SETS.iter().map(|(_, f, _)| *f).collect();
    assert_eq!(names, expected);
    assert!(v["files"][0]["data"].as_str().unwrap().starts_with("U1JT"));
    let back: RuleSetFiles = serde_json::from_value(v).unwrap();
    assert_eq!(back, set);
    assert_eq!(back.digest(), set.digest());
    let shown = format!("{set:?}");
    assert!(
        shown.contains("geoip-ru.srs") && shown.len() < 300,
        "{shown}"
    );

    let t = TempDir::new("handover-read");
    for (_, file, _) in RULE_SETS.iter().skip(1) {
        std::fs::copy(resources().join(file), t.path().join(file)).unwrap();
    }
    assert!(
        RuleSetFiles::read(t.path()).is_none(),
        "geoip-ru.srs missing"
    );
    let other = edited(|f| f.swap(0, 1));
    assert_ne!(other.digest(), set.digest());
}

/// The service's re-check: the app's set is checked with the service's own engine and stored as
/// `gen-<digest>`; the same set again is used as stored; a file that fails its canaries, a
/// changed order or an oversized set is refused and leaves nothing behind.
#[tokio::test]
async fn the_service_accepts_only_sets_that_pass_its_own_checks() {
    let Some(exe) = singbox_exe() else { return };
    let t = TempDir::new("handover-accept");
    let store = t.path().join("rulesets");
    let set = bundled_set();
    let dir = accept(&set, &exe, &store).await.expect("the bundled set");
    assert!(complete(&dir));
    for (_, file, _) in RULE_SETS {
        assert_eq!(
            std::fs::read(dir.join(file)).unwrap(),
            std::fs::read(resources().join(file)).unwrap()
        );
    }
    assert_eq!(accept(&set, &exe, &store).await, Ok(dir.clone()));

    let swapped = edited(|f| {
        let geoip = data(f, "geoip-ru.srs");
        f[3]["data"] = geoip;
    });
    assert_eq!(
        accept(&swapped, &exe, &store).await,
        Err(RefreshFault::Invalid {
            file: "geoip-ru-blocked.srs".into()
        })
    );
    let reordered = edited(|f| f.swap(2, 3));
    assert!(accept(&reordered, &exe, &store).await.is_err());
    let oversized = edited(|f| {
        let big = STANDARD.encode(vec![7u8; MAX_HANDOVER_BYTES]);
        f[0]["data"] = Value::String(big);
    });
    assert!(accept(&oversized, &exe, &store).await.is_err());
    let left: Vec<String> = std::fs::read_dir(&store)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, [dir.file_name().unwrap().to_string_lossy()]);

    let old = store.join(format!("{GEN_PREFIX}0123456789abcdef"));
    std::fs::create_dir_all(&old).unwrap();
    prune_store(&store, &[dir.as_path()]);
    assert!(dir.exists() && !old.exists());
}
