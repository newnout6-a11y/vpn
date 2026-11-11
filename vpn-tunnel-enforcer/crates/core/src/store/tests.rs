//! Store tests: storage spec B16 / B26 / B28 / B29, AT-09-013, atomic writes.
use serde::Deserialize;

use super::*;
use crate::secret::Secret;
use crate::test_support::TempDir;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Doc {
    count: u32,
    name: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Document for Doc {
    const FILE: &'static str = "nested/doc.json";
    const VERSION: u32 = 1;
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct Vault {
    label: String,
    key: Option<Secret>,
}

impl Document for Vault {
    const FILE: &'static str = "vault.json";
    const VERSION: u32 = 1;
    const HOLDS_SECRETS: bool = true;
}

fn put(root: &Path, file: &str, text: &str) -> PathBuf {
    let path = root.join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, text).unwrap();
    path
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn missing_file_gives_defaults_and_first_change_writes_it() {
    let tmp = TempDir::new("store");
    let store = Store::<Doc>::open(tmp.path());
    assert_eq!(store.snapshot(), Doc::default());
    assert_eq!(store.mode(), Mode::Writable);
    assert_eq!(store.notice(), None);
    assert!(
        !store.path().exists(),
        "nothing is created before the first change"
    );

    let mut rx = store.subscribe();
    store.update(|d| d.count = 7).unwrap();
    assert!(rx.has_changed().unwrap());
    assert_eq!(*rx.borrow_and_update(), 1);
    let text = std::fs::read_to_string(tmp.path().join("nested").join("doc.json")).unwrap();
    assert!(
        text.starts_with("{\n  \"schemaVersion\": 1,\n  \"count\": 7,"),
        "{text}"
    );
    assert_eq!(
        files_in(&tmp.path().join("nested")),
        ["doc.json"],
        "no temp files left"
    );

    let again = Store::<Doc>::open(tmp.path());
    assert_eq!(again.read(|d| d.count), 7);
}

/// AT-09-013: an update that changes nothing writes nothing and notifies nobody.
#[test]
fn unchanged_update_makes_no_write() {
    let tmp = TempDir::new("store");
    let store = Store::<Doc>::open(tmp.path());
    store.update(|d| d.name = "a".into()).unwrap();
    std::fs::remove_file(store.path()).unwrap();
    let rx = store.subscribe();
    store.update(|d| d.name = "a".into()).unwrap();
    store.replace(store.snapshot()).unwrap();
    assert!(!store.path().exists());
    assert!(!rx.has_changed().unwrap());
}

/// B26: keys this version does not know survive a rewrite.
#[test]
fn unknown_keys_are_preserved() {
    let tmp = TempDir::new("store");
    put(
        tmp.path(),
        "nested/doc.json",
        r#"{"schemaVersion":1,"count":1,"futureKey":{"a":[1,2]}}"#,
    );
    let store = Store::<Doc>::open(tmp.path());
    store.update(|d| d.count = 2).unwrap();
    let v: Value = serde_json::from_slice(&std::fs::read(store.path()).unwrap()).unwrap();
    assert_eq!(v["futureKey"], serde_json::json!({"a": [1, 2]}));
    assert_eq!(v["count"], 2);
}

/// B28: a newer file is shown read-only and never overwritten.
#[test]
fn newer_version_is_read_only() {
    let tmp = TempDir::new("store");
    let text = r#"{"schemaVersion":2,"count":5,"name":"x"}"#;
    let path = put(tmp.path(), "nested/doc.json", text);
    let store = Store::<Doc>::open(tmp.path());
    assert_eq!(
        store.mode(),
        Mode::ReadOnly(ReadOnlyReason::NewerVersion(2))
    );
    assert_eq!(store.read(|d| d.count), 5, "content still shown");
    let err = store.update(|d| d.count = 6).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert_eq!(store.read(|d| d.count), 5);
    assert!(store.set_aside().is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    assert_eq!(store.notice().unwrap().key, "core.store.newerVersion");
}

/// B16: a corrupt document without secrets is moved aside byte-for-byte; the app goes on.
#[test]
fn corrupt_document_is_moved_aside() {
    let tmp = TempDir::new("store");
    put(tmp.path(), "nested/doc.json", "{\"count\": 3,");
    let store = Store::<Doc>::open(tmp.path());
    assert_eq!(store.mode(), Mode::Writable);
    assert_eq!(store.snapshot(), Doc::default());
    let notice = store.notice().unwrap();
    assert_eq!(notice.key, "core.store.corruptSetAside");
    let names = files_in(&tmp.path().join("nested"));
    assert_eq!(names.len(), 1);
    assert!(
        names[0].starts_with("doc.corrupt-") && names[0].ends_with(".json"),
        "{names:?}"
    );
    let aside = tmp.path().join("nested").join(&names[0]);
    assert_eq!(std::fs::read_to_string(aside).unwrap(), "{\"count\": 3,");
    store.update(|d| d.count = 1).unwrap();
    assert_eq!(Store::<Doc>::open(tmp.path()).read(|d| d.count), 1);
}

#[test]
fn non_object_or_wrong_shape_is_corrupt() {
    for text in ["[1,2]", "\"x\"", r#"{"count":"many"}"#, ""] {
        let tmp = TempDir::new("store");
        put(tmp.path(), "nested/doc.json", text);
        let store = Store::<Doc>::open(tmp.path());
        assert_eq!(
            store.notice().unwrap().key,
            "core.store.corruptSetAside",
            "{text}"
        );
    }
}

/// B16: a corrupt document holding secrets stays untouched until the user decides.
#[test]
fn corrupt_secret_document_is_kept_read_only() {
    let tmp = TempDir::new("store");
    let path = put(tmp.path(), "vault.json", "{\"key\": \"dpapi:v1:");
    let store = Store::<Vault>::open(tmp.path());
    assert_eq!(store.mode(), Mode::ReadOnly(ReadOnlyReason::Corrupt));
    assert_eq!(store.notice().unwrap().key, "core.store.corruptKept");
    assert!(store.update(|v| v.label = "x".into()).is_err());
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "{\"key\": \"dpapi:v1:"
    );

    store.set_aside().unwrap();
    assert_eq!(store.mode(), Mode::Writable);
    assert!(!path.exists());
    assert_eq!(store.notice().unwrap().key, "core.store.corruptSetAside");
    store.update(|v| v.label = "fresh".into()).unwrap();
    assert!(path.exists());
}

/// B29: an undecryptable secret does not make the document read-only and is written back as is.
#[test]
fn locked_secret_round_trips_through_the_store() {
    let tmp = TempDir::new("store");
    let foreign = "dpapi:v1:QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
    put(
        tmp.path(),
        "vault.json",
        &format!(r#"{{"schemaVersion":1,"label":"a","key":"{foreign}"}}"#),
    );
    let store = Store::<Vault>::open(tmp.path());
    assert_eq!(store.mode(), Mode::Writable);
    assert!(store.read(|v| v.key.as_ref().unwrap().is_locked()));
    store.update(|v| v.label = "b".into()).unwrap();
    let v: Value = serde_json::from_slice(&std::fs::read(store.path()).unwrap()).unwrap();
    assert_eq!(v["key"], foreign);
    assert_eq!(v["label"], "b");
}

#[test]
fn secrets_are_sealed_on_disk() {
    let tmp = TempDir::new("store");
    let store = Store::<Vault>::open(tmp.path());
    store
        .update(|v| v.key = Some(Secret::new("FAKE-KEY")))
        .unwrap();
    let text = std::fs::read_to_string(store.path()).unwrap();
    assert!(
        !text.contains("FAKE-KEY") && text.contains("dpapi:v1:"),
        "{text}"
    );
    let again = Store::<Vault>::open(tmp.path());
    assert_eq!(
        again.read(|v| v.key.as_ref().and_then(|k| k.expose().map(str::to_owned))),
        Some("FAKE-KEY".into())
    );
}

/// A failed write leaves the in-memory state and the subscribers untouched.
#[test]
fn failed_write_keeps_the_old_state() {
    let tmp = TempDir::new("store");
    let not_a_dir = put(
        tmp.path(),
        "occupied",
        "a file where the data root should be",
    );
    let store = Store::<Doc>::open(&not_a_dir);
    let rx = store.subscribe();
    let err = store.update(|d| d.count = 9).unwrap_err();
    assert_eq!(err.msg.unwrap().key, "core.store.writeFailed");
    assert_eq!(store.read(|d| d.count), 0);
    assert!(!rx.has_changed().unwrap());
}

#[test]
fn bom_prefixed_file_loads() {
    let tmp = TempDir::new("store");
    put(
        tmp.path(),
        "nested/doc.json",
        "\u{feff}{\"schemaVersion\":1,\"count\":4}",
    );
    assert_eq!(Store::<Doc>::open(tmp.path()).read(|d| d.count), 4);
}

#[test]
fn concurrent_updates_are_not_lost() {
    let tmp = TempDir::new("store");
    let store = std::sync::Arc::new(Store::<Doc>::open(tmp.path()));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let store = store.clone();
            std::thread::spawn(move || {
                for _ in 0..25 {
                    store.update(|d| d.count += 1).unwrap();
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    assert_eq!(store.read(|d| d.count), 50);
    assert_eq!(Store::<Doc>::open(tmp.path()).read(|d| d.count), 50);
}

/// Opens `path` the way an antivirus scanner does: no FILE_SHARE_DELETE, so it cannot be replaced.
fn hold(path: &Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(path)
        .unwrap()
}

#[test]
fn write_atomic_waits_for_a_transient_holder() {
    let tmp = TempDir::new("store");
    let path = put(tmp.path(), "f.json", "old");
    let holder = hold(&path);
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(60));
        drop(holder);
    });
    write_atomic(&path, b"new").unwrap();
    release.join().unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    assert_eq!(files_in(tmp.path()), ["f.json"]);
}

#[test]
fn write_atomic_gives_up_and_cleans_up() {
    let tmp = TempDir::new("store");
    let path = put(tmp.path(), "f.json", "old");
    let holder = hold(&path);
    let err = write_atomic(&path, b"new").unwrap_err();
    assert!(matches!(err.raw_os_error(), Some(5 | 32)), "{err:?}");
    drop(holder);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "old");
    assert_eq!(files_in(tmp.path()), ["f.json"], "temp file removed");
}

/// A write that crashed between creating its temp file and the rename leaves `<name>.<hex>.tmp`
/// behind; the next open removes exactly those (other documents' temp files and look-alikes stay).
#[test]
fn open_sweeps_temp_files_left_by_a_crash() {
    let tmp = TempDir::new("store");
    let dir = tmp.path().join("nested");
    put(tmp.path(), "nested/doc.json", r#"{"count": 3}"#);
    put(tmp.path(), "nested/doc.json.0123456789abcdef.tmp", "torn");
    put(tmp.path(), "nested/doc.json.FEDCBA9876543210.tmp", "torn");
    put(tmp.path(), "nested/doc.json.0123.tmp", "not ours");
    put(
        tmp.path(),
        "nested/doc.json.0123456789abcdeg.tmp",
        "not ours",
    );
    put(
        tmp.path(),
        "nested/other.json.0123456789abcdef.tmp",
        "other document",
    );
    let store = Store::<Doc>::open(tmp.path());
    assert_eq!(store.read(|d| d.count), 3);
    assert_eq!(
        files_in(&dir),
        [
            "doc.json",
            "doc.json.0123.tmp",
            "doc.json.0123456789abcdeg.tmp",
            "other.json.0123456789abcdef.tmp",
        ]
    );
    store.update(|d| d.count = 4).unwrap();
    assert_eq!(
        files_in(&dir).len(),
        4,
        "a normal write leaves no temp file"
    );
}

/// The `core-store` fragment holds exactly the keys of `paths`, `store` and `settings`.
#[test]
fn locale_fragment_holds_the_package_keys() {
    let used = [
        "core.store.dataDirLocked",
        "core.store.readOnly",
        "core.store.writeFailed",
        "core.store.encodeFailed",
        "core.store.newerVersion",
        "core.store.corruptKept",
        "core.store.unreadable",
        "core.store.corruptSetAside",
        "core.settings.proxyOverrideInvalid",
        "core.settings.legacyProxyDropped",
    ];
    let used: std::collections::BTreeSet<String> = used.map(String::from).into();
    assert_eq!(crate::test_support::package_keys("core-store"), used);
}
