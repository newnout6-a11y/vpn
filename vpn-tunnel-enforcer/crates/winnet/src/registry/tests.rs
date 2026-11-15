use super::*;

fn create(t: &TestKey) -> Key {
    let (key, created) = Key::create(Hive::CurrentUser, &t.path, View::Native).unwrap();
    assert!(created);
    key
}

#[test]
fn typed_values_round_trip() {
    let t = TestKey::new();
    let key = create(&t);
    assert!(
        !Key::create(Hive::CurrentUser, &t.path, View::Native)
            .unwrap()
            .1
    );
    key.set_string("sz", "plain").unwrap();
    key.set_expand_string("expand", r"%USERPROFILE%\x").unwrap();
    key.set_dword("dword", 0xDEAD_BEEF).unwrap();
    key.set_multi_string("multi", &["a", "b c"]).unwrap();
    let raw = Value::Raw {
        kind: 3,
        data: vec![1, 2, 3],
    };
    key.set("raw", &raw).unwrap();

    assert_eq!(key.value("sz").unwrap(), Some(Value::Sz("plain".into())));
    let expand = Value::ExpandSz(r"%USERPROFILE%\x".into());
    assert_eq!(key.value("expand").unwrap(), Some(expand));
    assert_eq!(
        key.string("expand").unwrap().as_deref(),
        Some(r"%USERPROFILE%\x")
    );
    assert_eq!(key.dword("dword").unwrap(), Some(0xDEAD_BEEF));
    let multi = key.multi_string("multi").unwrap().unwrap();
    assert_eq!(multi, ["a", "b c"]);
    assert_eq!(key.value("raw").unwrap(), Some(raw));
    assert_eq!(key.value("missing").unwrap(), None);
    assert!(
        key.dword("sz").is_err(),
        "a type mismatch is an error, not None"
    );

    assert!(key.delete_value("sz").unwrap());
    assert!(!key.delete_value("sz").unwrap());
    assert_eq!(key.string("sz").unwrap(), None);
}

/// AT-09-003, E1: long values and `REG_EXPAND_SZ` round-trip byte-exact, type preserved.
#[test]
fn long_and_expandable_values_round_trip_exactly() {
    let t = TestKey::new();
    let key = create(&t);
    for len in [0, 1023, 1024, 1025, 4096] {
        let text: String = "socks5h://127.0.0.1:10808;"
            .chars()
            .cycle()
            .take(len)
            .collect();
        key.set_string("v", &text).unwrap();
        assert_eq!(
            key.value("v").unwrap(),
            Some(Value::Sz(text)),
            "length {len}"
        );
    }
    key.set_expand_string("v", "http://%PROXY_HOST%:8080")
        .unwrap();
    let expected = Value::ExpandSz("http://%PROXY_HOST%:8080".into());
    assert_eq!(key.value("v").unwrap(), Some(expected));
    key.set_string("v", "прокси ✓").unwrap();
    assert_eq!(key.string("v").unwrap().as_deref(), Some("прокси ✓"));
}

#[test]
fn empty_lists_round_trip_and_empty_items_are_refused() {
    let t = TestKey::new();
    let key = create(&t);
    key.set_multi_string::<&str>("m", &[]).unwrap();
    assert_eq!(key.multi_string("m").unwrap(), Some(vec![]));
    assert!(key.set_multi_string("m", &["a", "", "b"]).is_err());
    assert!(key.set_string("a\0b", "x").is_err());
    assert!(Key::open(Hive::CurrentUser, "a\0b", Access::Read, View::Native).is_err());
}

#[test]
fn enumerates_and_deletes_trees() {
    let t = TestKey::new();
    let key = create(&t);
    Key::create(
        Hive::CurrentUser,
        &format!(r"{}\a\deep", t.path),
        View::Native,
    )
    .unwrap();
    Key::create(Hive::CurrentUser, &format!(r"{}\b", t.path), View::Native).unwrap();
    key.set_dword("x", 1).unwrap();
    key.set_string("y", "2").unwrap();

    let mut subkeys = key.subkey_names().unwrap();
    subkeys.sort();
    assert_eq!(subkeys, ["a", "b"]);
    let mut values = key.value_names().unwrap();
    values.sort();
    assert_eq!(values, ["x", "y"]);
    assert!(!key.is_empty().unwrap());
    let b = key.open_subkey("b", Access::Read).unwrap().unwrap();
    assert!(b.is_empty().unwrap());
    assert!(key.open_subkey("nope", Access::Read).unwrap().is_none());
    drop((b, key));

    assert!(
        delete_key(Hive::CurrentUser, &t.path, View::Native).is_err(),
        "has subkeys"
    );
    assert!(delete_tree(Hive::CurrentUser, &t.path, View::Native).unwrap());
    assert!(
        Key::open(Hive::CurrentUser, &t.path, Access::Read, View::Native)
            .unwrap()
            .is_none()
    );
    assert!(!delete_tree(Hive::CurrentUser, &t.path, View::Native).unwrap());
    assert!(!delete_key(Hive::CurrentUser, &t.path, View::Native).unwrap());
}

/// Checked on the guard itself: a regression here must not get the chance to wipe HKCU.
#[test]
fn deleting_a_hive_root_is_refused() {
    for path in ["", r"\", r"\\"] {
        assert!(checked_path(path).is_err());
    }
    assert_eq!(checked_path(r"\Software\X\").unwrap(), r"Software\X");
}

/// Read-only: `ProgramFilesDir` differs between the 64- and 32-bit views on x64 Windows.
#[test]
fn views_resolve_differently() {
    let path = r"SOFTWARE\Microsoft\Windows\CurrentVersion";
    let read = |view| {
        let key = Key::open(Hive::LocalMachine, path, Access::Read, view)
            .unwrap()
            .unwrap();
        key.string("ProgramFilesDir").unwrap().unwrap()
    };
    let (bits64, bits32) = (read(View::Bits64), read(View::Bits32));
    assert_ne!(bits64, bits32);
    assert!(bits32.ends_with("(x86)"), "{bits32}");
    assert_eq!(read(View::Native), bits64);
}

/// Read-only: HKU holds the default profile hive.
#[test]
fn users_hive_is_reachable() {
    let default = Key::open(Hive::Users, ".DEFAULT", Access::Read, View::Native).unwrap();
    assert!(!default.unwrap().subkey_names().unwrap().is_empty());
}
