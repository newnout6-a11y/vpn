//! Link-scheme registration against throw-away keys (`HKCU\Software\VPNTE-Test-*`); the real
//! classes are touched only by the ignored `system_*` test.
use std::path::{Path, PathBuf};

use super::*;
use crate::registry::TestKey;

fn exe(dir: &str) -> PathBuf {
    PathBuf::from(format!(
        r"C:\Users\x\AppData\Local\Programs\{dir}\VPN Tunnel Enforcer.exe"
    ))
}

fn reg(t: &TestKey) -> Registrar {
    Registrar::under(&t.path)
}

/// Reads `<root>\Classes\<scheme>\shell\open\command`.
fn command(t: &TestKey, scheme: &str) -> Option<String> {
    let key = open(Hive::CurrentUser, &format!(r"{}\Classes\{scheme}", t.path)).unwrap()?;
    command_of(&key)
}

/// Another program's per-user registration, as such programs write it.
fn foreign(t: &TestKey, scheme: &str, program: &str) {
    let path = format!(r"{}\Classes\{scheme}", t.path);
    let key = create(&path).unwrap();
    key.set_string("", &format!("URL:{scheme} Protocol"))
        .unwrap();
    key.set_string("URL Protocol", "").unwrap();
    key.set_dword("EditFlags", 2).unwrap();
    let command = format!("\"C:\\Program Files\\{program}\\{program}.exe\" \"%1\"");
    create(&format!(r"{path}\shell\open\command"))
        .unwrap()
        .set_string("", &command)
        .unwrap();
}

fn owners(r: &Registrar, exe: &Path) -> Vec<(&'static str, Owner)> {
    r.states(exe)
        .unwrap()
        .into_iter()
        .map(|s| (s.scheme, s.owner))
        .collect()
}

/// RU-2026 item 4: the first run takes every free scheme for this exe, writes the classic URL
/// protocol layout and records the exact command; a second run adds nothing.
#[test]
fn free_schemes_are_registered_once() {
    let t = TestKey::new();
    let r = reg(&t);
    let a = exe("A");
    assert!(!r.initialized().unwrap());
    let done = r.ensure(&a).unwrap();
    assert_eq!(done.registered, SCHEMES.to_vec());
    assert!(r.initialized().unwrap());
    let expected = format!("\"{}\" --open-link \"%1\"", a.display());
    for scheme in SCHEMES {
        assert_eq!(
            command(&t, scheme).as_deref(),
            Some(expected.as_str()),
            "{scheme}"
        );
        assert_eq!(
            r.recorded(scheme).unwrap().as_deref(),
            Some(expected.as_str())
        );
        let key = open(Hive::CurrentUser, &r.scheme_path(scheme))
            .unwrap()
            .unwrap();
        assert_eq!(key.string("URL Protocol").unwrap().as_deref(), Some(""));
        let icon = key
            .open_subkey("DefaultIcon", Access::Read)
            .unwrap()
            .unwrap();
        assert_eq!(
            icon.string("").unwrap(),
            Some(format!("\"{}\",0", a.display()))
        );
    }
    assert!(owners(&r, &a).iter().all(|(_, o)| *o == Owner::Ours));
    assert_eq!(r.ensure(&a).unwrap(), Ensured::default());
}

/// An upgrade or a moved portable copy points our schemes at the new exe.
#[test]
fn later_runs_repoint_only_our_schemes() {
    let t = TestKey::new();
    let r = reg(&t);
    r.ensure(&exe("A")).unwrap();
    foreign(&t, "trojan", "Other");
    let b = exe("B");
    let done = r.ensure(&b).unwrap();
    assert!(done.registered.is_empty());
    assert_eq!(done.repointed, SCHEMES.len() - 1);
    assert_eq!(command(&t, "vless"), Some(Registrar::command(&b)));
    assert_eq!(
        command(&t, "trojan").as_deref(),
        Some("\"C:\\Program Files\\Other\\Other.exe\" \"%1\"")
    );
}

/// Schemes another program answers (per user or machine-wide) are never taken by default and
/// are named by their program.
#[test]
fn taken_schemes_are_left_alone_and_named() {
    let t = TestKey::new();
    let r = reg(&t);
    foreign(&t, "hiddify", "Hiddify");
    let machine = create(&format!(r"{}\Machine\clash", t.path)).unwrap();
    machine.set_string("", "URL:Clash Verge").unwrap();
    let done = r.ensure(&exe("A")).unwrap();
    assert!(!done.registered.contains(&"hiddify") && !done.registered.contains(&"clash"));
    assert_eq!(done.registered.len(), SCHEMES.len() - 2);
    let states = owners(&r, &exe("A"));
    assert!(states.contains(&("hiddify", Owner::Other(Some("Hiddify".into())))));
    assert!(states.contains(&("clash", Owner::Other(Some("Clash Verge".into())))));
    assert!(
        open(Hive::CurrentUser, &r.scheme_path("clash"))
            .unwrap()
            .is_none()
    );
}

/// Taking a scheme over on the user's request keeps the other program's key aside; turning ours
/// off puts that key back exactly (values of every type, subkeys).
#[test]
fn taking_over_keeps_and_restores_the_other_program_key() {
    let t = TestKey::new();
    let r = reg(&t);
    foreign(&t, "hiddify", "Hiddify");
    let theirs = command(&t, "hiddify");
    r.ensure(&exe("A")).unwrap();
    r.take("Hiddify", &exe("A")).unwrap();
    assert_eq!(r.owner("hiddify", &exe("A")).unwrap(), Owner::Ours);
    assert_eq!(command(&t, "hiddify"), Some(Registrar::command(&exe("A"))));
    assert!(r.unregister("hiddify", &exe("A")).unwrap());
    assert_eq!(command(&t, "hiddify"), theirs);
    let key = open(Hive::CurrentUser, &r.scheme_path("hiddify"))
        .unwrap()
        .unwrap();
    assert_eq!(key.dword("EditFlags").unwrap(), Some(2));
    assert_eq!(
        key.string("").unwrap().as_deref(),
        Some("URL:hiddify Protocol")
    );
    assert!(
        open(Hive::CurrentUser, &r.previous_path("hiddify"))
            .unwrap()
            .is_none()
    );
    assert_eq!(r.recorded("hiddify").unwrap(), None);
}

/// What the user turned off stays off at the next start and the next install.
#[test]
fn turned_off_schemes_stay_off() {
    let t = TestKey::new();
    let r = reg(&t);
    r.ensure(&exe("A")).unwrap();
    assert!(r.unregister("vless", &exe("A")).unwrap());
    assert!(!r.unregister("vless", &exe("A")).unwrap());
    assert_eq!(command(&t, "vless"), None);
    assert_eq!(r.owner("vless", &exe("A")).unwrap(), Owner::Free);
    assert_eq!(r.ensure(&exe("A")).unwrap(), Ensured::default());
    assert_eq!(command(&t, "vless"), None);
}

/// A program that took a scheme back after us keeps it: turning ours off only drops our record.
#[test]
fn a_newer_foreign_registration_is_never_removed() {
    let t = TestKey::new();
    let r = reg(&t);
    r.ensure(&exe("A")).unwrap();
    foreign(&t, "ss", "Shadow");
    assert!(!r.unregister("ss", &exe("A")).unwrap());
    assert!(command(&t, "ss").is_some_and(|c| c.contains("Shadow.exe")));
    assert_eq!(r.recorded("ss").unwrap(), None);
}

/// Uninstall of copy A removes exactly A's registrations, restores what A replaced, leaves a
/// newer foreign key and copy B's registration; the record goes with the last entry.
#[test]
fn uninstall_removes_exactly_what_we_wrote() {
    let t = TestKey::new();
    let r = reg(&t);
    let (a, b) = (exe("A"), exe("B"));
    foreign(&t, "hiddify", "Hiddify");
    r.ensure(&a).unwrap();
    r.take("hiddify", &a).unwrap();
    r.unregister("tuic", &a).unwrap();
    r.take("tuic", &b).unwrap();
    foreign(&t, "trojan", "Other");
    let removed = r.unregister_for(&a).unwrap();
    assert_eq!(removed.len(), SCHEMES.len() - 2, "{removed:?}");
    for scheme in SCHEMES {
        let left = command(&t, scheme);
        match scheme {
            "hiddify" => assert!(left.is_some_and(|c| c.contains("Hiddify.exe"))),
            "trojan" => assert!(left.is_some_and(|c| c.contains("Other.exe"))),
            "tuic" => assert_eq!(left, Some(Registrar::command(&b))),
            _ => assert_eq!(left, None, "{scheme}"),
        }
    }
    assert!(r.initialized().unwrap(), "copy B's entry keeps the record");
    assert_eq!(r.unregister_for(&b).unwrap(), ["tuic"]);
    assert!(!r.initialized().unwrap());
    assert_eq!(command(&t, "tuic"), None);
}

/// Only the app's own schemes are ever written: a name from the UI addresses nothing else.
#[test]
fn unknown_schemes_are_refused() {
    let t = TestKey::new();
    let r = reg(&t);
    for name in ["http", "https", "", r"vless\..\http", "ms-settings"] {
        assert!(r.take(name, &exe("A")).is_err(), "{name}");
        assert!(r.unregister(name, &exe("A")).is_err(), "{name}");
    }
    assert!(
        open(Hive::CurrentUser, &format!(r"{}\Classes", t.path))
            .unwrap()
            .is_none()
    );
}

#[test]
fn owner_names_come_from_the_program_or_the_description() {
    let t = TestKey::new();
    let key = create(&t.path).unwrap();
    let name = |command: &str| owner_name(&key, Some(command));
    assert_eq!(
        name(r#""C:\Program Files\Happ\Happ.exe" "%1""#).as_deref(),
        Some("Happ")
    );
    assert_eq!(name(r"C:\Tools\v2rayN.exe %1").as_deref(), Some("v2rayN"));
    assert_eq!(name("").as_deref(), None);
    key.set_string("", "URL:Hiddify Protocol").unwrap();
    assert_eq!(owner_name(&key, None).as_deref(), Some("Hiddify Protocol"));
}

/// The real per-user classes, end to end (CI's disposable runner only): a first run takes the
/// free schemes, uninstall removes them and the record. Skipped where the app already registered.
#[test]
#[ignore = "changes system state"]
fn system_current_user_round_trip() {
    let r = Registrar::current_user();
    if r.initialized().unwrap() {
        return;
    }
    let fake = exe("VPNTE-Test");
    let done = r.ensure(&fake).unwrap();
    r.notify_shell();
    for scheme in &done.registered {
        assert_eq!(r.owner(scheme, &fake).unwrap(), Owner::Ours);
    }
    let removed = r.unregister_for(&fake).unwrap();
    assert_eq!(removed.len(), done.registered.len());
    assert!(!r.initialized().unwrap());
    for scheme in &done.registered {
        assert_eq!(r.owner(scheme, &fake).unwrap(), Owner::Free);
    }
}

/// A handler the user picked in Windows' chooser wins over every class key: such a scheme is
/// the user's choice, never registered by default (ours would not be reached).
#[test]
fn a_users_choice_of_another_program_wins() {
    let t = TestKey::new();
    let r = reg(&t);
    let choice = create(&format!(r"{}\Choices\vless\UserChoice", t.path)).unwrap();
    choice.set_string("ProgId", "AppX1234.Phone").unwrap();
    let own = create(&format!(r"{}\Choices\vmess\UserChoice", t.path)).unwrap();
    own.set_string("ProgId", "VMESS").unwrap();
    let done = r.ensure(&exe("A")).unwrap();
    assert!(!done.registered.contains(&"vless"));
    assert!(
        done.registered.contains(&"vmess"),
        "a choice of the class key itself"
    );
    assert_eq!(
        r.owner("vless", &exe("A")).unwrap(),
        Owner::Chosen("AppX1234.Phone".into())
    );
    assert_eq!(r.owner("vmess", &exe("A")).unwrap(), Owner::Ours);
}

fn choose(t: &TestKey, scheme: &str, prog_id: &str) {
    create(&format!(r"{}\Choices\{scheme}\UserChoice", t.path))
        .unwrap()
        .set_string("ProgId", prog_id)
        .unwrap();
}

fn saved(r: &Registrar, scheme: &str) -> bool {
    open(Hive::CurrentUser, &r.previous_path(scheme))
        .unwrap()
        .is_some()
}

/// phones-a3 / b3: while the user's Windows choice names another program, taking the scheme
/// moves nobody's key (ours is never saved as "theirs", a saved foreign key is never replaced)
/// and says so; uninstall then removes exactly our key and leaves theirs.
#[test]
fn a_windows_choice_is_reported_and_nothing_is_moved() {
    let t = TestKey::new();
    let r = reg(&t);
    let a = exe("A");
    r.ensure(&a).unwrap();
    choose(&t, "vless", "AppX1234.Phone");
    r.unregister("hiddify", &a).unwrap();
    foreign(&t, "hiddify", "Hiddify");
    choose(&t, "hiddify", "Hiddify.Protocol");
    let theirs = command(&t, "hiddify");
    for _ in 0..2 {
        let vless = r.take("vless", &a).unwrap();
        assert_eq!(vless, Took::Chosen("AppX1234.Phone".into()));
        let hiddify = r.take("hiddify", &a).unwrap();
        assert_eq!(hiddify, Took::Chosen("Hiddify.Protocol".into()));
    }
    assert_eq!(command(&t, "vless"), Some(Registrar::command(&a)));
    assert_eq!(command(&t, "hiddify"), theirs);
    assert!(!saved(&r, "vless") && !saved(&r, "hiddify"));
    let chosen = Owner::Chosen("AppX1234.Phone".into());
    assert_eq!(r.owner("vless", &a).unwrap(), chosen);

    let removed = r.unregister_for(&a).unwrap();
    assert!(removed.contains(&"vless".to_owned()));
    assert_eq!(command(&t, "vless"), None, "our key outlived the uninstall");
    assert_eq!(command(&t, "hiddify"), theirs);
    assert!(!r.initialized().unwrap());
}

/// phones-a5: a key of this exe without a record (a cleaner removed the record, a reinstall)
/// can be turned off, and a first run records it so that uninstall finds it.
#[test]
fn an_unrecorded_key_of_ours_can_be_removed() {
    let t = TestKey::new();
    let r = reg(&t);
    let a = exe("A");
    r.ensure(&a).unwrap();
    r.forget("vless").unwrap();
    assert_eq!(r.owner("vless", &a).unwrap(), Owner::Ours);
    assert!(r.unregister("vless", &a).unwrap());
    assert_eq!(command(&t, "vless"), None);

    r.write("vless", &a).unwrap();
    delete_tree(&r.record).unwrap();
    r.ensure(&a).unwrap();
    assert_eq!(r.recorded("vless").unwrap(), Some(Registrar::command(&a)));
    r.unregister_for(&a).unwrap();
    assert_eq!(command(&t, "vless"), None);
}

/// phones-a6: a key kept from an earlier take-over is dropped once its program removed its
/// registration; turning ours off later does not bring a dead handler back.
#[test]
fn a_stale_saved_key_is_not_brought_back() {
    let t = TestKey::new();
    let r = reg(&t);
    let a = exe("A");
    foreign(&t, "hiddify", "Hiddify");
    r.ensure(&a).unwrap();
    assert_eq!(r.take("hiddify", &a).unwrap(), Took::Ours);
    assert!(saved(&r, "hiddify"));
    // Hiddify's uninstaller deletes the class key, ours by then.
    delete_tree(&r.scheme_path("hiddify")).unwrap();
    assert_eq!(r.take("hiddify", &a).unwrap(), Took::Ours);
    assert!(!saved(&r, "hiddify"));
    assert!(r.unregister("hiddify", &a).unwrap());
    assert_eq!(command(&t, "hiddify"), None);
}

/// phones-a10: a recorded name this build does not list (a newer version took it) does not stop
/// the uninstall: it is removed like the others, and a value that is no scheme name just goes.
#[test]
fn unknown_recorded_names_do_not_stop_uninstall() {
    let t = TestKey::new();
    let r = reg(&t);
    let a = exe("A");
    r.ensure(&a).unwrap();
    let ours = Registrar::command(&a);
    let newer = format!(r"{}\Classes\newscheme", t.path);
    create(&format!(r"{newer}\shell\open\command"))
        .unwrap()
        .set_string("", &ours)
        .unwrap();
    let record = create(&r.record).unwrap();
    record.set_string("newscheme", &ours).unwrap();
    record.set_string(r"..\x", &ours).unwrap();
    drop(record);
    let removed = r.unregister_for(&a).unwrap();
    assert_eq!(removed.len(), SCHEMES.len() + 1);
    assert!(removed.contains(&"newscheme".to_owned()));
    assert!(open(Hive::CurrentUser, &newer).unwrap().is_none());
    assert!(!r.initialized().unwrap());
}

/// phones-b7: a portable copy's «open links here» takes the free schemes and points ours at its
/// exe; another program's scheme and a Windows choice stay theirs.
#[test]
fn adopting_takes_free_and_ours_only() {
    let t = TestKey::new();
    let r = reg(&t);
    let (installed, portable) = (exe("A"), exe("Portable"));
    foreign(&t, "hiddify", "Hiddify");
    choose(&t, "clash", "Clash.Verge");
    r.ensure(&installed).unwrap();
    r.unregister("vless", &installed).unwrap();
    let done = r.adopt(&portable).unwrap();
    assert_eq!(done.registered, ["vless"]);
    assert_eq!(done.repointed, SCHEMES.len() - 3);
    assert_eq!(command(&t, "vmess"), Some(Registrar::command(&portable)));
    assert_eq!(
        r.owner("hiddify", &portable).unwrap(),
        Owner::Other(Some("Hiddify".into()))
    );
    assert_eq!(
        r.owner("clash", &portable).unwrap(),
        Owner::Chosen("Clash.Verge".into())
    );
}

/// Happ's machine-wide registration, as Happ's installer writes it (HKLM, here the stand-in).
fn happ_machine_wide(t: &TestKey, scheme: &str) {
    let path = format!(r"{}\Machine\{scheme}", t.path);
    create(&path)
        .unwrap()
        .set_string("", "URL:Custom Protocol")
        .unwrap();
    create(&format!(r"{path}\shell\open\command"))
        .unwrap()
        .set_string("", r#""C:\Program Files\FlyFrogLLC\Happ\Happ.exe" "%1""#)
        .unwrap();
}

/// p-small (RU-2026 item 4): `happ://` and `incy://` open this app only while no other program
/// has them: taken free at the first run, never taken from an installed Happ, and given back
/// at the next start once Happ registers machine-wide later (our per-user key would hide it).
/// One the user took on purpose stays ours.
#[test]
fn client_schemes_are_held_only_while_free() {
    let t = TestKey::new();
    let r = reg(&t);
    let a = exe("A");
    happ_machine_wide(&t, "happ");
    let done = r.ensure(&a).unwrap();
    assert!(done.registered.contains(&"incy") && !done.registered.contains(&"happ"));
    assert_eq!(
        r.owner("happ", &a).unwrap(),
        Owner::Other(Some("Happ".into()))
    );
    assert_eq!(command(&t, "happ"), None, "Happ's scheme stays Happ's");

    // Happ moves on; a new user of the same PC (fresh record) gets happ:// while it is free.
    let t = TestKey::new();
    let r = reg(&t);
    let done = r.ensure(&a).unwrap();
    assert!(done.registered.contains(&"happ") && done.registered.contains(&"incy"));
    assert_eq!(r.ensure(&a).unwrap(), Ensured::default());

    // Happ and Incy are installed later, machine-wide; the user took incy:// on purpose.
    happ_machine_wide(&t, "happ");
    happ_machine_wide(&t, "incy");
    assert_eq!(r.take("incy", &a).unwrap(), Took::Ours);
    let done = r.ensure(&a).unwrap();
    assert_eq!(done.released, ["happ"]);
    assert!(done.changed());
    assert_eq!(command(&t, "happ"), None);
    assert_eq!(r.recorded("happ").unwrap(), None);
    assert_eq!(
        r.owner("happ", &a).unwrap(),
        Owner::Other(Some("Happ".into()))
    );
    assert_eq!(r.owner("incy", &a).unwrap(), Owner::Ours);
    assert_eq!(r.ensure(&a).unwrap(), Ensured::default());

    // A share-link scheme taken free is no client's: a later machine-wide key changes nothing.
    let machine = create(&format!(r"{}\Machine\vless", t.path)).unwrap();
    machine.set_string("", "URL:vless").unwrap();
    assert_eq!(r.ensure(&a).unwrap(), Ensured::default());
    assert_eq!(r.owner("vless", &a).unwrap(), Owner::Ours);

    // Uninstall removes ours and every mark with the record.
    r.unregister_for(&a).unwrap();
    assert!(!r.initialized().unwrap());
}

/// Every client scheme is one of the registered schemes (the give-back covers only those).
#[test]
fn client_schemes_are_registered_schemes() {
    assert!(CLIENT_SCHEMES.iter().all(|c| SCHEMES.contains(c)));
}
