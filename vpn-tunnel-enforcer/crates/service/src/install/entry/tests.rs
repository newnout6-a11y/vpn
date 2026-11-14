use std::path::PathBuf;

use super::*;

/// A throw-away `HKCU\Software\VPNTE-Test-*` root, deleted with everything under it.
struct TestRoot(String);

impl TestRoot {
    fn new(tag: &str) -> TestRoot {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        TestRoot(format!(
            r"Software\VPNTE-Test-{tag}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn place(&self) -> Place {
        Place {
            hive: Hive::CurrentUser,
            path: format!(r"{}\Uninstall\{SERVICE_NAME}", self.0),
        }
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = registry::delete_tree(Hive::CurrentUser, &self.0, View::Bits64);
    }
}

fn read(place: &Place) -> Option<Key> {
    Key::open(
        place.hive,
        &place.path,
        registry::Access::Read,
        View::Bits64,
    )
    .unwrap()
}

/// p-tails-a: the entry Settings > Apps lists: name in the machine's language, version,
/// publisher, folder, icon, size, no Modify / Repair, an uninstall command that asks Windows for
/// the prompt itself and a quiet one for tools that run elevated; an upgrade rewrites it, a
/// removal leaves nothing (a second removal finds none).
#[test]
fn the_entry_is_written_rewritten_and_removed() {
    let root = TestRoot::new("entry");
    let place = root.place();
    let exe = PathBuf::from(r"C:\Program Files\VPN Tunnel Enforcer Service\vpnte-service.exe");
    let entry = Entry {
        exe: &exe,
        version: "2.0.0",
        bytes: 60 * 1024 * 1024 + 1,
        lang: Lang::Ru,
    };
    write(&place, &entry).unwrap();
    let key = read(&place).expect("entry written");
    let text = |name: &str| key.string(name).unwrap().unwrap_or_default();
    let number = |name: &str| key.dword(name).unwrap();
    assert_eq!(text("DisplayName"), "VPN Tunnel Enforcer — служба-помощник");
    assert_eq!(text("DisplayVersion"), "2.0.0");
    assert_eq!(text("Publisher"), PUBLISHER);
    assert_eq!(
        text("InstallLocation"),
        r"C:\Program Files\VPN Tunnel Enforcer Service"
    );
    assert_eq!(
        text("DisplayIcon"),
        r"C:\Program Files\VPN Tunnel Enforcer Service\vpnte-service.exe,0"
    );
    assert_eq!(number("EstimatedSize"), Some(60 * 1024 + 1));
    assert_eq!((number("NoModify"), number("NoRepair")), (Some(1), Some(1)));
    assert_eq!(
        text("UninstallString"),
        r#""C:\Program Files\VPN Tunnel Enforcer Service\vpnte-service.exe" request-uninstall"#
    );
    assert_eq!(
        text("QuietUninstallString"),
        r#""C:\Program Files\VPN Tunnel Enforcer Service\vpnte-service.exe" uninstall"#
    );
    drop(key);

    let upgrade = Entry {
        version: "2.0.1",
        lang: Lang::En,
        ..entry
    };
    write(&place, &upgrade).unwrap();
    let key = read(&place).expect("entry rewritten");
    assert_eq!(key.string("DisplayVersion").unwrap().unwrap(), "2.0.1");
    assert_eq!(
        key.string("DisplayName").unwrap().unwrap(),
        "VPN Tunnel Enforcer — helper service"
    );
    drop(key);

    assert!(remove(&place).unwrap());
    assert!(read(&place).is_none());
    assert!(!remove(&place).unwrap(), "nothing left to remove");
}

/// p-tails-a: a start rewrites the entry only when it does not name the running version (none
/// yet, or a swap brought another exe in).
#[test]
fn the_entry_names_its_version() {
    let root = TestRoot::new("names");
    let place = root.place();
    assert!(!names(&place, "2.0.0"), "no entry yet");
    let exe = PathBuf::from(r"C:\Program Files\VPN Tunnel Enforcer Service\vpnte-service.exe");
    let entry = Entry {
        exe: &exe,
        version: "2.0.0",
        bytes: 1,
        lang: Lang::En,
    };
    write(&place, &entry).unwrap();
    assert!(names(&place, "2.0.0"));
    assert!(!names(&place, "2.0.1"), "the swapped-in version");
    assert!(remove(&place).unwrap());
    assert!(!names(&place, "2.0.0"));
}

/// The real place is HKLM's uninstall list under the service's own name.
#[test]
fn the_real_entry_is_the_machine_uninstall_key() {
    let place = Place::machine();
    assert_eq!(place.hive, Hive::LocalMachine);
    assert_eq!(
        place.path,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VpnTunnelEnforcerService"
    );
    assert!(matches!(system_lang(), Lang::Ru | Lang::En));
}
