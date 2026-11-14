//! Elevated check (CI's disposable elevated runner: `-- --ignored elevated_`) of the helper
//! service's entry in Settings > Apps: the real install lists it under HKLM, and the installed
//! exe's own `uninstall` (what the entry's commands run, from the program folder) removes the
//! service and the entry. The entry's values and commands are unit-tested on a throw-away HKCU
//! key in `install::entry::tests`. Skips quietly when not elevated.
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use vpnte_service::install::entry::{PUBLISHER, Place};
use vpnte_service::paths::{self, EXE_NAME};
use vpnte_service::scm::manage;
use vpnte_winnet::registry::{Access, Key, View};

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");
const BUILT: &str = env!("CARGO_BIN_EXE_vpnte-service");

/// Runs a verb; its exit code.
fn verb(exe: &Path, args: &[&str]) -> i32 {
    let out = Command::new(exe)
        .args(args)
        .output()
        .expect("run vpnte-service");
    eprintln!(
        "vpnte-service {args:?}: {} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
    out.status.code().unwrap_or(-1)
}

/// Uninstalls whatever happened.
struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = verb(Path::new(BUILT), &["uninstall"]);
    }
}

/// Elevated and with the engines in place, else `None` (skipped).
fn ready() -> Option<PathBuf> {
    if !vpnte_winnet::elevation::is_elevated() {
        eprintln!("skipped: the process is not elevated");
        return None;
    }
    let resources = std::fs::canonicalize(RESOURCES).ok()?;
    let text = resources.to_string_lossy().into_owned();
    let resources = PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text));
    if !resources.join("sing-box.exe").exists() {
        eprintln!("skipped: engine binaries missing under {RESOURCES}");
        return None;
    }
    Some(resources)
}

fn entry() -> Option<Key> {
    let place = Place::machine();
    Key::open(place.hive, &place.path, Access::Read, View::Bits64).expect("registry readable")
}

/// p-tails-a: installed = listed (name, version, publisher, commands of the installed exe); a
/// start rewrites a version that is not the running one; removed by the installed exe's own
/// `uninstall` = not listed, and the service is gone.
#[test]
#[ignore = "needs elevation"]
fn elevated_settings_apps_lists_the_service_until_it_is_removed() {
    let Some(resources) = ready() else { return };
    let _guard = Guard;
    let app = std::env::temp_dir().join(format!("vpnte-svc-entry-{}", std::process::id()));
    std::fs::create_dir_all(&app).expect("temp app dir");
    let copy = app.join(EXE_NAME);
    std::fs::copy(BUILT, &copy).expect("copy the build");
    let resources = resources.to_string_lossy().into_owned();
    assert_eq!(verb(&copy, &["install", "--resources", &resources]), 0);

    let installed = paths::install_dir().expect("install dir").join(EXE_NAME);
    let key = entry().expect("listed in Settings > Apps");
    let text = |name: &str| key.string(name).expect("value").unwrap_or_default();
    let exe = installed.display();
    assert_eq!(
        text("UninstallString"),
        format!("\"{exe}\" request-uninstall")
    );
    assert_eq!(text("QuietUninstallString"), format!("\"{exe}\" uninstall"));
    assert_eq!(text("DisplayVersion"), env!("CARGO_PKG_VERSION"));
    assert_eq!(text("Publisher"), PUBLISHER);
    assert!(text("DisplayName").starts_with("VPN Tunnel Enforcer — "));
    let size = key.dword("EstimatedSize").expect("value");
    assert!(size.is_some_and(|kib| kib > 1024), "{size:?} KiB");
    drop(key);

    // The service's own update swaps its exe under the entry: a start names the running version.
    let place = Place::machine();
    let (stale, _) = Key::create(place.hive, &place.path, View::Bits64).expect("entry writable");
    stale
        .set_string("DisplayVersion", "0.0.1")
        .expect("stale version");
    drop(stale);
    assert_eq!(manage::stop(Duration::from_secs(30)).ok(), Some(true));
    assert_eq!(manage::start(Duration::from_secs(30)).ok(), Some(true));
    let key = entry().expect("still listed");
    let version = key.string("DisplayVersion").expect("value");
    assert_eq!(version.as_deref(), Some(env!("CARGO_PKG_VERSION")));
    drop(key);

    assert_eq!(
        verb(&installed, &["uninstall"]),
        0,
        "from the program folder"
    );
    assert!(
        manage::installed_binary().expect("SCM").is_none(),
        "deleted"
    );
    assert!(entry().is_none(), "no longer listed");
    let _ = std::fs::remove_dir_all(&app);
}
