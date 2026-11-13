use std::fs::OpenOptions;
use std::io;

use sha2::{Digest, Sha256};
use vpnte_base::ErrorKind;
use vpnte_base::types::Engine;

use super::*;
use crate::singbox_process::spawn_error;
use crate::test_support::{TempDir, hidden, resources, singbox_exe, xray_exe};

const SHARING_VIOLATION: i32 = 32;

/// PR review 4533368399: the `[[local]]` rule sets are pinned too, and the shipped files match
/// their pins (the handle is dropped at once: the real files are not held by the test run).
#[test]
fn manifest_pins_the_bundled_rule_sets() {
    let dir = Path::new(r"C:\Apps\VPN\resources");
    let files = rule_set_files(dir);
    assert_eq!(files.len(), 2);
    for (path, name) in files {
        assert_eq!(path, dir.join(name));
        assert!(pin(name).is_some(), "{name}");
        if resources().join(name).is_file() {
            open_verified(&resources().join(name), pin(name)).unwrap();
        }
    }
    assert_eq!(
        pin("geoip-ru.srs").map(hex::encode).as_deref(),
        Some("133d045108290b7e1ea929e3021807ad1842876d959bfc5ae347fdc7db4b5865")
    );
}

/// The compiled manifest pins every file an engine runs or loads; the exe comes first.
#[test]
fn manifest_pins_every_engine_file() {
    for name in ["sing-box.exe", "libcronet.dll", "wintun.dll", "xray.exe"] {
        assert!(pin(name).is_some(), "{name}");
    }
    assert_eq!(
        pin("sing-box.exe").map(hex::encode).as_deref(),
        Some("8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9")
    );
    let exe = Path::new(r"C:\Apps\VPN\resources\sing-box.exe");
    let files = engine_files(Engine::SingBox, exe);
    assert_eq!(files[0], (exe.to_owned(), "sing-box.exe"));
    assert_eq!(
        files[2],
        (
            PathBuf::from(r"C:\Apps\VPN\resources\wintun.dll"),
            "wintun.dll"
        )
    );
    assert_eq!(engine_files(Engine::Xray, exe).len(), 1);
}

/// A matching file stays open: no writer, no rename and no delete until it is released. A
/// different, missing or unpinned file is refused by name.
#[test]
fn verified_files_are_held_and_others_refused() {
    let dir = TempDir::new("pin");
    let path = dir.path().join("sing-box.exe");
    std::fs::write(&path, b"fake engine").unwrap();
    let sha: [u8; 32] = Sha256::digest(b"fake engine").into();

    let held = open_verified(&path, Some(sha)).unwrap();
    let write = OpenOptions::new().write(true).open(&path).unwrap_err();
    assert_eq!(write.raw_os_error(), Some(SHARING_VIOLATION));
    assert!(std::fs::rename(&path, dir.path().join("moved.exe")).is_err());
    assert!(std::fs::remove_file(&path).is_err());
    drop(held);
    assert!(OpenOptions::new().write(true).open(&path).is_ok());

    let refused = |pin| {
        open_verified(&path, pin)
            .map(drop)
            .map_err(|e| (e.file, e.missing))
    };
    assert_eq!(
        refused(Some([0; 32])),
        Err(("sing-box.exe".to_owned(), false))
    );
    assert_eq!(refused(None), Err(("sing-box.exe".to_owned(), false)));
    let missing = open_verified(&dir.path().join("wintun.dll"), Some(sha));
    assert_eq!(
        missing.map(drop).map_err(|e| (e.file, e.missing)),
        Err(("wintun.dll".to_owned(), true))
    );
}

/// The held handle (read sharing only) does not stop Windows from starting the exe: the image
/// loader opens it for read / execute, which read sharing allows.
#[test]
fn a_held_exe_still_starts() {
    let system = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let original = Path::new(&system).join(r"System32\hostname.exe");
    let Ok(bytes) = std::fs::read(&original) else {
        return;
    };
    let dir = TempDir::new("pin-run");
    let exe = dir.path().join("hostname.exe");
    std::fs::write(&exe, &bytes).unwrap();
    let held = open_verified(&exe, Some(Sha256::digest(&bytes).into())).unwrap();
    let out = hidden(&mut std::process::Command::new(&exe))
        .output()
        .unwrap();
    assert!(out.status.success());
    drop(held);
}

/// A refused file reaches the user as its own message naming the file: a changed file as
/// "differs", a missing one as "missing" (both say to reinstall).
#[test]
fn not_pinned_has_its_own_message() {
    let refused = |missing| {
        let kind = if missing {
            io::ErrorKind::NotFound
        } else {
            io::ErrorKind::InvalidData
        };
        let file = "wintun.dll".into();
        spawn_error(
            "sing-box",
            &io::Error::new(kind, NotPinned { file, missing }),
        )
    };
    let (kind, msg) = refused(false);
    assert_eq!(kind, ErrorKind::Internal);
    assert_eq!(msg.key, "engine.process.notPinned");
    assert_eq!(msg.args.first().map(|(k, _)| k.as_ref()), Some("file"));
    let (kind, msg) = refused(true);
    assert_eq!(kind, ErrorKind::Internal);
    assert_eq!(msg.key, "engine.process.fileMissing");
    assert_eq!(msg.args.first().map(|(k, _)| k.as_ref()), Some("file"));
    let (kind, msg) = spawn_error("Xray", &io::Error::from(io::ErrorKind::PermissionDenied));
    assert_eq!(
        (kind, msg.key.as_ref()),
        (ErrorKind::Permission, "engine.process.spawnFailed")
    );
}

/// The bundled engines (and sing-box's DLLs) match the release pins (CI's elevated runner).
#[test]
#[ignore = "needs elevation"]
fn elevated_bundled_engines_match_their_pins() {
    let (Some(singbox), Some(xray)) = (singbox_exe(), xray_exe()) else {
        return;
    };
    assert!(vpnte_winnet::elevation::is_elevated());
    check(Engine::SingBox, &singbox).unwrap();
    check(Engine::Xray, &xray).unwrap();
    assert!(check(Engine::Xray, Path::new("xray.exe")).is_err());
}
