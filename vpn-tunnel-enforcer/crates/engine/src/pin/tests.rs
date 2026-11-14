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
    assert_eq!(files.len(), RULE_SETS.len());
    for (path, name) in files {
        assert_eq!(path, dir.join(name));
        assert!(pin(name).is_some(), "{name}");
        if resources().join(name).is_file() {
            open_verified(&resources().join(name), pin(name).as_slice()).unwrap();
        }
    }
    assert_eq!(
        pin("geoip-ru.srs").map(hex::encode).as_deref(),
        Some("133d045108290b7e1ea929e3021807ad1842876d959bfc5ae347fdc7db4b5865")
    );
}

/// The compiled manifest pins every file an engine runs or loads; the exe comes first. The pin
/// is read from the manifest line itself, so an engine bump (engines-watch) keeps this green.
#[test]
fn manifest_pins_every_engine_file() {
    for name in ["sing-box.exe", "libcronet.dll", "wintun.dll", "xray.exe"] {
        assert!(pin(name).is_some(), "{name}");
    }
    let line = MANIFEST
        .lines()
        .find(|l| l.contains(r#"install = "resources/sing-box.exe""#))
        .unwrap();
    let listed = line.split("sha256 = \"").nth(1).unwrap().get(..64).unwrap();
    assert_eq!(
        pin("sing-box.exe").map(hex::encode).as_deref(),
        Some(listed)
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

    let held = open_verified(&path, &[sha]).unwrap();
    let write = OpenOptions::new().write(true).open(&path).unwrap_err();
    assert_eq!(write.raw_os_error(), Some(SHARING_VIOLATION));
    assert!(std::fs::rename(&path, dir.path().join("moved.exe")).is_err());
    assert!(std::fs::remove_file(&path).is_err());
    drop(held);
    assert!(OpenOptions::new().write(true).open(&path).is_ok());

    let refused = |pin: &[[u8; 32]]| {
        open_verified(&path, pin)
            .map(drop)
            .map_err(|e| (e.file, e.missing))
    };
    assert_eq!(refused(&[[0; 32]]), Err(("sing-box.exe".to_owned(), false)));
    assert_eq!(refused(&[]), Err(("sing-box.exe".to_owned(), false)));
    let missing = open_verified(&dir.path().join("wintun.dll"), &[sha]);
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
    let held = open_verified(&exe, &[Sha256::digest(&bytes).into()]).unwrap();
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

/// A throw-away minisign key: (the app's view of the public key, the signer).
fn test_key() -> (PublicKey, minisign::KeyPair) {
    let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    (PublicKey::from_base64(&pair.pk.to_base64()).unwrap(), pair)
}

fn sha_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `<tmp>\sing-box\<folder>\` with an exe, libcronet and a feed listing sing-box `listed`
/// (exe, libcronet and a would-be Wintun) signed by `signer`.
fn downloaded(folder: &str, listed: &str, signer: &minisign::KeyPair) -> (TempDir, PathBuf) {
    let tmp = TempDir::new("pin-feed");
    let dir = tmp.path().join("sing-box").join(folder);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sing-box.exe"), b"new engine").unwrap();
    std::fs::write(dir.join("libcronet.dll"), b"new cronet").unwrap();
    let member = |name: &str, body: &[u8]| serde_json::json!({ "path": format!("d/{name}"), "name": name, "sha256": sha_hex(body) });
    let feed = serde_json::json!({
        "schema": 1, "seq": 5, "issued": "2026-11-12T10:00:00Z", "app": { "stable": null },
        "engines": [{ "id": "sing-box", "version": listed,
            "archive": { "url": "https://example.invalid/a.zip", "size": 1, "sha256": sha_hex(b"zip") },
            "files": [member("sing-box.exe", b"new engine"), member("libcronet.dll", b"new cronet"),
                      member("wintun.dll", b"other wintun")] }]
    });
    let bytes = serde_json::to_vec(&feed).unwrap();
    let sig = minisign::sign(
        Some(&signer.pk),
        &signer.sk,
        std::io::Cursor::new(&bytes),
        None,
        None,
    )
    .unwrap()
    .into_string();
    std::fs::write(dir.join("update.json"), &bytes).unwrap();
    std::fs::write(dir.join("update.json.minisig"), sig).unwrap();
    (tmp, dir.join("sing-box.exe"))
}

/// The refusal of `name` under `pins` as the user sees it (`None` = accepted).
fn verdict(expected: &[Expected], name: &str) -> Option<String> {
    let (path, pins) = expected.iter().find(|(p, _)| p.ends_with(name)).unwrap();
    match open_verified(path, pins) {
        Ok(_) => None,
        Err(err) => Some(
            spawn_error("sing-box", &io::Error::new(io::ErrorKind::InvalidData, err))
                .1
                .key
                .into_owned(),
        ),
    }
}

/// AT-11-010 / research §4.8: a downloaded version whose signed feed verifies with a compiled
/// key and lies inside the compiled range runs elevated; Wintun still needs the release pin.
#[test]
fn a_signed_download_is_pinned_by_its_feed() {
    let (public, signer) = test_key();
    let (_tmp, exe) = downloaded("1.14.5", "1.14.5", &signer);
    let pins = expected(Engine::SingBox, &exe, &[public]);
    assert_eq!(verdict(&pins, "sing-box.exe"), None);
    assert_eq!(verdict(&pins, "libcronet.dll"), None);
    let wintun = &pins
        .iter()
        .find(|(p, _)| p.ends_with("wintun.dll"))
        .unwrap()
        .1;
    assert_eq!(wintun, &pin("wintun.dll").into_iter().collect::<Vec<_>>());
    assert!(pins.iter().all(|(_, p)| !p.is_empty()));
    // A relative exe has no pins at all.
    assert!(
        expected(Engine::SingBox, Path::new("sing-box.exe"), &[test_key().0])
            .iter()
            .all(|(_, p)| p.is_empty())
    );
}

/// A swapped file, a swapped feed, a foreign key, a version below the minimum, outside the
/// range, or a folder that is not the listed version: `engine.process.notPinned`.
#[test]
fn every_tampering_is_refused() {
    let refused = Some("engine.process.notPinned".to_owned());
    let (public, signer) = test_key();

    let (_a, exe) = downloaded("1.14.5", "1.14.5", &signer);
    std::fs::write(&exe, b"swapped engine").unwrap();
    assert_eq!(
        verdict(
            &expected(Engine::SingBox, &exe, std::slice::from_ref(&public)),
            "sing-box.exe"
        ),
        refused
    );

    let (_b, exe) = downloaded("1.14.5", "1.14.5", &signer);
    let feed = exe.with_file_name("update.json");
    let text = std::fs::read_to_string(&feed)
        .unwrap()
        .replace("\"seq\":5", "\"seq\":6");
    std::fs::write(&feed, text).unwrap();
    assert_eq!(
        verdict(
            &expected(Engine::SingBox, &exe, std::slice::from_ref(&public)),
            "sing-box.exe"
        ),
        refused
    );

    let (_c, exe) = downloaded("1.14.5", "1.14.5", &signer);
    assert_eq!(
        verdict(
            &expected(Engine::SingBox, &exe, &[test_key().0]),
            "sing-box.exe"
        ),
        refused
    );

    for (folder, listed) in [
        ("1.14.3", "1.14.3"),
        ("1.15.0", "1.15.0"),
        ("1.14.6", "1.14.5"),
    ] {
        let (_d, exe) = downloaded(folder, listed, &signer);
        let got = verdict(
            &expected(Engine::SingBox, &exe, std::slice::from_ref(&public)),
            "sing-box.exe",
        );
        assert_eq!(got, refused, "{folder} / {listed}");
    }
}

/// speed3 S3-06 (feasibility review): a start's check that meets the warm-up waits for it and
/// finds the files held: two holds at once hash every file once, a later hold none.
#[test]
fn concurrent_checks_hash_each_file_once() {
    let dir = TempDir::new("pin-once");
    let files: Vec<Expected> = ["sing-box.exe", "wintun.dll"]
        .iter()
        .map(|name| {
            let path = dir.path().join(name);
            std::fs::write(&path, name.as_bytes()).unwrap();
            let sha: [u8; 32] = Sha256::digest(name.as_bytes()).into();
            (path, vec![sha])
        })
        .collect();
    let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
    let runs: Vec<_> = (0..2)
        .map(|_| {
            let (files, gate) = (files.clone(), gate.clone());
            std::thread::spawn(move || {
                gate.wait();
                hold(files)
            })
        })
        .collect();
    for run in runs {
        assert!(run.join().unwrap().is_ok());
    }
    hold(files.clone()).unwrap();
    let hashed = HASHED.lock().clone();
    for (path, _) in &files {
        assert_eq!(hashed.iter().filter(|p| *p == path).count(), 1, "{path:?}");
    }
    // The held handles go with the files' folder.
    HELD.lock()
        .retain(|(held, _)| !files.iter().any(|(p, _)| p == held));
}

/// S3-06: unelevated the warm-up checks nothing; elevated it refuses what a start would refuse
/// (a relative path), and a refused file is not remembered: once it matches it is taken.
#[test]
fn warm_checks_like_a_start_and_remembers_no_refusal() {
    assert!(warm(Engine::Xray, Path::new("xray.exe"), false).is_ok());
    assert!(warm_rule_sets(Path::new("missing-dir"), false));
    assert!(warm(Engine::Xray, Path::new("xray.exe"), true).is_err());
    let dir = TempDir::new("pin-again");
    let path = dir.path().join("xray.exe");
    std::fs::write(&path, b"changed").unwrap();
    let sha: [u8; 32] = Sha256::digest(b"original").into();
    let expected = vec![(path.clone(), vec![sha])];
    assert!(hold(expected.clone()).is_err());
    std::fs::write(&path, b"original").unwrap();
    assert!(hold(expected).is_ok());
    HELD.lock().retain(|(held, _)| *held != path);
}
