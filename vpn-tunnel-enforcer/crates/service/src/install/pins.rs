//! The engine files the service installs next to itself, checked against the release pins of
//! `resources/engines.toml` (compiled in, as the engine crate does).
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use sha2::{Digest, Sha256};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

const MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../resources/engines.toml"
));

/// What the service runs or loads (sing-box loads both DLLs from its own folder) and the bundled
/// Smart RU rule sets.
pub const FILES: [&str; 6] = [
    "sing-box.exe",
    "libcronet.dll",
    "wintun.dll",
    "xray.exe",
    "geoip-ru.srs",
    "geosite-category-gov-ru.srs",
];

/// `(file name, SHA-256)` of every manifest entry installed under `resources/` (archive members
/// on one line, `[[local]]` entries over two).
static PINS: LazyLock<Vec<(String, [u8; 32])>> = LazyLock::new(|| {
    let entry = Regex::new(r#"install = "resources/([^"/]+)"[,\s]*sha256 = "([0-9a-f]{64})""#)
        .expect("static regex");
    entry
        .captures_iter(MANIFEST)
        .filter_map(|c| Some((c[1].to_owned(), hex::decode(&c[2]).ok()?.try_into().ok()?)))
        .collect()
});

/// The release pin of `name`.
pub fn pin(name: &str) -> Option<[u8; 32]> {
    PINS.iter().find(|(n, _)| n == name).map(|(_, sha)| *sha)
}

fn refused(key: &'static str, name: &str) -> AppError {
    AppError::msg(
        ErrorKind::Validation,
        Msg::new(key).arg("file", name.to_owned()),
    )
}

/// The bytes of `name` in `from`, when they match its release pin. Read once and written from the
/// same buffer ([`write_replacing`]): the source folder is user-writable, so a file swapped after a
/// separate check would never reach the admin-only folder.
pub fn read_verified(from: &Path, name: &str) -> AppResult<Vec<u8>> {
    let expected = pin(name).ok_or_else(|| refused("service.install.fileMismatch", name))?;
    let bytes = match std::fs::read(from.join(name)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(refused("service.install.fileMissing", name));
        }
        Err(e) => return Err(AppError::internal(e)),
    };
    let sha: [u8; 32] = Sha256::digest(&bytes).into();
    if sha != expected {
        return Err(refused("service.install.fileMismatch", name));
    }
    Ok(bytes)
}

/// Writes `path` through a sibling temp file and a rename (an older copy is replaced whole).
///
/// Elevated (the install verbs, the service), the file is born owned by Administrators: a file a
/// user's elevated installer creates is otherwise owned by that user, and an owner may rewrite its
/// DACL even from an unelevated process, so the service's trusted-folder check refuses it. No
/// other process may open it while it is written. The temp file never outlives a call: one left
/// by a crash is removed first (the folder is admin-only, so it can only be ours), and a failed
/// write or rename removes it, so a retry starts clean.
pub fn write_replacing(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let tmp = path.with_extension("new");
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(AppError::internal(e)),
    }
    let written = (|| {
        let mut file = if vpnte_winnet::elevation::is_elevated() {
            crate::sddl::create_admin_owned(&tmp)
        } else {
            std::fs::File::create(&tmp)
        }?;
        std::io::Write::write_all(&mut file, bytes)?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");

    fn temp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vpnte-pins-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn every_installed_file_has_a_pin() {
        for name in FILES {
            assert!(pin(name).is_some(), "{name}");
        }
        assert!(
            pin("vpnte-service.exe").is_none(),
            "our own exe is not a release pin"
        );
    }

    #[test]
    fn a_pinned_file_is_read_and_a_changed_or_missing_one_is_refused() {
        let from = temp("from");
        let resources = Path::new(RESOURCES);
        if resources.join("wintun.dll").exists() {
            read_verified(resources, "wintun.dll").expect("pinned wintun.dll");
        }
        std::fs::write(from.join("sing-box.exe"), b"not the release").expect("fake");
        let err = read_verified(&from, "sing-box.exe").expect_err("changed");
        assert_eq!(err.user_msg().key, "service.install.fileMismatch");
        let err = read_verified(&from, "xray.exe").expect_err("missing");
        assert_eq!(err.user_msg().key, "service.install.fileMissing");
        let _ = std::fs::remove_dir_all(&from);
    }

    /// Review 4555370688: a temp file left by an earlier failed write does not block the next
    /// one, and a failed write leaves none behind (a retry of the same replace starts clean).
    #[test]
    fn the_temp_file_never_outlives_a_write() {
        let dir = temp("tmp");
        let file = dir.join("engine.exe");
        std::fs::write(dir.join("engine.new"), b"left by a crash").expect("stale temp");
        write_replacing(&file, b"one").expect("replaces past a stale temp");
        assert_eq!(std::fs::read(&file).expect("written"), b"one");
        assert!(!dir.join("engine.new").exists());
        // A rename onto a folder fails: the temp file is removed with the error.
        let blocked = dir.join("blocked.exe");
        std::fs::create_dir_all(&blocked).expect("a folder in the way");
        write_replacing(&blocked, b"two").expect_err("cannot replace a folder");
        assert!(!dir.join("blocked.new").exists(), "no temp left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
