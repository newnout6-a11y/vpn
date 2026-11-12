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

/// Copies `name` from `from` into `to`. The bytes are read once, hashed and written from the same
/// buffer: the source folder is user-writable, so a file swapped after a separate check would
/// never reach the admin-only folder.
pub fn copy_verified(from: &Path, to: &Path, name: &str) -> AppResult<()> {
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
    write_replacing(&to.join(name), &bytes)
}

/// Writes `path` through a sibling temp file and a rename (an older copy is replaced whole).
///
/// Elevated (the install verbs, the service), the file is born owned by Administrators: a file a
/// user's elevated installer creates is otherwise owned by that user, and an owner may rewrite its
/// DACL even from an unelevated process, so the service's trusted-folder check refuses it. No
/// other process may open it while it is written.
pub fn write_replacing(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let tmp = path.with_extension("new");
    let mut file = if vpnte_winnet::elevation::is_elevated() {
        crate::sddl::create_admin_owned(&tmp)
    } else {
        std::fs::File::create(&tmp)
    }
    .map_err(AppError::internal)?;
    std::io::Write::write_all(&mut file, bytes).map_err(AppError::internal)?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(AppError::internal)
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
    fn a_pinned_file_copies_and_a_changed_or_missing_one_is_refused() {
        let (from, to) = (temp("from"), temp("to"));
        let resources = Path::new(RESOURCES);
        if resources.join("wintun.dll").exists() {
            copy_verified(resources, &to, "wintun.dll").expect("pinned wintun.dll");
            assert!(to.join("wintun.dll").exists());
        }
        std::fs::write(from.join("sing-box.exe"), b"not the release").expect("fake");
        let err = copy_verified(&from, &to, "sing-box.exe").expect_err("changed");
        assert_eq!(err.user_msg().key, "service.install.fileMismatch");
        assert!(!to.join("sing-box.exe").exists());
        let err = copy_verified(&from, &to, "xray.exe").expect_err("missing");
        assert_eq!(err.user_msg().key, "service.install.fileMissing");
        let _ = std::fs::remove_dir_all(&from);
        let _ = std::fs::remove_dir_all(&to);
    }
}
