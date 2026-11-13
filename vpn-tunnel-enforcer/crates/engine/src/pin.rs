//! Release pins of the engine files and the bundled Smart RU rule sets, enforced while the
//! process is elevated. The per-user install folder is writable by the user, so any program
//! running as the user could swap an engine (or a DLL it loads from its own folder, or a rule set
//! it parses) and have it used with administrator rights. Unelevated, an engine runs with the
//! user's own rights: nothing to gain, nothing checked.
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use parking_lot::Mutex;
use regex::Regex;
use sha2::{Digest, Sha256};
use vpnte_base::types::Engine;
use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;

use crate::routing::smart_ru::RULE_SETS;

/// The release's pin manifest (`cargo xtask engines` checks every download against it).
const MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../resources/engines.toml"
));

/// `(file name, SHA-256)` of every file the manifest installs under `resources/`: archive
/// members (`install = …, sha256 = …` on one line) and `[[local]]` files such as the Smart RU
/// rule sets (the two keys on consecutive lines).
static PINS: LazyLock<Vec<(String, [u8; 32])>> = LazyLock::new(|| {
    let member =
        Regex::new(r#"install = "resources/([^"/]+)"(?:, |\r?\n)sha256 = "([0-9a-f]{64})""#)
            .expect("static regex");
    member
        .captures_iter(MANIFEST)
        .filter_map(|c| Some((c[1].to_owned(), hex::decode(&c[2]).ok()?.try_into().ok()?)))
        .collect()
});

/// Verified files, open without write or delete sharing until the process ends: nobody can
/// change them between the check and a start, and later starts need no second hash.
static HELD: Mutex<Vec<(PathBuf, File)>> = Mutex::new(Vec::new());

/// An engine file that is missing, unreadable or different from its release pin.
#[derive(Debug, thiserror::Error)]
#[error("{file} is missing or does not match the engine file shipped with the app")]
pub(crate) struct NotPinned {
    /// File name only: the full path would carry the user's profile name.
    pub file: String,
    /// The file does not exist: an incomplete install, not a changed file.
    pub missing: bool,
}

/// Elevated: refuses to run `exe` unless it and the DLLs `engine` loads from its folder match
/// their release pins (`InvalidData` carrying [`NotPinned`]). A relative `exe` is refused too:
/// Windows would search several folders for it, not only the one checked here. The first start
/// hashes the files once (sing-box with its DLLs is about 90 MB: a fraction of a second in a
/// release build).
pub(crate) fn check(engine: Engine, exe: &Path) -> io::Result<()> {
    if !vpnte_winnet::elevation::is_elevated() {
        return Ok(());
    }
    hold(engine_files(engine, exe), exe.is_absolute()).map_err(|err| {
        // A missing DLL is refused too: Windows would search PATH for it.
        let kind = if err.missing {
            io::ErrorKind::NotFound
        } else {
            io::ErrorKind::InvalidData
        };
        io::Error::new(kind, err)
    })
}

/// `true` when the bundled Smart RU rule sets in `dir` match their release pins; they are held
/// like the engines afterwards. Call it only while elevated (an elevated sing-box parses them
/// from a user-writable folder); a refused file means Smart RU off for the run.
pub(crate) fn rule_sets_pinned(dir: &Path) -> bool {
    hold(rule_set_files(dir), dir.is_absolute()).is_ok()
}

/// Verifies and holds every file not held yet; the first refusal stops (and is logged).
fn hold(files: Vec<(PathBuf, &'static str)>, absolute: bool) -> Result<(), NotPinned> {
    for (path, name) in files {
        if HELD.lock().iter().any(|(held, _)| *held == path) {
            continue;
        }
        let pin = pin(name).filter(|_| absolute);
        let file = open_verified(&path, pin).inspect_err(|err| {
            tracing::warn!(file = %err.file, missing = err.missing, "file refused by its release pin");
        })?;
        HELD.lock().push((path, file));
    }
    Ok(())
}

/// The bundled rule-set files in `dir`, with the manifest name of each.
fn rule_set_files(dir: &Path) -> Vec<(PathBuf, &'static str)> {
    RULE_SETS
        .iter()
        .map(|(_, file, _)| (dir.join(file), *file))
        .collect()
}

/// What `engine` runs or loads from its own folder (wintun.dll and libcronet.dll are loaded from
/// the application directory), with the manifest name of each.
fn engine_files(engine: Engine, exe: &Path) -> Vec<(PathBuf, &'static str)> {
    let dir = exe.parent().unwrap_or(Path::new(""));
    match engine {
        Engine::SingBox => vec![
            (exe.to_owned(), "sing-box.exe"),
            (dir.join("libcronet.dll"), "libcronet.dll"),
            (dir.join("wintun.dll"), "wintun.dll"),
        ],
        Engine::Xray => vec![(exe.to_owned(), "xray.exe")],
        #[cfg(feature = "lab")]
        Engine::Mihomo => vec![(exe.to_owned(), "mihomo.exe")],
    }
}

fn pin(name: &str) -> Option<[u8; 32]> {
    PINS.iter().find(|(n, _)| n == name).map(|(_, sha)| *sha)
}

/// Opens `path` sharing only reads (no writer, no rename or delete while it is open) and checks
/// the SHA-256 of that very handle against `pin`.
fn open_verified(path: &Path, pin: Option<[u8; 32]>) -> Result<File, NotPinned> {
    let refused = |missing| NotPinned {
        file: path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned(),
        missing,
    };
    let not_pinned = || refused(false);
    let pin = pin.ok_or_else(not_pinned)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
        .map_err(|err| refused(err.kind() == io::ErrorKind::NotFound))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(not_pinned()),
        }
    }
    let sha: [u8; 32] = hasher.finalize().into();
    if sha == pin {
        Ok(file)
    } else {
        Err(not_pinned())
    }
}

#[cfg(test)]
mod tests;
