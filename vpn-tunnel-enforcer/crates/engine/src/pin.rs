//! Release pins of the engine files and the bundled Smart RU rule sets, enforced while the
//! process is elevated. The per-user install folder is writable by the user, so any program
//! running as the user could swap an engine (or a DLL it loads from its own folder, or a rule set
//! it parses) and have it used with administrator rights. Unelevated, an engine runs with the
//! user's own rights: nothing to gain, nothing checked.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use parking_lot::Mutex;
use regex::Regex;
use vpnte_base::types::Engine;
use vpnte_update::download::{parse_sha, sha256_of};
use vpnte_update::feed::{FEED_FILE, PublicKey, SIG_FILE, verify};
use vpnte_update::policy;
use vpnte_update::version::Version;
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
/// their pins (`InvalidData` carrying [`NotPinned`]): the release pins compiled in, plus — for a
/// version the update channel downloaded — the pins of the signed feed stored next to it,
/// re-verified here with the compiled keys at every elevated start. Wintun is never updated: it
/// always has to match the release pin. A relative `exe` is refused too: Windows would search
/// several folders for it, not only the one checked here. The first start hashes the files once
/// (sing-box with its DLLs is about 90 MB: a fraction of a second in a release build).
pub(crate) fn check(engine: Engine, exe: &Path) -> io::Result<()> {
    if !vpnte_winnet::elevation::is_elevated() {
        return Ok(());
    }
    hold(expected(engine, exe, policy::trusted_keys())).map_err(|err| {
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
    let files = rule_set_files(dir)
        .into_iter()
        .map(|(path, name)| (path, release_pins(name, dir.is_absolute())))
        .collect();
    hold(files).is_ok()
}

/// A file to check and every hash it may have (none = refused).
type Expected = (PathBuf, Vec<[u8; 32]>);

/// Verifies and holds every file not held yet; the first refusal stops (and is logged).
fn hold(files: Vec<Expected>) -> Result<(), NotPinned> {
    for (path, pins) in files {
        if HELD.lock().iter().any(|(held, _)| *held == path) {
            continue;
        }
        let file = open_verified(&path, &pins).inspect_err(|err| {
            tracing::warn!(file = %err.file, missing = err.missing, "file refused by its pin");
        })?;
        HELD.lock().push((path, file));
    }
    Ok(())
}

/// The files `engine` runs or loads with their pins: release pins, plus the signed feed's for
/// a downloaded version (never for Wintun).
fn expected(engine: Engine, exe: &Path, keys: &[PublicKey]) -> Vec<Expected> {
    let absolute = exe.is_absolute();
    let feed = feed_pins(engine, exe, keys);
    engine_files(engine, exe)
        .into_iter()
        .map(|(path, name)| {
            let from_feed = feed
                .iter()
                .filter(|(n, _)| n == name && name != "wintun.dll")
                .map(|(_, sha)| *sha)
                .filter(|_| absolute);
            (
                path,
                release_pins(name, absolute)
                    .into_iter()
                    .chain(from_feed)
                    .collect(),
            )
        })
        .collect()
}

fn release_pins(name: &str, absolute: bool) -> Vec<[u8; 32]> {
    pin(name).filter(|_| absolute).into_iter().collect()
}

/// The pins the signed feed stored with a downloaded engine gives its files: only when the
/// feed verifies with `keys`, lists this engine at exactly the version its folder is named
/// after, and that version lies inside this build's range. The range's floor is what stops an
/// old signed feed from bringing back an older engine: the remembered feed `seq` lives where
/// the user can write it, so the elevated path does not rely on it.
fn feed_pins(engine: Engine, exe: &Path, keys: &[PublicKey]) -> Vec<(String, [u8; 32])> {
    let id = match engine {
        Engine::SingBox => policy::SINGBOX,
        Engine::Xray => policy::XRAY,
        #[cfg(feature = "lab")]
        Engine::Mihomo => return Vec::new(),
    };
    let Some(dir) = exe.parent() else {
        return Vec::new();
    };
    let version = dir
        .file_name()
        .and_then(|n| n.to_str()?.parse::<Version>().ok());
    let Some(version) = version.filter(|v| policy::engine_allowed(id, *v)) else {
        return Vec::new();
    };
    let (Ok(bytes), Ok(sig)) = (
        std::fs::read(dir.join(FEED_FILE)),
        std::fs::read_to_string(dir.join(SIG_FILE)),
    ) else {
        return Vec::new();
    };
    let feed = match verify(&bytes, &sig, keys) {
        Ok(feed) => feed,
        Err(err) => {
            tracing::warn!(%err, engine = id, "feed next to a downloaded engine refused");
            return Vec::new();
        }
    };
    let Some(entry) = feed.engine(id).filter(|e| e.version == version) else {
        return Vec::new();
    };
    entry
        .files
        .iter()
        .filter_map(|m| Some((m.name.clone(), parse_sha(&m.sha256)?)))
        .collect()
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
/// the SHA-256 of that very handle against `pins` (any of them; none = refused).
fn open_verified(path: &Path, pins: &[[u8; 32]]) -> Result<File, NotPinned> {
    let refused = |missing| NotPinned {
        file: path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned(),
        missing,
    };
    let not_pinned = || refused(false);
    if pins.is_empty() {
        return Err(not_pinned());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
        .map_err(|err| refused(err.kind() == io::ErrorKind::NotFound))?;
    let sha = sha256_of(&mut file).map_err(|_| not_pinned())?;
    if pins.contains(&sha) {
        Ok(file)
    } else {
        Err(not_pinned())
    }
}

#[cfg(test)]
mod tests;
