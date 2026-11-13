//! Installing a version (research §4.7 steps 1-4): the verified archive -> only the members the
//! signed feed lists, each checked -> the version's folder -> the engine reports the feed's version
//! inside this build's range -> every config the app would build now passes the engine's own
//! check -> `state.json` switched (atomic write). Any refusal leaves nothing behind.
use std::fs::OpenOptions;
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use super::state::{self, Choice};
use super::{EngineStore, exe_name};
use crate::download::{Verified, parse_sha};
use crate::feed::{EngineEntry, FEED_FILE, MemberEntry, SIG_FILE, verify};
use crate::policy::{self, bundled_version, engine_allowed};
use crate::version::Version;

/// No engine file comes near this; a larger member is not the one the feed means.
const MEMBER_CAP: u64 = 256 << 20;

/// How the app checks a new engine before it is switched on (implemented over `vpnte-engine`).
pub trait EngineCheck {
    /// The version `exe` reports (`sing-box version`, `xray version`).
    fn version(&self, id: &str, exe: &Path) -> impl Future<Output = io::Result<Version>>;
    /// Every config the app would build now for the current profile and modes (proxy and TUN,
    /// the Xray slots, Smart RU, the user's rules), checked by `exe`; `Err` carries the first
    /// refusal, redacted, for the user.
    fn check_configs(&self, id: &str, exe: &Path) -> impl Future<Output = Result<(), String>>;
}

/// Why a version was not installed.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("engine {0} cannot be updated by this build")]
    Unknown(String),
    #[error("version {0} is outside what this build allows")]
    NotAllowed(Version),
    #[error("the stored feed does not verify or does not list this version")]
    Feed,
    #[error("archive member {0} is missing or does not match the feed")]
    Member(String),
    #[error("the engine reports {got}, the feed says {want}")]
    VersionMismatch { got: String, want: Version },
    #[error("the engine refused our configuration: {0}")]
    ConfigRefused(String),
    #[error("file error: {0}")]
    Io(#[from] io::Error),
}

/// A version switched on (on trial until it starts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub id: String,
    pub version: Version,
    pub previous: Choice,
}

impl EngineStore {
    /// Installs `entry` from `archive` (downloaded and verified against the feed); `feed` and
    /// `sig` are the signed feed that lists it, stored with the version. The archive file is
    /// removed afterwards either way.
    pub async fn install(
        &self,
        entry: &EngineEntry,
        feed: &[u8],
        sig: &str,
        archive: Verified,
        check: &impl EngineCheck,
    ) -> Result<Installed, InstallError> {
        let (id, version) = (entry.id.as_str(), entry.version);
        exe_name(id).ok_or_else(|| InstallError::Unknown(id.to_owned()))?;
        let newer = bundled_version(id).is_none_or(|b| version > b);
        if !engine_allowed(id, version) || !entry.app.contains(policy::app_version()) || !newer {
            return Err(InstallError::NotAllowed(version));
        }
        match verify(feed, sig, self.keys) {
            Ok(signed) if signed.engine(id) == Some(entry) => {}
            _ => return Err(InstallError::Feed),
        }
        // Unpacked straight into the version's own folder: an elevated check of the new engine
        // (the pin check) accepts only a folder named after the version, next to its feed. The
        // folder is not used before `state.json` points at it, and a refusal removes it.
        let target = self.version_dir(id, version);
        if target.exists() {
            std::fs::remove_dir_all(&target)?;
        }
        let result = self
            .stage(entry, (feed, sig), archive, &target, check)
            .await;
        if result.is_err() {
            let _ = std::fs::remove_dir_all(&target);
        }
        result?;
        let mut state = self.state();
        let record = state.engine_mut(id);
        let previous = record.active;
        if previous != Choice::Downloaded(version) {
            record.previous = Some(previous);
        }
        record.active = Choice::Downloaded(version);
        record.trial = Some(0);
        record
            .installed
            .insert(version.to_string(), vpnte_base::types::now_ms());
        state::write(&self.root, &state)?;
        self.prune(id);
        tracing::info!(engine = id, %version, %previous, "engine installed");
        Ok(Installed {
            id: id.to_owned(),
            version,
            previous,
        })
    }

    /// Steps 1-3 into `dir`; `signed` = the feed bytes and their signature.
    async fn stage(
        &self,
        entry: &EngineEntry,
        (feed, sig): (&[u8], &str),
        archive: Verified,
        dir: &Path,
        check: &impl EngineCheck,
    ) -> Result<(), InstallError> {
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
        }
        std::fs::create_dir_all(dir)?;
        let (members, into) = (entry.files.clone(), dir.to_owned());
        let Verified { path, mut file } = archive;
        let extracted = tokio::task::spawn_blocking(move || {
            let result = extract(&mut file, &members, &into);
            drop(file);
            let _ = std::fs::remove_file(&path);
            result
        })
        .await
        .map_err(|e| InstallError::Io(io::Error::other(e)))?;
        extracted?;
        if entry.id == policy::SINGBOX {
            // sing-box loads Wintun from its own folder for the TUN; Wintun is never updated, so
            // the copy is the bundled file (the pin check holds it to the release pin).
            let wintun = self.resources.join("wintun.dll");
            if wintun.is_file() {
                std::fs::copy(&wintun, dir.join("wintun.dll"))?;
            }
        }
        std::fs::write(dir.join(FEED_FILE), feed)?;
        std::fs::write(dir.join(SIG_FILE), sig)?;
        let exe = dir.join(exe_name(&entry.id).unwrap_or_default());
        let got = check.version(&entry.id, &exe).await?;
        if got != entry.version {
            return Err(InstallError::VersionMismatch {
                got: got.to_string(),
                want: entry.version,
            });
        }
        check
            .check_configs(&entry.id, &exe)
            .await
            .map_err(InstallError::ConfigRefused)
    }
}

/// Writes exactly the listed members of `archive` into `dir`, each checked against its SHA-256.
pub(super) fn extract(
    archive: &mut std::fs::File,
    members: &[MemberEntry],
    dir: &Path,
) -> Result<(), InstallError> {
    archive.seek(SeekFrom::Start(0))?;
    let bad = |m: &MemberEntry| InstallError::Member(m.name.clone());
    let mut zip = zip::ZipArchive::new(archive).map_err(|e| io::Error::other(e.to_string()))?;
    for member in members {
        let pin = parse_sha(&member.sha256).ok_or_else(|| bad(member))?;
        if member.name.is_empty()
            || member.name.contains(['/', '\\', ':'])
            || member.name.starts_with('.')
        {
            return Err(bad(member));
        }
        let mut from = zip.by_name(&member.path).map_err(|_| bad(member))?;
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(&member.name))?;
        let (mut hasher, mut total, mut buf) = (Sha256::new(), 0u64, vec![0u8; 1 << 16]);
        loop {
            let n = from.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MEMBER_CAP {
                return Err(bad(member));
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])?;
        }
        if <[u8; 32]>::from(hasher.finalize()) != pin {
            return Err(bad(member));
        }
    }
    Ok(())
}
