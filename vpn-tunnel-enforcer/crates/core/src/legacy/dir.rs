//! The old Electron build's data dir, opened strictly read-only.
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use super::crypto::{ChromiumKey, KeyError, chromium_key};
use super::doc::{DocError, LegacyDoc, STORES};

/// The largest observed document is ~1 MB; a bigger file is not one the old app wrote.
pub(super) const MAX_DOC_BYTES: u64 = 64 << 20;

/// The old app's data dir. Every method only reads; nothing under it is ever written, renamed or
/// deleted, so the old version keeps working after the import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyDir {
    path: PathBuf,
}

impl LegacyDir {
    /// The legacy dir at `path`: `DataDirs::legacy_electron` (`VPNTE_LEGACY_DIR`, else
    /// `%APPDATA%\vpn-tunnel-enforcer`). Does not check existence.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The dir itself (for the import report and the "remove old version data" action).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Names of the known stores ([`STORES`]) that have a `<store>.json` here; empty when the dir
    /// is missing (nothing to import). Any other I/O error is returned: "nothing to import" ends
    /// the one-time import for good, so it must have been observed.
    pub fn stores_present(&self) -> std::io::Result<Vec<&'static str>> {
        let mut present = Vec::new();
        for (name, _) in STORES {
            match std::fs::metadata(self.path.join(format!("{name}.json"))) {
                Ok(meta) if meta.is_file() => present.push(*name),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(present)
    }

    /// File names (not paths) of plaintext copies the old app left behind and never protected:
    /// `settings.json.bak-*` (may hold VPN keys), `live-server-checks.json.bak` / `.v0.bak`
    /// (storage B9). The import lists them; it never copies them.
    pub fn plaintext_leftovers(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.path) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| {
                let lower = name.to_ascii_lowercase();
                lower.starts_with("settings.json.bak-")
                    || lower == "live-server-checks.json.bak"
                    || lower == "live-server-checks.json.v0.bak"
            })
            .collect();
        names.sort();
        names
    }

    /// Reads and admits `<store>.json`; `Ok(None)` when the file does not exist.
    pub fn read(&self, store: &str) -> Result<Option<LegacyDoc>, DocError> {
        self.read_file(store, &format!("{store}.json"))
    }

    /// Reads `<store>.json.bak`, the previous good copy the live-check history kept (storage §2.4 H2).
    pub fn read_backup(&self, store: &str) -> Result<Option<LegacyDoc>, DocError> {
        self.read_file(store, &format!("{store}.json.bak"))
    }

    /// Loads the `safeStorage` key from `Local State` in this dir (see [`chromium_key`]).
    pub fn chromium_key(&self) -> Result<ChromiumKey, KeyError> {
        chromium_key(&self.path)
    }

    fn read_file(&self, store: &str, file: &str) -> Result<Option<LegacyDoc>, DocError> {
        if !STORES.iter().any(|(name, _)| *name == store) {
            return Err(DocError::Unregistered(store.to_owned()));
        }
        // std opens with FILE_SHARE_READ | WRITE | DELETE, so a running old app can still replace
        // the file atomically while we read it.
        let file = match File::open(self.path.join(file)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if file.metadata()?.len() > MAX_DOC_BYTES {
            return Err(DocError::TooLarge);
        }
        // The file may grow between the size check and the read: cap the read as well.
        let mut bytes = Vec::new();
        file.take(MAX_DOC_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_DOC_BYTES {
            return Err(DocError::TooLarge);
        }
        LegacyDoc::parse(store, &bytes).map(Some)
    }
}
