//! The signed feed `update.json` (research/updates.md §4.3): what the app, its engines and the
//! helper service may update to. One verification ([`verify`]) serves every reader — the
//! network check, the engine install, the elevated pin check and the helper service — so a feed
//! that one of them accepts is a feed all of them accept (AT-11-010).
use std::collections::BTreeMap;

/// A minisign public key (re-exported for the pin check and the helper service).
pub use minisign_verify::PublicKey;
use minisign_verify::Signature;
use serde::{Deserialize, Serialize};

use crate::version::{Range, Version};

/// The only feed layout this build reads. A newer one means the app is too old to read it.
pub const SCHEMA: u32 = 1;
/// File names of the feed and its signature (on the mirrors and next to downloaded engines).
pub const FEED_FILE: &str = "update.json";
pub const SIG_FILE: &str = "update.json.minisig";

/// The whole feed. Unknown fields are ignored, so a later publisher can add some.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Feed {
    pub schema: u32,
    /// Only grows with every publication; the app remembers the highest it accepted.
    pub seq: u64,
    /// When CI signed it (RFC 3339, UTC).
    pub issued: String,
    pub app: AppChannels,
    #[serde(default)]
    pub engines: Vec<EngineEntry>,
    /// The helper service's own executable, for its self-update.
    #[serde(default)]
    pub service: Option<ServiceEntry>,
}

/// Release channels of the app. Only `stable` is published; `beta` stays `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppChannels {
    pub stable: Option<AppRelease>,
    #[serde(default)]
    pub beta: Option<AppRelease>,
    /// Below this version the banner cannot be hidden with «Пропустить» (never forced).
    #[serde(default)]
    pub warn_below: Option<Version>,
}

/// One app version and its installer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRelease {
    pub version: Version,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub notes: Notes,
    pub file: FileEntry,
    /// The oldest version that still reads this version's data: a rollback target.
    #[serde(default)]
    pub rollback_to: Option<Version>,
    /// The installer of `rollback_to`.
    #[serde(default)]
    pub rollback_file: Option<FileEntry>,
}

/// How urgent an update is. Unknown words read as `Normal`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Security,
    Critical,
    #[default]
    #[serde(other)]
    Normal,
}

impl Severity {
    /// Security and critical updates get one tray notice and no «Пропустить».
    pub fn is_security(self) -> bool {
        matches!(self, Severity::Security | Severity::Critical)
    }
}

/// Release notes by language code (`ru`, `en`).
pub type Notes = BTreeMap<String, String>;

/// A file to download: size cap and SHA-256 from the signed feed, mirrors in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub urls: Vec<String>,
}

/// One engine version our CI tested: an `[[archive]]` of `resources/engines.toml` in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineEntry {
    /// `sing-box` or `xray`.
    pub id: String,
    pub version: Version,
    /// App versions this entry is meant for; it can only narrow the compiled range.
    #[serde(default)]
    pub app: Range,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub notes: Notes,
    /// Day our tests passed with it (`2026-11-12`).
    #[serde(default)]
    pub tested_on: Option<String>,
    /// The CI run that tested it.
    #[serde(default)]
    pub tested: Option<String>,
    pub archive: ArchiveEntry,
    pub files: Vec<MemberEntry>,
}

/// The engine author's archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub url: String,
    pub size: u64,
    pub sha256: String,
}

/// One member of the archive to install: `path` inside the zip, `name` in the version folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberEntry {
    pub path: String,
    pub name: String,
    pub sha256: String,
}

/// The helper service's executable (`vpnte-service.exe`) of a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub version: Version,
    pub size: u64,
    pub sha256: String,
    pub urls: Vec<String>,
}

impl Feed {
    /// The entry of engine `id`, if the feed lists one.
    pub fn engine(&self, id: &str) -> Option<&EngineEntry> {
        self.engines.iter().find(|e| e.id == id)
    }
}

/// Why a feed was refused. Logged in English; the UI shows one calm line per kind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    /// No trusted key is compiled into this build yet.
    #[error("no update key is configured in this build")]
    NoKeys,
    /// The signature is malformed, made by another key, or does not match the bytes.
    #[error("the feed signature does not verify")]
    Signature,
    /// The signed bytes are not a feed this build understands.
    #[error("the feed is not readable: {0}")]
    Format(String),
    /// A newer feed layout: this app is too old to read it.
    #[error("unknown feed schema {0}")]
    Schema(u32),
}

/// Verifies `sig` (the `.minisig` text: prehashed Ed25519) over the exact `bytes` with one of
/// `keys`, then parses the feed. The one check every reader runs; the caller adds its own
/// freshness rules (`seq`, `issued`) where they apply.
pub fn verify(bytes: &[u8], sig: &str, keys: &[PublicKey]) -> Result<Feed, FeedError> {
    if keys.is_empty() {
        return Err(FeedError::NoKeys);
    }
    let sig = Signature::decode(sig).map_err(|_| FeedError::Signature)?;
    // Legacy (not prehashed) signatures are refused: every feed is signed with `minisign -S`'s
    // default prehashed mode, and allowing both would only widen what an attacker can try.
    if !keys.iter().any(|k| k.verify(bytes, &sig, false).is_ok()) {
        return Err(FeedError::Signature);
    }
    // The schema is read first so a newer layout reports "too old", not a parse error.
    #[derive(Deserialize)]
    struct Head {
        schema: u32,
    }
    let head: Head = serde_json::from_slice(bytes).map_err(|e| FeedError::Format(e.to_string()))?;
    if head.schema != SCHEMA {
        return Err(FeedError::Schema(head.schema));
    }
    serde_json::from_slice(bytes).map_err(|e| FeedError::Format(e.to_string()))
}

/// [`verify`] with the keys compiled into this build ([`crate::policy::trusted_keys`]).
pub fn verify_trusted(bytes: &[u8], sig: &str) -> Result<Feed, FeedError> {
    verify(bytes, sig, crate::policy::trusted_keys())
}

#[cfg(test)]
pub(crate) mod tests;
