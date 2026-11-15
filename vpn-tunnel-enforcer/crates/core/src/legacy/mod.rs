//! Read-only primitives for the one-time import of the old Electron build's data dir
//! (`%APPDATA%\vpn-tunnel-enforcer`, storage §2.2-2.7, §6.6): read its electron-store documents
//! leniently, load the Chromium `safeStorage` key and open the secrets. Where the dir is comes from
//! `paths::DataDirs::legacy_electron`.
//!
//! Nothing here writes, renames or deletes anything under the legacy dir. The app orchestrates the
//! import; each crate maps the opened documents into its own types (`from_legacy` / `import_legacy`).
//! Everything is blocking (file reads; DPAPI may ask a domain controller for a master key), so
//! async callers use `spawn_blocking`.
mod crypto;
mod dir;
mod doc;
mod json;
#[cfg(test)]
mod tests;

pub use crypto::{
    ChromiumKey, KeyError, LegacyValue, SecretFault, chromium_key, is_encrypted_backup,
    legacy_secret, open_ciphertext, open_v10, secret_ref_ciphertext,
};
pub use dir::LegacyDir;
pub use doc::{DocError, LOCKED_MARKER, LegacyDoc, OpenedDoc, STORES, is_locked};
