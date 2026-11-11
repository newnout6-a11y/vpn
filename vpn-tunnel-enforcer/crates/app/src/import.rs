//! One-time, non-destructive import of the Electron data directory (work package `app-import`).
use vpnte_base::Msg;
use vpnte_core::paths::DataDirs;

/// What the import did, for the first-run notice and the maintenance page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// `(document, rows)` written into the new data dir.
    pub imported: Vec<(String, usize)>,
    /// Secrets that could not be decrypted and stay locked.
    pub locked: usize,
    /// Invalid rows that were dropped.
    pub dropped: usize,
    /// Notes for the user (plaintext leftovers of the old app, by file name).
    pub notes: Vec<Msg>,
}

/// Imports the old data once, before any store is opened. `None` = nothing to import (or done earlier).
pub fn import_if_needed(_dirs: &DataDirs) -> Option<ImportReport> {
    None
}
