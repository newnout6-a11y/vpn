//! One-time, non-destructive import of the Electron data directory (work package `app-import`,
//! storage §6.6, CONTRACT §3.5). Every old store is read through `vpnte_core::legacy`, its
//! secrets are opened, the owning crate converts it (`from_legacy` / `import_legacy`), the new
//! documents are written, and `migration.json` is written last: a crash before it imports again
//! at the next start, and every step is idempotent (a document that already exists in the new
//! data dir is the user's and is kept). Nothing under the old directory is written, renamed or
//! deleted. Nothing here needs administrator rights (NOADMIN): the old files belong to the user
//! and DPAPI runs as the user.
use vpnte_base::Msg;

#[cfg(feature = "app-import")]
mod run;
#[cfg(feature = "app-import")]
mod steps;
#[cfg(all(test, feature = "app-import"))]
mod tests;

/// What the import did, for the first-run notice and the maintenance page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// `(document, rows)` written into the new data dir (document = its file under the data
    /// root, e.g. `profiles.json`; rows = entries in it, 1 for a settings document).
    pub imported: Vec<(String, usize)>,
    /// Encrypted values of the old data that could not be decrypted (the old app's key is
    /// missing or belongs to another Windows account, or the value is damaged): they stay locked
    /// in the old directory, and the rows that needed them were not imported.
    pub locked: usize,
    /// Invalid rows that were dropped (the owning crate refused them).
    pub dropped: usize,
    /// Notes for the user: the owning crates' warnings, settings adapted to an unelevated app,
    /// plaintext leftovers of the old app (by file name), files to retry.
    pub notes: Vec<Msg>,
}

#[cfg(feature = "app-import")]
pub use run::import_if_needed;

/// Build scaffolding: without the `app-import` feature there is never anything to import.
#[cfg(not(feature = "app-import"))]
pub fn import_if_needed(_dirs: &vpnte_core::paths::DataDirs) -> Option<ImportReport> {
    None
}
