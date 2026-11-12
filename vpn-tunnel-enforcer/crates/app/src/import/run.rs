//! The orchestration: marker, old directory, key, the steps, notes, marker.
use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;
use vpnte_automation::hardening;
use vpnte_automation::tweaks::{self, legacy::LegacySources};
use vpnte_base::Msg;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_core::legacy::{ChromiumKey, DocError, KeyError, LegacyDir};
use vpnte_core::paths::{DataDirs, ENV_LEGACY_DIR};
use vpnte_core::store::{Document, Store, write_atomic};

use super::{ImportReport, steps};

/// The commit marker in the data root, written last (storage §6.6).
pub(super) const MARKER: &str = "migration.json";

/// What the import reads from the machine besides the two directories, injected so that tests
/// never touch this user's real state.
pub(super) struct Host<'a> {
    /// The process is elevated: Hard mode (TUN) and the strict kill switch can work.
    pub elevated: bool,
    /// Where the old app kept its Soft-mode receipts and how to read the current values;
    /// `None` skips their adoption.
    pub tweaks: Option<(&'a LegacySources, &'a dyn tweaks::Backend)>,
    /// Where the old app kept its browser-policy and location receipts and how to read the
    /// registry; `None` skips their adoption (adopted second, after the Soft receipts).
    pub hardening: Option<(
        &'a hardening::legacy::LegacySources,
        &'a dyn hardening::System,
    )>,
}

/// Imports the old data once, before any store is opened. `None` = nothing to import (or done
/// earlier). Blocking (file reads, DPAPI): call it before the UI starts.
pub fn import_if_needed(dirs: &DataDirs) -> Option<ImportReport> {
    if dirs.root.join(MARKER).exists() {
        return None;
    }
    // The receipts belong to this account's own old install: an old dir redirected through
    // `VPNTE_LEGACY_DIR` (tests, CI, a copied install) is not theirs, so they are left alone.
    let own_install = std::env::var_os(ENV_LEGACY_DIR).is_none_or(|v| v.is_empty());
    let sources = LegacySources::current_user();
    let system = own_install.then(tweaks::SoftSystem::current_user);
    let marks = hardening::legacy::LegacySources::new(&dirs.legacy_electron);
    let registry = own_install.then(hardening::WinSystem::new);
    let host = Host {
        elevated: vpnte_winnet::elevation::is_elevated(),
        tweaks: system
            .as_ref()
            .map(|system| (&sources, system as &dyn tweaks::Backend)),
        hardening: registry
            .as_ref()
            .map(|sys| (&marks, sys as &dyn hardening::System)),
    };
    run(dirs, &host)
}

/// The import with an explicit host (see [`import_if_needed`]).
pub(super) fn run(dirs: &DataDirs, host: &Host<'_>) -> Option<ImportReport> {
    let marker = dirs.root.join(MARKER);
    if marker.exists() {
        return None;
    }
    // The old app's Soft-mode leftovers live outside its data dir and carry their own marker.
    let mut adopted = ImportReport::default();
    if let Some((sources, system)) = host.tweaks {
        steps::tweaks(&mut adopted, &dirs.root, sources, system);
    }
    if let Some((sources, system)) = host.hardening {
        steps::hardening(&mut adopted, &dirs.root, sources, system);
    }
    let legacy = LegacyDir::at(&dirs.legacy_electron);
    let present = match legacy.stores_present() {
        Ok(present) => present,
        Err(err) => {
            // "Nothing to import" ends the import for good, so it must have been observed.
            tracing::warn!(%err, "old data dir not readable; import retried at the next start");
            return (adopted != ImportReport::default()).then_some(adopted);
        }
    };
    if present.is_empty() {
        write_marker(&marker, &Marker::new("none", &adopted));
        return (adopted != ImportReport::default()).then_some(adopted);
    }
    tracing::info!(stores = present.len(), "importing the old version's data");
    let mut cx = Ctx::new(&dirs.root, legacy, host.elevated, adopted);
    steps::all(&mut cx);
    Some(cx.finish(&marker))
}

/// State of one import run, shared by the steps.
pub(super) struct Ctx<'a> {
    /// New data root (documents are written under it).
    pub root: &'a Path,
    /// The process is elevated (see [`Host::elevated`]).
    pub elevated: bool,
    pub report: ImportReport,
    legacy: LegacyDir,
    key: Option<ChromiumKey>,
    /// `Local State` could not be read right now (an I/O error, not a missing or bad key).
    key_transient: bool,
    /// Old files that could not be read and new documents that could not be written right now:
    /// no marker, the next start imports again.
    retry: Vec<String>,
}

impl<'a> Ctx<'a> {
    fn new(root: &'a Path, legacy: LegacyDir, elevated: bool, report: ImportReport) -> Self {
        let (key, key_transient) = match legacy.chromium_key() {
            Ok(key) => (Some(key), false),
            // Data from before encryption has no key; encrypted values are counted as locked.
            Err(KeyError::Missing) => (None, false),
            Err(err) => {
                tracing::warn!(%err, "old app's key unavailable: its secrets stay locked");
                (None, matches!(err, KeyError::Io(_)))
            }
        };
        Self {
            root,
            elevated,
            report,
            legacy,
            key,
            key_transient,
            retry: Vec::new(),
        }
    }

    /// The old `store` with its secrets opened; `None` when absent or not importable (noted).
    pub fn open(&mut self, store: &str) -> Option<Value> {
        let file = format!("{store}.json");
        match self.legacy.read(store) {
            Ok(None) => None,
            Ok(Some(doc)) => {
                let opened = doc.open(self.key.as_ref());
                self.report.locked += opened.locked.len() + opened.invalid.len();
                Some(opened.value)
            }
            // Held by another program, or a permission problem: worth another try.
            Err(DocError::Io(err)) => {
                tracing::warn!(%err, store, "old file not readable");
                self.retry.push(file);
                None
            }
            Err(err) => {
                tracing::warn!(%err, store, "old file not imported");
                let key = match err {
                    DocError::Newer { .. } => "app.import.fileNewer",
                    _ => "app.import.fileInvalid",
                };
                self.note(Msg::new(key).arg("file", file));
                None
            }
        }
    }

    /// Adds a note for the user.
    pub fn note(&mut self, msg: Msg) {
        self.report.notes.push(msg);
    }

    /// The rolling backup `<store>.json.bak` (only the live-check history had one); `None` when
    /// absent or not importable, and while the main file waits for a retry (held by another
    /// program: the next start imports the main file itself). Plain JSON: nothing is sealed.
    pub fn open_backup(&mut self, store: &str) -> Option<Value> {
        let main = format!("{store}.json");
        if self.retry.contains(&main) {
            return None;
        }
        match self.legacy.read_backup(store) {
            Ok(doc) => doc.map(|doc| doc.open(self.key.as_ref()).value),
            Err(err) => {
                tracing::warn!(%err, store, "old backup not imported");
                None
            }
        }
    }

    /// Records `(file, rows)` as imported.
    pub fn imported(&mut self, file: &str, rows: usize) {
        self.report.imported.push((file.to_owned(), rows));
    }

    /// Writes `doc` as a new document. One that already exists in the new data dir is the
    /// user's (or this import's, before a crash) and is kept; a default one has nothing in it.
    pub fn write_new<T: Document>(&mut self, doc: T, rows: usize) {
        if doc == T::default() {
            return;
        }
        if self.root.join(T::FILE).exists() {
            tracing::info!(file = T::FILE, "kept: the new data dir has it already");
            return;
        }
        match Store::<T>::open(self.root).replace(doc) {
            Ok(()) => self.imported(T::FILE, rows),
            Err(err) => self.write_failed(T::FILE, &err),
        }
    }

    /// A new document could not be written: the next start imports again.
    pub fn write_failed(&mut self, file: &str, err: &dyn std::fmt::Display) {
        tracing::warn!(%err, file, "imported document not written");
        self.retry.push(file.to_owned());
    }
}

impl Ctx<'_> {
    /// The closing notes, then the marker unless something has to be retried.
    fn finish(mut self, marker: &Path) -> ImportReport {
        if self.report.locked > 0 {
            if self.key_transient {
                self.retry.push("Local State".to_owned());
            }
            let count = self.report.locked;
            self.note(Msg::new("app.import.locked").arg("count", count));
        }
        let leftovers = self.legacy.plaintext_leftovers();
        if !leftovers.is_empty() {
            self.note(Msg::new("app.import.leftovers").arg("files", leftovers.join(", ")));
        }
        if self.retry.is_empty() {
            write_marker(marker, &Marker::new("electron", &self.report));
        } else {
            tracing::warn!(files = ?self.retry, "import incomplete; retried at the next start");
            let files = self.retry.join(", ");
            self.note(Msg::new("app.import.retry").arg("files", files));
        }
        // Keys only: the arguments are counts and old file names, but no reader needs them here.
        let notes: Vec<&str> = self.report.notes.iter().map(|m| m.key.as_ref()).collect();
        tracing::info!(
            documents = self.report.imported.len(),
            locked = self.report.locked,
            dropped = self.report.dropped,
            ?notes,
            "old version's data imported"
        );
        self.report
    }
}

/// `migration.json`: when and what was imported (no notes, no secrets).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Marker {
    schema_version: u32,
    imported_at: UnixMs,
    /// `electron` = the old directory was imported, `none` = there was nothing to import.
    source: &'static str,
    imported: BTreeMap<String, usize>,
    locked: usize,
    dropped: usize,
}

impl Marker {
    fn new(source: &'static str, report: &ImportReport) -> Self {
        Self {
            schema_version: 1,
            imported_at: now_ms(),
            source,
            imported: report.imported.iter().cloned().collect(),
            locked: report.locked,
            dropped: report.dropped,
        }
    }
}

/// Writes the marker atomically. A failure only means the next start imports again, which
/// changes nothing that was written now.
fn write_marker(path: &Path, marker: &Marker) {
    let written = serde_json::to_vec_pretty(marker)
        .map_err(std::io::Error::other)
        .and_then(|mut bytes| {
            bytes.push(b'\n');
            write_atomic(path, &bytes)
        });
    if let Err(err) = written {
        tracing::warn!(%err, "import marker not written; the import runs again next start");
    }
}
