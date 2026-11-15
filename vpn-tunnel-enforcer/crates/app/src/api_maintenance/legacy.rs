//! The old version's leftovers and storage repair: what the panel shows (`view`), deleting the
//! old data directory after the user confirmed it, setting a corrupt document aside, and the
//! snapshots folder. Everything here is the user's own data: no elevation needed.
use std::io;
use std::path::Path;
use std::sync::Arc;

use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_cleanup::legacy::{CleanupMarker, Outcome};
use vpnte_core::legacy::LegacyDir as OldDir;
use vpnte_core::paths::DataDirs;
use vpnte_core::store::{Mode, ReadOnlyReason};
use vpnte_ui::maintenance::{CorruptStore, LegacyDir, LegacyView};

use super::{Shared, project, refused};
use crate::support::blocking;

/// The import's commit marker in the data root (written last by `app-import`): the old data is
/// no longer needed once it exists.
const MIGRATION_MARKER: &str = "migration.json";
/// Id of the server list in [`CorruptStore::id`] (the only document holding secrets).
const PROFILES: &str = "profiles";
/// The size walk gives up after this many entries (the size is then shown as unknown).
const MAX_ENTRIES: usize = 200_000;

/// The panel's view, read on a blocking thread (directory walk, small file reads).
pub(crate) async fn view(shared: &Arc<Shared>) -> LegacyView {
    let shared = shared.clone();
    tokio::task::spawn_blocking(move || read_view(&shared))
        .await
        .unwrap_or_default()
}

fn read_view(shared: &Shared) -> LegacyView {
    let backend = &shared.backend;
    let data_dir = old_dir(&backend.dirs.legacy_electron);
    LegacyView {
        secrets_pending: data_dir.is_some() && locked_at_import(&backend.dirs.root) > 0,
        data_dir,
        corrupt: corrupt_stores(backend.servers.mode()),
        cleanup_failures: cleanup_failures(&shared.backend.cleanup.snapshot()),
    }
}

/// The old data directory, `None` when it is gone (or never existed).
fn old_dir(dir: &Path) -> Option<LegacyDir> {
    let meta = std::fs::symlink_metadata(dir).ok()?;
    if !meta.is_dir() {
        return None;
    }
    Some(LegacyDir {
        path: dir.display().to_string(),
        bytes: dir_size(dir),
        plaintext_files: u32::try_from(OldDir::at(dir).plaintext_leftovers().len())
            .unwrap_or(u32::MAX),
    })
}

/// Bytes under `dir`, links not followed; `None` when unreadable or too large to walk.
fn dir_size(dir: &Path) -> Option<u64> {
    let mut total = 0u64;
    let mut seen = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).ok()? {
            let entry = entry.ok()?;
            seen += 1;
            if seen > MAX_ENTRIES {
                return None;
            }
            let kind = entry.file_type().ok()?;
            if kind.is_dir() {
                stack.push(entry.path());
            } else if kind.is_file() {
                total += entry.metadata().ok()?.len();
            }
        }
    }
    Some(total)
}

/// Encrypted values the import could not open (`locked` of the import marker).
fn locked_at_import(root: &Path) -> u64 {
    std::fs::read(root.join(MIGRATION_MARKER))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|marker| marker.get("locked")?.as_u64())
        .unwrap_or(0)
}

/// The server list opened read-only because its file is damaged (it holds keys, so the store
/// keeps it untouched until the user sets it aside).
pub(crate) fn corrupt_stores(mode: Mode) -> Vec<CorruptStore> {
    match mode {
        Mode::ReadOnly(ReadOnlyReason::Corrupt | ReadOnlyReason::Unreadable) => {
            vec![CorruptStore {
                id: PROFILES.to_owned(),
                name: Msg::new("app.maintenance.legacy.store.profiles"),
                file: "profiles.json".to_owned(),
            }]
        }
        Mode::Writable | Mode::ReadOnly(ReadOnlyReason::NewerVersion(_)) => Vec::new(),
    }
}

/// Steps of the old version's network cleanup whose last run failed.
pub(crate) fn cleanup_failures(marker: &CleanupMarker) -> Vec<Msg> {
    marker
        .steps
        .iter()
        .filter(|r| r.outcome == Outcome::Failed)
        .map(|r| r.msg())
        .collect()
}

/// Deletes the old data directory (after the page's confirmation). Refused while the tunnel
/// is in transition and before the import finished (it would read the old files again).
pub(crate) async fn delete(shared: Arc<Shared>) -> AppResult<()> {
    project::settled(&shared)?;
    let dirs = shared.backend.dirs.clone();
    let result = blocking(move || remove_old_dir(&dirs)).await;
    shared.touch();
    match &result {
        Ok(()) => tracing::warn!("old version's data directory deleted by the user"),
        Err(err) => tracing::warn!(error = %err, "old version's data directory not deleted"),
    }
    result
}

/// Removes `dirs.legacy_electron` when it is recognisably the old app's own folder: a plain
/// directory (no link), apart from the new data dir, with the old app's files in it.
pub(crate) fn remove_old_dir(dirs: &DataDirs) -> AppResult<()> {
    if !dirs.root.join(MIGRATION_MARKER).is_file() {
        return Err(refused("app.maintenance.legacy.importPending"));
    }
    // Keys the import could not open live only in the old files: they would go with the folder.
    if locked_at_import(&dirs.root) > 0 {
        return Err(refused("app.maintenance.legacy.keysPending"));
    }
    let dir = &dirs.legacy_electron;
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(io_failure(err)),
    };
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || !apart(dir, &dirs.root)
        || !looks_like_old_app(dir)
    {
        return Err(AppError::validation(Msg::new(
            "app.maintenance.legacy.notOldData",
        )));
    }
    std::fs::remove_dir_all(dir).map_err(io_failure)
}

/// Neither folder contains the other, compared in their real spelling (case, short names and
/// links resolved): an override that points at the new data must never delete it.
fn apart(dir: &Path, root: &Path) -> bool {
    match (std::fs::canonicalize(dir), std::fs::canonicalize(root)) {
        (Ok(dir), Ok(root)) => !root.starts_with(&dir) && !dir.starts_with(&root),
        _ => false,
    }
}

/// The folder holds the old app's documents or its key file (`Local State`), and is not a data
/// folder of this version (those carry the import marker and a `settings.json` of their own).
fn looks_like_old_app(dir: &Path) -> bool {
    !dir.join(MIGRATION_MARKER).exists()
        && (dir.join("Local State").is_file()
            || OldDir::at(dir)
                .stores_present()
                .is_ok_and(|stores| !stores.is_empty()))
}

/// A failed delete: files still in use (the old app runs), no access, or anything else.
fn io_failure(err: io::Error) -> AppError {
    // ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION: another process holds a file open.
    let (kind, key) = match (err.kind(), err.raw_os_error()) {
        (_, Some(32 | 33)) => (ErrorKind::Conflict, "app.maintenance.legacy.inUse"),
        (io::ErrorKind::PermissionDenied, _) => {
            (ErrorKind::Permission, "app.maintenance.legacy.denied")
        }
        _ => (ErrorKind::Internal, "app.maintenance.legacy.deleteFailed"),
    };
    AppError::msg(kind, Msg::new(key)).with_source(err)
}

/// Moves the damaged document `id` aside (`<name>.corrupt-<unix ms>.json`) and starts it empty.
pub(crate) async fn set_aside(shared: Arc<Shared>, id: String) -> AppResult<()> {
    project::settled(&shared)?;
    if id != PROFILES {
        return Err(AppError::validation(Msg::new(
            "app.maintenance.legacy.unknownStore",
        )));
    }
    let servers = shared.backend.servers.clone();
    let result = blocking(move || servers.set_aside()).await;
    shared.touch();
    result
}

/// Opens the snapshots folder (`<data>\snapshots`), created when it does not exist yet.
pub(crate) async fn open_snapshots(shared: &Shared) -> AppResult<()> {
    let dir = vpnte_probes::diagnostics::snapshot::dir(&shared.backend.dirs.root);
    let created = dir.clone();
    blocking(move || {
        std::fs::create_dir_all(&created).map_err(|err| {
            AppError::msg(
                ErrorKind::Internal,
                Msg::new("app.maintenance.snapshotsFailed"),
            )
            .with_source(err)
        })
    })
    .await?;
    vpnte_winnet::shell::open_folder(&dir).await
}
