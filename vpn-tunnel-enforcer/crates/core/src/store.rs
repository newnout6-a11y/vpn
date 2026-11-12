//! One persistence mechanism for every JSON document: loaded once, kept in memory, written through
//! atomically on change, with a change notification for the services that depend on it.
//!
//! On-disk form: a pretty-printed JSON object whose first key is `"schemaVersion"`. A file written by a
//! newer version is opened read-only and never overwritten (storage B28); a corrupt file is moved aside
//! (or, if it holds secrets, kept untouched and opened read-only) instead of stopping the app (B16).
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use tokio::sync::watch;
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};
use windows::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows::core::HSTRING;

/// Key of the format version in every document.
pub const SCHEMA_KEY: &str = "schemaVersion";

/// Antivirus scanners and the search indexer hold freshly written files for a moment; these waits
/// (≈0.8 s in total) cover that without hanging the caller.
const RETRY_DELAYS_MS: [u64; 5] = [20, 50, 100, 200, 400];

/// A persisted document type. Each crate owns its documents (contract §3.4).
pub trait Document:
    Serialize + DeserializeOwned + Default + Clone + PartialEq + Send + Sync + 'static
{
    /// Path under the data root, `/`-separated (`"settings.json"`, `"history/connections.json"`).
    const FILE: &'static str;
    /// Current `schemaVersion`.
    const VERSION: u32;
    /// A corrupt file that holds secrets is kept untouched and opened read-only instead of being moved
    /// aside, so the user decides what happens to the keys.
    const HOLDS_SECRETS: bool = false;
}

/// Whether changes to a document are persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Normal operation.
    Writable,
    /// Changes are refused; the file on disk is left exactly as it is.
    ReadOnly(ReadOnlyReason),
}

/// Why a document is read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOnlyReason {
    /// Written by a newer app version (the value is its `schemaVersion`).
    NewerVersion(u32),
    /// Not valid JSON or not the expected shape, and it holds secrets or could not be moved aside.
    Corrupt,
    /// The file exists but could not be read (locked or access denied).
    Unreadable,
}

/// The single in-memory owner of one document.
pub struct Store<T: Document> {
    path: PathBuf,
    state: RwLock<T>,
    mode: RwLock<Mode>,
    /// Where a corrupt file was moved (reported by [`Store::notice`]).
    moved_aside: RwLock<Option<PathBuf>>,
    /// Serialises writers so two concurrent updates cannot lose each other's change.
    writer: Mutex<()>,
    changes: watch::Sender<u64>,
}

impl<T: Document> Store<T> {
    /// Loads `T::FILE` under `root`. A missing file gives `T::default()`; no file is created until the
    /// first change. Never fails: problems become a read-only [`Mode`] or a [`Store::notice`].
    /// Temp files left next to the document by a write that crashed before its rename are removed.
    pub fn open(root: &Path) -> Self {
        let path = T::FILE
            .split('/')
            .fold(root.to_path_buf(), |dir, part| dir.join(part));
        let stale = sweep_temp_files(&path);
        if stale > 0 {
            tracing::info!(file = T::FILE, count = stale, "stale temp files removed");
        }
        let (doc, mode, moved_aside) = load::<T>(&path);
        Self {
            path,
            state: RwLock::new(doc),
            mode: RwLock::new(mode),
            moved_aside: RwLock::new(moved_aside),
            writer: Mutex::new(()),
            changes: watch::channel(0).0,
        }
    }

    /// Full path of the backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Runs `f` on the current document (the lock is held only for the duration of `f`, so `f`
    /// must not call [`Store::update`] on the same store: that would deadlock).
    pub fn read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        f(&self.state.read())
    }

    /// A copy of the current document.
    pub fn snapshot(&self) -> T {
        self.state.read().clone()
    }

    /// Applies `f` to a copy, writes the copy atomically and only then makes it current. A change that
    /// leaves the document equal makes no write (AT-09-013). On any error the in-memory state stays
    /// the old one. `f` must not call `update` on the same store (writers are serialised). Blocking
    /// file I/O: async callers with large documents use `spawn_blocking`.
    pub fn update<R>(&self, f: impl FnOnce(&mut T) -> R) -> AppResult<R> {
        let _writer = self.writer.lock();
        if let Mode::ReadOnly(_) = self.mode() {
            return Err(AppError::conflict(
                Msg::new("core.store.readOnly").arg("file", T::FILE),
            ));
        }
        let mut next = self.snapshot();
        let out = f(&mut next);
        if *self.state.read() == next {
            return Ok(out);
        }
        let bytes = encode(&next)?;
        write_atomic(&self.path, &bytes).map_err(|e| {
            let mut err = AppError::from(e);
            err.msg = Some(Msg::new("core.store.writeFailed").arg("file", T::FILE));
            err
        })?;
        *self.state.write() = next;
        self.changes.send_modify(|generation| *generation += 1);
        Ok(out)
    }

    /// Replaces the whole document (same rules as [`Store::update`]).
    pub fn replace(&self, next: T) -> AppResult<()> {
        self.update(|doc| *doc = next)
    }

    /// A receiver whose value (a generation counter) changes after every persisted change.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Whether changes are persisted.
    pub fn mode(&self) -> Mode {
        *self.mode.read()
    }

    /// One-line warning or banner for the UI: read-only reasons, or a corrupt file moved aside at open.
    pub fn notice(&self) -> Option<Msg> {
        let key = match self.mode() {
            Mode::ReadOnly(ReadOnlyReason::NewerVersion(_)) => "core.store.newerVersion",
            Mode::ReadOnly(ReadOnlyReason::Corrupt) => "core.store.corruptKept",
            Mode::ReadOnly(ReadOnlyReason::Unreadable) => "core.store.unreadable",
            Mode::Writable => {
                let aside = self.moved_aside.read();
                let name = aside.as_deref()?.file_name()?.to_string_lossy();
                return Some(
                    Msg::new("core.store.corruptSetAside")
                        .arg("file", T::FILE)
                        .arg("backup", name),
                );
            }
        };
        Some(Msg::new(key).arg("file", T::FILE))
    }

    /// The user's choice for a corrupt or unreadable document: move the file aside as
    /// `<name>.corrupt-<unix ms>.json` and continue with an empty document. Refused for a file written
    /// by a newer version (that data is valid, just not ours to change).
    pub fn set_aside(&self) -> AppResult<()> {
        let _writer = self.writer.lock();
        match self.mode() {
            Mode::Writable => return Ok(()),
            Mode::ReadOnly(ReadOnlyReason::NewerVersion(_)) => {
                return Err(AppError::conflict(
                    Msg::new("core.store.readOnly").arg("file", T::FILE),
                ));
            }
            Mode::ReadOnly(_) => {}
        }
        let moved = match set_aside_file(&self.path) {
            Ok(moved) => Some(moved),
            // Already gone (deleted by hand): nothing to keep, just start empty.
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                let mut err = AppError::from(e);
                err.msg = Some(Msg::new("core.store.writeFailed").arg("file", T::FILE));
                return Err(err);
            }
        };
        *self.state.write() = T::default();
        *self.mode.write() = Mode::Writable;
        *self.moved_aside.write() = moved;
        self.changes.send_modify(|generation| *generation += 1);
        Ok(())
    }
}

enum Decoded<T> {
    Current(T),
    /// A newer version; the content is shown read-only when it still fits the current shape.
    Newer(u32, Option<T>),
    Corrupt(serde_json::Error),
}

fn load<T: Document>(path: &Path) -> (T, Mode, Option<PathBuf>) {
    let bytes = match with_retry(|| std::fs::read(path)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return (T::default(), Mode::Writable, None);
        }
        Err(e) => {
            tracing::warn!(file = T::FILE, error = %e, "document unreadable; opened read-only");
            return (
                T::default(),
                Mode::ReadOnly(ReadOnlyReason::Unreadable),
                None,
            );
        }
    };
    match decode::<T>(&bytes) {
        Decoded::Current(doc) => (doc, Mode::Writable, None),
        Decoded::Newer(version, doc) => {
            tracing::warn!(
                file = T::FILE,
                version,
                "document written by a newer version; read-only"
            );
            let mode = Mode::ReadOnly(ReadOnlyReason::NewerVersion(version));
            (doc.unwrap_or_default(), mode, None)
        }
        Decoded::Corrupt(e) => {
            // Only the error position is logged: serde messages can quote values (keys, hosts).
            let (category, line, column) = (e.classify(), e.line(), e.column());
            let corrupt = (T::default(), Mode::ReadOnly(ReadOnlyReason::Corrupt), None);
            if T::HOLDS_SECRETS {
                tracing::warn!(
                    file = T::FILE,
                    ?category,
                    line,
                    column,
                    "corrupt document with secrets kept read-only"
                );
                return corrupt;
            }
            match set_aside_file(path) {
                Ok(moved) => {
                    tracing::warn!(
                        file = T::FILE,
                        ?category,
                        line,
                        column,
                        "corrupt document moved aside; starting from defaults"
                    );
                    (T::default(), Mode::Writable, Some(moved))
                }
                Err(err) => {
                    tracing::warn!(file = T::FILE, error = %err, "corrupt document could not be moved aside; read-only");
                    corrupt
                }
            }
        }
    }
}

fn decode<T: Document>(bytes: &[u8]) -> Decoded<T> {
    // Notepad and some editors prepend a UTF-8 BOM, which the JSON parser rejects.
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let mut map = match serde_json::from_slice::<Map<String, Value>>(bytes) {
        Ok(map) => map,
        Err(e) => return Decoded::Corrupt(e),
    };
    // A missing or non-integer version is read as the current one: we always write it, so its absence
    // means a hand-made file, which is better loaded than discarded.
    let version = map.remove(SCHEMA_KEY).and_then(|v| v.as_u64());
    let parsed = serde_json::from_value::<T>(Value::Object(map));
    match version {
        Some(v) if v > u64::from(T::VERSION) => {
            Decoded::Newer(u32::try_from(v).unwrap_or(u32::MAX), parsed.ok())
        }
        _ => match parsed {
            Ok(doc) => Decoded::Current(doc),
            Err(e) => Decoded::Corrupt(e),
        },
    }
}

/// Serialises a document with `"schemaVersion"` first, pretty-printed with two spaces.
fn encode<T: Document>(doc: &T) -> AppResult<Vec<u8>> {
    let failed = |e: serde_json::Error| {
        // In practice the only way to get here is a DPAPI refusal while sealing a secret.
        AppError::msg(
            ErrorKind::Internal,
            Msg::new("core.store.encodeFailed").arg("file", T::FILE),
        )
        .with_source(e)
    };
    let Value::Object(body) = serde_json::to_value(doc).map_err(failed)? else {
        return Err(AppError::internal(anyhow::anyhow!(
            "document {} does not serialise to a JSON object",
            T::FILE
        )));
    };
    let mut out = Map::with_capacity(body.len() + 1);
    out.insert(SCHEMA_KEY.to_owned(), T::VERSION.into());
    out.extend(body.into_iter().filter(|(k, _)| k != SCHEMA_KEY));
    let mut bytes = serde_json::to_vec_pretty(&Value::Object(out)).map_err(failed)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Writes `bytes` to `path` so that a reader sees either the old or the new file, never a torn one:
/// temp file `<name>.<rand>.tmp` in the same directory (create-new, write, flush to disk), then
/// `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`. The rename is retried while another process holds
/// the target; the temp file is removed on failure. Creates the parent directory if needed.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "target has no file name");
    let dir = path.parent().ok_or_else(invalid)?;
    let name = path.file_name().ok_or_else(invalid)?.to_string_lossy();
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("{name}.{:016x}.tmp", fastrand::u64(..)));
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        with_retry(|| move_file(&tmp, path, true))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Removes the `<name>.<16 hex>.tmp` siblings of `path` (the temp names of [`write_atomic`]) and
/// returns how many went. Safe only at [`Store::open`]: the data-dir lock keeps other instances out
/// and no write of this document has started yet, so every match is the leftover of a crash.
fn sweep_temp_files(path: &Path) -> usize {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return 0;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let prefix = format!("{}.", name.to_string_lossy());
    let is_temp = |file: &str| {
        file.strip_prefix(prefix.as_str())
            .and_then(|rest| rest.strip_suffix(".tmp"))
            .is_some_and(|hex| hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    entries
        .flatten()
        .filter(|entry| entry.file_name().to_str().is_some_and(is_temp))
        .filter(|entry| std::fs::remove_file(entry.path()).is_ok())
        .count()
}

/// Moves a corrupt file to `<stem>.corrupt-<unix ms>.json` next to it and returns the new path.
fn set_aside_file(path: &Path) -> io::Result<PathBuf> {
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let mut stamp = now_ms();
    loop {
        let target = path.with_file_name(format!("{stem}.corrupt-{stamp}.json"));
        match with_retry(|| move_file(path, &target, false)) {
            Ok(()) => return Ok(target),
            // Two corruptions within one millisecond: never overwrite an earlier backup.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => stamp += 1,
            Err(e) => return Err(e),
        }
    }
}

fn move_file(from: &Path, to: &Path, replace: bool) -> io::Result<()> {
    let flags = if replace {
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
    } else {
        MOVEFILE_WRITE_THROUGH
    };
    let (from, to) = (HSTRING::from(from), HSTRING::from(to));
    // SAFETY: both arguments are NUL-terminated UTF-16 strings that outlive the call.
    unsafe { MoveFileExW(&from, &to, flags) }.map_err(|e| {
        // A Win32 error wrapped as HRESULT 0x8007xxxx: unwrap it so `io::ErrorKind` is meaningful.
        let code = e.code().0 as u32;
        if code & 0xFFFF_0000 == 0x8007_0000 {
            io::Error::from_raw_os_error((code & 0xFFFF) as i32)
        } else {
            io::Error::other(e)
        }
    })
}

/// Retries `op` while it fails with a sharing violation or access denied (transient holders).
fn with_retry<R>(mut op: impl FnMut() -> io::Result<R>) -> io::Result<R> {
    let transient = |e: &io::Error| {
        e.raw_os_error().is_some_and(|c| {
            c == ERROR_SHARING_VIOLATION.0 as i32 || c == ERROR_ACCESS_DENIED.0 as i32
        })
    };
    let mut delays = RETRY_DELAYS_MS.iter();
    loop {
        match op() {
            Err(e) if transient(&e) => match delays.next() {
                Some(ms) => std::thread::sleep(Duration::from_millis(*ms)),
                None => return Err(e),
            },
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests;
