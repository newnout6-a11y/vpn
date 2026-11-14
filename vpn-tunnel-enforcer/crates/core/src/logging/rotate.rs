//! Size-capped log file with one previous generation (`<stem>.log` → `<stem>.1.log`) and an
//! optional in-memory tail of the last lines.
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Weak};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::redact;

/// Cap of an engine log generation.
pub const ENGINE_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Engine output lines kept in memory as outcome evidence (`singboxStderrTail`).
pub const ENGINE_TAIL_LINES: usize = 64;
/// How often a writer checks that its file was not deleted underneath it.
const EXISTS_CHECK: Duration = Duration::from_secs(1);

/// Every open writer, so `clear` can go through the owner of a file instead of racing it.
static OPEN: LazyLock<Mutex<Vec<Weak<Mutex<Inner>>>>> = LazyLock::new(Mutex::default);

/// A log file the app writes itself: engine output from pipes, and the app log behind the lane.
///
/// Clones share one file; opening the same stem twice in a directory returns the live writer,
/// which reopens the file on its next write (the engine moves the last session's log away first).
#[derive(Clone)]
pub struct RotatingFile {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    path: PathBuf,
    prev: PathBuf,
    max: u64,
    file: Option<File>,
    size: u64,
    /// Last check that the file still exists.
    checked: Instant,
    tail: VecDeque<String>,
    tail_cap: usize,
}

impl RotatingFile {
    /// Opens (creating the directory) `<dir>/<stem>.log`, capped at `max_bytes`, keeping the last
    /// `tail_lines` lines in memory. `stem` is `[a-z0-9-]+`.
    pub fn open(dir: &Path, stem: &str, max_bytes: u64, tail_lines: usize) -> io::Result<Self> {
        if !valid_stem(stem) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad log stem"));
        }
        let (path, prev) = paths(dir, stem)?;
        let mut open = OPEN.lock();
        open.retain(|w| w.strong_count() > 0);
        if let Some(inner) = open
            .iter()
            .filter_map(Weak::upgrade)
            .find(|i| i.lock().path == path)
        {
            inner.lock().file = None;
            return Ok(Self { inner });
        }
        let mut inner = Inner {
            path,
            prev,
            max: max_bytes,
            file: None,
            size: 0,
            checked: Instant::now(),
            tail: VecDeque::with_capacity(tail_lines),
            tail_cap: tail_lines,
        };
        inner.file()?;
        let inner = Arc::new(Mutex::new(inner));
        open.push(Arc::downgrade(&inner));
        Ok(Self { inner })
    }

    /// Engine log: 10 MiB per generation, last 64 lines in memory.
    pub fn engine(dir: &Path, stem: &str) -> io::Result<Self> {
        Self::open(dir, stem, ENGINE_LOG_MAX_BYTES, ENGINE_TAIL_LINES)
    }

    /// Appends one line after [`redact::for_log`]. The tail keeps the line even when the disk
    /// write fails; a failed write loses only this line (the file is reopened on the next one).
    pub fn write_line(&self, line: &str) -> io::Result<()> {
        let clean = redact::for_log(line.trim_end_matches(['\r', '\n']));
        let mut bytes = Vec::with_capacity(clean.len() + 1);
        bytes.extend_from_slice(clean.as_bytes());
        bytes.push(b'\n');
        let mut inner = self.inner.lock();
        if inner.tail_cap > 0 {
            if inner.tail.len() == inner.tail_cap {
                inner.tail.pop_front();
            }
            inner.tail.push_back(clean.into_owned());
        }
        inner.append(&bytes)
    }

    /// The last lines written (already redacted), oldest first.
    pub fn tail(&self) -> Vec<String> {
        self.inner.lock().tail.iter().cloned().collect()
    }

    /// Path of the current generation.
    pub fn path(&self) -> PathBuf {
        self.inner.lock().path.clone()
    }

    /// Appends pre-formatted, already redacted bytes (the app log lane).
    pub(super) fn append_raw(&self, bytes: &[u8]) -> io::Result<()> {
        self.inner.lock().append(bytes)
    }

    /// Truncates the current generation and deletes the previous one; `Ok(false)` = absent.
    pub(super) fn clear(&self) -> (io::Result<bool>, io::Result<bool>) {
        let mut inner = self.inner.lock();
        inner.file = None;
        inner.size = 0;
        (truncate(&inner.path), remove(&inner.prev))
    }
}

impl Inner {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        let incoming = bytes.len() as u64;
        if self.size > 0 && self.size + incoming > self.max {
            self.rotate();
        }
        // An open handle keeps writing into a file whose directory was deleted (the user cleaned
        // up the logs folder): notice it within a second and reopen, recreating the directory.
        if self.file.is_some() && self.checked.elapsed() >= EXISTS_CHECK {
            self.checked = Instant::now();
            if !self.path.exists() {
                self.file = None;
            }
        }
        let file = self.file()?;
        match file.write_all(bytes) {
            Ok(()) => {
                self.size += incoming;
                Ok(())
            }
            Err(err) => {
                self.file = None;
                Err(err)
            }
        }
    }

    fn rotate(&mut self) {
        // Our own handle must be closed for the rename; `fs::rename` replaces the old `.1.log`.
        self.file = None;
        match fs::rename(&self.path, &self.prev) {
            Ok(()) => self.size = 0,
            // Locked by AV or an editor, or something else sits at the target: keep the measured
            // size so the next write retries the rotation (§3.13).
            Err(_) => self.size = fs::metadata(&self.path).map_or(self.size, |m| m.len()),
        }
    }

    fn file(&mut self) -> io::Result<&mut File> {
        if self.file.is_none() {
            let mut file = match open_append(&self.path) {
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    // The logs directory was deleted while running: recreate it (§3.13).
                    if let Some(dir) = self.path.parent() {
                        fs::create_dir_all(dir)?;
                    }
                    open_append(&self.path)?
                }
                other => other?,
            };
            let mut size = file.metadata()?.len();
            // A record cut short by a crash must not merge with the next one (§3.13).
            if size > 0 && !ends_with_newline(&self.path)? {
                file.write_all(b"\n")?;
                size += 1;
            }
            self.size = size;
            self.file = Some(file);
        }
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("log file not open"))
    }
}

/// `<dir>/<stem>.log` and `<dir>/<stem>.1.log`, with the directory created and canonicalized so
/// writers and `clear` agree on one spelling of a path.
fn paths(dir: &Path, stem: &str) -> io::Result<(PathBuf, PathBuf)> {
    fs::create_dir_all(dir)?;
    let dir = fs::canonicalize(dir)?;
    Ok((
        dir.join(format!("{stem}.log")),
        dir.join(format!("{stem}.1.log")),
    ))
}

/// The live writer of `<dir>/<stem>.log`, if any.
pub(super) fn writer(dir: &Path, stem: &str) -> Option<RotatingFile> {
    let path = fs::canonicalize(dir).ok()?.join(format!("{stem}.log"));
    let open = OPEN.lock();
    open.iter()
        .filter_map(Weak::upgrade)
        .find(|i| i.lock().path == path)
        .map(|inner| RotatingFile { inner })
}

/// Stems of the live writers in `dir`.
pub(super) fn writer_stems(dir: &Path) -> Vec<String> {
    let Ok(dir) = fs::canonicalize(dir) else {
        return Vec::new();
    };
    let open = OPEN.lock();
    open.iter()
        .filter_map(Weak::upgrade)
        .filter_map(|i| {
            let inner = i.lock();
            let name = inner.path.file_name()?.to_str()?;
            (inner.path.parent() == Some(dir.as_path()))
                .then(|| name.trim_end_matches(".log").to_owned())
        })
        .collect()
}

/// `[a-z0-9-]+`, at most 32 chars: a file stem that cannot escape the logs directory.
pub(super) fn valid_stem(stem: &str) -> bool {
    !stem.is_empty()
        && stem.len() <= 32
        && stem
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn open_append(path: &Path) -> io::Result<File> {
    // std opens with FILE_SHARE_READ | WRITE | DELETE, so readers never block our rename.
    OpenOptions::new().create(true).append(true).open(path)
}

fn ends_with_newline(path: &Path) -> io::Result<bool> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    Ok(last[0] == b'\n')
}

/// Truncates an existing file in place; `Ok(false)` when it does not exist.
pub(super) fn truncate(path: &Path) -> io::Result<bool> {
    match OpenOptions::new().write(true).truncate(true).open(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// Deletes a file; `Ok(false)` when it does not exist.
pub(super) fn remove(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}
