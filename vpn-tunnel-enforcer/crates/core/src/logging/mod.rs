//! Application and engine logs (storage spec §6.5): `tracing` events as redacted JSON lines in
//! `logs\app.log` (5 MiB + `app.1.log`), engine output in `logs\<engine>.log` (10 MiB + `.1.log`).
//!
//! No per-call logging and no integrity machinery (B5, B25): log state changes, operations and
//! errors. Every message and string field is redacted before it reaches the file or the console.
//! Rules for callers: keep the default target (events whose target does not start with `vpnte`
//! count as library noise and are kept from warn only); put ids in the `profile`, `group`, `op`,
//! `corr` or `slot` fields, the only strings written verbatim (a UUID in free text is masked).
mod lane;
mod layer;
mod rotate;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing_subscriber::layer::SubscriberExt as _;
use vpnte_base::types::UnixMs;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

pub use rotate::{ENGINE_LOG_MAX_BYTES, ENGINE_TAIL_LINES, RotatingFile};

use lane::Lane;
use layer::{JsonLayer, Shared};

/// Cap of an app log generation.
pub const APP_LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;
/// Default and maximum size of a [`tail`] read.
pub const TAIL_MAX_BYTES: usize = 1024 * 1024;
/// Stem of the app log (`app.log`, `app.1.log`).
pub const APP_STEM: &str = "app";

/// How long `flush`/`clear` wait for the writer thread.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

struct Global {
    shared: Arc<Shared>,
    lane: Arc<Lane>,
}

static GLOBAL: OnceLock<Global> = OnceLock::new();

/// One line of `app.log`: `{"ts","level","target","msg","fields"?,"corr"?}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogLine {
    /// UTC, RFC 3339 with milliseconds (`2026-11-11T08:00:00.000Z`).
    pub ts: String,
    /// `ERROR`, `WARN`, `INFO` or `DEBUG`.
    pub level: String,
    /// Module path of the event (`vpnte_tunnel::runtime`).
    pub target: String,
    /// The redacted message (at most 4000 chars + `...<truncated>`).
    pub msg: String,
    /// The event's fields plus those of its spans: redacted strings, numbers, booleans.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub fields: Map<String, Value>,
    /// Correlation id of the operation (`op_<32 hex>`), from the event or an enclosing span.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corr: Option<String>,
}

/// A recent warning or error, kept in memory for the diagnostics report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// When it was logged.
    pub at: UnixMs,
    /// `WARN` or `ERROR`.
    pub level: tracing::Level,
    /// Module path of the event.
    pub target: String,
    /// The redacted message.
    pub msg: String,
}

/// Keeps the app log running; dropping it writes what is queued and stops the writer thread.
#[must_use = "dropping the guard stops the app log"]
pub struct LogGuard {
    lane: Arc<Lane>,
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        self.lane.stop();
    }
}

/// Installs the global subscriber writing `<dir>\app.log` (info, or debug when `debug`) and a
/// panic hook that logs panics. Fails with `Conflict` when a global subscriber already exists.
pub fn init(dir: &Path, debug: bool) -> AppResult<LogGuard> {
    let sink = RotatingFile::open(dir, APP_STEM, APP_LOG_MAX_BYTES, 0)?;
    let lane = Arc::new(Lane::start(sink)?);
    let shared = Arc::new(Shared::new(debug));
    let layer = JsonLayer::new(
        Arc::clone(&shared),
        Arc::clone(&lane),
        cfg!(all(debug_assertions, not(test))),
    );
    let subscriber = tracing_subscriber::registry().with(layer);
    if let Err(err) = tracing::subscriber::set_global_default(subscriber) {
        lane.stop();
        return Err(AppError::new(ErrorKind::Conflict).with_source(err));
    }
    let _ = GLOBAL.set(Global {
        shared,
        lane: Arc::clone(&lane),
    });
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // The release build has no console: without this a panic leaves no trace at all. Wait
        // for the disk: a panic that cannot unwind (in a Win32 callback, or while unwinding)
        // aborts right after the hook, taking the queue with it.
        tracing::error!(panic = %info, "panic");
        if std::thread::current().name() != Some(lane::THREAD) {
            flush();
        }
        previous(info);
    }));
    Ok(LogGuard { lane })
}

/// Switches debug lines on or off at runtime (`ui.debugLog`).
pub fn set_debug(on: bool) {
    if let Some(global) = GLOBAL.get() {
        global.shared.set_debug(on);
    }
}

/// Waits (up to 2 s) until the lines logged so far are on disk.
pub fn flush() {
    if let Some(global) = GLOBAL.get() {
        global.lane.flush(FLUSH_TIMEOUT);
    }
}

/// The last 200 warnings and errors of this run, oldest first.
pub fn recent_problems() -> Vec<Problem> {
    GLOBAL.get().map(|g| g.shared.recent()).unwrap_or_default()
}

/// A file in the logs directory: `<stem>.log`, or its previous generation `<stem>.1.log`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LogFile {
    /// `app` or an engine stem (`sing-box`, `xray`, …): `[a-z0-9-]+`.
    pub stem: String,
    /// The previous generation (`<stem>.1.log`).
    pub previous: bool,
}

impl LogFile {
    /// The current app log.
    pub fn app() -> Self {
        Self::engine(APP_STEM)
    }

    /// The current log of an engine (any stem).
    pub fn engine(stem: impl Into<String>) -> Self {
        Self {
            stem: stem.into(),
            previous: false,
        }
    }

    /// The previous generation of this log.
    #[must_use]
    pub fn previous(mut self) -> Self {
        self.previous = true;
        self
    }

    /// `<stem>.log` or `<stem>.1.log`.
    pub fn file_name(&self) -> String {
        let generation = if self.previous { ".1" } else { "" };
        format!("{}{generation}.log", self.stem)
    }

    /// Name in a [`ClearReport`]: `app-log`, `app-previous-log`, `sing-box-log`, …
    pub fn artifact(&self) -> String {
        let generation = if self.previous { "-previous" } else { "" };
        format!("{}{generation}-log", self.stem)
    }

    /// Display name for the log viewer.
    pub fn label(&self) -> Msg {
        match (self.stem == APP_STEM, self.previous) {
            (true, false) => Msg::new("core.log.file.app"),
            (true, true) => Msg::new("core.log.file.appPrevious"),
            (false, false) => Msg::new("core.log.file.engine").arg("engine", &self.stem),
            (false, true) => Msg::new("core.log.file.enginePrevious").arg("engine", &self.stem),
        }
    }

    fn parse(file_name: &str) -> Option<Self> {
        let stem = file_name.strip_suffix(".log")?;
        let (stem, previous) = match stem.strip_suffix(".1") {
            Some(stem) => (stem, true),
            None => (stem, false),
        };
        rotate::valid_stem(stem).then(|| Self {
            stem: stem.to_owned(),
            previous,
        })
    }
}

/// The end of a log file for the viewer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSnapshot {
    /// File name (`app.log`, `sing-box.1.log`, …).
    pub name: String,
    /// `false` when the file does not exist (then everything else is empty).
    pub exists: bool,
    /// Size of the whole file in bytes.
    pub size: u64,
    /// The file is longer than what `content` holds.
    pub truncated: bool,
    /// Whole lines, already redacted when written.
    pub content: String,
}

/// Result of [`clear`]: artifact names (see [`LogFile::artifact`]) per outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClearReport {
    /// Truncated (current) or deleted (previous).
    pub cleared: Vec<String>,
    /// Did not exist.
    pub absent: Vec<String>,
    /// Could not be cleared, with the category of the I/O failure.
    pub errors: Vec<(String, ErrorKind)>,
}

/// Log files present in `dir`: the app log first, then engines by name; current before previous.
pub fn list(dir: &Path) -> io::Result<Vec<LogFile>> {
    let mut files: Vec<LogFile> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|entry| LogFile::parse(entry.file_name().to_str()?))
        .collect();
    files.sort_by_key(|f| (f.stem != APP_STEM, f.stem.clone(), f.previous));
    Ok(files)
}

/// The last `max_bytes` (at most [`TAIL_MAX_BYTES`]) of a log file, starting at a whole line.
pub fn tail(dir: &Path, file: &LogFile, max_bytes: usize) -> io::Result<LogSnapshot> {
    if !rotate::valid_stem(&file.stem) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad log stem"));
    }
    if file.stem == APP_STEM {
        flush();
    }
    let name = file.file_name();
    let mut handle = match File::open(dir.join(&name)) {
        Ok(handle) => handle,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(LogSnapshot {
                name,
                exists: false,
                size: 0,
                truncated: false,
                content: String::new(),
            });
        }
        Err(err) => return Err(err),
    };
    let size = handle.metadata()?.len();
    let limit = max_bytes.min(TAIL_MAX_BYTES) as u64;
    let start = size.saturating_sub(limit);
    handle.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    handle.take(limit).read_to_end(&mut bytes)?;
    if start > 0 {
        // The read began inside a line: drop that partial first line.
        let cut = bytes
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |p| p + 1);
        bytes.drain(..cut);
    }
    Ok(LogSnapshot {
        name,
        exists: true,
        size,
        truncated: start > 0,
        content: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

/// Clears the logs in `dir` once the queued app log lines are written: every current log is
/// truncated in place (through its live writer, if any), every previous generation deleted.
/// The outcome is logged after clearing, so the cleanup cannot erase its own evidence (§3.13).
pub fn clear(dir: &Path) -> ClearReport {
    flush();
    let mut stems = BTreeSet::new();
    stems.extend(list(dir).unwrap_or_default().into_iter().map(|f| f.stem));
    stems.extend(rotate::writer_stems(dir));
    stems.remove(APP_STEM);
    let mut report = ClearReport::default();
    for stem in std::iter::once(APP_STEM).chain(stems.iter().map(String::as_str)) {
        let (current, previous) = match rotate::writer(dir, stem) {
            Some(writer) => writer.clear(),
            None => (
                rotate::truncate(&dir.join(format!("{stem}.log"))),
                rotate::remove(&dir.join(format!("{stem}.1.log"))),
            ),
        };
        report.record(LogFile::engine(stem).artifact(), current);
        report.record(LogFile::engine(stem).previous().artifact(), previous);
    }
    if report.errors.is_empty() {
        tracing::info!(cleared = report.cleared.len(), "logs cleared");
    } else {
        let failed: Vec<&str> = report.errors.iter().map(|(a, _)| a.as_str()).collect();
        tracing::warn!(cleared = report.cleared.len(), failed = ?failed, "logs cleared with errors");
    }
    report
}

impl ClearReport {
    fn record(&mut self, artifact: String, outcome: io::Result<bool>) {
        match outcome {
            Ok(true) => self.cleared.push(artifact),
            Ok(false) => self.absent.push(artifact),
            Err(err) => self.errors.push((artifact, AppError::from(err).kind)),
        }
    }
}
