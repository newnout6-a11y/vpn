//! NDJSON row writer: one thread, buffered, flushed every 250 ms, rotated at 64 MiB so a long
//! session keeps its tail (the old hard cap of 250 000 rows silenced the rest of the session).
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::digest::LiveDigest;

/// Rows of the current file.
pub const EVENTS_FILE: &str = "events.ndjson";
/// The previous file after a rotation (replaced on the next one).
pub const EVENTS_PREV_FILE: &str = "events.prev.ndjson";
/// Rotation threshold.
pub const ROTATE_BYTES: u64 = 64 * 1024 * 1024;
/// Rows queued between the ETW thread and the writer.
pub const QUEUE_ROWS: usize = 65_536;
/// `sidecar` value of every row (old rows carry `vpnte-etw-sidecar.exe`).
pub const SIDECAR: &str = "vpnte";
/// Interval of the heartbeat health row.
pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(30);
const FLUSH_EVERY: Duration = Duration::from_millis(250);
const BUFFER_BYTES: usize = 256 * 1024;

/// Builds the heartbeat row on the writer thread.
pub type Heartbeat = Box<dyn FnMut() -> Map<String, Value> + Send>;

/// What the writer did, returned when it finishes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriterStats {
    pub rows_written: u64,
    pub bytes_written: u64,
    pub write_errors: u64,
    pub rotations: u32,
    /// Bytes moved to [`EVENTS_PREV_FILE`] by rotations.
    pub rotated_bytes: u64,
}

enum Cmd {
    Row(Map<String, Value>),
    Stop,
}

/// Cloneable handle the ETW callback uses; never blocks.
#[derive(Clone)]
pub struct RowSender {
    tx: SyncSender<Cmd>,
    digest: Arc<LiveDigest>,
}

impl RowSender {
    /// Counts the row in the digest and queues it; a full queue drops it (counted).
    pub fn send(&self, row: Map<String, Value>) {
        self.digest.observe(&row);
        if self.tx.try_send(Cmd::Row(row)).is_err() {
            self.digest.note_backpressure();
        }
    }
}

/// The writer thread and its queue.
pub struct RowWriter {
    sender: RowSender,
    thread: JoinHandle<WriterStats>,
}

impl RowWriter {
    /// Opens `<dir>\events.ndjson` (append) and starts the writer thread; `heartbeat` builds the
    /// health row written every [`HEARTBEAT_EVERY`].
    pub fn spawn(
        dir: &Path,
        session: &str,
        digest: Arc<LiveDigest>,
        rotate_at: u64,
        mut heartbeat: Option<Heartbeat>,
    ) -> io::Result<Self> {
        let path = dir.join(EVENTS_FILE);
        let file = open_append(&path)?;
        let size = file.metadata()?.len();
        let (tx, rx) = mpsc::sync_channel(QUEUE_ROWS);
        let mut sink = Sink {
            path,
            prev: dir.join(EVENTS_PREV_FILE),
            out: Some(BufWriter::with_capacity(BUFFER_BYTES, file)),
            size,
            rotate_at,
            session: session.to_string(),
            digest: digest.clone(),
            stats: WriterStats::default(),
            unreported_errors: 0,
        };
        let thread = std::thread::Builder::new()
            .name("vpnte-etw-writer".into())
            .spawn(move || {
                let mut last_flush = Instant::now();
                let mut last_heartbeat = Instant::now();
                loop {
                    match rx.recv_timeout(FLUSH_EVERY) {
                        Ok(Cmd::Row(row)) => sink.write(row),
                        Ok(Cmd::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => {}
                    }
                    if let Some(build) = heartbeat.as_mut()
                        && last_heartbeat.elapsed() >= HEARTBEAT_EVERY
                    {
                        let row = build();
                        sink.digest.observe(&row);
                        sink.write(row);
                        last_heartbeat = Instant::now();
                    }
                    if last_flush.elapsed() >= FLUSH_EVERY {
                        sink.flush();
                        last_flush = Instant::now();
                    }
                }
                sink.flush();
                sink.stats
            })?;
        Ok(Self {
            sender: RowSender { tx, digest },
            thread,
        })
    }

    /// A handle for the ETW callback.
    pub fn sender(&self) -> RowSender {
        self.sender.clone()
    }

    /// Queues `last` (waits for room), stops the thread after it and returns the totals.
    pub fn finish(self, last: Option<Map<String, Value>>) -> WriterStats {
        if let Some(row) = last {
            self.sender.digest.observe(&row);
            let _ = self.sender.tx.send(Cmd::Row(row));
        }
        let _ = self.sender.tx.send(Cmd::Stop);
        self.thread.join().unwrap_or_default()
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// RFC 3339 UTC with milliseconds (`2026-06-19T00:00:00.000Z`); the epoch for out-of-range input.
pub fn rfc3339_ms(ms: i64) -> String {
    let ts = jiff::Timestamp::from_millisecond(ms).unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    format!("{ts:.3}")
}

struct Sink {
    path: PathBuf,
    prev: PathBuf,
    /// `None` after a failed reopen; retried on the next row.
    out: Option<BufWriter<File>>,
    size: u64,
    rotate_at: u64,
    session: String,
    digest: Arc<LiveDigest>,
    stats: WriterStats,
    /// Failures not yet reported by a health row.
    unreported_errors: u64,
}

impl Sink {
    fn write(&mut self, mut row: Map<String, Value>) {
        row.insert("session".into(), self.session.clone().into());
        row.insert("sidecar".into(), SIDECAR.into());
        if !row.contains_key("ts") {
            row.insert("ts".into(), rfc3339_ms(vpnte_base::types::now_ms()).into());
        }
        let Ok(mut line) = serde_json::to_vec(&Value::Object(row)) else {
            self.failed();
            return;
        };
        line.push(b'\n');
        if !self.write_line(&line) {
            self.failed();
            return;
        }
        if self.unreported_errors > 0 {
            let mut health = Map::new();
            health.insert("provider".into(), "sidecar".into());
            health.insert("category".into(), "health".into());
            health.insert("event".into(), "write-errors".into());
            health.insert("writeErrors".into(), self.unreported_errors.into());
            self.unreported_errors = 0;
            self.digest.observe(&health);
            self.write(health);
        }
        if self.size >= self.rotate_at {
            self.rotate();
        }
    }

    fn write_line(&mut self, line: &[u8]) -> bool {
        if self.out.is_none() {
            self.out = open_append(&self.path)
                .ok()
                .map(|f| BufWriter::with_capacity(BUFFER_BYTES, f));
        }
        let Some(out) = self.out.as_mut() else {
            return false;
        };
        if out.write_all(line).is_err() {
            return false;
        }
        let len = line.len() as u64;
        self.size += len;
        self.stats.rows_written += 1;
        self.stats.bytes_written += len;
        true
    }

    fn failed(&mut self) {
        self.stats.write_errors += 1;
        self.unreported_errors += 1;
        self.digest.note_write_error();
    }

    fn flush(&mut self) {
        if let Some(out) = self.out.as_mut()
            && let Err(e) = out.flush()
        {
            tracing::warn!("etw events flush failed: {e}");
        }
    }

    /// Closes the file, moves it to the `.prev` name (replacing the older one) and reopens.
    /// A failed rename keeps appending to the current file: rows are never thrown away.
    fn rotate(&mut self) {
        self.flush();
        self.out = None;
        match std::fs::rename(&self.path, &self.prev) {
            Ok(()) => {
                self.stats.rotations += 1;
                self.stats.rotated_bytes += self.size;
                self.size = 0;
            }
            Err(e) => {
                tracing::warn!("etw events rotation failed: {e}");
                self.rotate_at = self.rotate_at.saturating_mul(2);
            }
        }
        self.out = open_append(&self.path)
            .ok()
            .map(|f| BufWriter::with_capacity(BUFFER_BYTES, f));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use serde_json::json;

    fn lines(path: &Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// Rows are stamped (session, sidecar, ts), the last row lands after all queued rows.
    #[test]
    fn stamps_rows_and_writes_the_last_row_last() {
        let dir = TempDir::new("writer-stamp");
        let digest = Arc::new(LiveDigest::default());
        let w = RowWriter::spawn(dir.path(), "s-1", digest.clone(), ROTATE_BYTES, None).unwrap();
        let tx = w.sender();
        let mut row = Map::new();
        row.insert("category".into(), "tcp".into());
        row.insert("ts".into(), "2026-06-19T00:00:00.000Z".into());
        tx.send(row);
        let last = json!({"provider":"sidecar","category":"lifecycle","event":"stopped"});
        let stats = w.finish(last.as_object().cloned());
        assert_eq!(stats.rows_written, 2);
        assert_eq!(stats.write_errors, 0);
        let rows = lines(&dir.path().join(EVENTS_FILE));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["session"], "s-1");
        assert_eq!(rows[0]["sidecar"], SIDECAR);
        assert_eq!(rows[0]["ts"], "2026-06-19T00:00:00.000Z");
        assert_eq!(rows[1]["event"], "stopped");
        assert!(rows[1]["ts"].as_str().unwrap().ends_with('Z'));
        assert_eq!(digest.snapshot().events, 2);
        assert_eq!(digest.snapshot().data_events, 1);
    }

    /// Rotation moves the full file to `.prev` and keeps writing (tail kept, D-09).
    #[test]
    fn rotates_and_keeps_the_tail() {
        let dir = TempDir::new("writer-rotate");
        let digest = Arc::new(LiveDigest::default());
        let w = RowWriter::spawn(dir.path(), "s-2", digest, 400, None).unwrap();
        let tx = w.sender();
        for i in 0..20 {
            let mut row = Map::new();
            row.insert("category".into(), "dns".into());
            row.insert("n".into(), i.into());
            tx.send(row);
        }
        let stats = w.finish(None);
        assert!(stats.rotations >= 1, "{stats:?}");
        assert_eq!(stats.rows_written, 20);
        let prev = lines(&dir.path().join(EVENTS_PREV_FILE));
        let cur = lines(&dir.path().join(EVENTS_FILE));
        assert!(!prev.is_empty());
        // The newest row survives: last of the current file, or of `.prev` when the final write
        // itself triggered a rotation.
        let newest = cur.last().or(prev.last()).unwrap();
        assert_eq!(newest["n"], 19);
        assert!(
            prev.iter()
                .chain(&cur)
                .all(|r| r["n"].as_u64().unwrap() >= prev[0]["n"].as_u64().unwrap())
        );
        let on_disk = std::fs::metadata(dir.path().join(EVENTS_FILE))
            .unwrap()
            .len()
            + std::fs::metadata(dir.path().join(EVENTS_PREV_FILE))
                .unwrap()
                .len();
        assert!(on_disk <= stats.bytes_written);
    }

    #[test]
    fn formats_timestamps_with_milliseconds() {
        assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_ms(1_781_827_200_123), "2026-06-19T00:00:00.123Z");
    }
}
