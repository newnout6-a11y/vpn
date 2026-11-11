//! In-process ETW consumer: the old `vpnte-etw-sidecar` folded in as a library module.
//!
//! One real-time session `VPNTE-ETW` with TCPIP, DNS-Client, WFP, Winsock-AFD and WebIO; one row per
//! significant event appended to `<session dir>\events.ndjson` (row schema of the old sidecar), a
//! live in-memory digest for the status, and a graceful stop that writes the final row after the
//! trace stopped (the old sidecar was killed with TerminateProcess, B-01). Starting needs
//! elevation (or membership in "Performance Log Users").
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub mod classify;
pub mod digest;
mod fields;
pub mod session;
pub mod writer;

pub use digest::{Counted, DigestSnapshot, LiveDigest};
pub use session::{LossStats, PROVIDERS, SESSION_NAME, reclaim_orphan};
pub use writer::{EVENTS_FILE, EVENTS_PREV_FILE, WriterStats};

use writer::{RowSender, RowWriter};

/// `engine` of our lifecycle rows (old rows: `ferrisetw-realtime`, `powershell-poller`).
pub const ENGINE: &str = "etw-inproc";
/// Upper bound of [`EtwConsumer::stop`] waiting for the processing thread.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Why the consumer did not start.
#[derive(Debug, thiserror::Error)]
pub enum EtwError {
    #[error("cannot open the events file: {0}")]
    Io(#[from] io::Error),
    #[error("failed to start ETW trace: {0}")]
    Start(String),
}

/// Totals reported when the consumer stops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EtwStopStats {
    pub writer: WriterStats,
    pub digest: DigestSnapshot,
    /// Loss counters queried just before the stop; `None` when the query failed.
    pub loss: Option<LossStats>,
    /// `false` when the processing thread did not end in time and the session was stopped by name.
    pub clean: bool,
}

/// A running consumer.
pub struct EtwConsumer {
    running: session::Running,
    writer: RowWriter,
    digest: Arc<LiveDigest>,
}

impl EtwConsumer {
    /// Reclaims an orphaned session, opens the writer and starts the trace. Blocking (ETW API
    /// calls): run it on a blocking thread.
    pub fn start(dir: &Path, session_id: &str) -> Result<Self, EtwError> {
        let reclaimed = session::reclaim_orphan();
        if reclaimed {
            tracing::warn!("reclaimed orphaned ETW session {SESSION_NAME}");
        }
        let digest = Arc::new(LiveDigest::default());
        let writer = RowWriter::spawn(
            dir,
            session_id,
            digest.clone(),
            writer::ROTATE_BYTES,
            Some(heartbeat(digest.clone())),
        )?;
        let tx = writer.sender();
        let mut started = sidecar_row("lifecycle", "started");
        started.insert("engine".into(), ENGINE.into());
        started.insert("providers".into(), providers_csv().into());
        started.insert(
            "eventsPath".into(),
            dir.join(EVENTS_FILE).display().to_string().into(),
        );
        tx.send(started);
        if reclaimed {
            send_health(&tx, "orphan-reclaimed");
        }
        match session::start(&tx, &digest) {
            Ok(running) => Ok(Self {
                running,
                writer,
                digest,
            }),
            Err(e) => {
                let mut stopped = sidecar_row("lifecycle", "stopped");
                stopped.insert(
                    "reason".into(),
                    format!("failed to start ETW trace: {e}").into(),
                );
                writer.finish(Some(stopped));
                Err(EtwError::Start(e))
            }
        }
    }

    /// The live digest (shared; keeps counting until [`stop`](Self::stop)).
    pub fn digest(&self) -> Arc<LiveDigest> {
        self.digest.clone()
    }

    /// `false` once `ProcessTrace` returned on its own (session stopped from outside or failed).
    pub fn is_running(&self) -> bool {
        self.running.is_processing()
    }

    /// Queries the loss counters, stops the trace, writes the final `stopped` row (after the trace
    /// stopped) and joins the writer. Blocking, about [`STOP_TIMEOUT`] at most plus the flush.
    pub fn stop(self, reason: &str) -> EtwStopStats {
        let loss = session::query_loss();
        let clean = self.running.stop(STOP_TIMEOUT);
        let mut stopped = sidecar_row("lifecycle", "stopped");
        stopped.insert("reason".into(), reason.into());
        add_counters(&mut stopped, &self.digest.snapshot(), loss);
        let writer = self.writer.finish(Some(stopped));
        EtwStopStats {
            writer,
            digest: self.digest.snapshot(),
            loss,
            clean,
        }
    }
}

fn providers_csv() -> String {
    PROVIDERS.map(|(name, _)| name).join(",")
}

fn sidecar_row(category: &str, event: &str) -> Map<String, Value> {
    let mut row = Map::new();
    row.insert("provider".into(), "sidecar".into());
    row.insert("category".into(), category.into());
    row.insert("event".into(), event.into());
    row
}

fn send_health(tx: &RowSender, event: &str) {
    tx.send(sidecar_row("health", event));
}

/// Counters of heartbeat and stop rows. `observedEvents` now counts ETW callbacks (the old
/// sidecar counted written rows under this key).
fn add_counters(row: &mut Map<String, Value>, d: &DigestSnapshot, loss: Option<LossStats>) {
    row.insert("observedEvents".into(), d.observed.into());
    row.insert("dataEvents".into(), d.data_events.into());
    row.insert("filteredNoise".into(), d.filtered.into());
    row.insert("unparsed".into(), d.unparsed.into());
    row.insert("backpressureDropped".into(), d.backpressure_dropped.into());
    row.insert("writeErrors".into(), d.write_errors.into());
    if let Some(loss) = loss {
        row.insert("eventsLost".into(), loss.events_lost.into());
        row.insert("buffersLost".into(), loss.buffers_lost.into());
    }
}

fn heartbeat(digest: Arc<LiveDigest>) -> writer::Heartbeat {
    Box::new(move || {
        let mut row = sidecar_row("health", "heartbeat");
        add_counters(&mut row, &digest.snapshot(), session::query_loss());
        row.insert("enabledProviders".into(), providers_csv().into());
        row
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    fn rows(dir: &Path) -> Vec<Value> {
        std::fs::read_to_string(dir.join(EVENTS_FILE))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// AT-08-003: graceful stop; the final `stopped` row is written after the trace stopped.
    #[test]
    #[ignore = "needs elevation"]
    fn live_consumer_writes_rows_and_stops_gracefully() {
        let dir = TempDir::new("etw-live");
        let consumer = EtwConsumer::start(dir.path(), "live-test").unwrap();
        // Some DNS traffic for the DNS-Client provider.
        let _ = std::net::ToSocketAddrs::to_socket_addrs(&("example.com", 443));
        std::thread::sleep(Duration::from_secs(3));
        assert!(consumer.is_running());
        let stats = consumer.stop("test");
        assert!(stats.clean);
        // ControlTraceW QUERY answered for the live session (F-106 counters present).
        assert!(stats.loss.is_some(), "{stats:?}");
        let rows = rows(dir.path());
        assert_eq!(rows[0]["event"], "started");
        assert_eq!(rows[0]["engine"], ENGINE);
        let last = rows.last().unwrap();
        assert_eq!(last["event"], "stopped");
        assert_eq!(last["reason"], "test");
        assert!(stats.digest.observed > 0, "{stats:?}");
        assert!(!reclaim_orphan(), "the session must be gone after stop");
    }

    /// AT-08-004: a session left behind by a killed consumer is reclaimed (and logged) by name.
    #[test]
    #[ignore = "needs elevation"]
    fn live_orphan_is_reclaimed() {
        let dir = TempDir::new("etw-orphan");
        let digest = Arc::new(LiveDigest::default());
        let w = RowWriter::spawn(
            dir.path(),
            "orphan",
            digest.clone(),
            writer::ROTATE_BYTES,
            None,
        )
        .unwrap();
        let running = session::start(&w.sender(), &digest).unwrap();
        // Simulate a crash: the kernel session outlives its consumer.
        std::mem::forget(running);
        assert!(reclaim_orphan());
        assert!(!reclaim_orphan());
        w.finish(None);
    }
}
