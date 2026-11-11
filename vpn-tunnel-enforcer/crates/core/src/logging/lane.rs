//! The append lane of the app log: formatted lines go through a bounded channel to one writer
//! thread, so UI and tunnel threads never wait for the disk.
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::rotate::RotatingFile;

/// Lines that may wait for the disk; beyond that new lines are dropped and counted.
const CAPACITY: usize = 8192;
/// How long `stop` waits for the queue to drain before leaving the thread behind.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
/// Name of the writer thread (the panic hook must not wait for itself).
pub(super) const THREAD: &str = "vpnte-log";

enum Cmd {
    Line(Vec<u8>),
    /// Acknowledged once every earlier line was written.
    Flush(SyncSender<()>),
    /// Acknowledged right before the thread ends.
    Stop(SyncSender<()>),
}

/// Handle of the writer thread. Sending a line never blocks; a full queue drops the line and the
/// next written line is preceded by a record saying how many were lost.
pub(super) struct Lane {
    tx: SyncSender<Cmd>,
    dropped: Arc<AtomicU64>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl Lane {
    pub(super) fn start(sink: RotatingFile) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel(CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let lost = Arc::clone(&dropped);
        let worker = std::thread::Builder::new()
            .name(THREAD.into())
            .spawn(move || run(&rx, &sink, &lost))?;
        Ok(Self {
            tx,
            dropped,
            worker: Mutex::new(Some(worker)),
        })
    }

    pub(super) fn send(&self, line: Vec<u8>) {
        if let Err(TrySendError::Full(_)) = self.tx.try_send(Cmd::Line(line)) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Waits until every line queued before this call is on disk; `false` after `timeout`.
    pub(super) fn flush(&self, timeout: Duration) -> bool {
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        let deadline = Instant::now() + timeout;
        self.send_until(Cmd::Flush(ack_tx), deadline)
            && ack_rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .is_ok()
    }

    /// Writes what is queued and ends the thread; later lines are discarded. A thread stuck on
    /// the disk is left behind after 5 s rather than hanging the app's exit.
    pub(super) fn stop(&self) {
        let Some(worker) = self.worker.lock().take() else {
            return;
        };
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        let deadline = Instant::now() + STOP_TIMEOUT;
        if self.send_until(Cmd::Stop(ack_tx), deadline)
            && ack_rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .is_ok()
        {
            let _ = worker.join();
        }
    }

    /// A control command waits for room in a full queue, but never past `deadline`.
    fn send_until(&self, mut cmd: Cmd, deadline: Instant) -> bool {
        loop {
            match self.tx.try_send(cmd) {
                Ok(()) => return true,
                Err(TrySendError::Full(back)) if Instant::now() < deadline => {
                    cmd = back;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return false,
            }
        }
    }
}

fn run(rx: &Receiver<Cmd>, sink: &RotatingFile, dropped: &AtomicU64) {
    for cmd in rx {
        // Before a flush or stop too: a burst right before exit must not vanish unreported.
        let lost = dropped.swap(0, Ordering::Relaxed);
        if lost > 0 {
            let _ = sink.append_raw(&super::layer::overflow_line(lost));
        }
        match cmd {
            // A failed write loses this line only; the sink reopens the file next time.
            Cmd::Line(line) => {
                let _ = sink.append_raw(&line);
            }
            Cmd::Flush(ack) => {
                let _ = ack.send(());
            }
            Cmd::Stop(ack) => {
                let _ = ack.send(());
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    /// Lines dropped right before a flush or stop are still reported.
    #[test]
    fn overflow_is_reported_without_a_following_line() {
        let tmp = TempDir::new("lane-overflow");
        let sink = RotatingFile::open(tmp.path(), "app", 1024 * 1024, 0).expect("sink");
        let (tx, rx) = mpsc::sync_channel(2);
        let (ack, _ack_rx) = mpsc::sync_channel(2);
        tx.send(Cmd::Flush(ack.clone())).expect("queued");
        tx.send(Cmd::Stop(ack)).expect("queued");
        run(&rx, &sink, &AtomicU64::new(3));
        assert!(tmp.read("app.log").contains(r#""dropped":3"#));
    }
}
