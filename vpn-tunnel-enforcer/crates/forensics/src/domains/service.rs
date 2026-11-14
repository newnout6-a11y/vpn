//! The history as a service: Clash API polling while the engine runs, log-line observation and
//! the delayed writer.
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult};
use vpnte_core::store::Store;

use super::history::History;
use super::{DomainRecord, DomainsDoc, PERSIST_DELAY};
use crate::connections::{ClashEndpoint, ClashPoller, FailureCounter, POLL_INTERVAL, SourceHealth};

/// Called with the host of every newly seen connection (the domain-rule hit counter, F-011).
pub type NewConnectionHook = Arc<dyn Fn(&str) + Send + Sync>;

struct Shared {
    history: Mutex<History>,
    store: Arc<Store<DomainsDoc>>,
    health: watch::Sender<SourceHealth>,
    revision: watch::Sender<u64>,
    /// Bumped by every start / stop of polling: outcomes of an older run never set the health.
    run: AtomicU64,
    dirty: Notify,
    /// Serialises persists so an older document never overwrites a newer one.
    write: tokio::sync::Mutex<()>,
    on_new: Option<NewConnectionHook>,
}

impl Shared {
    fn changed(&self) {
        self.revision.send_modify(|r| *r = r.wrapping_add(1));
        self.dirty.notify_one();
    }

    /// Writes the pending changes, if any; on failure they stay pending.
    async fn persist(self: &Arc<Self>) -> AppResult<()> {
        let _order = self.write.lock().await;
        let Some(doc) = self.history.lock().take_doc() else {
            return Ok(());
        };
        let shared = Arc::clone(self);
        let written = tokio::task::spawn_blocking(move || shared.store.replace(doc))
            .await
            .unwrap_or_else(|err| Err(AppError::internal(err)));
        if written.is_err() {
            self.history.lock().dirty = true;
        }
        written
    }
}

/// Writes a change [`PERSIST_DELAY`] after the first unsaved one, so a busy tunnel costs one
/// write per 10 s and a crash loses at most that much.
async fn write_behind(shared: Arc<Shared>, cancel: CancellationToken) {
    let mut failing = false;
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            () = shared.dirty.notified() => {}
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(PERSIST_DELAY) => {}
        }
        match shared.persist().await {
            Ok(()) => failing = false,
            Err(err) if !failing => {
                tracing::warn!(error = %err, "traffic history not saved");
                failing = true;
            }
            Err(_) => {}
        }
    }
}

/// The history as a service: polls the engine's Clash API while it runs, observes engine log
/// lines, writes changes at most [`PERSIST_DELAY`] after they happen and on [`Self::flush`].
pub struct HistoryService {
    shared: Arc<Shared>,
    poller: Mutex<Option<ClashPoller>>,
    writer: CancellationToken,
}

impl HistoryService {
    /// Loads the stored history and starts the delayed writer (inside a tokio runtime).
    pub fn open(store: Arc<Store<DomainsDoc>>, on_new: Option<NewConnectionHook>) -> Self {
        let shared = Arc::new(Shared {
            history: Mutex::new(History::new(store.snapshot())),
            store,
            health: watch::Sender::new(SourceHealth::Idle),
            revision: watch::Sender::new(0),
            run: AtomicU64::new(0),
            dirty: Notify::new(),
            write: tokio::sync::Mutex::new(()),
            on_new,
        });
        let writer = CancellationToken::new();
        tokio::spawn(write_behind(Arc::clone(&shared), writer.clone()));
        Self {
            shared,
            poller: Mutex::new(None),
            writer,
        }
    }

    /// Replaces the configured server hosts (they and DoH resolvers are never "sites").
    pub fn set_server_hosts<S: AsRef<str>>(&self, hosts: impl IntoIterator<Item = S>) {
        self.shared.history.lock().set_infra(hosts);
        self.shared.revision.send_modify(|r| *r = r.wrapping_add(1));
    }

    /// Starts polling the Clash API of a new engine run (replaces a previous poller).
    pub fn start_polling(&self, endpoint: &ClashEndpoint) -> AppResult<()> {
        // Dropping the previous run's poller stops it, even if the new one cannot start.
        drop(self.poller.lock().take());
        let run = self.shared.run.fetch_add(1, Ordering::SeqCst) + 1;
        self.shared.health.send_replace(SourceHealth::Idle);
        let shared = Arc::clone(&self.shared);
        let mut failures = FailureCounter::default();
        let mut new_hosts = Vec::new();
        let poller = ClashPoller::spawn(endpoint, POLL_INTERVAL, move |outcome| {
            let health = failures.record(outcome.is_ok());
            if let Ok(snapshot) = outcome {
                let changed =
                    shared
                        .history
                        .lock()
                        .merge_snapshot(&snapshot, now_ms(), &mut new_hosts);
                if changed {
                    shared.changed();
                }
                // Outside the lock: the hook is foreign code.
                for host in new_hosts.drain(..) {
                    if let Some(hook) = &shared.on_new {
                        hook(&host);
                    }
                }
            }
            let flipped = health.is_some_and(|health| {
                shared.health.send_if_modified(|h| {
                    let flip = shared.run.load(Ordering::SeqCst) == run && *h != health;
                    if flip {
                        *h = health;
                    }
                    flip
                })
            });
            if flipped && health == Some(SourceHealth::Unavailable) {
                tracing::warn!("traffic history source unavailable: Clash API polls keep failing");
            }
        })?;
        *self.poller.lock() = Some(poller);
        Ok(())
    }

    /// Stops polling (engine stopped) and writes the pending changes.
    pub async fn stop_polling(&self) -> AppResult<()> {
        self.shared.run.fetch_add(1, Ordering::SeqCst);
        drop(self.poller.lock().take());
        self.shared.health.send_replace(SourceHealth::Idle);
        self.flush().await
    }

    /// Feeds one engine stdout / stderr line (the DNS answer observer).
    pub fn observe_log_line(&self, line: &str) {
        if self.shared.history.lock().observe_log_line(line, now_ms()) {
            self.shared.changed();
        }
    }

    /// Records newest first. UI reads are side-effect free: nothing is queued here.
    pub fn list(&self) -> Vec<DomainRecord> {
        self.shared.history.lock().list()
    }

    /// Health of the connections source.
    pub fn health(&self) -> watch::Receiver<SourceHealth> {
        self.shared.health.subscribe()
    }

    /// Revision counter, bumped whenever the list may have changed.
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.shared.revision.subscribe()
    }

    /// Empties the history and saves at once; engine logs are not touched (B-22). The site-name
    /// cache is cleared separately (`Enricher::clear`).
    pub async fn clear(&self) -> AppResult<()> {
        self.shared.history.lock().clear();
        self.shared.changed();
        self.shared.persist().await
    }

    /// Writes pending changes now (engine stop, app exit).
    pub async fn flush(&self) -> AppResult<()> {
        self.shared.persist().await
    }
}

impl Drop for HistoryService {
    fn drop(&mut self) {
        self.writer.cancel();
    }
}
