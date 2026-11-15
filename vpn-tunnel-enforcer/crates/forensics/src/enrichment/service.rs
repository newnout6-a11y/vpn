//! The site-name cache and its bounded lookup queue, driven by the background tick.
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{Semaphore, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult};
use vpnte_core::net::Route;
use vpnte_core::store::Store;

use super::fetch::inspect;
use super::page::sanitize;
use super::{
    DomainEnrichment, EnrichInputs, EnrichStatus, EnrichmentDoc, HistoryEntry, LOOKUP_TIMEOUT,
    MAX_CONCURRENT, MAX_ENTRIES, MAX_PENDING, TICK, registrable,
};
use crate::domains::{DomainRecord, HistoryService};

#[derive(Default)]
pub(super) struct State {
    pub(super) cache: HashMap<String, DomainEnrichment>,
    /// Queued or running keys.
    pub(super) pending: HashSet<String>,
    /// Bumped by every `disable` (setting off, route changed, clear): results of older jobs are
    /// dropped. Kept under the same lock as `pending`, so a job is queued either before a disable
    /// (and aborted by it) or after it, never half-way.
    generation: u64,
    /// Cancels the jobs of the current generation.
    cancel: CancellationToken,
}

pub(super) struct Inner {
    store: Arc<Store<EnrichmentDoc>>,
    pub(super) state: Mutex<State>,
    pub(super) slots: Semaphore,
    revision: watch::Sender<u64>,
    /// Serialises persists so an older document never overwrites a newer one.
    write: tokio::sync::Mutex<()>,
}

impl Inner {
    async fn persist(self: &Arc<Self>) -> AppResult<()> {
        let _order = self.write.lock().await;
        let doc = EnrichmentDoc {
            entries: self
                .state
                .lock()
                .cache
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };
        let inner = Arc::clone(self);
        tokio::task::spawn_blocking(move || inner.store.replace(doc))
            .await
            .unwrap_or_else(|err| Err(AppError::internal(err)))
    }
}

/// The site-name cache and its bounded lookup queue (2 at a time, 8 pending at most).
#[derive(Clone)]
pub struct Enricher {
    pub(super) inner: Arc<Inner>,
}

impl Enricher {
    /// Loads the cache document.
    pub fn open(store: Arc<Store<EnrichmentDoc>>) -> Self {
        let cache = store.snapshot().entries.into_iter().collect();
        Self {
            inner: Arc::new(Inner {
                store,
                state: Mutex::new(State {
                    cache,
                    ..State::default()
                }),
                slots: Semaphore::new(MAX_CONCURRENT),
                revision: watch::Sender::new(0),
                write: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// Site info of `domain`'s registrable domain: `pending` while queued, the cached result
    /// while fresh, else `None`.
    pub fn get(&self, domain: &str) -> Option<DomainEnrichment> {
        let key = registrable(domain)?;
        let now = now_ms();
        let state = self.inner.state.lock();
        if state.pending.contains(&key) {
            return Some(DomainEnrichment::empty(EnrichStatus::Pending, now));
        }
        state.cache.get(&key).filter(|e| e.is_fresh(now)).cloned()
    }

    /// History rows with site info attached only when enrichment is on and a route exists.
    pub fn entries(&self, records: Vec<DomainRecord>, inputs: &EnrichInputs) -> Vec<HistoryEntry> {
        let attach = inputs.enabled && inputs.route.is_some();
        records
            .into_iter()
            .map(|record| HistoryEntry {
                enrichment: attach.then(|| self.get(&record.domain)).flatten(),
                record,
            })
            .collect()
    }

    /// Revision counter, bumped whenever a result arrives or the cache is cleared.
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.inner.revision.subscribe()
    }

    /// Queues lookups for `domains` (newest first) through `route`: registrable keys not
    /// pending and not fresh, up to [`MAX_PENDING`] in total. Must run inside a tokio runtime.
    pub fn queue(&self, domains: &[String], route: &Route) {
        let now = now_ms();
        let (keys, generation, cancel) = {
            let mut state = self.inner.state.lock();
            let room = MAX_PENDING.saturating_sub(state.pending.len());
            let mut keys = Vec::new();
            for key in domains.iter().filter_map(|d| registrable(d)) {
                if keys.len() >= room {
                    break;
                }
                let fresh = state.cache.get(&key).is_some_and(|e| e.is_fresh(now));
                if !fresh && state.pending.insert(key.clone()) {
                    keys.push(key);
                }
            }
            (keys, state.generation, state.cancel.clone())
        };
        if keys.is_empty() {
            return;
        }
        for key in keys {
            let job = lookup_job(
                Arc::clone(&self.inner),
                key,
                route.clone(),
                generation,
                cancel.clone(),
            );
            tokio::spawn(job);
        }
        self.inner.revision.send_modify(|r| *r = r.wrapping_add(1));
    }

    /// Drops the queue and aborts running lookups (setting off, route changed); the cache stays.
    pub fn disable(&self) {
        let mut state = self.inner.state.lock();
        state.generation += 1;
        state.pending.clear();
        std::mem::take(&mut state.cancel).cancel();
    }

    /// Aborts lookups and empties the cache (history «clear»).
    pub async fn clear(&self) -> AppResult<()> {
        self.disable();
        self.inner.state.lock().cache.clear();
        self.inner.revision.send_modify(|r| *r = r.wrapping_add(1));
        self.inner.persist().await
    }

    /// The only trigger of lookups, for the app's lifetime: every [`TICK`], when enabled and a
    /// route exists, queues the history's domains newest first. Switching the setting off or
    /// changing the route aborts queued and running lookups at once: a direct lookup queued
    /// while the tunnel ran must not leave outside it after it stopped. Ends when `cancel` fires.
    pub fn spawn_tick(
        &self,
        history: Arc<HistoryService>,
        mut inputs: watch::Receiver<EnrichInputs>,
        cancel: CancellationToken,
    ) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The egress of the lookups in flight: any other route makes them stale.
            let mut route = None;
            loop {
                let due = tokio::select! {
                    () = cancel.cancelled() => break,
                    changed = inputs.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        false
                    }
                    _ = tick.tick() => true,
                };
                let current = inputs.borrow_and_update().clone();
                if !current.enabled || current.route != route {
                    this.disable();
                    route.clone_from(&current.route);
                }
                if let (true, true, Some(egress)) = (due, current.enabled, &current.route) {
                    let domains: Vec<String> =
                        history.list().into_iter().map(|r| r.domain).collect();
                    this.queue(&domains, egress);
                }
            }
            this.disable();
        });
    }
}

/// One lookup: waits for a slot, runs under the deadline, stores the result unless the
/// generation changed meanwhile.
async fn lookup_job(
    inner: Arc<Inner>,
    key: String,
    route: Route,
    generation: u64,
    cancel: CancellationToken,
) {
    let outcome = tokio::select! {
        // Cancellation first: a job aborted before it ran must not start a lookup.
        biased;
        () = cancel.cancelled() => None,
        outcome = async {
            let _slot = inner.slots.acquire().await.ok()?;
            Some(tokio::time::timeout(LOOKUP_TIMEOUT, inspect(&key, &route)).await)
        } => outcome,
    };
    let now = now_ms();
    let entry = match outcome {
        None => return,
        Some(Ok(Ok((meta, final_url)))) => sanitize(meta, &final_url, now),
        Some(Ok(Err(err))) => {
            tracing::debug!(error = %err, route = ?route, "site info lookup failed");
            DomainEnrichment::empty(EnrichStatus::Unavailable, now)
        }
        Some(Err(_)) => {
            tracing::debug!(route = ?route, "site info lookup timed out");
            DomainEnrichment::empty(EnrichStatus::Unavailable, now)
        }
    };
    {
        let mut state = inner.state.lock();
        if state.generation != generation {
            return;
        }
        state.pending.remove(&key);
        state.cache.insert(key, entry);
        if state.cache.len() > MAX_ENTRIES {
            let mut by_age: Vec<(UnixMs, String)> = state
                .cache
                .iter()
                .map(|(k, e)| (e.fetched_at, k.clone()))
                .collect();
            by_age.sort();
            let excess = state.cache.len() - MAX_ENTRIES;
            for (_, k) in by_age.into_iter().take(excess) {
                state.cache.remove(&k);
            }
        }
    }
    inner.revision.send_modify(|r| *r = r.wrapping_add(1));
    if let Err(err) = inner.persist().await {
        tracing::warn!(error = %err, "site info cache not saved");
    }
}
