//! The live-check history (`history/live-checks.json`, storage spec §6.1): rows per target, newest
//! first, ≤ 20 per target and ≤ 500 / 180 days in all (B-22), sanitised before they are stored,
//! persisted through `vpnte_core::store` (atomic write; a corrupt file is moved aside and the
//! history starts empty, B-20; a newer version's file is read-only). Rows that do not decode are
//! dropped one by one, never the whole file.
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::store::{Document, Store};

use super::HISTORY_PER_TARGET;
use super::diff::is_baseline;
use super::model::LiveCheck;
use super::sanitize::sanitize;
use crate::live_stages::icmp::sanitize_hop_line;

/// Rows kept in all.
pub(crate) const MAX_ROWS: usize = 500;
/// Rows older than this are dropped.
pub(crate) const MAX_AGE_MS: UnixMs = 180 * 24 * 3600 * 1000;

/// The document: target key → rows, newest first.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LiveHistory {
    #[serde(default, deserialize_with = "lenient_targets")]
    pub targets: BTreeMap<String, Vec<LiveCheck>>,
}

impl Document for LiveHistory {
    const FILE: &'static str = "history/live-checks.json";
    const VERSION: u32 = 1;
}

/// `profile:<id>` when the check is for a saved profile, else `host:<lowercased host>`, else
/// `global` (old `targetKey`; the port is not part of the key).
pub fn target_key(profile_id: Option<&str>, host: &str) -> String {
    match profile_id.map(str::trim).filter(|id| !id.is_empty()) {
        Some(id) => format!("profile:{id}"),
        None => {
            let host = host.trim().to_lowercase();
            if host.is_empty() {
                "global".into()
            } else {
                format!("host:{host}")
            }
        }
    }
}

/// One decodable, valid row (unknown fields ignored).
fn decode_row(value: Value) -> Option<LiveCheck> {
    serde_json::from_value::<LiveCheck>(value)
        .ok()
        .filter(LiveCheck::is_valid)
}

/// Reads the targets keeping every row that decodes and sits under its own key.
fn lenient_targets<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<String, Vec<LiveCheck>>, D::Error> {
    let raw = BTreeMap::<String, Value>::deserialize(d)?;
    let mut rejected = 0usize;
    let mut targets = BTreeMap::new();
    for (key, rows) in raw {
        let Value::Array(items) = rows else {
            rejected += 1;
            continue;
        };
        let total = items.len();
        let rows: Vec<LiveCheck> = items
            .into_iter()
            .filter_map(decode_row)
            .filter(|r| target_key(r.profile_id.as_deref(), &r.host) == key)
            .take(HISTORY_PER_TARGET)
            .collect();
        rejected += total - rows.len();
        if !rows.is_empty() {
            targets.insert(key, rows);
        }
    }
    if rejected > 0 {
        // Counts only: rows can hold hosts and addresses.
        tracing::warn!(rejected, "live history rows dropped while reading");
    }
    Ok(targets)
}

impl LiveHistory {
    /// Applies the caps: 180 days, 20 per target (newest first), 500 rows in all.
    fn enforce_caps(&mut self, now: UnixMs) {
        for rows in self.targets.values_mut() {
            rows.retain(|r| now.saturating_sub(r.finished_at) <= MAX_AGE_MS);
            rows.sort_by_key(|r| Reverse(r.finished_at));
            rows.truncate(HISTORY_PER_TARGET);
        }
        let total: usize = self.targets.values().map(Vec::len).sum();
        if total > MAX_ROWS {
            // The oldest rows go first, whatever their target.
            let mut stamps: Vec<UnixMs> = self
                .targets
                .values()
                .flatten()
                .map(|r| r.finished_at)
                .collect();
            stamps.sort_unstable_by(|a, b| b.cmp(a));
            let cutoff = stamps[MAX_ROWS - 1];
            let mut at_cutoff = stamps[..MAX_ROWS].iter().filter(|s| **s == cutoff).count();
            for rows in self.targets.values_mut() {
                rows.retain(|r| {
                    if r.finished_at > cutoff {
                        true
                    } else if r.finished_at == cutoff && at_cutoff > 0 {
                        at_cutoff -= 1;
                        true
                    } else {
                        false
                    }
                });
            }
        }
        self.targets.retain(|_, rows| !rows.is_empty());
    }
}

/// The history service: one per app, shared (`Arc`). File I/O is blocking: async callers use
/// `spawn_blocking` for [`HistoryStore::add`], [`HistoryStore::clear`] and [`HistoryStore::prune`].
pub struct HistoryStore {
    store: Store<LiveHistory>,
}

impl HistoryStore {
    /// Opens `history/live-checks.json` under the data root (never fails; see `Store::open`).
    pub fn open(root: &Path) -> Self {
        HistoryStore {
            store: Store::open(root),
        }
    }

    /// The underlying store (mode, notice for the UI banner, change subscription).
    pub fn store(&self) -> &Store<LiveHistory> {
        &self.store
    }

    /// Stores a finished check: sanitised, newest first under its target, caps applied. Memory
    /// changes only after the write succeeded. An invalid row is refused before any I/O.
    pub fn add(&self, mut check: LiveCheck) -> AppResult<()> {
        sanitize(&mut check);
        self.insert(check)
    }

    /// [`HistoryStore::add`] for a row its caller already sanitised: the check pipeline returns
    /// exactly the stored row (sanitising is not idempotent: a second pass would decode an
    /// escaped `%` in a redirect path again).
    pub(crate) fn insert(&self, check: LiveCheck) -> AppResult<()> {
        if !check.is_valid() {
            return Err(AppError::validation(Msg::new(
                "probes.live.history.invalidRow",
            )));
        }
        let key = target_key(check.profile_id.as_deref(), &check.host);
        let now = now_ms().max(check.finished_at);
        self.store.update(|doc| {
            doc.targets.entry(key).or_default().insert(0, check);
            doc.enforce_caps(now);
        })
    }

    /// Rows of one target (`profile_id` wins over `host`), or with neither the newest 20 of all.
    /// Returned rows are copies.
    pub fn list(&self, profile_id: Option<&str>, host: Option<&str>) -> Vec<LiveCheck> {
        let host = host.map(str::trim).filter(|h| !h.is_empty());
        let profile_id = profile_id.map(str::trim).filter(|p| !p.is_empty());
        self.store.read(|doc| {
            if profile_id.is_none() && host.is_none() {
                let mut all: Vec<LiveCheck> = doc.targets.values().flatten().cloned().collect();
                all.sort_by_key(|r| Reverse(r.finished_at));
                all.truncate(HISTORY_PER_TARGET);
                return all;
            }
            let key = target_key(profile_id, host.unwrap_or_default());
            doc.targets.get(&key).cloned().unwrap_or_default()
        })
    }

    /// The comparison baseline: the newest row of the target on the same port whose server
    /// answered (B-18).
    pub fn baseline(&self, profile_id: Option<&str>, host: &str, port: u16) -> Option<LiveCheck> {
        let key = target_key(profile_id, host);
        self.store.read(|doc| {
            doc.targets
                .get(&key)?
                .iter()
                .find(|r| is_baseline(r, Some(port)))
                .cloned()
        })
    }

    /// Deletes every row (AT-05-008); nothing can come back from a backup.
    pub fn clear(&self) -> AppResult<()> {
        self.store.replace(LiveHistory::default())?;
        tracing::info!("live history cleared");
        Ok(())
    }

    /// The whole history as pretty JSON (rows are already sanitised) for the user's export.
    pub fn export_json(&self) -> String {
        self.store
            .read(|doc| serde_json::to_string_pretty(doc).unwrap_or_else(|_| "{}".into()))
    }

    /// Drops the targets of deleted profiles and applies the caps (at startup). Returns the
    /// number of rows removed.
    pub fn prune(&self, live_profiles: &HashSet<String>) -> AppResult<usize> {
        let now = now_ms();
        let removed = self.store.update(|doc| {
            let before: usize = doc.targets.values().map(Vec::len).sum();
            doc.targets
                .retain(|key, _| match key.strip_prefix("profile:") {
                    Some(id) => live_profiles.contains(id),
                    None => true,
                });
            doc.enforce_caps(now);
            before - doc.targets.values().map(Vec::len).sum::<usize>()
        })?;
        if removed > 0 {
            tracing::info!(removed, "live history pruned");
        }
        Ok(removed)
    }
}

impl LiveHistory {
    /// One-time import of the Electron `live-server-checks.json` (v0 or v1, already read and
    /// decoded by the app; `.bak` fallback is the app's): valid rows only, cancelled ones
    /// skipped, re-sanitised (the old UI re-sanitised hop lines at render time, so imported ones
    /// may still be raw), re-keyed (`global` rows get a real key), caps applied. A file of a newer
    /// Electron build (`schemaVersion` > 1 or not a number) is skipped. The old file is not touched.
    pub fn from_legacy(old: &Value) -> LiveHistory {
        let mut doc = LiveHistory::default();
        let Some(root) = old.as_object() else {
            return doc;
        };
        match root.get("schemaVersion") {
            None => {}
            Some(v) if v.as_u64().is_some_and(|v| v <= 1) => {}
            Some(_) => {
                tracing::warn!("legacy live history has a newer or invalid schema; not imported");
                return doc;
            }
        }
        let rows = root
            .iter()
            .filter(|(k, _)| {
                k.as_str() == "global" || k.starts_with("profile:") || k.starts_with("host:")
            })
            .filter_map(|(_, v)| v.as_array())
            .flatten();
        for row in rows {
            let Some(mut check) = decode_row(row.clone()).filter(|c| !c.cancelled) else {
                continue;
            };
            if let Some(route) = &mut check.route {
                for hop in &mut route.hop_details {
                    *hop = sanitize_hop_line(hop);
                }
            }
            sanitize(&mut check);
            let key = target_key(check.profile_id.as_deref(), &check.host);
            doc.targets.entry(key).or_default().push(check);
        }
        doc.enforce_caps(now_ms());
        doc
    }
}
