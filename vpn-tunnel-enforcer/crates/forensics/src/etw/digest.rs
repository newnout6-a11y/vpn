//! Live digest of the rows the consumer produces: counters for the health line and the small
//! "top domains / top endpoints" lists of the Diagnostics card (replaces the old file probe, so
//! a busy machine never shows a false "no data events" state, B-17).
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vpnte_base::types::UnixMs;

/// Distinct keys kept per top map; further keys are counted in `overflow`, never fatal.
pub const MAX_KEYS: usize = 4096;
/// Distinct categories kept.
pub const MAX_CATEGORIES: usize = 64;
/// Length of the top lists.
pub const TOP_N: usize = 5;

/// A key with its count (top domains / endpoints).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counted {
    pub name: String,
    pub count: u64,
}

/// Point-in-time copy of the digest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DigestSnapshot {
    /// `engine` of the last lifecycle row (`etw-inproc`).
    pub engine: Option<String>,
    /// Rows produced (lifecycle and health rows included).
    pub events: u64,
    /// Rows that are neither lifecycle nor health.
    pub data_events: u64,
    /// ETW callbacks received (the old heartbeat counted written rows under this name).
    pub observed: u64,
    /// Events dropped by the task filter.
    pub filtered: u64,
    /// Events without a decodable schema (kept as `unparsed` rows).
    pub unparsed: u64,
    /// Rows dropped because the writer queue was full.
    pub backpressure_dropped: u64,
    /// Rows the writer failed to write.
    pub write_errors: u64,
    /// Keys not counted because a map was full.
    pub overflow: u64,
    pub categories: BTreeMap<String, u64>,
    pub wfp_blocks: u64,
    pub top_domains: Vec<Counted>,
    pub top_remotes: Vec<Counted>,
    /// Event time of the last data row.
    pub last_data_at: Option<UnixMs>,
}

/// Counter map that remembers first-seen order for stable ties (also the summary's top lists).
#[derive(Default)]
pub(crate) struct TopMap {
    counts: HashMap<String, (u64, u64)>,
    next_seq: u64,
}

impl TopMap {
    /// Counts `key`; `false` when the key was new and the map already holds `cap` keys.
    pub(crate) fn bump(&mut self, key: &str, cap: usize) -> bool {
        if let Some((count, _)) = self.counts.get_mut(key) {
            *count += 1;
            return true;
        }
        if self.counts.len() >= cap {
            return false;
        }
        self.counts.insert(key.to_string(), (1, self.next_seq));
        self.next_seq += 1;
        true
    }

    /// The `n` highest counts, ties by first seen.
    pub(crate) fn top(&self, n: usize) -> Vec<Counted> {
        let mut all: Vec<(&String, &(u64, u64))> = self.counts.iter().collect();
        all.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(a.1.1.cmp(&b.1.1)));
        all.into_iter()
            .take(n)
            .map(|(name, (count, _))| Counted {
                name: name.clone(),
                count: *count,
            })
            .collect()
    }
}

/// A non-empty string field of an `events.ndjson` row.
pub(crate) fn text_field<'a>(row: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    row.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// `remoteAddress[:remotePort]` of a row (port 0 means none).
pub(crate) fn remote_endpoint(row: &Map<String, Value>) -> Option<String> {
    let addr = text_field(row, "remoteAddress")?;
    Some(match row.get("remotePort").and_then(Value::as_u64) {
        Some(port) if port > 0 => format!("{addr}:{port}"),
        _ => addr.to_string(),
    })
}

#[derive(Default)]
struct Maps {
    engine: Option<String>,
    categories: TopMap,
    domains: TopMap,
    remotes: TopMap,
}

/// Shared between the ETW callback, the writer thread and the status reader.
#[derive(Default)]
pub struct LiveDigest {
    events: AtomicU64,
    data: AtomicU64,
    observed: AtomicU64,
    filtered: AtomicU64,
    unparsed: AtomicU64,
    backpressure: AtomicU64,
    write_errors: AtomicU64,
    overflow: AtomicU64,
    wfp_blocks: AtomicU64,
    /// 0 = none yet (no ETW event is dated 1970).
    last_data_ms: AtomicI64,
    maps: Mutex<Maps>,
}

impl LiveDigest {
    /// Counts one produced row (semantics of the old probe, SEP:54-90).
    pub fn observe(&self, row: &Map<String, Value>) {
        self.events.fetch_add(1, Ordering::Relaxed);
        let str_of = |key: &str| text_field(row, key);
        let category = str_of("category").unwrap_or("other");
        match category {
            "lifecycle" => {
                if let Some(engine) = str_of("engine") {
                    self.maps.lock().engine = Some(engine.to_string());
                }
                return;
            }
            "health" => return,
            _ => {}
        }
        self.data.fetch_add(1, Ordering::Relaxed);
        let blocked = category == "wfp"
            && (str_of("event") == Some("block")
                || matches!(str_of("action"), Some("block" | "drop")));
        if blocked {
            self.wfp_blocks.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(ms) = str_of("ts").and_then(|s| s.parse::<jiff::Timestamp>().ok()) {
            self.last_data_ms
                .store(ms.as_millisecond(), Ordering::Relaxed);
        }
        let remote = remote_endpoint(row);
        let mut overflow = 0;
        {
            let mut maps = self.maps.lock();
            overflow += u64::from(!maps.categories.bump(category, MAX_CATEGORIES));
            if let Some(domain) = str_of("queryName") {
                overflow += u64::from(!maps.domains.bump(domain, MAX_KEYS));
            }
            if let Some(remote) = remote {
                overflow += u64::from(!maps.remotes.bump(&remote, MAX_KEYS));
            }
        }
        if overflow > 0 {
            self.overflow.fetch_add(overflow, Ordering::Relaxed);
        }
    }

    /// One ETW callback received.
    pub fn note_observed(&self) {
        self.observed.fetch_add(1, Ordering::Relaxed);
    }

    /// One event dropped by the task filter.
    pub fn note_filtered(&self) {
        self.filtered.fetch_add(1, Ordering::Relaxed);
    }

    /// One event without a decodable schema.
    pub fn note_unparsed(&self) {
        self.unparsed.fetch_add(1, Ordering::Relaxed);
    }

    /// One row dropped because the writer queue was full.
    pub fn note_backpressure(&self) {
        self.backpressure.fetch_add(1, Ordering::Relaxed);
    }

    /// One row the writer could not write.
    pub fn note_write_error(&self) {
        self.write_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Current values; top lists hold the [`TOP_N`] highest counts, ties by first seen.
    pub fn snapshot(&self) -> DigestSnapshot {
        let maps = self.maps.lock();
        let last = self.last_data_ms.load(Ordering::Relaxed);
        DigestSnapshot {
            engine: maps.engine.clone(),
            events: self.events.load(Ordering::Relaxed),
            data_events: self.data.load(Ordering::Relaxed),
            observed: self.observed.load(Ordering::Relaxed),
            filtered: self.filtered.load(Ordering::Relaxed),
            unparsed: self.unparsed.load(Ordering::Relaxed),
            backpressure_dropped: self.backpressure.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            overflow: self.overflow.load(Ordering::Relaxed),
            categories: maps
                .categories
                .counts
                .iter()
                .map(|(k, (n, _))| (k.clone(), *n))
                .collect(),
            wfp_blocks: self.wfp_blocks.load(Ordering::Relaxed),
            top_domains: maps.domains.top(TOP_N),
            top_remotes: maps.remotes.top(TOP_N),
            last_data_at: (last != 0).then_some(last),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    const TS: &str = "2026-06-19T00:00:00.000Z";

    /// §7.7 'counts native ETW data events…' (trafficForensics.test.ts:603-660), AT-08-007.
    #[test]
    fn counts_data_rows_and_builds_tops() {
        let d = LiveDigest::default();
        for r in [
            json!({"provider":"sidecar","category":"lifecycle","event":"started","engine":"ferrisetw-realtime","ts":TS}),
            json!({"provider":"Microsoft-Windows-TCPIP","category":"tcp","event":"Connect","remoteAddress":"142.250.1.2","remotePort":443,"ts":TS}),
            json!({"provider":"Microsoft-Windows-DNS-Client","category":"dns","event":"query","queryName":"youtube.com","remoteAddress":"142.250.1.2","ts":TS}),
            json!({"provider":"Microsoft-Windows-WFP","category":"wfp","event":"block","ts":TS}),
            json!({"provider":"sidecar","category":"health","event":"heartbeat","ts":TS}),
        ] {
            d.observe(&row(r));
        }
        let s = d.snapshot();
        assert_eq!(s.events, 5);
        assert_eq!(s.data_events, 3);
        assert_eq!(s.engine.as_deref(), Some("ferrisetw-realtime"));
        let cats: Vec<(&str, u64)> = s.categories.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        assert_eq!(cats, [("dns", 1), ("tcp", 1), ("wfp", 1)]);
        assert_eq!(s.wfp_blocks, 1);
        assert_eq!(
            s.top_domains,
            [Counted {
                name: "youtube.com".into(),
                count: 1
            }]
        );
        assert!(s.top_remotes.contains(&Counted {
            name: "142.250.1.2:443".into(),
            count: 1
        }));
        assert_eq!(
            s.last_data_at,
            Some(
                "2026-06-19T00:00:00Z"
                    .parse::<jiff::Timestamp>()
                    .unwrap()
                    .as_millisecond()
            )
        );
    }

    /// §7.7 `action: "drop"` and Unicode vectors (sidecarEventProbe.test.ts:46-56).
    #[test]
    fn counts_drop_actions_and_unicode_domains() {
        let d = LiveDigest::default();
        d.observe(&row(
            json!({"category":"wfp","event":"observed","action":"drop","ts":TS}),
        ));
        d.observe(&row(
            json!({"category":"dns","event":"query","queryName":"пример.рф","ts":TS}),
        ));
        d.observe(&row(json!({"category":"lifecycle","event":"stopped"})));
        let s = d.snapshot();
        assert_eq!(s.wfp_blocks, 1);
        assert_eq!(s.data_events, 2);
        assert_eq!(s.top_domains[0].name, "пример.рф");
    }

    /// Ties keep first-seen order; the lists hold five entries; full maps count overflow.
    #[test]
    fn tops_are_stable_and_bounded() {
        let d = LiveDigest::default();
        for name in ["a", "b", "c", "d", "e", "f", "b"] {
            d.observe(&row(json!({"category":"dns","queryName":name})));
        }
        let names: Vec<String> = d
            .snapshot()
            .top_domains
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert_eq!(names, ["b", "a", "c", "d", "e"]);

        let mut map = TopMap::default();
        assert!(map.bump("x", 1));
        assert!(map.bump("x", 1));
        assert!(!map.bump("y", 1));
    }
}
