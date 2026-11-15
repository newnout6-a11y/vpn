//! Connection history: one row per session in `history/connections.json`, a ring of
//! [`MAX_ENTRIES`] rows, oldest first (lifecycle-app §3.23, storage §2.4 H1 / §3.9).
//!
//! Rows are validated by one reader contract for new rows, our own file and the Electron-era
//! store; a row that fails it is skipped (and counted), never shown and never carried over.
use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use tokio::sync::watch;
use vpnte_base::i18n::Lang;
use vpnte_base::types::{Owner, UnixMs};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::ops::{CorrelationId, Source};
use vpnte_core::store::{Document, Store};

use crate::outcome::{self, Confidence, DisconnectReason, SessionOutcome};

/// Rows kept; the oldest go first.
pub const MAX_ENTRIES: usize = 1000;

/// How the session carried traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionMode {
    Hard,
    Soft,
    Direct,
}

impl SessionMode {
    /// Wire name, as in the CSV export.
    pub fn as_str(self) -> &'static str {
        match self {
            SessionMode::Hard => "hard",
            SessionMode::Soft => "soft",
            SessionMode::Direct => "direct",
        }
    }
}

/// The configured traffic mechanism (not proof that traffic used it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Route {
    Tun,
    SoftEnv,
    Unconfirmed,
}

impl Route {
    /// Wire name, as in the CSV export.
    pub fn as_str(self) -> &'static str {
        match self {
            Route::Tun => "tun",
            Route::SoftEnv => "soft-env",
            Route::Unconfirmed => "unconfirmed",
        }
    }
}

/// Who started the session, how it was carried and how sure the recorded cause is. Exactly these
/// four keys (an extra key fails the old validator, so it fails ours).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source: Source,
    /// `None` is written as `"unknown"`.
    #[serde(with = "owner_or_unknown")]
    pub owner: Option<Owner>,
    pub route: Route,
    pub confidence: Confidence,
}

const OWNERS: [(Owner, &str); 6] = [
    (Owner::AdaptiveRetry, "adaptive-retry"),
    (Owner::Autopilot, "autopilot"),
    (Owner::Rotation, "rotation"),
    (Owner::Schedule, "schedule"),
    (Owner::Manual, "manual"),
    (Owner::Recovery, "recovery"),
];

fn owner_str(owner: Option<Owner>) -> &'static str {
    owner
        .and_then(|o| OWNERS.iter().find(|(known, _)| *known == o))
        .map_or("unknown", |(_, name)| name)
}

fn source_str(source: Source) -> &'static str {
    match source {
        Source::Ui => "ui",
        Source::Tray => "tray",
        Source::Lifecycle => "lifecycle",
        Source::Runtime => "runtime",
        Source::Unknown => "unknown",
    }
}

mod owner_or_unknown {
    use super::*;

    pub fn serialize<S: Serializer>(owner: &Option<Owner>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(owner_str(*owner))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Owner>, D::Error> {
        let name = String::deserialize(d)?;
        if name == "unknown" {
            return Ok(None);
        }
        OWNERS
            .iter()
            .find(|(_, known)| *known == name)
            .map(|(owner, _)| Some(*owner))
            .ok_or_else(|| D::Error::custom("unknown owner"))
    }
}

/// A field that may be absent but not `null` (old reader contract): use with `default`.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// A field that must be present but may be `null`: use without `default`.
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

/// One finished session (or a start that never came up). Field names are the Electron ones.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    /// The connect action's id (not the stop's), so logs and the row can be joined.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub correlation_id: Option<CorrelationId>,
    /// Always written now; Electron rows before provenance existed have none.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub provenance: Option<Provenance>,
    pub started_at: UnixMs,
    /// `None` only in old rows of a session that never finished.
    #[serde(deserialize_with = "nullable")]
    pub ended_at: Option<UnixMs>,
    /// Monotonic elapsed time; absent in old rows (then the calendar times count).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub duration_ms: Option<u64>,
    pub profile_name: String,
    pub profile_id: String,
    pub mode: SessionMode,
    pub bytes_down: u64,
    pub bytes_up: u64,
    pub disconnect_reason: DisconnectReason,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "outcome::de::opt_msg_or_text"
    )]
    pub error_message: Option<Msg>,
    /// Absent in rows written before v1.1.18.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<SessionOutcome>,
}

impl Entry {
    /// Elapsed time of the session: calendar dates may jump, so the monotonic duration wins;
    /// old rows fall back to `ended - started` (never negative); an unfinished row counts 0.
    pub fn connection_ms(&self) -> u64 {
        match self.ended_at {
            None => 0,
            Some(ended) => self.duration_ms.unwrap_or_else(|| {
                u64::try_from(ended.saturating_sub(self.started_at)).unwrap_or(0)
            }),
        }
    }

    /// The rules serde cannot express: no negative times, and the route must fit the mode.
    pub fn is_valid(&self) -> bool {
        let route_fits = self.provenance.is_none_or(|p| match p.route {
            Route::SoftEnv => self.mode == SessionMode::Soft,
            Route::Tun => self.mode != SessionMode::Soft,
            Route::Unconfirmed => true,
        });
        self.started_at >= 0 && self.ended_at.is_none_or(|t| t >= 0) && route_fits
    }

    /// Builds the row for a finished session (id, bucket, confidence and message derived).
    pub fn from_new(new: NewEntry) -> AppResult<Entry> {
        // Soft mode only sets the system proxy: our counters do not see its traffic.
        let soft = new.mode == SessionMode::Soft;
        let entry = Entry {
            id: uuid::Uuid::new_v4().to_string(),
            correlation_id: new.correlation_id,
            provenance: Some(Provenance {
                source: new.source,
                owner: new.owner,
                route: new.route,
                confidence: new.outcome.kind.confidence(),
            }),
            started_at: new.started_at,
            ended_at: Some(new.ended_at),
            duration_ms: Some(new.duration_ms),
            profile_name: new.profile_name,
            profile_id: new.profile_id,
            mode: new.mode,
            bytes_down: if soft { 0 } else { new.bytes_down },
            bytes_up: if soft { 0 } else { new.bytes_up },
            disconnect_reason: new.outcome.kind.bucket(),
            error_message: Some(new.outcome.headline.clone()),
            outcome: Some(new.outcome),
        };
        if entry.is_valid() {
            Ok(entry)
        } else {
            Err(AppError::validation(Msg::new(
                "tunnel.history.invalidEntry",
            )))
        }
    }
}

/// A finished session as the lifecycle reports it. Provenance, the monotonic duration and the
/// outcome are required for every new row.
#[derive(Debug, Clone, PartialEq)]
pub struct NewEntry {
    pub correlation_id: Option<CorrelationId>,
    pub source: Source,
    /// `None` = no operation owned the session (runtime-initiated).
    pub owner: Option<Owner>,
    pub route: Route,
    pub started_at: UnixMs,
    pub ended_at: UnixMs,
    pub duration_ms: u64,
    pub profile_name: String,
    /// Server-picker id, or the synthetic `direct-vpn` / `local-proxy` / `local-proxy-soft-<type>`.
    pub profile_id: String,
    pub mode: SessionMode,
    pub bytes_down: u64,
    pub bytes_up: u64,
    pub outcome: SessionOutcome,
}

/// Reads one stored row; `None` when it breaks the reader contract.
fn read_row(row: Value) -> Option<Entry> {
    serde_json::from_value::<Entry>(row)
        .ok()
        .filter(Entry::is_valid)
}

/// Reads stored rows in order, skipping invalid ones; returns the rows and how many were skipped.
fn read_rows(rows: impl IntoIterator<Item = Value>) -> (Vec<Entry>, usize) {
    let mut skipped = 0;
    let entries = rows
        .into_iter()
        .filter_map(|row| {
            let entry = read_row(row);
            skipped += usize::from(entry.is_none());
            entry
        })
        .collect();
    (entries, skipped)
}

/// The `history/connections.json` document.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ConnectionHistory {
    /// Oldest first, at most [`MAX_ENTRIES`].
    pub entries: VecDeque<Entry>,
}

impl Document for ConnectionHistory {
    const FILE: &'static str = "history/connections.json";
    const VERSION: u32 = 1;
}

impl<'de> Deserialize<'de> for ConnectionHistory {
    /// Lenient per row: one damaged row must not cost the whole history (old repairing reader).
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            entries: Vec<Value>,
        }
        let (entries, skipped) = read_rows(Raw::deserialize(d)?.entries);
        if skipped > 0 {
            // Row contents are never logged: they hold profile names and addresses.
            tracing::warn!(skipped, "invalid connection history rows skipped");
        }
        let mut history = ConnectionHistory::default();
        history.extend(entries);
        Ok(history)
    }
}

impl ConnectionHistory {
    /// Appends a row, dropping the oldest past [`MAX_ENTRIES`].
    pub fn push(&mut self, entry: Entry) {
        self.extend([entry]);
    }

    fn extend(&mut self, rows: impl IntoIterator<Item = Entry>) {
        self.entries.extend(rows);
        let excess = self.entries.len().saturating_sub(MAX_ENTRIES);
        self.entries.drain(..excess);
    }

    /// Maps the Electron `connection-history` store (`{connectionHistory: [...],
    /// rejectedConnectionHistory?: [...]}`, already opened) into rows. Rows failing the reader
    /// contract and the rows the old app had already rejected are counted and not carried over
    /// (storage B21). Returns the history and that count.
    pub fn from_legacy(legacy: &Value) -> (ConnectionHistory, usize) {
        let rows = match legacy.get("connectionHistory") {
            Some(Value::Array(rows)) => rows.clone(),
            other => {
                if other.is_some() || !legacy.is_object() {
                    tracing::warn!("legacy connection history has no row list; nothing imported");
                }
                Vec::new()
            }
        };
        let rejected = legacy
            .get("rejectedConnectionHistory")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let (entries, skipped) = read_rows(rows);
        let entries = entries.into_iter().map(|mut e| {
            // Same rules as new rows: blank text dropped, secrets in engine output masked.
            if let Some(o) = e.outcome.as_mut() {
                o.evidence = std::mem::take(&mut o.evidence).normalized();
            }
            e
        });
        let mut history = ConnectionHistory::default();
        history.extend(entries);
        (history, skipped + rejected)
    }
}

/// Outcome of the one-time Electron import, for the import report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LegacyImport {
    /// Rows added to the history.
    pub imported: usize,
    /// Damaged rows that were not carried over.
    pub dropped: usize,
}

impl LegacyImport {
    /// The report line about damaged rows, if there were any.
    pub fn warning(&self) -> Option<Msg> {
        (self.dropped > 0)
            .then(|| Msg::new("tunnel.history.legacyDropped").arg("count", self.dropped))
    }
}

mod export;

pub use export::{CSV_HEADER, Filter, Period, Stats, filter, stats, to_csv, to_json};

/// Shared handle to the history document (cheap to clone). Changes do blocking file I/O: call
/// them from `spawn_blocking` in async code.
#[derive(Clone)]
pub struct History {
    store: Arc<Store<ConnectionHistory>>,
}

impl History {
    /// Wraps the process-wide store of the document.
    pub fn new(store: Arc<Store<ConnectionHistory>>) -> Self {
        Self { store }
    }

    /// Opens `history/connections.json` under the data root.
    pub fn open(root: &Path) -> Self {
        Self::new(Arc::new(Store::open(root)))
    }

    /// The underlying store (mode, notice, `set_aside` for the maintenance page).
    pub fn store(&self) -> &Arc<Store<ConnectionHistory>> {
        &self.store
    }

    /// Bumped after every persisted change.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.store.subscribe()
    }

    /// Records a finished session and returns the stored row. History is best effort: the caller
    /// logs a failure and carries on.
    pub fn add(&self, new: NewEntry) -> AppResult<Entry> {
        let entry = Entry::from_new(new)?;
        self.store.update(|h| h.push(entry.clone()))?;
        Ok(entry)
    }

    /// All rows, oldest first.
    pub fn list(&self) -> Vec<Entry> {
        self.store.read(|h| h.entries.iter().cloned().collect())
    }

    /// Rows matching `f`, oldest first.
    pub fn filter(&self, f: &Filter, lang: Lang) -> Vec<Entry> {
        self.store.read(|h| filter(&h.entries, f, lang))
    }

    /// Totals for `period` ending at `now`.
    pub fn stats(&self, period: Period, now: UnixMs) -> Stats {
        self.store.read(|h| stats(&h.entries, period, now))
    }

    /// Removes every row.
    pub fn clear(&self) -> AppResult<()> {
        self.store.update(|h| h.entries.clear())
    }

    /// CSV of all rows (see [`to_csv`]).
    pub fn export_csv(&self, lang: Lang) -> String {
        self.store.read(|h| to_csv(&h.entries, lang))
    }

    /// JSON of all rows (see [`to_json`]).
    pub fn export_json(&self, lang: Lang) -> AppResult<String> {
        self.store.read(|h| to_json(&h.entries, lang))
    }

    /// One-time Electron import. Old rows go before the current ones (they are older); a row whose
    /// id is already here is skipped (re-run after an interrupted import); the ring keeps the
    /// newest [`MAX_ENTRIES`]. The legacy value is only read.
    pub fn import_legacy(&self, legacy: &Value) -> AppResult<LegacyImport> {
        let (old, dropped) = ConnectionHistory::from_legacy(legacy);
        let imported = self.store.update(move |h| {
            let fresh: Vec<Entry> = {
                let known: HashSet<&str> = h.entries.iter().map(|e| e.id.as_str()).collect();
                old.entries
                    .into_iter()
                    .filter(|e| !known.contains(e.id.as_str()))
                    .collect()
            };
            let trimmed = (fresh.len() + h.entries.len()).saturating_sub(MAX_ENTRIES);
            let imported = fresh.len().saturating_sub(trimmed);
            let current = std::mem::take(&mut h.entries);
            h.extend(fresh.into_iter().chain(current));
            imported
        })?;
        Ok(LegacyImport { imported, dropped })
    }
}

#[cfg(test)]
mod tests;
