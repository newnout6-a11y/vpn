//! The event journal (p-logs): what happened, for the «События» tab of «Журнал». A capped,
//! rotating JSON-lines file in the data folder (`events.jsonl` + `events.1.jsonl`) that stores
//! Msg keys and their arguments, redacted like the app log, never keys, subscription URLs,
//! tokens or HWIDs. Fed by one hook on every notice the app shows (`attach`), by session starts
//! and ends with their outcome and by the runtime's warnings (`feed`), by the notices the
//! documents raised at this start (once per occurrence), and by [`record`]: the update channel
//! and the kill-switch settings. A journal that did not exist yet starts with the stored sessions
//! history, so the tab is not empty after an upgrade.
mod feed;
mod file;
mod record;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Weak};

use parking_lot::Mutex;
use tokio::sync::watch;
use vpnte_base::types::{KillSwitchLevel, UnixMs, now_ms};
use vpnte_base::{AppResult, Msg};
use vpnte_engine::routing::rulesets::RefreshOutcome;
use vpnte_tunnel::history::Entry;

use crate::services::Backend;

pub use feed::spawn as spawn_feeds;
pub use file::{CAP_BYTES, FILE, PREVIOUS};
pub use record::{
    NewRecord, Record, SessionFacts, Tone, Topic, from_notice, session_end, session_up,
};

use file::EventFile;

/// Records kept in memory at most (the files hold fewer: about 1 700 per generation).
const MAX_RECORDS: usize = 5000;

type Registry = Mutex<Vec<(PathBuf, Weak<Journal>)>>;

/// Journals open in this process, one per data folder (the root's hook and the Logs API share
/// it).
static OPEN: LazyLock<Registry> = LazyLock::new(Mutex::default);

/// The event journal of one data folder.
pub struct Journal {
    file: EventFile,
    state: Mutex<State>,
    changes: watch::Sender<u64>,
    /// No journal file existed when it was opened: the history is written in once.
    fresh: bool,
    seeded: AtomicBool,
}

struct State {
    records: Vec<Record>,
    next: u64,
}

impl Journal {
    /// The journal of the data folder `root` (the same instance while one is alive).
    pub fn open(root: &Path) -> Arc<Journal> {
        Self::open_capped(root, CAP_BYTES)
    }

    fn open_capped(root: &Path, cap: u64) -> Arc<Journal> {
        let mut open = OPEN.lock();
        open.retain(|(_, journal)| journal.strong_count() > 0);
        if let Some(journal) = open
            .iter()
            .find(|(dir, _)| dir == root)
            .and_then(|(_, journal)| journal.upgrade())
        {
            return journal;
        }
        let file = EventFile::new(root, cap);
        let fresh = !file.exists();
        let records = file.read();
        let next = records.iter().map(|r| r.seq).max().map_or(1, |m| m + 1);
        let journal = Arc::new(Journal {
            file,
            state: Mutex::new(State { records, next }),
            changes: watch::Sender::new(0),
            fresh,
            seeded: AtomicBool::new(false),
        });
        open.push((root.to_owned(), Arc::downgrade(&journal)));
        journal
    }

    /// Adds events (numbered, redacted, written in order). A failed write is logged; the event
    /// stays on the page until the app exits.
    pub fn append(&self, news: impl IntoIterator<Item = NewRecord>) {
        let mut state = self.state.lock();
        let mut rotated = false;
        let mut added = false;
        for new in news {
            let record = Record::redacted(state.next, new);
            state.next += 1;
            match self.file.append(&record) {
                Ok(r) => rotated |= r,
                Err(err) => tracing::warn!(error = %err, "event not written"),
            }
            state.records.push(record);
            added = true;
        }
        if rotated {
            // Whatever the deleted generation held is gone from the page too.
            let kept = self.file.read();
            if !kept.is_empty() {
                state.records = kept;
            }
        }
        let len = state.records.len();
        if len > MAX_RECORDS {
            state.records.drain(..len - MAX_RECORDS);
        }
        drop(state);
        if added {
            self.changes.send_modify(|n| *n += 1);
        }
    }

    /// Every event, oldest first.
    pub fn records(&self) -> Vec<Record> {
        self.state.lock().records.clone()
    }

    /// A session start at `at` is already written (a session taken over after an app restart).
    pub fn has_start(&self, at: UnixMs) -> bool {
        let state = self.state.lock();
        state
            .records
            .iter()
            .rev()
            .any(|r| r.at == at && r.title.key == record::SESSION_UP)
    }

    /// Changes on every append and clear.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Deletes every event; nothing else.
    pub fn clear(&self) -> AppResult<()> {
        let mut state = self.state.lock();
        self.file.clear()?;
        state.records.clear();
        drop(state);
        tracing::info!("event journal cleared");
        self.changes.send_modify(|n| *n += 1);
        Ok(())
    }

    /// Writes the stored sessions in as events (a start and an end each), once, and only into a
    /// journal that did not exist before this start (after an upgrade the tab is not empty).
    pub fn seed(&self, entries: &[Entry]) {
        if !self.fresh || self.seeded.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut news: Vec<NewRecord> = entries
            .iter()
            .flat_map(|entry| {
                let up = session_up(entry.started_at, &entry.profile_name, entry.mode, None);
                [up, session_end(entry)]
            })
            .collect();
        news.sort_by_key(|n| n.at);
        let count = news.len();
        self.append(news);
        tracing::info!(events = count, "event journal started from the history");
    }
}

/// At start, right after the backend exists: the journal of the data folder, the history in a
/// new journal, and the hook that writes every notice the app shows.
pub fn attach(backend: &Backend) -> Arc<Journal> {
    let journal = Journal::open(&backend.dirs.root);
    journal.seed(&backend.history.list());
    // The one-time import of the old version's data said something only Maintenance showed.
    if let Some(report) = &backend.import {
        journal.append(import_events(report, now_ms()));
    }
    journal.append(store_notices(backend, now_ms()));
    // The notifier lives as long as the process: so does the journal it writes to.
    let hook = journal.clone();
    backend
        .notifier
        .set_hook(Arc::new(move |notice, category, at| {
            if let Some(new) = from_notice(notice, category, at) {
                hook.append([new]);
            }
        }));
    journal
}

/// Adds one event, now, to the journal of the data folder `root` (the instance the root's hook
/// writes to): what the update channel and the kill-switch settings record.
pub fn record(root: &Path, topic: Topic, tone: Tone, title: Msg, body: Option<Msg>) {
    Journal::open(root).append([NewRecord {
        at: now_ms(),
        topic,
        tone,
        title,
        body,
        session: None,
    }]);
}

/// The kill-switch level chosen in Settings (or by the tray's «Выключить «Всегда»»).
pub fn kill_switch_level(root: &Path, level: KillSwitchLevel) {
    let key = match level {
        KillSwitchLevel::Off => "app.journal.killSwitch.off",
        KillSwitchLevel::Standard => "app.journal.killSwitch.onDrop",
        KillSwitchLevel::Strict => "app.journal.killSwitch.always",
    };
    record(root, Topic::Protection, Tone::Info, Msg::new(key), None);
}

/// A Smart RU list refresh that brought new lists (asked by p-tails-a); a failed one reaches
/// the journal through its toast, once per streak.
pub fn smart_ru_refreshed(root: &Path, outcome: &RefreshOutcome) {
    if matches!(outcome, RefreshOutcome::Updated { .. }) {
        let title = Msg::new("app.journal.smartRu.updated");
        record(root, Topic::Update, Tone::Ok, title, None);
    }
}

/// A kill-switch exception added (`true`) or removed in Settings, by its user label.
pub fn kill_switch_exception(root: &Path, label: &str, added: bool) {
    let key = if added {
        "app.journal.killSwitch.exceptionAdded"
    } else {
        "app.journal.killSwitch.exceptionRemoved"
    };
    let title = Msg::new(key).arg("label", label);
    record(root, Topic::Protection, Tone::Info, title, None);
}

/// What the backend's documents raised at this start and not at the previous one (a document
/// set aside, or read-only): a standing read-only state is recorded once, not at every start.
/// The server list's documents are the servers crate's (`Servers::notice` has no such flag).
fn store_notices(backend: &Backend, at: UnixMs) -> Vec<NewRecord> {
    [
        backend.settings.new_notice(),
        backend.protection.new_notice(),
        backend.themes.new_notice(),
        backend.soft.new_notice(),
        backend.cleanup.new_notice(),
        backend.rules.new_notice(),
        backend.history.store().new_notice(),
    ]
    .into_iter()
    .flatten()
    .map(|title| NewRecord {
        at,
        topic: Topic::Other,
        tone: Tone::Warn,
        title,
        body: None,
        session: None,
    })
    .collect()
}

/// The notes of this start's import of the old version's data, as update events.
pub fn import_events(report: &crate::import::ImportReport, at: UnixMs) -> Vec<NewRecord> {
    report
        .notes
        .iter()
        .map(|note| NewRecord {
            at,
            topic: Topic::Update,
            tone: Tone::Info,
            title: note.clone(),
            body: None,
            session: None,
        })
        .collect()
}
