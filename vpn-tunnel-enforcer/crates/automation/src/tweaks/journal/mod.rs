//! The tweak journal (`tweaks.json` in the data dir): for every system value we changed, the value
//! before our first change (`baseline`) and the value we wrote (`applied`).
//!
//! The file is user-writable while the app runs elevated, so a record is only ever trusted after
//! admission (closed enums for our own targets, well-formed managed text, a caller-supplied
//! allow-list for registry values): a doctored journal cannot steer an elevated write elsewhere
//! (spec B1/L1).
//!
//! Several processes of ours can hold the same journal (the app, its crash watcher, the next
//! start, installer helpers), each with its own copy: every change runs under the journal's file
//! lock on a copy read from disk under it, and a record whose value is already back at its
//! baseline is simply retired, so a rollback repeated by another process changes nothing.
use std::io;
use std::path::{Path, PathBuf};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use vpnte_base::Msg;
use vpnte_core::store::{Document, Mode, Store};

mod admission;
mod error;
mod lock;
mod model;
#[cfg(test)]
mod multi;
#[cfg(test)]
mod tests;
mod writer;

pub(crate) use admission::admitted;
pub use admission::{RegAdmit, no_registry};
pub use error::TweakError;
pub use lock::LOCK_FILE;
pub use model::{
    BlockKind, EnvVar, Feature, GitKey, Record, RegHive, StudioOption, Target, Val, tool_name,
};
pub use writer::Writer;

/// Reads and writes the system values behind [`Target`]s. Blocking: the journal runs on a blocking
/// thread. A backend answers only for the targets of the features it was built for.
pub trait Backend: Send + Sync {
    /// The current value. `Err` = cannot tell (apply aborts; rollback keeps the record).
    fn read(&self, target: &Target) -> io::Result<Val>;
    /// Writes `value` (`Val::Absent` removes it). Returns `true` when the write had to create the
    /// container (registry key or file) the value lives in.
    fn write(&self, target: &Target, value: &Val) -> io::Result<bool>;
    /// Removes the container of `target` if nothing else is left in it (only called for a
    /// container our first write created).
    fn prune(&self, target: &Target) -> io::Result<()>;
    /// Called once after a batch that changed values (the environment broadcast).
    fn changed(&self, _targets: &[Target]) {}
}

/// The persisted journal document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TweakDoc {
    /// In apply order; rollback walks it backwards. A record that does not parse is dropped alone
    /// instead of making the whole journal "corrupt", which would lose the obligations it holds.
    #[serde(default, deserialize_with = "crate::lenient::list")]
    pub records: Vec<Record>,
    /// The old app's leftovers were looked at once (`tweaks::legacy`).
    #[serde(default)]
    pub legacy_imported: bool,
    /// The process that last changed the obligations (apply, rollback, adoption); `None` in a
    /// journal no such process has changed yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer: Option<Writer>,
}

impl Document for TweakDoc {
    const FILE: &'static str = "tweaks.json";
    const VERSION: u32 = 1;
}

/// What a feature's values look like now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TweakState {
    /// Nothing journalled.
    Off,
    /// Journalled and every value still holds ours.
    On,
    /// Journalled, but some value was changed by someone else since.
    Drifted,
    /// A value could not be read: not checked.
    Unknown,
}

/// Outcome of a rollback; `failed` records stay in the journal for the next attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RollbackReport {
    /// Back at the baseline (written now, or already there).
    pub restored: Vec<Target>,
    /// Changed by someone else after our write: left as it is, record dropped (F-121).
    pub kept_user_value: Vec<Target>,
    /// Unreadable, unwritable or not verified.
    pub failed: Vec<Target>,
}

impl RollbackReport {
    /// Every obligation of the rolled-back features is retired.
    pub fn is_complete(&self) -> bool {
        self.failed.is_empty()
    }

    /// Adds another report (several features rolled back one after another).
    pub fn merge(&mut self, other: RollbackReport) {
        self.restored.extend(other.restored);
        self.kept_user_value.extend(other.kept_user_value);
        self.failed.extend(other.failed);
    }

    /// For the user when values could not be restored (the stop result appends it; a retry of
    /// the rollback picks the kept records up).
    pub fn failure_msg(&self) -> Option<Msg> {
        (!self.failed.is_empty()).then(|| Msg::new("automation.tweaks.rollbackFailed"))
    }

    /// For the user when values changed by someone else were left as they are.
    pub fn kept_msg(&self) -> Option<Msg> {
        let n = self.kept_user_value.len();
        (n > 0).then(|| Msg::new("automation.tweaks.keptUserValue").arg("count", n))
    }
}

/// The journal: one per process, shared by every tweak feature. Operations are serialised and
/// blocking (run them on a blocking thread).
pub struct Journal {
    root: PathBuf,
    /// This process's copy; replaced by a fresh read from disk before every change.
    store: RwLock<Store<TweakDoc>>,
    /// Warning of the last load that had one (corrupt file moved aside, read-only store).
    notice: Mutex<Option<Msg>>,
    admit_reg: RegAdmit,
    lock: Mutex<()>,
    me: Writer,
}

impl Journal {
    /// Opens `tweaks.json` under the data `root`, dropping records outside the allow-list. A corrupt
    /// file is moved aside by the store and reported by [`Journal::notice`].
    pub fn open(root: &Path, admit_reg: RegAdmit) -> Self {
        Self::open_as(root, admit_reg, Writer::current())
    }

    fn open_as(root: &Path, admit_reg: RegAdmit, me: Writer) -> Self {
        let _held = lock::hold(root);
        let journal = Self {
            root: root.to_path_buf(),
            store: RwLock::new(Store::open(root)),
            notice: Mutex::new(None),
            admit_reg,
            lock: Mutex::new(()),
            me,
        };
        journal.remember_notice();
        let rejected =
            journal.doc(|d| d.records.iter().filter(|r| !admitted(r, admit_reg)).count());
        if rejected > 0 {
            tracing::warn!(
                rejected,
                "tweak journal records outside the allow-list dropped"
            );
            // Housekeeping, not a change of obligations: `writer` stays, so the crash watcher of
            // the app that wrote them still recognises its journal.
            if let Err(e) = journal
                .store
                .read()
                .update(|d| d.records.retain(|r| admitted(r, admit_reg)))
            {
                tracing::warn!(error = %e, "tweak journal not cleaned");
            }
        }
        journal
    }

    /// Runs `f` on this process's copy.
    fn doc<R>(&self, f: impl FnOnce(&TweakDoc) -> R) -> R {
        self.store.read().read(f)
    }

    /// Re-reads the file (call with the file lock held): another process may have changed it.
    fn reload(&self) {
        *self.store.write() = Store::open(&self.root);
        self.remember_notice();
    }

    fn remember_notice(&self) {
        let store = self.store.read();
        let Some(notice) = store.notice() else {
            return;
        };
        *self.notice.lock() = Some(match store.mode() {
            Mode::Writable => Msg::new("automation.tweaks.journalCorrupt"),
            Mode::ReadOnly(_) => notice,
        });
    }

    /// Warning for the user: the journal was corrupt (moved aside, obligations lost: check proxy
    /// variables and policies by hand), or it cannot be written.
    pub fn notice(&self) -> Option<Msg> {
        self.notice.lock().clone()
    }

    /// The admitted records of `feature`, in apply order.
    pub fn records(&self, feature: Feature) -> Vec<Record> {
        self.doc(|d| {
            d.records
                .iter()
                .filter(|r| r.feature == feature && admitted(r, self.admit_reg))
                .cloned()
                .collect()
        })
    }

    /// Whether `feature` holds journalled values.
    pub fn is_applied(&self, feature: Feature) -> bool {
        !self.records(feature).is_empty()
    }

    /// Serialises a change: this process first, then every process (the file lock), on a copy
    /// read from disk under the lock.
    fn begin(&self) -> Change<'_> {
        let serial = self.lock.lock();
        let held = lock::hold(&self.root);
        self.reload();
        Change {
            _held: held,
            _serial: serial,
        }
    }

    /// Sets every `(feature, target, value)` of `plan` as one unit: all current values are read
    /// first (an unreadable one aborts with nothing written), the records are saved before the
    /// first write, each write is read back, and on any failure the writes of this call are undone
    /// (a refresh returns to the previous values; the original baseline is always kept).
    pub fn apply(
        &self,
        backend: &dyn Backend,
        plan: &[(Feature, Target, Val)],
    ) -> Result<(), TweakError> {
        let _change = self.begin();
        let current = plan
            .iter()
            .map(|(_, t, _)| {
                backend
                    .read(t)
                    .map_err(|e| TweakError::Unreadable(t.label(), e))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let before = self.doc(|d| d.records.clone());
        let mut records = before.clone();
        for ((feature, target, value), cur) in plan.iter().zip(&current) {
            match find(&mut records, *feature, target) {
                Some(r) => r.applied = value.clone(),
                None => records.push(Record {
                    feature: *feature,
                    target: target.clone(),
                    baseline: target.fresh_baseline(cur.clone()),
                    applied: value.clone(),
                    created: false,
                }),
            }
        }
        self.save(records.clone()).map_err(TweakError::Journal)?;

        let mut created = vec![false; plan.len()];
        let mut failure = None;
        let mut attempted = 0;
        for (i, (_, target, value)) in plan.iter().enumerate() {
            if current[i] == *value {
                continue; // already ours: no write
            }
            attempted = i + 1;
            let (made, verified) = write_verified(backend, target, value);
            created[i] = made;
            if let Err(e) = verified {
                failure = Some(e);
                break;
            }
        }
        let touched: Vec<Target> = plan[..attempted]
            .iter()
            .zip(&current)
            .filter(|((_, _, v), cur)| v != *cur)
            .map(|((_, t, _), _)| t.clone())
            .collect();

        let Some(failure) = failure else {
            for ((feature, target, _), made) in plan.iter().zip(&created) {
                if let Some(r) = find(&mut records, *feature, target) {
                    r.created |= *made;
                }
            }
            if let Err(e) = self.save(records) {
                tracing::warn!(error = %e, "tweak journal: created-container flags not saved");
            }
            if !touched.is_empty() {
                backend.changed(&touched);
            }
            return Ok(());
        };

        // Undo this call: back to the value each target had before it (a failed write usually
        // changed nothing, so look first). A target that cannot be put back keeps its new
        // record, so a later rollback still owns it.
        let mut kept = before;
        for i in (0..attempted).rev() {
            let (feature, target, value) = &plan[i];
            if current[i] == *value {
                continue;
            }
            let undone = match backend.read(target) {
                Ok(now) if now == current[i] => Ok(()),
                Ok(_) => write_verified(backend, target, &current[i]).1,
                Err(e) => Err(TweakError::Unreadable(target.label(), e)),
            };
            match undone {
                Ok(()) => {
                    if created[i] {
                        prune(backend, target);
                    }
                }
                Err(e) => {
                    tracing::warn!(target = %target.label(), error = %e, "tweak apply not undone; record kept");
                    if let Some(new) = find(&mut records, *feature, target).cloned() {
                        let created_now = new.created || created[i];
                        match find(&mut kept, *feature, target) {
                            Some(r) => {
                                r.applied = value.clone();
                                r.created |= created_now;
                            }
                            None => kept.push(Record {
                                created: created_now,
                                ..new
                            }),
                        }
                    }
                }
            }
        }
        if let Err(e) = self.save(kept) {
            tracing::warn!(error = %e, "tweak journal not saved after an undone apply");
        }
        if !touched.is_empty() {
            backend.changed(&touched);
        }
        Err(failure)
    }

    fn save(&self, records: Vec<Record>) -> vpnte_base::AppResult<()> {
        let me = self.me;
        self.store.read().update(|d| {
            d.records = records;
            d.writer = Some(me);
        })
    }

    /// Whether the old app's leftovers were already looked at.
    pub fn legacy_imported(&self) -> bool {
        self.doc(|d| d.legacy_imported)
    }

    /// Takes over obligations the old app left (nothing is written to the system) and marks the
    /// one-time import done. Records outside the allow-list, or for a target already journalled,
    /// are skipped. Returns how many were adopted.
    pub fn adopt_legacy(&self, records: Vec<Record>) -> vpnte_base::AppResult<usize> {
        let _change = self.begin();
        let me = self.me;
        self.store.read().update(|d| {
            let before = d.records.len();
            for r in records {
                let known = d
                    .records
                    .iter()
                    .any(|k| k.feature == r.feature && k.target == r.target);
                if !known && admitted(&r, self.admit_reg) {
                    d.records.push(r);
                }
            }
            d.legacy_imported = true;
            let adopted = d.records.len() - before;
            if adopted > 0 {
                d.writer = Some(me);
            }
            adopted
        })
    }

    /// Restores the journalled values of `features`, newest first. A value is put back only while
    /// it still holds ours; one changed by someone else is kept and its record retired; one that
    /// fails keeps its record for the next attempt while the others carry on.
    pub fn rollback(&self, backend: &dyn Backend, features: &[Feature]) -> RollbackReport {
        let _change = self.begin();
        self.rollback_held(backend, features)
    }

    /// [`Journal::rollback`] for the crash watcher of the app `writer`: only while that app is
    /// still the last process that changed the journal. `None`: another process (the next start,
    /// an uninstall helper) changed it since and handles what is left.
    pub fn rollback_left_by(
        &self,
        writer: Writer,
        backend: &dyn Backend,
        features: &[Feature],
    ) -> Option<RollbackReport> {
        let _change = self.begin();
        (self.doc(|d| d.writer) == Some(writer)).then(|| self.rollback_held(backend, features))
    }

    fn rollback_held(&self, backend: &dyn Backend, features: &[Feature]) -> RollbackReport {
        let records = self.doc(|d| d.records.clone());
        let mut report = RollbackReport::default();
        let mut retired = Vec::new();
        let mut touched = Vec::new();
        for r in records.iter().rev() {
            if !features.contains(&r.feature) || !admitted(r, self.admit_reg) {
                continue;
            }
            match restore(backend, r) {
                Ok(Restored::Written) => {
                    touched.push(r.target.clone());
                    report.restored.push(r.target.clone());
                }
                Ok(Restored::Already) => report.restored.push(r.target.clone()),
                Ok(Restored::KeptUserValue) => {
                    tracing::info!(target = %r.target.label(), "value changed by someone else; kept");
                    report.kept_user_value.push(r.target.clone());
                }
                Err(e) => {
                    tracing::warn!(target = %r.target.label(), error = %e, "tweak rollback failed; record kept");
                    report.failed.push(r.target.clone());
                    continue;
                }
            }
            retired.push(r.clone());
        }
        let me = self.me;
        if !retired.is_empty()
            && let Err(e) = self.store.read().update(|d| {
                d.records.retain(|r| !retired.contains(r));
                d.writer = Some(me);
            })
        {
            // The values are back; the stale records find them at the baseline next time.
            tracing::warn!(error = %e, "tweak journal not saved after rollback");
        }
        if !touched.is_empty() {
            backend.changed(&touched);
        }
        report
    }

    /// Reads the journalled values of `feature` back.
    pub fn status(&self, backend: &dyn Backend, feature: Feature) -> TweakState {
        let _serial = self.lock.lock();
        let records = self.records(feature);
        if records.is_empty() {
            return TweakState::Off;
        }
        let mut state = TweakState::On;
        for r in &records {
            match backend.read(&r.target) {
                Ok(v) if v == r.applied => {}
                Ok(_) => state = TweakState::Drifted,
                Err(_) => return TweakState::Unknown,
            }
        }
        state
    }
}

/// A change in progress: the file lock, then this process's lock, released together.
struct Change<'a> {
    _held: lock::Held,
    _serial: parking_lot::MutexGuard<'a, ()>,
}

enum Restored {
    Written,
    Already,
    KeptUserValue,
}

fn restore(backend: &dyn Backend, r: &Record) -> Result<Restored, TweakError> {
    let current = backend
        .read(&r.target)
        .map_err(|e| TweakError::Unreadable(r.target.label(), e))?;
    let outcome = if current == r.baseline {
        Restored::Already
    } else if current == r.applied {
        write_verified(backend, &r.target, &r.baseline).1?;
        Restored::Written
    } else {
        return Ok(Restored::KeptUserValue);
    };
    if r.created && r.baseline == Val::Absent {
        prune(backend, &r.target);
    }
    Ok(outcome)
}

fn find<'a>(
    records: &'a mut [Record],
    feature: Feature,
    target: &Target,
) -> Option<&'a mut Record> {
    records
        .iter_mut()
        .find(|r| r.feature == feature && r.target == *target)
}

/// Writes and reads back. Also reports whether the write created the container, even when the
/// verification failed (the undo must still remove it).
fn write_verified(
    backend: &dyn Backend,
    target: &Target,
    value: &Val,
) -> (bool, Result<(), TweakError>) {
    let created = match backend.write(target, value) {
        Ok(created) => created,
        Err(e) => return (false, Err(TweakError::Write(target.label(), e))),
    };
    let verified = match backend.read(target) {
        Ok(v) if v == *value => Ok(()),
        Ok(_) => Err(TweakError::NotVerified(target.label())),
        Err(e) => Err(TweakError::Unreadable(target.label(), e)),
    };
    (created, verified)
}

/// An empty container left behind is cosmetic: logged, never a failure.
fn prune(backend: &dyn Backend, target: &Target) {
    if let Err(e) = backend.prune(target) {
        tracing::warn!(target = %target.label(), error = %e, "empty tweak container not removed");
    }
}
