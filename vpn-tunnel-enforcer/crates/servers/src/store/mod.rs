//! [`Servers`]: the one owner of the server list. Every change is a closure applied to the current
//! document under the store's writer lock (S-10: no read-await-write races), written through
//! atomically, then announced on a broadcast channel. Pings live in memory only.
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use tokio::sync::broadcast;
use vpnte_base::types::{ClientDevice, now_ms};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::store::{Mode, Store};
use vpnte_profiles::model::SubscriptionMeta;

use crate::model::{
    ArchiveReason, GroupId, GroupSummary, HealthRecord, Ping, ProfileId, ServerRow, ServerSummary,
    ServersDoc, ServersView, VerdictRecord, VerifiedCountry,
};

mod add;
mod edit;
mod probes;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod verdict_tests;

pub use add::subscription_name;

/// Something changed in the list; re-read with [`Servers::view`] / [`Servers::active`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServersEvent {
    /// Groups or rows changed.
    Changed,
    /// The stored selection changed (`None`: cleared; [`Servers::active`] then falls back).
    ActiveChanged(Option<ProfileId>),
    /// A ping result was recorded (memory only).
    Ping(ProfileId),
    /// A subscription refresh started / finished (sent by the refresh code).
    RefreshStarted(GroupId),
    RefreshFinished(GroupId),
}

/// Who selects: automation refuses every archived row, the user only rows they removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectBy {
    User,
    Automation,
}

/// The server a connection uses.
#[derive(Debug, Clone, PartialEq)]
pub struct Active {
    pub row: ServerRow,
    /// True when this is not the user's selection but the first usable row (the UI says so, S-37).
    pub fallback: bool,
}

/// Where [`Servers::add`] puts new keys.
#[derive(Debug, Clone)]
pub enum AddTarget {
    /// Keys the user pasted, into `group` (`None`: the manual-keys group, created on demand). They
    /// are `origin = manual`, keep their own device and are never archived by a refresh (S-22).
    Keys {
        group: Option<GroupId>,
        device: ClientDevice,
    },
    /// The first import of a subscription. Its group (key: URL + device) is looked up again inside
    /// the commit, so a concurrent import of the same URL appends instead of duplicating.
    Subscription(Box<NewSubscription>),
}

/// A fetched subscription for [`AddTarget::Subscription`].
#[derive(Debug, Clone)]
pub struct NewSubscription {
    /// Canonical `http(s)` URL.
    pub url: url::Url,
    pub device: ClientDevice,
    /// Everything the provider sent (S-45: stored at import, not only after the first refresh).
    pub info: SubscriptionMeta,
    /// The parser skipped entries.
    pub partial: bool,
}

/// What [`Servers::add`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddReport {
    pub group: GroupId,
    pub added: Vec<ProfileId>,
    /// Archived rows of the target group that the same key brought back.
    pub restored: Vec<ProfileId>,
    /// Keys already in the target group (or repeated in the input).
    pub duplicates: usize,
    /// Set when nothing was selected before: the first new row became the selection.
    pub selected: Option<ProfileId>,
}

/// One key-health result for [`Servers::record_health`].
#[derive(Debug, Clone, PartialEq)]
pub struct HealthUpdate {
    pub id: ProfileId,
    /// [`ServerRow::identity`] when the probe started: a key changed meanwhile is not overwritten.
    pub identity: [u8; 16],
    pub record: HealthRecord,
    pub country: Option<VerifiedCountry>,
}

/// One classifier verdict for [`Servers::record_verdicts`].
#[derive(Debug, Clone, PartialEq)]
pub struct VerdictUpdate {
    pub id: ProfileId,
    /// [`ServerRow::identity`] when the check started: a key changed meanwhile is not judged.
    pub identity: [u8; 16],
    pub record: VerdictRecord,
}

/// Handle to the server list (`profiles.json`). Share it in an `Arc`.
pub struct Servers {
    store: Store<ServersDoc>,
    events: broadcast::Sender<ServersEvent>,
    pings: Mutex<HashMap<ProfileId, Ping>>,
    /// Bumped by every selection: exit-country lookups started before it are discarded.
    geo_generation: AtomicU64,
}

impl Servers {
    /// Opens `profiles.json` under the data root and purges archive rows past their 30 days.
    pub fn open(root: &Path) -> Self {
        let (events, _) = broadcast::channel(64);
        let servers = Self {
            store: Store::open(root),
            events,
            pings: Mutex::new(HashMap::new()),
            geo_generation: AtomicU64::new(0),
        };
        // A read-only document (newer version, damaged) is left exactly as it is.
        if servers.mode() == Mode::Writable
            && let Err(err) = servers.purge_expired(now_ms())
        {
            tracing::warn!("servers: archive purge at start failed: {err}");
        }
        servers
    }

    /// Change notifications (on `Lagged`, re-read the view).
    pub fn subscribe(&self) -> broadcast::Receiver<ServersEvent> {
        self.events.subscribe()
    }

    /// Runs `f` on the current document (no lock is held after it returns).
    pub fn read<R>(&self, f: impl FnOnce(&ServersDoc) -> R) -> R {
        self.store.read(f)
    }

    /// Whether changes can be saved; [`Servers::notice`] explains a read-only document.
    pub fn mode(&self) -> Mode {
        self.store.mode()
    }

    /// Banner text for a read-only or set-aside `profiles.json`.
    pub fn notice(&self) -> Option<Msg> {
        self.store.notice()
    }

    /// Maintenance: moves a corrupt / unreadable `profiles.json` aside and starts empty.
    pub fn set_aside(&self) -> AppResult<()> {
        self.store.set_aside()?;
        self.pings.lock().clear();
        self.emit(ServersEvent::Changed);
        Ok(())
    }

    /// Applies `f` to a copy of the document and saves it. An `Err` from `f` discards every change
    /// it made; listeners hear about a change only after it is on disk.
    pub(crate) fn update<R>(
        &self,
        f: impl FnOnce(&mut ServersDoc) -> AppResult<R>,
    ) -> AppResult<R> {
        let (mut changed, mut active) = (false, None);
        let out = self.store.update(|doc| {
            let out = f(doc);
            // Under the writer lock the store still holds the saved document: compare against it,
            // or put it back (core would otherwise save the half-applied change).
            self.store.read(|saved| match &out {
                Ok(_) => {
                    changed = doc != saved;
                    if doc.active_profile_id != saved.active_profile_id {
                        active = Some(doc.active_profile_id.clone());
                    }
                }
                Err(_) => *doc = saved.clone(),
            });
            out
        })??;
        if changed {
            self.emit(ServersEvent::Changed);
        }
        if let Some(id) = active {
            self.emit(ServersEvent::ActiveChanged(id));
        }
        Ok(out)
    }

    /// Sends an event; having no listener is fine.
    pub(crate) fn emit(&self, event: ServersEvent) {
        let _ = self.events.send(event);
    }
}

// --- reading and selection ---
impl Servers {
    /// Groups and rows without secrets, the effective selection and the live pings.
    pub fn view(&self) -> ServersView {
        let now = now_ms();
        let pings = self.pings.lock().clone();
        let notice = self.store.notice();
        self.store.read(|doc| {
            let active = resolve_active(doc);
            let selected = active.map(|(row, _)| &row.id);
            ServersView {
                groups: doc
                    .groups
                    .iter()
                    .map(|g| GroupSummary::of(g, &doc.profiles, now))
                    .collect(),
                servers: doc
                    .profiles
                    .iter()
                    .map(|r| {
                        ServerSummary::of(r, pings.get(&r.id).copied(), selected == Some(&r.id))
                    })
                    .collect(),
                active: selected.cloned(),
                fallback: active.is_some_and(|(_, fallback)| fallback),
                notice,
            }
        })
    }

    /// The row with `id` (with its sealed profile: open it with [`ServerRow::profile`]).
    pub fn get(&self, id: &ProfileId) -> Option<ServerRow> {
        self.store.read(|doc| doc.row(id).cloned())
    }

    /// The selected row when it is still usable (a provider-archived row is, with a warning), else
    /// the first row that is neither archived nor locked, flagged as a fallback.
    pub fn active(&self) -> Option<Active> {
        self.store.read(|doc| {
            resolve_active(doc).map(|(row, fallback)| Active {
                row: row.clone(),
                fallback,
            })
        })
    }

    /// Selects `id` and supersedes in-flight exit-country lookups, even when `id` was already selected.
    pub fn select(&self, id: &ProfileId, by: SelectBy) -> AppResult<ServerRow> {
        self.update(|doc| {
            let row = doc.row(id).ok_or_else(server_not_found)?;
            let refused = match by {
                SelectBy::User => row.archived_for(ArchiveReason::User),
                SelectBy::Automation => row.archived.is_some(),
            };
            if refused {
                return Err(AppError::conflict(Msg::new("servers.select.archived")));
            }
            if row.is_locked() {
                return Err(AppError::conflict(Msg::new("servers.locked")));
            }
            let row = row.clone();
            doc.active_profile_id = Some(id.clone());
            // Under the writer lock, so `record_country` sees either the old or the new generation
            // together with the matching selection.
            self.geo_generation.fetch_add(1, Ordering::SeqCst);
            Ok(row)
        })
    }

    /// Current selection generation (pass it back to [`Servers::record_country`]).
    pub fn geo_generation(&self) -> u64 {
        self.geo_generation.load(Ordering::SeqCst)
    }

    /// The subscription group of `(url, device)`: a re-paste refreshes it instead of importing again.
    pub fn find_subscription(&self, url: &url::Url, device: ClientDevice) -> Option<GroupId> {
        self.store
            .read(|doc| doc.subscription_group(url, device).map(|g| g.id.clone()))
    }

    /// Every server host of the list, lower case and de-duplicated (traffic-history infra filter).
    pub fn all_hosts(&self) -> Vec<String> {
        self.store.read(|doc| {
            let mut seen = HashSet::new();
            doc.profiles
                .iter()
                .map(|r| r.server.to_ascii_lowercase())
                .filter(|h| !h.is_empty() && seen.insert(h.clone()))
                .collect()
        })
    }
}

fn resolve_active(doc: &ServersDoc) -> Option<(&ServerRow, bool)> {
    let selected = doc
        .active_profile_id
        .as_ref()
        .and_then(|id| doc.row(id))
        .filter(|row| !row.archived_for(ArchiveReason::User));
    match selected {
        Some(row) => Some((row, false)),
        None => doc
            .profiles
            .iter()
            .find(|r| r.archived.is_none() && !r.is_locked())
            .map(|row| (row, true)),
    }
}

/// `Conflict servers.notFound`: the row is gone (deleted meanwhile).
pub(crate) fn server_not_found() -> AppError {
    AppError::conflict(Msg::new("servers.notFound"))
}

/// `Conflict servers.group.notFound`: the group is gone (deleted meanwhile).
pub(crate) fn group_not_found() -> AppError {
    AppError::conflict(Msg::new("servers.group.notFound"))
}
