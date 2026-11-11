//! Runtime state of the Servers page: per-row and per-group transient state, dialogs, the bulk
//! notice. Lives in the page root, which the shell keeps mounted, so pings, health verdicts, the
//! add draft and running imports / refreshes / exports survive navigation (ui-servers §3.1).
use std::collections::{HashMap, HashSet};

use dioxus::core::{ScopeId, Task};
use dioxus::prelude::*;
use vpnte_base::types::{ClientDevice, UnixMs, now_ms};

use super::model::{AddTarget, ExportReport, ImportReport, KeyHealth, ServerView, ServersView};
use super::present::PingState;
use crate::widgets::UiError;

/// Transient state of one server row.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct RowRt {
    pub ping: PingState,
    /// This session's health verdict (newer than the persisted one).
    pub health: Option<KeyHealth>,
    pub verifying: bool,
    pub starting_proxy: bool,
    pub exporting: bool,
    pub restoring: bool,
}

impl RowRt {
    /// A finished direct ping. One that answered clears this session's health verdict: it
    /// proves the endpoint is reachable now; a failed one does not (direct TCP pings are often
    /// filtered while the key works — only positive evidence overrides).
    pub fn ping_done(&mut self, ms: Option<u32>) {
        self.ping = PingState::Done(ms);
        if ms.is_some() {
            self.health = None;
        }
    }
}

/// The health verdict a row shows: this session's, else the persisted one.
pub(crate) fn effective_health<'a>(
    row: Option<&'a RowRt>,
    server: &'a ServerView,
) -> Option<&'a KeyHealth> {
    row.and_then(|r| r.health.as_ref())
        .or(server.health.as_ref())
}

/// Busy flags of one group's actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct GroupBusy {
    pub refresh: bool,
    pub health: bool,
    pub proxies: bool,
    pub policy: bool,
}

/// A destructive action waiting for confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Confirm {
    DeleteGroup {
        id: String,
        name: String,
        servers: usize,
    },
    DeleteServer {
        id: String,
        name: String,
        connected: bool,
    },
    /// Deleting an already removed server for good.
    PurgeServer { id: String, name: String },
}

/// Which bulk export a notice is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BulkKind {
    Keys,
    Proxies,
}

/// The notice above the list while / after a bulk export runs.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Bulk {
    Working(BulkKind),
    Done(BulkKind, ExportReport),
    Failed(BulkKind, UiError),
}

/// Draft and outcome of the add dialog.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct AddForm {
    pub input: String,
    pub target: AddTarget,
    pub device: ClientDevice,
    pub busy: bool,
    pub error: Option<UiError>,
    pub report: Option<ImportReport>,
}

/// The page state, `Copy`, provided to every part of the page through context.
#[derive(Clone, Copy, PartialEq)]
pub(crate) struct Store {
    /// The page root: long work is spawned here so it outlives rows and dialogs.
    pub scope: ScopeId,
    pub view: Signal<ServersView>,
    /// Wall clock for relative times («5 минут назад»), ticked by the page while it is visible.
    pub now: Signal<UnixMs>,
    pub rows: Signal<HashMap<String, RowRt>>,
    pub busy: Signal<HashMap<String, GroupBusy>>,
    pub expanded: Signal<Vec<String>>,
    /// Groups expanded automatically once (a sole group); a later collapse sticks.
    pub auto_expanded: Signal<HashSet<String>>,
    /// A `select` call of this page in flight.
    pub selecting: Signal<Option<String>>,
    pub detail: Signal<Option<String>>,
    pub batch_open: Signal<bool>,
    pub add_open: Signal<bool>,
    pub add: Signal<AddForm>,
    pub confirm: Signal<Option<Confirm>>,
    pub confirm_busy: Signal<bool>,
    /// Group being renamed and the draft name.
    pub rename: Signal<Option<(String, String)>>,
    pub bulk: Signal<Option<Bulk>>,
    /// The running ping-all (a second click cancels it) and the row states it replaced.
    pub ping_task: Signal<Option<Task>>,
    pub ping_before: Signal<Vec<(String, PingState)>>,
}

impl Store {
    /// Creates the state in the page root (call inside `use_hook`).
    pub fn new(scope: ScopeId, view: ServersView, expanded: Vec<String>) -> Self {
        Self {
            scope,
            view: Signal::new(view),
            now: Signal::new(now_ms()),
            rows: Signal::new(HashMap::new()),
            busy: Signal::new(HashMap::new()),
            expanded: Signal::new(expanded),
            auto_expanded: Signal::new(HashSet::new()),
            selecting: Signal::new(None),
            detail: Signal::new(None),
            batch_open: Signal::new(false),
            add_open: Signal::new(false),
            add: Signal::new(AddForm::default()),
            confirm: Signal::new(None),
            confirm_busy: Signal::new(false),
            rename: Signal::new(None),
            bulk: Signal::new(None),
            ping_task: Signal::new(None),
            ping_before: Signal::new(Vec::new()),
        }
    }

    /// Changes one row's transient state.
    pub fn row(&self, id: &str, f: impl FnOnce(&mut RowRt)) {
        let mut rows = self.rows;
        f(rows.write().entry(id.to_owned()).or_default());
    }

    /// Changes one group's busy flags.
    pub fn group_busy(&self, id: &str, f: impl FnOnce(&mut GroupBusy)) {
        let mut busy = self.busy;
        f(busy.write().entry(id.to_owned()).or_default());
    }
}

/// Expanded ids after a store change: drops ids of groups that no longer exist (keeps unknown
/// ones until the first loaded snapshot) and expands a sole group once per id.
pub(crate) fn reconcile_expanded(
    expanded: &[String],
    auto_done: &HashSet<String>,
    bucket_ids: &[String],
    loaded: bool,
) -> Option<(Vec<String>, Option<String>)> {
    let mut next: Vec<String> = if loaded {
        expanded
            .iter()
            .filter(|id| bucket_ids.contains(id))
            .cloned()
            .collect()
    } else {
        expanded.to_vec()
    };
    let mut auto = None;
    if let [only] = bucket_ids
        && !auto_done.contains(only)
    {
        if !next.contains(only) {
            next.push(only.clone());
        }
        auto = Some(only.clone());
    }
    (next != expanded || auto.is_some()).then_some((next, auto))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::servers::model::KeyHealthReason;

    fn dead() -> KeyHealth {
        KeyHealth {
            online: false,
            latency_ms: None,
            reason: Some(KeyHealthReason::Timeout),
            checked_at: 1,
        }
    }

    /// Source-pinned rule "a successful direct ping clears the stale health verdict"; a failed
    /// one keeps it (S-16: only positive evidence overrides).
    #[test]
    fn a_fresh_ping_clears_only_on_success() {
        let mut row = RowRt {
            health: Some(dead()),
            ..RowRt::default()
        };
        row.ping_done(None);
        assert_eq!(row.ping, PingState::Done(None));
        assert!(row.health.is_some());
        row.ping_done(Some(42));
        assert_eq!(row.ping, PingState::Done(Some(42)));
        assert!(row.health.is_none());
    }

    #[test]
    fn session_health_wins_over_the_persisted_one() {
        let server = ServerView {
            health: Some(KeyHealth {
                online: true,
                ..dead()
            }),
            ..ServerView::default()
        };
        assert!(effective_health(None, &server).is_some_and(|h| h.online));
        let row = RowRt {
            health: Some(dead()),
            ..RowRt::default()
        };
        assert!(effective_health(Some(&row), &server).is_some_and(|h| !h.online));
    }

    /// §3.1 auto-expand: a sole group opens once per id; a later collapse sticks; ids of deleted
    /// groups are forgotten once the store has loaded.
    #[test]
    fn expanded_groups_follow_the_store() {
        let ids = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let mut done = HashSet::new();
        let (next, auto) = reconcile_expanded(&[], &done, &ids(&["g1"]), true).expect("changed");
        assert_eq!((next, auto.clone()), (ids(&["g1"]), Some("g1".into())));
        done.insert(auto.unwrap_or_default());
        assert_eq!(
            reconcile_expanded(&[], &done, &ids(&["g1"]), true),
            None,
            "collapse sticks"
        );
        let (next, _) = reconcile_expanded(&ids(&["g1", "gone"]), &done, &ids(&["g1", "g2"]), true)
            .expect("pruned");
        assert_eq!(next, ids(&["g1"]));
        assert_eq!(
            reconcile_expanded(&ids(&["later"]), &done, &[], false),
            None,
            "nothing is pruned before the first snapshot"
        );
    }
}
