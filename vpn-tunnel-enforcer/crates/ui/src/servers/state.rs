//! Runtime state of the Servers page: per-row and per-group transient state, dialogs, the bulk
//! notice. Lives in the page root, which the shell keeps mounted, so pings, health verdicts, the
//! add draft and running imports / refreshes / exports survive navigation (ui-servers §3.1).
use std::collections::{HashMap, HashSet};

use dioxus::core::{ScopeId, Task};
use dioxus::prelude::*;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, UnixMs, now_ms};

use super::check::{Totals, row_tags, totals};
use super::check_model::{CheckKey, CheckStage};
use super::model::{
    AddTarget, ExportReport, ImportReport, KeyHealth, ServerView, ServersView, SubscriptionRequest,
};
use super::present::PingState;
use super::schemes::SchemesPanel;
use crate::widgets::UiError;

/// Transient state of one server row.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct RowRt {
    pub ping: PingState,
    /// This session's health verdict (newer than the persisted one), and the tag of the key it
    /// is about: shown only while the row holds that key (b2).
    pub health: Option<KeyHealth>,
    pub health_tag: u64,
    pub verifying: bool,
    pub starting_proxy: bool,
    pub exporting: bool,
    pub restoring: bool,
    /// Where the row's key is in the last key check that took it (p-check-live): said on the
    /// row in numbers as it happens, kept after the run until the next check of the row.
    pub check: Option<RowCheck>,
}

/// Which key check a row's stage belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum RunKey {
    /// «Проверить работу» over the whole list.
    List,
    /// A group's «Проверить».
    Group(String),
}

/// A row's stage in a key check, and the tag of the key it is about (shown and counted only
/// while the row holds that key, b2).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RowCheck {
    pub run: RunKey,
    pub tag: u64,
    pub stage: CheckStage,
}

/// A key check of the page that told its first stage, running or over.
#[derive(Debug, Clone)]
pub(crate) struct CheckRun {
    /// «Отменить» cancels it: the backend answers what landed.
    pub stop: CancellationToken,
    pub state: RunState,
    /// Its numbers as they were when it ended: a later check takes its rows' lines, and an
    /// ended strip never changes after (a1).
    pub totals: Option<Totals>,
}

/// Where a key check is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunState {
    Running,
    /// «Отменить» was pressed; the answer with what landed is on its way.
    Stopping,
    Ended {
        stopped: bool,
    },
}

impl RunState {
    pub fn running(self) -> bool {
        !matches!(self, RunState::Ended { .. })
    }
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
    row.filter(|r| r.health_tag == server.key_tag)
        .and_then(|r| r.health.as_ref())
        .or(server.health.as_ref())
}

/// Busy flags of one group's actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct GroupBusy {
    pub refresh: bool,
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
    /// Request settings a new subscription group starts with (HWID off by default).
    pub request: SubscriptionRequest,
    pub busy: bool,
    /// A source (clipboard, file, QR) is being read into the draft.
    pub reading: bool,
    /// The draft is a link Windows handed over (the dialog says so; the user confirms it).
    pub from_link: bool,
    pub error: Option<UiError>,
    pub report: Option<ImportReport>,
}

impl AddForm {
    /// After an import: the next paste starts its own group with the new-group defaults. The
    /// previous provider's headers (they may be tokens) and HWID choice never reach the next one.
    pub(crate) fn imported(&mut self) {
        self.input.clear();
        self.from_link = false;
        self.target = AddTarget::Auto;
        self.request = SubscriptionRequest::default();
    }

    /// A link Windows handed over becomes the draft, with the new-group defaults: whatever the
    /// user set up for the previous provider (headers that may be tokens, HWID, a target group)
    /// never reaches the provider the link names. It came from outside until the user edits it.
    pub(crate) fn linked(&mut self, link: String) {
        self.input = link;
        self.error = None;
        self.report = None;
        self.from_link = true;
        self.target = AddTarget::Auto;
        self.request = SubscriptionRequest {
            from_outside: true,
            ..SubscriptionRequest::default()
        };
    }

    /// The dialog closed: the report goes, and so do the request settings (header values may be
    /// tokens, and the hint promises they are never shown again); the pasted text stays a draft,
    /// still marked when it came from outside.
    pub(crate) fn closed(&mut self) {
        self.report = None;
        self.from_link = false;
        self.request = SubscriptionRequest {
            from_outside: self.request.from_outside,
            ..SubscriptionRequest::default()
        };
    }
}

/// The request dialog of one subscription: the HWID switch acts at once; the headers are a draft
/// that replaces all of them (values never come back from the backend: they may be tokens).
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct RequestForm {
    pub group: String,
    pub name: String,
    pub headers: String,
    pub busy: bool,
    pub error: Option<UiError>,
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
    /// The link-scheme panel.
    pub schemes_open: Signal<bool>,
    pub schemes: Signal<SchemesPanel>,
    /// The open request dialog (`None`: closed).
    pub request: Signal<Option<RequestForm>>,
    pub confirm: Signal<Option<Confirm>>,
    pub confirm_busy: Signal<bool>,
    /// Group being renamed and the draft name.
    pub rename: Signal<Option<(String, String)>>,
    pub bulk: Signal<Option<Bulk>>,
    /// The running ping-all (a second click cancels it) and the row states it replaced.
    pub ping_task: Signal<Option<Task>>,
    pub ping_before: Signal<Vec<(String, PingState)>>,
    /// The key checks of this page (the list-wide one and the groups') that told a stage,
    /// running or over: their strips.
    pub checks: Signal<HashMap<RunKey, CheckRun>>,
    /// A check started whose first stage has not come yet: no strip until it does, and a start
    /// refused before any stage leaves the previous strip and lines as they were (a4).
    pub launching: Signal<Option<(RunKey, CancellationToken)>>,
    /// Re-renders the countdowns every second while a check runs and when the page is shown
    /// again; they read the clock themselves (a2).
    pub tick: Signal<UnixMs>,
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
            schemes_open: Signal::new(false),
            schemes: Signal::new(SchemesPanel::default()),
            request: Signal::new(None),
            confirm: Signal::new(None),
            confirm_busy: Signal::new(false),
            rename: Signal::new(None),
            bulk: Signal::new(None),
            ping_task: Signal::new(None),
            ping_before: Signal::new(Vec::new()),
            checks: Signal::new(HashMap::new()),
            launching: Signal::new(None),
            tick: Signal::new(now_ms()),
        }
    }

    /// Changes one row's transient state.
    pub fn row(&self, id: &str, f: impl FnOnce(&mut RowRt)) {
        let mut rows = self.rows;
        f(rows.write().entry(id.to_owned()).or_default());
    }

    /// The tag of the key row `id` holds now (`None`: the row is gone).
    fn holds(&self, id: &str) -> Option<u64> {
        let view = self.view.peek();
        view.servers.iter().find(|s| s.id == id).map(|s| s.key_tag)
    }

    /// A key check's verdict for a row; dropped when the row is gone or holds another key now
    /// (a refresh re-keyed it while the check ran, b2).
    pub fn health_landed(&self, key: &CheckKey, health: KeyHealth) {
        if self.holds(&key.id) == Some(key.tag) {
            self.row(&key.id, |r| {
                r.health = Some(health);
                r.health_tag = key.tag;
            });
        }
    }

    /// A row's key reached `stage` in the check `run` (its first stage shows the run's strip);
    /// dropped like a verdict for a key the row no longer holds.
    pub fn staged(&self, run: &RunKey, key: &CheckKey, stage: CheckStage) {
        self.first_stage(run);
        if self.holds(&key.id) == Some(key.tag) {
            let (run, tag) = (run.clone(), key.tag);
            self.row(&key.id, |r| r.check = Some(RowCheck { run, tag, stage }));
        }
    }

    /// The check of the servers going on in this page, if any: one at a time (a1).
    pub fn current_run(&self) -> Option<RunKey> {
        if let Some((run, _)) = &*self.launching.read() {
            return Some(run.clone());
        }
        let checks = self.checks.read();
        let running = checks.iter().find(|(_, c)| c.state.running());
        running.map(|(run, _)| run.clone())
    }

    /// A new check `run` starts; its strip shows with its first stage.
    pub fn run_started(&self, run: RunKey, stop: CancellationToken) {
        let mut launching = self.launching;
        launching.set(Some((run, stop)));
    }

    /// The first stage of `run`: the rows its previous run left lose their lines, its strip
    /// starts.
    fn first_stage(&self, run: &RunKey) {
        let mut launching = self.launching;
        let Some(stop) = launching
            .peek()
            .as_ref()
            .filter(|(r, _)| r == run)
            .map(|(_, stop)| stop.clone())
        else {
            return;
        };
        launching.set(None);
        let mut rows = self.rows;
        for r in rows.write().values_mut() {
            if r.check.as_ref().is_some_and(|c| c.run == *run) {
                r.check = None;
            }
        }
        let mut checks = self.checks;
        let state = if stop.is_cancelled() {
            RunState::Stopping
        } else {
            RunState::Running
        };
        let started = CheckRun {
            stop,
            state,
            totals: None,
        };
        checks.write().insert(run.clone(), started);
    }

    /// «Отменить»: the check stops at once and answers what landed.
    pub fn stop_run(&self, run: &RunKey) {
        if let Some((_, stop)) = self.launching.peek().as_ref().filter(|(r, _)| r == run) {
            stop.cancel();
            return;
        }
        let mut checks = self.checks;
        if let Some(c) = checks
            .write()
            .get_mut(run)
            .filter(|c| c.state == RunState::Running)
        {
            c.stop.cancel();
            c.state = RunState::Stopping;
        }
    }

    /// The check `run` is over: its rows without a result are not checked and its numbers are
    /// kept as they are now. One that ended before its first stage (refused, failed) leaves
    /// nothing behind.
    pub fn run_ended(&self, run: &RunKey) {
        let mut launching = self.launching;
        if launching.peek().as_ref().is_some_and(|(r, _)| r == run) {
            launching.set(None);
            return;
        }
        let mut rows = self.rows;
        for r in rows.write().values_mut() {
            if let Some(c) = r
                .check
                .as_mut()
                .filter(|c| c.run == *run && !c.stage.is_final())
            {
                c.stage = CheckStage::NotChecked;
            }
        }
        let view = self.view.peek();
        let numbers = totals(&self.rows.peek(), &row_tags(&view), run, now_ms());
        drop(view);
        let mut checks = self.checks;
        if let Some(c) = checks.write().get_mut(run) {
            let stopped = c.stop.is_cancelled();
            c.state = RunState::Ended { stopped };
            c.totals = Some(numbers);
        }
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
