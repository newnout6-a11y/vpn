//! Request-lifetime vectors of ui-servers §7.4 / §7.5 (AT-00-003 / AT-00-004 / AT-00-008), run in
//! a real `VirtualDom` against a fake backend whose replies the test holds: a cancelled or
//! aborted run drops the backend future (so a late reply has nowhere to go), typed cancellation
//! is silent, a timeout is shown, history reloads never touch a running check, a soft stop keeps
//! the partial batch.
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::time::Duration;

use dioxus::core::ScopeId;
use dioxus::prelude::*;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::ClientDevice;
use vpnte_base::{AppError, AppResult, ErrorKind};

use super::api::ServersApi;
use super::batch::BatchCtl;
use super::live::{History, LiveCtl};
use super::live_model::*;
use super::model::*;

type Reply<T> = oneshot::Receiver<AppResult<T>>;

/// Counts futures dropped before they finished (= cancelled by the UI).
struct Track(Rc<Cell<u32>>, bool);

impl Drop for Track {
    fn drop(&mut self) {
        if !self.1 {
            self.0.set(self.0.get() + 1);
        }
    }
}

/// Backend whose live / history / batch replies are queued by the test.
#[derive(Default)]
struct FakeApi {
    state: watch::Sender<ServersView>,
    live: RefCell<VecDeque<Reply<LiveCheck>>>,
    history: RefCell<VecDeque<AppResult<Vec<LiveCheck>>>>,
    batch: RefCell<VecDeque<Reply<BatchResult>>>,
    batch_token: RefCell<Option<CancellationToken>>,
    batch_progress: RefCell<Option<mpsc::UnboundedSender<BatchProgress>>>,
    dropped: Rc<Cell<u32>>,
}

async fn held<T>(reply: Option<Reply<T>>, dropped: Rc<Cell<u32>>) -> AppResult<T> {
    let mut track = Track(dropped, false);
    let result = match reply {
        Some(rx) => rx.await.unwrap_or_else(|_| Err(AppError::cancelled())),
        None => Err(AppError::new(ErrorKind::Internal)),
    };
    track.1 = true;
    result
}

fn unused<T>() -> AppResult<T> {
    Err(AppError::new(ErrorKind::Internal))
}

#[async_trait::async_trait(?Send)]
impl ServersApi for FakeApi {
    fn state(&self) -> watch::Receiver<ServersView> {
        self.state.subscribe()
    }
    fn expanded_groups(&self) -> Vec<String> {
        Vec::new()
    }
    async fn save_expanded_groups(&self, _: Vec<String>) -> AppResult<()> {
        Ok(())
    }
    async fn resolve_ips(&self) -> AppResult<()> {
        Ok(())
    }
    async fn add(&self, _: String, _: AddTarget, _: ClientDevice) -> AppResult<ImportReport> {
        unused()
    }
    async fn remove(&self, _: &str) -> AppResult<()> {
        unused()
    }
    async fn restore(&self, _: &str) -> AppResult<()> {
        unused()
    }
    async fn purge(&self, _: &str) -> AppResult<()> {
        unused()
    }
    async fn select(&self, _: &str) -> AppResult<SelectOutcome> {
        unused()
    }
    async fn cancel_switch(&self) -> AppResult<()> {
        unused()
    }
    async fn ping_one(&self, _: &str) -> AppResult<Option<u32>> {
        unused()
    }
    async fn ping_many(
        &self,
        _: Vec<String>,
        _: mpsc::UnboundedSender<(String, Option<u32>)>,
    ) -> AppResult<()> {
        unused()
    }
    async fn verify_country(&self, _: &str) -> AppResult<CountryCheck> {
        unused()
    }
    async fn copy_key(&self, _: &str) -> AppResult<Duration> {
        unused()
    }
    async fn save_key(&self, _: &str) -> AppResult<Option<String>> {
        unused()
    }
    async fn export_all_keys(&self) -> AppResult<Option<ExportReport>> {
        unused()
    }
    async fn export_proxy_list(&self) -> AppResult<Option<ExportReport>> {
        unused()
    }
    async fn start_proxies(&self, _: Vec<String>) -> AppResult<ProxyStartReport> {
        unused()
    }
    async fn refresh_group(&self, _: &str) -> AppResult<RefreshOutcome> {
        unused()
    }
    async fn set_refresh_interval(&self, _: &str, _: Option<NonZeroU32>) -> AppResult<()> {
        unused()
    }
    async fn rename_group(&self, _: &str, _: String) -> AppResult<()> {
        unused()
    }
    async fn delete_group(&self, _: &str, _: bool) -> AppResult<()> {
        unused()
    }
    async fn check_group_health(&self, _: &str) -> AppResult<Vec<(String, KeyHealth)>> {
        unused()
    }
    async fn set_device(&self, _: &str, _: ClientDevice) -> AppResult<()> {
        unused()
    }
    async fn probe(&self, _: &str) -> AppResult<ProbeReport> {
        unused()
    }
    async fn geo(&self, _: &str) -> AppResult<Option<GeoInfo>> {
        unused()
    }
    async fn live_check(
        &self,
        _: &str,
        _: LiveMode,
        _: mpsc::UnboundedSender<LiveProgress>,
    ) -> AppResult<LiveCheck> {
        let reply = self.live.borrow_mut().pop_front();
        held(reply, self.dropped.clone()).await
    }
    async fn live_history(&self, _: &str) -> AppResult<Vec<LiveCheck>> {
        self.history
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Ok(Vec::new()))
    }
    async fn live_batch(
        &self,
        _: Vec<String>,
        stop: CancellationToken,
        progress: mpsc::UnboundedSender<BatchProgress>,
    ) -> AppResult<BatchResult> {
        self.batch_token.replace(Some(stop));
        self.batch_progress.replace(Some(progress));
        let reply = self.batch.borrow_mut().pop_front();
        held(reply, self.dropped.clone()).await
    }
    async fn open_url(&self, _: String) -> AppResult<()> {
        Ok(())
    }
}

fn fake() -> Rc<FakeApi> {
    Rc::new(FakeApi {
        state: watch::Sender::new(ServersView::default()),
        live: RefCell::default(),
        history: RefCell::default(),
        batch: RefCell::default(),
        batch_token: RefCell::default(),
        batch_progress: RefCell::default(),
        dropped: Rc::default(),
    })
}

/// The controllers created by the test root.
#[derive(Clone, Default)]
struct Harness {
    live: Rc<Cell<Option<LiveCtl>>>,
    batch: Rc<Cell<Option<BatchCtl>>>,
}

fn root() -> Element {
    let harness = use_context::<Harness>();
    let live = use_hook(LiveCtl::new);
    let batch = use_hook(BatchCtl::new);
    harness.live.set(Some(live));
    harness.batch.set(Some(batch));
    rsx! {}
}

fn mount() -> (VirtualDom, LiveCtl, BatchCtl) {
    let harness = Harness::default();
    let mut dom = VirtualDom::new(root).with_root_context(harness.clone());
    dom.rebuild_in_place();
    let (live, batch) = (harness.live.get(), harness.batch.get());
    (dom, live.expect("live ctl"), batch.expect("batch ctl"))
}

use crate::test_support::settle;

fn receipt(id: &str) -> LiveCheck {
    LiveCheck {
        id: id.into(),
        host: "vpn.mock.net".into(),
        port: 443,
        ..LiveCheck::default()
    }
}

fn hold_live(api: &FakeApi) -> oneshot::Sender<AppResult<LiveCheck>> {
    let (tx, rx) = oneshot::channel();
    api.live.borrow_mut().push_back(rx);
    tx
}

/// §7.4 "Defect 2" (AT-00-003): start → cancel → start; the first run's backend future is
/// dropped, so its late result can never overwrite the second one.
#[tokio::test]
async fn cancelled_live_check_never_lands() {
    let (mut dom, ctl, _) = mount();
    let api = fake();
    let first = hold_live(&api);
    dom.in_scope(ScopeId::APP, || ctl.start(api.clone(), "p".into()));
    settle(&mut dom, 4, 20).await;
    assert!(dom.in_runtime(|| ctl.run.peek().is_some()));
    dom.in_runtime(|| ctl.cancel());
    settle(&mut dom, 4, 20).await;
    assert!(dom.in_runtime(|| ctl.run.peek().is_none()), "idle at once");
    assert_eq!(api.dropped.get(), 1, "the backend run was dropped");
    assert!(first.send(Ok(receipt("late"))).is_err(), "nowhere to land");
    let second = hold_live(&api);
    dom.in_scope(ScopeId::APP, || ctl.start(api.clone(), "p".into()));
    settle(&mut dom, 4, 20).await;
    second.send(Ok(receipt("fresh"))).expect("run alive");
    settle(&mut dom, 4, 20).await;
    let (result, history) =
        dom.in_runtime(|| (ctl.result.peek().clone(), ctl.history.peek().clone()));
    assert_eq!(result.map(|r| r.id), Some("fresh".to_owned()));
    assert_eq!(
        history.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        ["fresh"]
    );
}

/// §7.4 AT-00-003 / AT-00-004: typed cancellation shows nothing; a timeout is shown; the run
/// button is usable again afterwards.
#[tokio::test]
async fn cancellation_is_silent_and_timeout_is_shown() {
    let (mut dom, ctl, _) = mount();
    let api = fake();
    let run = hold_live(&api);
    dom.in_scope(ScopeId::APP, || ctl.start(api.clone(), "p".into()));
    settle(&mut dom, 4, 20).await;
    run.send(Err(AppError::cancelled())).expect("run alive");
    settle(&mut dom, 4, 20).await;
    assert_eq!(
        dom.in_runtime(|| (ctl.error.peek().clone(), ctl.run.peek().is_some())),
        (None, false)
    );
    let run = hold_live(&api);
    dom.in_scope(ScopeId::APP, || ctl.start(api.clone(), "p".into()));
    settle(&mut dom, 4, 20).await;
    run.send(Err(AppError::timeout())).expect("run alive");
    settle(&mut dom, 4, 20).await;
    let error = dom
        .in_runtime(|| ctl.error.peek().clone())
        .expect("timeout shown");
    assert_eq!(
        (error.kind, error.msg.key.as_ref()),
        (ErrorKind::Timeout, "errors.timeout")
    );
    assert!(dom.in_runtime(|| ctl.run.peek().is_none()));
}

/// §7.4 "second review" + L-7: a failed history load says so (typed state, no sentinel text);
/// retrying it while a check runs does not cancel the check; history merges by id, newest first.
#[tokio::test]
async fn history_retry_leaves_a_running_check_alone() {
    let (mut dom, ctl, _) = mount();
    let api = fake();
    api.history
        .borrow_mut()
        .push_back(Err(AppError::new(ErrorKind::Network)));
    dom.in_scope(ScopeId::APP, || ctl.load_history(api.clone(), "p".into()));
    settle(&mut dom, 4, 20).await;
    assert_eq!(
        dom.in_runtime(|| *ctl.history_state.peek()),
        History::Failed
    );
    let run = hold_live(&api);
    dom.in_scope(ScopeId::APP, || ctl.start(api.clone(), "p".into()));
    api.history
        .borrow_mut()
        .push_back(Ok(vec![receipt("c1"), receipt("c0")]));
    dom.in_scope(ScopeId::APP, || ctl.load_history(api.clone(), "p".into()));
    settle(&mut dom, 4, 20).await;
    assert_eq!(dom.in_runtime(|| *ctl.history_state.peek()), History::Ready);
    assert!(
        dom.in_runtime(|| ctl.run.peek().is_some()),
        "the check still runs"
    );
    assert_eq!(api.dropped.get(), 0);
    assert_eq!(
        dom.in_runtime(|| ctl.result.peek().clone()).map(|r| r.id),
        Some("c1".into())
    );
    run.send(Ok(receipt("c2"))).expect("run alive");
    settle(&mut dom, 4, 20).await;
    let ids: Vec<String> =
        dom.in_runtime(|| ctl.history.peek().iter().map(|c| c.id.clone()).collect());
    assert_eq!(ids, ["c2", "c1", "c0"]);
}

fn hold_batch(api: &FakeApi) -> oneshot::Sender<AppResult<BatchResult>> {
    let (tx, rx) = oneshot::channel();
    api.batch.borrow_mut().push_back(rx);
    tx
}

fn batch_progress(index: u16, status: ProgressStatus, stage: Stage) -> BatchProgress {
    BatchProgress {
        profile_id: format!("s{index}"),
        index,
        total: 3,
        status,
        stage: Some(stage),
        median_mbps: None,
    }
}

/// §7.5 "accepts only matching, increasing progress" — now by construction: progress arrives on
/// the run's own channel, in order; B-2: «Остановить» is a soft stop and the partial batch the
/// backend returns is shown (the old dialog threw it away).
#[tokio::test]
async fn soft_stop_keeps_the_partial_batch() {
    let (mut dom, _, ctl) = mount();
    let api = fake();
    let reply = hold_batch(&api);
    dom.in_runtime(|| ctl.reset(vec!["s0".into(), "s1".into(), "s2".into()]));
    dom.in_scope(ScopeId::APP, || ctl.start(api.clone()));
    settle(&mut dom, 4, 20).await;
    let progress = api
        .batch_progress
        .borrow()
        .clone()
        .expect("progress channel");
    progress
        .send(batch_progress(0, ProgressStatus::Running, Stage::Dns))
        .expect("open");
    progress
        .send(batch_progress(
            0,
            ProgressStatus::Completed,
            Stage::Throughput,
        ))
        .expect("open");
    settle(&mut dom, 4, 20).await;
    let seen = dom
        .in_runtime(|| ctl.progress.peek().clone())
        .expect("progress shown");
    assert_eq!((seen.index, seen.status), (0, ProgressStatus::Completed));
    let token = api.batch_token.borrow().clone().expect("token passed");
    assert!(!token.is_cancelled());
    dom.in_runtime(|| ctl.stop());
    assert!(token.is_cancelled(), "soft stop goes through the token");
    assert!(dom.in_runtime(|| *ctl.stopping.peek()));
    let partial = BatchResult {
        cancelled: true,
        results: vec![receipt("s0")],
        errors: Vec::new(),
    };
    reply
        .send(Ok(partial.clone()))
        .expect("run alive after a soft stop");
    settle(&mut dom, 4, 20).await;
    assert_eq!(dom.in_runtime(|| ctl.result.peek().clone()), Some(partial));
    assert_eq!(
        dom.in_runtime(|| (ctl.run.peek().is_some(), *ctl.stopping.peek())),
        (false, false)
    );
    assert_eq!(api.dropped.get(), 0);
}

/// §7.5 "cancels on hide/unmount, ignoring a late error" + B-6: closing while running aborts —
/// the backend future is dropped, its late reply shows nothing, a new run starts clean.
#[tokio::test]
async fn closing_aborts_the_batch() {
    let (mut dom, _, ctl) = mount();
    let api = fake();
    let late = hold_batch(&api);
    dom.in_runtime(|| ctl.reset(vec!["s0".into()]));
    dom.in_scope(ScopeId::APP, || ctl.start(api.clone()));
    settle(&mut dom, 4, 20).await;
    dom.in_runtime(|| ctl.abort());
    settle(&mut dom, 4, 20).await;
    assert_eq!(api.dropped.get(), 1);
    assert!(late.send(Err(AppError::new(ErrorKind::Network))).is_err());
    assert_eq!(
        dom.in_runtime(|| (ctl.error.peek().clone(), ctl.result.peek().clone())),
        (None, None)
    );
    let reply = hold_batch(&api);
    dom.in_scope(ScopeId::APP, || ctl.start(api.clone()));
    settle(&mut dom, 4, 20).await;
    reply.send(Err(AppError::timeout())).expect("run alive");
    settle(&mut dom, 4, 20).await;
    assert_eq!(
        dom.in_runtime(|| ctl.error.peek().clone()).map(|e| e.kind),
        Some(ErrorKind::Timeout)
    );
}

/// The batch never starts without a selection (the start button is disabled for it too).
#[tokio::test]
async fn empty_selection_does_not_start() {
    let (mut dom, _, ctl) = mount();
    let api = fake();
    dom.in_runtime(|| ctl.reset(Vec::new()));
    dom.in_scope(ScopeId::APP, || ctl.start(api.clone()));
    settle(&mut dom, 4, 20).await;
    assert!(dom.in_runtime(|| ctl.run.peek().is_none()));
    assert!(
        api.batch_token.borrow().is_none(),
        "the backend was not called"
    );
}

/// Literal i18n keys in a source file (`"ui.servers.add.title"`, `"servers.pingAll"`, …);
/// prefixes that end in a dot are completed at run time and checked separately.
fn literal_keys(source: &str) -> Vec<String> {
    const PREFIXES: [&str; 5] = [
        "ui.servers.",
        "servers.",
        "serverDetail.",
        "liveCheck.",
        "common.",
    ];
    let mut out = Vec::new();
    for part in source.split('"').skip(1).step_by(2) {
        let is_key = PREFIXES.iter().any(|p| part.starts_with(p))
            && !part.ends_with('.')
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if is_key {
            out.push(part.to_owned());
        }
    }
    out
}

/// ui-pages §7.12 i18n gate for this package: every key the page asks for exists in both
/// languages (spec §2.4: "the build must fail on a missing key") — also the run-time ones (stage
/// captions, key-health reasons). The fragment rules are checked crate-wide.
#[test]
fn every_key_the_page_uses_exists() {
    let sources = [
        include_str!("actions.rs"),
        include_str!("add.rs"),
        include_str!("batch.rs"),
        include_str!("demo.rs"),
        include_str!("demo_data.rs"),
        include_str!("detail.rs"),
        include_str!("group.rs"),
        include_str!("live.rs"),
        include_str!("live_present.rs"),
        include_str!("menu.rs"),
        include_str!("page.rs"),
        include_str!("present.rs"),
        include_str!("report.rs"),
        include_str!("row.rs"),
    ];
    let mut keys: Vec<String> = sources.iter().flat_map(|s| literal_keys(s)).collect();
    let stages = [
        Stage::Dns,
        Stage::Reachability,
        Stage::Tls,
        Stage::Http,
        Stage::Ports,
        Stage::Route,
        Stage::Infrastructure,
        Stage::Handshake,
        Stage::Egress,
        Stage::MediaStream,
        Stage::Throughput,
        Stage::Path,
        Stage::Pmtu,
    ];
    keys.extend(stages.map(|stage| format!("ui.servers.stage.{}", stage.key())));
    let reasons = [
        "auth-failed",
        "tls-failed",
        "timeout",
        "config-failed",
        "handshake-failed",
        "no-outbound",
        "hy2-auth-failed",
        "hy2-udp-blocked",
        "hy2-tls-failed",
        "hy2-config-failed",
        "hy2-handshake-failed",
    ];
    for code in reasons {
        assert_eq!(KeyHealthReason::from_code(code).code(), code);
        keys.push(format!("servers.health.reasons.{code}"));
    }
    crate::test_locales::assert_resolve(
        &crate::test_locales::catalogs(&[]),
        keys.iter().map(String::as_str),
    );
}
