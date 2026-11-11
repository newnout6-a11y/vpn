//! Port of `Maintenance.requestLifetime.test.tsx` and `DiagnosticsExport.requestLifetime`
//! (ui-pages §7.6 / §7.10, AT-00-003 / AT-00-004 / AT-00-008): "token" = the run's
//! `CancellationToken`; a late reply has nowhere to go because its future is gone.
use std::cell::RefCell;
use std::collections::VecDeque;

use async_trait::async_trait;
use dioxus::core::{NoOpMutations, ScopeId};
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::*;
use crate::maintenance::model::*;
use crate::widgets::{Toast, ToastKind, Toasts};

type Queue<T> = RefCell<VecDeque<oneshot::Receiver<AppResult<T>>>>;

/// A backend whose every answer the test sends by hand.
#[derive(Default)]
struct Script {
    state: watch::Sender<MaintenanceState>,
    reports: Queue<SystemReport>,
    repairs: Queue<RepairView>,
    leaks: Queue<LeakTestView>,
    routes: Queue<RouteTestView>,
    exports: Queue<Option<ExportDone>>,
    tokens: RefCell<Vec<(&'static str, CancellationToken)>>,
    calls: RefCell<Vec<&'static str>>,
}

fn reply<T>(queue: &Queue<T>) -> oneshot::Sender<AppResult<T>> {
    let (tx, rx) = oneshot::channel();
    queue.borrow_mut().push_back(rx);
    tx
}

async fn answer<T>(queue: &Queue<T>) -> AppResult<T> {
    let rx = queue.borrow_mut().pop_front();
    match rx {
        Some(rx) => rx.await.unwrap_or_else(|_| Err(AppError::cancelled())),
        None => Err(AppError::new(ErrorKind::Internal)),
    }
}

impl Script {
    fn token(&self, name: &str, nth: usize) -> CancellationToken {
        self.tokens
            .borrow()
            .iter()
            .filter(|(n, _)| *n == name)
            .nth(nth)
            .map(|(_, t)| t.clone())
            .expect("token recorded")
    }
    fn calls(&self, name: &str) -> usize {
        self.calls.borrow().iter().filter(|c| **c == name).count()
    }
    fn record(&self, name: &'static str, token: Option<CancellationToken>) {
        self.calls.borrow_mut().push(name);
        if let Some(token) = token {
            self.tokens.borrow_mut().push((name, token));
        }
    }
}

#[async_trait(?Send)]
impl MaintenanceApi for Script {
    fn state(&self) -> watch::Receiver<MaintenanceState> {
        self.state.subscribe()
    }
    async fn system_report(&self, cancel: CancellationToken) -> AppResult<SystemReport> {
        self.record("report", Some(cancel));
        answer(&self.reports).await
    }
    async fn verify_protection(&self) -> AppResult<ProtectionView> {
        self.record("verify", None);
        Ok(ProtectionView {
            bfe_running: true,
            ..ProtectionView::default()
        })
    }
    async fn repair(&self) -> AppResult<RepairView> {
        self.record("repair", None);
        answer(&self.repairs).await
    }
    async fn leak_self_test(&self, cancel: CancellationToken) -> AppResult<LeakTestView> {
        self.record("leak", Some(cancel));
        answer(&self.leaks).await
    }
    async fn routing_self_test(&self, cancel: CancellationToken) -> AppResult<RouteTestView> {
        self.record("route", Some(cancel));
        answer(&self.routes).await
    }
    async fn export_diagnostics(&self, cancel: CancellationToken) -> AppResult<Option<ExportDone>> {
        self.record("export", Some(cancel));
        answer(&self.exports).await
    }
    async fn restart_capture(&self) -> AppResult<CaptureView> {
        Ok(CaptureView::default())
    }
    async fn open_snapshots_folder(&self) -> AppResult<()> {
        Ok(())
    }
    async fn delete_legacy_data(&self) -> AppResult<()> {
        Ok(())
    }
    async fn retry_secrets_import(&self) -> AppResult<SecretsImport> {
        Ok(SecretsImport {
            restored: 0,
            pending: false,
        })
    }
    async fn set_aside_corrupt(&self, _id: String) -> AppResult<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct Probe {
    api: Rc<Script>,
    show: Rc<std::cell::Cell<bool>>,
    ctl: Rc<std::cell::Cell<Option<Controller>>>,
    scope: Rc<std::cell::Cell<Option<ScopeId>>>,
    toasts: Rc<std::cell::Cell<Option<Toasts>>>,
}

fn root() -> Element {
    let probe = use_context::<Probe>();
    let toasts = Toasts::use_provider();
    probe.toasts.set(Some(toasts));
    rsx! {
        if probe.show.get() {
            PageStandIn {}
        }
    }
}

/// The page's hooks without its markup.
#[component]
fn PageStandIn() -> Element {
    let probe = use_context::<Probe>();
    let api: Rc<dyn MaintenanceApi> = probe.api.clone();
    let state = crate::hooks::use_watch(|| api.state());
    probe.ctl.set(Some(use_controller(api, state)));
    probe.scope.set(Some(dioxus::core::current_scope_id()));
    rsx! {}
}

fn mount(tunnel: TunnelPhase) -> (VirtualDom, Probe) {
    let api = Rc::new(Script::default());
    api.state.send_modify(|s| s.tunnel = tunnel);
    let probe = Probe {
        api,
        show: Rc::new(std::cell::Cell::new(true)),
        ctl: Rc::default(),
        scope: Rc::default(),
        toasts: Rc::default(),
    };
    let mut dom = VirtualDom::new(root).with_root_context(probe.clone());
    dom.rebuild_in_place();
    (dom, probe)
}

use crate::test_support::settle;

fn ctl(probe: &Probe) -> Controller {
    probe.ctl.get().expect("page mounted")
}

/// Runs an action the way a click does: inside the page's scope.
fn act(dom: &VirtualDom, probe: &Probe, f: impl FnOnce(Controller)) {
    let ctl = ctl(probe);
    let scope = probe.scope.get().expect("page mounted");
    dom.in_scope(scope, || f(ctl));
}

fn unmount(dom: &mut VirtualDom, probe: &Probe) {
    probe.show.set(false);
    dom.mark_dirty(ScopeId::APP);
    dom.render_immediate(&mut NoOpMutations);
}

fn outcome(dom: &VirtualDom, probe: &Probe) -> Option<Outcome> {
    let ctl = ctl(probe);
    dom.in_runtime(|| ctl.outcome.peek().clone())
}

fn toasts(dom: &VirtualDom, probe: &Probe) -> Vec<Toast> {
    let toasts = probe.toasts.get().expect("provider");
    dom.in_runtime(|| toasts.list())
}

fn leak_view(headline: Msg) -> LeakTestView {
    LeakTestView {
        at: 1,
        verdict: LeakVerdict::Ok,
        cancelled: false,
        headline,
        tun_ip: Some("1.2.3.4".into()),
        adapters: Vec::new(),
        disagreement: None,
    }
}

fn route_ok() -> RouteTestView {
    RouteTestView {
        verdict: RouteVerdict::Ok,
        message: Msg::new("route.ok"),
    }
}

fn keys(o: &Outcome) -> Vec<String> {
    o.parts.iter().map(|m| m.key.to_string()).collect()
}

/// §7.6 "unmount cancels the routing token … late result or error → nothing changes" and
/// "leak and routing use independent tokens; both are cancelled at unmount".
#[tokio::test]
async fn unmount_cancels_both_probes_and_drops_late_replies() {
    let (mut dom, probe) = mount(TunnelPhase::On);
    let (leak, route) = (reply(&probe.api.leaks), reply(&probe.api.routes));
    act(&dom, &probe, Controller::protection_test);
    settle(&mut dom, 6, 20).await;
    let (lt, rt) = (probe.api.token("leak", 0), probe.api.token("route", 0));
    assert!(!lt.is_cancelled() && !rt.is_cancelled());
    unmount(&mut dom, &probe);
    assert!(lt.is_cancelled() && rt.is_cancelled());
    assert!(
        leak.send(Ok(leak_view(Msg::new("late")))).is_err(),
        "future gone"
    );
    assert!(route.send(Ok(route_ok())).is_err(), "future gone");
}

/// §7.6 "leak probe rejects (network) → routing cancelled; last result = «Сетевая операция
/// не выполнена»".
#[tokio::test]
async fn a_leak_failure_cancels_the_routing_probe() {
    let (mut dom, probe) = mount(TunnelPhase::On);
    let (leak, _route) = (reply(&probe.api.leaks), reply(&probe.api.routes));
    act(&dom, &probe, Controller::protection_test);
    settle(&mut dom, 6, 20).await;
    let _ = leak.send(Err(AppError::new(ErrorKind::Network)));
    settle(&mut dom, 6, 20).await;
    assert!(probe.api.token("route", 0).is_cancelled());
    assert!(!probe.api.token("leak", 0).is_cancelled());
    let o = outcome(&dom, &probe).expect("result line");
    assert_eq!(
        (o.verdict, keys(&o)),
        (Verdict::Fail, vec!["errors.network".to_owned()])
    );
    assert!(
        toasts(&dom, &probe)
            .iter()
            .any(|t| t.kind == ToastKind::Error)
    );
}

/// §7.6 "routing rejects → the pending leak probe is cancelled once".
#[tokio::test]
async fn a_routing_failure_cancels_the_leak_probe() {
    let (mut dom, probe) = mount(TunnelPhase::On);
    let (_leak, route) = (reply(&probe.api.leaks), reply(&probe.api.routes));
    act(&dom, &probe, Controller::protection_test);
    settle(&mut dom, 6, 20).await;
    let _ = route.send(Err(AppError::new(ErrorKind::Timeout)));
    settle(&mut dom, 6, 20).await;
    assert!(probe.api.token("leak", 0).is_cancelled());
    assert_eq!(
        keys(&outcome(&dom, &probe).expect("line")),
        ["errors.timeout"]
    );
}

/// §7.6 "cancellation → quiet; the next run's success → last result contains FAKE-current";
/// "an old reply never clears a newer run" (new tokens per run).
#[tokio::test]
async fn cancellation_is_quiet_and_the_next_run_has_new_tokens() {
    let (mut dom, probe) = mount(TunnelPhase::On);
    let (leak, _route) = (reply(&probe.api.leaks), reply(&probe.api.routes));
    act(&dom, &probe, Controller::protection_test);
    settle(&mut dom, 6, 20).await;
    let _ = leak.send(Err(AppError::cancelled()));
    settle(&mut dom, 6, 20).await;
    assert_eq!(outcome(&dom, &probe), None);
    assert!(toasts(&dom, &probe).is_empty());
    let ctl = ctl(&probe);
    assert!(!dom.in_runtime(|| ctl.protect.running()));

    let (leak, route) = (reply(&probe.api.leaks), reply(&probe.api.routes));
    act(&dom, &probe, Controller::protection_test);
    settle(&mut dom, 6, 20).await;
    assert!(!probe.api.token("leak", 1).is_cancelled());
    let headline = Msg::new("probes.leak.selfTest.okIp").arg("ip", "FAKE-current");
    let _ = leak.send(Ok(leak_view(headline)));
    let _ = route.send(Ok(route_ok()));
    settle(&mut dom, 6, 20).await;
    let o = outcome(&dom, &probe).expect("line");
    assert_eq!(o.verdict, Verdict::Ok);
    assert!(
        o.parts
            .iter()
            .any(|m| m.args.iter().any(|(_, v)| v == "FAKE-current"))
    );
    assert!(dom.in_runtime(|| ctl.test.peek().is_some()));
}

/// §7.6 "a late tunnel-status reply after unmount → neither probe starts": the phase is read
/// synchronously, so without a session nothing starts at all.
#[tokio::test]
async fn the_protection_test_needs_a_session() {
    let (mut dom, probe) = mount(TunnelPhase::Off);
    act(&dom, &probe, Controller::protection_test);
    settle(&mut dom, 6, 20).await;
    assert_eq!(probe.api.calls("leak") + probe.api.calls("route"), 0);
    let o = outcome(&dom, &probe).expect("line");
    assert_eq!(keys(&o), ["ui.maintenance.protectionTest.needsVpn"]);
}

fn done(path: &str, cleanup_failed: bool) -> Option<ExportDone> {
    Some(ExportDone {
        path: path.into(),
        cleanup_failed,
    })
}

/// §7.10 "double click → one export"; a success with `cleanup-failed` → not busy, result
/// «Диагностика сохранена: current.zip», plus a warning toast.
#[tokio::test]
async fn one_export_per_double_click_and_a_visible_cleanup_failure() {
    let (mut dom, probe) = mount(TunnelPhase::Off);
    let tx = reply(&probe.api.exports);
    act(&dom, &probe, Controller::export_zip);
    act(&dom, &probe, Controller::export_zip);
    settle(&mut dom, 6, 20).await;
    assert_eq!(probe.api.calls("export"), 1);
    let _ = tx.send(Ok(done("current.zip", true)));
    settle(&mut dom, 6, 20).await;
    let ctl = ctl(&probe);
    assert!(!dom.in_runtime(|| ctl.export.running()));
    let o = outcome(&dom, &probe).expect("line");
    assert_eq!(
        o.parts,
        [Msg::new("ui.maintenance.export.saved").arg("path", "current.zip")]
    );
    let kinds: Vec<ToastKind> = toasts(&dom, &probe).iter().map(|t| t.kind).collect();
    assert!(kinds.contains(&ToastKind::Success) && kinds.contains(&ToastKind::Warning));
}

/// §7.10 "unmount → cancel with its token; a late old success writes nothing"; after a
/// remount a new export starts with a new token.
#[tokio::test]
async fn unmount_cancels_the_export_and_a_late_success_is_dropped() {
    let (mut dom, probe) = mount(TunnelPhase::Off);
    let tx = reply(&probe.api.exports);
    act(&dom, &probe, Controller::export_zip);
    settle(&mut dom, 6, 20).await;
    let token = probe.api.token("export", 0);
    unmount(&mut dom, &probe);
    assert!(token.is_cancelled());
    assert!(tx.send(Ok(done("old.zip", false))).is_err());
    assert!(toasts(&dom, &probe).is_empty());

    probe.show.set(true);
    dom.mark_dirty(ScopeId::APP);
    dom.render_immediate(&mut NoOpMutations);
    let _tx = reply(&probe.api.exports);
    act(&dom, &probe, Controller::export_zip);
    settle(&mut dom, 6, 20).await;
    assert!(!probe.api.token("export", 1).is_cancelled());
}

/// §7.10: a dismissed save dialog and a typed cancel are quiet; a permission rejection shows
/// «Недостаточно прав…» with «Выберите локальную личную папку» and an error toast.
#[tokio::test]
async fn export_dismissal_cancel_and_permission() {
    let (mut dom, probe) = mount(TunnelPhase::Off);
    for answer in [Ok(None), Err(AppError::cancelled())] {
        let tx = reply(&probe.api.exports);
        act(&dom, &probe, Controller::export_zip);
        settle(&mut dom, 6, 20).await;
        let _ = tx.send(answer);
        settle(&mut dom, 6, 20).await;
        assert_eq!(outcome(&dom, &probe), None);
        assert!(toasts(&dom, &probe).is_empty());
    }
    let tx = reply(&probe.api.exports);
    act(&dom, &probe, Controller::export_zip);
    settle(&mut dom, 6, 20).await;
    let _ = tx.send(Err(AppError::new(ErrorKind::Permission)));
    settle(&mut dom, 6, 20).await;
    let o = outcome(&dom, &probe).expect("line");
    assert_eq!(
        keys(&o),
        [
            "ui.maintenance.export.failed",
            "errors.permission",
            "ui.maintenance.export.permissionHint"
        ]
    );
    assert!(
        toasts(&dom, &probe)
            .iter()
            .any(|t| t.kind == ToastKind::Error)
    );
}

fn view(outcomes: [StepOutcome; 3]) -> RepairView {
    RepairView {
        running: false,
        steps: RepairStep::ALL
            .into_iter()
            .zip(outcomes.map(StepState::Done))
            .collect(),
    }
}

fn fine() -> StepOutcome {
    StepOutcome::done(Vec::new())
}

/// U-13 / AT-00-004: refused while connected (no call, warning toast); a partial step makes
/// «…с ошибками»; a failed re-check still ends in that summary.
#[tokio::test]
async fn repair_is_refused_while_connected_and_always_ends_in_a_summary() {
    let (mut dom, probe) = mount(TunnelPhase::On);
    act(&dom, &probe, Controller::repair);
    settle(&mut dom, 6, 20).await;
    assert_eq!(probe.api.calls("repair"), 0);
    let o = outcome(&dom, &probe).expect("line");
    assert_eq!(keys(&o), ["ui.maintenance.repair.disconnectFirst"]);
    assert!(
        toasts(&dom, &probe)
            .iter()
            .any(|t| t.kind == ToastKind::Warning)
    );

    probe.api.state.send_modify(|s| s.tunnel = TunnelPhase::Off);
    settle(&mut dom, 6, 20).await;
    let tx = reply(&probe.api.repairs);
    let check = reply(&probe.api.reports);
    act(&dom, &probe, Controller::repair);
    settle(&mut dom, 6, 20).await;
    let partial = StepOutcome::failed(Msg::new("partial").arg("killed", 1).arg("total", 2));
    let _ = tx.send(Ok(view([fine(), fine(), partial])));
    settle(&mut dom, 6, 20).await;
    let _ = check.send(Err(AppError::new(ErrorKind::Internal)));
    settle(&mut dom, 6, 20).await;
    let o = outcome(&dom, &probe).expect("line");
    assert_eq!(o.verdict, Verdict::Fail);
    assert_eq!(
        keys(&o),
        [
            "ui.maintenance.repair.failed",
            "ui.maintenance.repair.recheckFailed",
            "errors.internal"
        ]
    );
}

/// AT-00-004: every step fine → «Авто-починка завершена», success toast, fresh report.
#[tokio::test]
async fn a_clean_repair_says_done_and_refreshes_the_report() {
    let (mut dom, probe) = mount(TunnelPhase::Off);
    let tx = reply(&probe.api.repairs);
    let check = reply(&probe.api.reports);
    act(&dom, &probe, Controller::repair);
    settle(&mut dom, 6, 20).await;
    let _ = tx.send(Ok(view([fine(), fine(), fine()])));
    settle(&mut dom, 6, 20).await;
    let _ = check.send(Ok(SystemReport::default()));
    settle(&mut dom, 6, 20).await;
    let o = outcome(&dom, &probe).expect("line");
    assert_eq!(o.verdict, Verdict::Ok);
    assert_eq!(keys(&o), ["ui.maintenance.repair.done"]);
    assert!(
        toasts(&dom, &probe)
            .iter()
            .any(|t| t.kind == ToastKind::Success)
    );
    let ctl = ctl(&probe);
    assert!(dom.in_runtime(|| ctl.report.peek().is_some()));
}

/// AT-00-005 through the page: a Network warning → «есть пункты для внимания»; a failed
/// check → its error and an error toast.
#[tokio::test]
async fn health_check_results() {
    let (mut dom, probe) = mount(TunnelPhase::Off);
    let tx = reply(&probe.api.reports);
    act(&dom, &probe, Controller::health_check);
    settle(&mut dom, 6, 20).await;
    let item = DiagItem {
        id: "ip".into(),
        category: DiagCategory::Network,
        label: Msg::new("l"),
        verdict: Some(Verdict::Warn),
        value: Msg::new("v"),
        details: Vec::new(),
        notes: Vec::new(),
    };
    let _ = tx.send(Ok(SystemReport {
        ran_at: 1,
        items: vec![item],
    }));
    settle(&mut dom, 6, 20).await;
    let o = outcome(&dom, &probe).expect("line");
    assert_eq!(o.verdict, Verdict::Warn);
    assert_eq!(keys(&o), ["ui.maintenance.health.attention"]);
    assert_eq!(probe.api.calls("verify"), 1);

    let tx = reply(&probe.api.reports);
    act(&dom, &probe, Controller::health_check);
    settle(&mut dom, 6, 20).await;
    let _ = tx.send(Err(AppError::new(ErrorKind::Timeout)));
    settle(&mut dom, 6, 20).await;
    let o = outcome(&dom, &probe).expect("line");
    assert_eq!(keys(&o), ["ui.maintenance.health.failed", "errors.timeout"]);
    assert!(
        toasts(&dom, &probe)
            .iter()
            .any(|t| t.kind == ToastKind::Error)
    );
}

/// The result line reads as sentences: a part without punctuation gets a period, a part
/// ending in a colon is followed by its explanation.
#[test]
fn sentences_are_joined_readably() {
    let parts = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        join_sentences(parts(&[
            "Проверка защиты пройдена.",
            "Утечек не обнаружено",
            "Маршрутизация в порядке."
        ])),
        "Проверка защиты пройдена. Утечек не обнаружено. Маршрутизация в порядке."
    );
    assert_eq!(
        join_sentences(parts(&[
            "Не удалось создать архив:",
            "Недостаточно прав",
            "",
            "Выберите папку."
        ])),
        "Не удалось создать архив: Недостаточно прав. Выберите папку."
    );
    assert_eq!(join_sentences(parts(&["Готово"])), "Готово");
}
