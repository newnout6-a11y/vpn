//! VirtualDom runs: every demo scene renders, and the page's commands against a gated fake API
//! (cancel, the power press, Smart RU, the leak check, the kill-switch banner).
use std::cell::RefCell;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;

use dioxus::prelude::*;
use tokio::sync::{oneshot, watch};
use vpnte_base::types::Verdict;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_view::labels::{PowerLook, cancel_label, power_button};
use vpnte_view::swiss::{ConnView, Mode, Transition, TunnelState};

use super::super::demo::{DashScene, DemoDashboard};
use super::super::model::*;
use super::super::*;
use crate::lang::{tr, translate};
use crate::widgets::{Toast, ToastKind, Toasts};

use crate::test_support::settle;

#[derive(Clone, Copy)]
struct Scene(DashScene);

fn scene_root() -> Element {
    let Scene(scene) = use_context::<Scene>();
    let (api, panels, start) = use_hook(|| DemoDashboard::handle(scene));
    use_context_provider(|| api);
    use_context_provider(|| panels);
    use_hook(|| start.start());
    Toasts::use_provider();
    rsx! {
        Dashboard {}
    }
}

/// The whole page mounts and runs over every demo scene (frames, mascot, panels) without a
/// panic.
#[tokio::test]
async fn every_scene_renders() {
    for (name, scene) in DashScene::ALL {
        let mut dom = VirtualDom::new(scene_root).with_root_context(Scene(scene));
        dom.rebuild_in_place();
        settle(&mut dom, 10, 40).await;
        drop(dom);
        eprintln!("rendered {name}");
    }
}

/// A fake backend whose cancel waits for the test; every call is logged.
struct GateApi {
    tx: watch::Sender<DashboardView>,
    calls: RefCell<Vec<String>>,
    cancel: RefCell<Option<oneshot::Receiver<AppResult<Option<Msg>>>>>,
    leak: RefCell<Option<AppResult<Verdict>>>,
}

impl GateApi {
    fn log(&self, call: impl Into<String>) {
        self.calls.borrow_mut().push(call.into());
    }
}

#[async_trait::async_trait(?Send)]
impl DashboardApi for GateApi {
    fn state(&self) -> watch::Receiver<DashboardView> {
        self.tx.subscribe()
    }
    async fn connect(&self) -> AppResult<()> {
        self.log("connect");
        Ok(())
    }
    async fn disconnect(&self) -> AppResult<Option<Msg>> {
        self.log("disconnect");
        Ok(None)
    }
    async fn cancel(&self) -> AppResult<Option<Msg>> {
        self.log("cancel");
        let gate = self
            .cancel
            .borrow_mut()
            .take()
            .ok_or_else(AppError::cancelled)?;
        gate.await.unwrap_or_else(|_| Err(AppError::cancelled()))
    }
    async fn set_smart_ru(&self, on: bool) -> AppResult<()> {
        self.log(format!("smart {on}"));
        Ok(())
    }
    async fn run_leak_check(&self) -> AppResult<Verdict> {
        self.log("leak");
        self.leak.borrow_mut().take().unwrap_or(Ok(Verdict::Ok))
    }
    async fn copy_ip(&self, ip: IpAddr) -> AppResult<()> {
        self.log(format!("copy {ip}"));
        Ok(())
    }
    async fn recheck_firewall(&self) -> AppResult<()> {
        self.log("recheck");
        Ok(())
    }
    async fn release_kill_switch(&self) -> AppResult<()> {
        self.log("release");
        Err(AppError::new(ErrorKind::Permission))
    }

    async fn retry_now(&self) -> AppResult<()> {
        self.log("retry");
        Ok(())
    }
}

#[derive(Clone)]
struct Probe {
    api: Rc<GateApi>,
    dash: Rc<RefCell<Option<(Dash, ScopeId)>>>,
    toasts: Rc<RefCell<Option<Toasts>>>,
}

fn gate_root() -> Element {
    let probe = use_context::<Probe>();
    use_context_provider(|| probe.api.clone() as Rc<dyn DashboardApi>);
    let toasts = Toasts::use_provider();
    probe.toasts.replace(Some(toasts));
    rsx! {
        Harness {}
    }
}

/// Holds the page state like the page root does, and hands it to the test.
#[component]
fn Harness() -> Element {
    let probe = use_context::<Probe>();
    let dash = use_dash();
    probe
        .dash
        .replace(Some((dash, dioxus::core::current_scope_id())));
    rsx! {}
}

fn mount(view: DashboardView) -> (VirtualDom, Probe) {
    let probe = Probe {
        api: Rc::new(GateApi {
            tx: watch::Sender::new(view),
            calls: RefCell::new(Vec::new()),
            cancel: RefCell::new(None),
            leak: RefCell::new(None),
        }),
        dash: Rc::new(RefCell::new(None)),
        toasts: Rc::new(RefCell::new(None)),
    };
    let mut dom = VirtualDom::new(gate_root).with_root_context(probe.clone());
    dom.rebuild_in_place();
    (dom, probe)
}

/// Runs `f` with the page state inside the harness scope (where a click handler runs).
fn act<T>(dom: &VirtualDom, probe: &Probe, f: impl FnOnce(&Dash) -> T) -> T {
    let (dash, scope) = probe.dash.borrow().clone().expect("harness mounted");
    dom.in_scope(scope, || f(&dash))
}

fn toasts(dom: &VirtualDom, probe: &Probe) -> Vec<Toast> {
    let toasts = probe.toasts.borrow().expect("provider");
    dom.in_runtime(|| toasts.list())
}

fn calls(probe: &Probe) -> Vec<String> {
    probe.api.calls.borrow().clone()
}

fn gate_cancel(probe: &Probe) -> oneshot::Sender<AppResult<Option<Msg>>> {
    let (tx, rx) = oneshot::channel();
    probe.api.cancel.replace(Some(rx));
    tx
}

fn state(conn: ConnView) -> DashboardView {
    DashboardView {
        conn,
        smart_ru: true,
        ..DashboardView::default()
    }
}

fn connecting() -> ConnView {
    ConnView {
        transition: Some(Transition::Connecting),
        cleanup_required: true,
        ..ConnView::default()
    }
}

fn connected() -> ConnView {
    ConnView {
        state: TunnelState::Connected,
        mode: Some(Mode::Tun),
        cleanup_required: true,
        ..ConnView::default()
    }
}

/// AT-00-003 / AT-00-008 (spec §7.8 #16): «Отменить подключение» responds at once — the page
/// reads as cancelling (power `.is-cancel`, spinner, «Отменяем…»), a second press does nothing —
/// and the outcome is reported when the backend answers.
#[tokio::test]
async fn cancel_responds_at_once_and_runs_once() {
    let (mut dom, probe) = mount(state(connecting()));
    let gate = gate_cancel(&probe);
    act(&dom, &probe, Dash::cancel_transition);
    act(&dom, &probe, Dash::cancel_transition);
    settle(&mut dom, 3, 40).await;
    assert_eq!(calls(&probe), ["cancel"]);
    let conn = act(&dom, &probe, Dash::conn);
    assert!(conn.cancelling);
    let power = power_button(&conn);
    assert_eq!(power.look, PowerLook::Cancelling);
    assert!(power.waiting);
    assert_eq!(power.label.key, "dashboard.cancelling");
    assert_eq!(
        cancel_label(&conn).map(|m| m.key),
        Some("dashboard.cancelling".into())
    );
    gate.send(Ok(None)).expect("cancel pending");
    probe.api.tx.send_replace(state(ConnView::default()));
    settle(&mut dom, 4, 40).await;
    assert!(!act(&dom, &probe, Dash::conn).cancelling);
    let shown = toasts(&dom, &probe);
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].kind, ToastKind::Info);
    assert!(
        renders(&dom, &shown[0].title, "dashboard.connectionCancelled", &[]),
        "{}",
        shown[0].title
    );
}

/// AT-00-008 (spec §7.8 #17): a cancellation with recovery warnings says so, with the warning.
#[tokio::test]
async fn cancel_with_warnings_shows_them() {
    let (mut dom, probe) = mount(state(connecting()));
    let gate = gate_cancel(&probe);
    act(&dom, &probe, Dash::cancel_transition);
    gate.send(Ok(Some(Msg::new("test.recoveryNotVerified"))))
        .expect("cancel pending");
    settle(&mut dom, 4, 40).await;
    let shown = toasts(&dom, &probe);
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].kind, ToastKind::Warning);
    assert!(
        renders(
            &dom,
            &shown[0].title,
            "dashboard.cancelledWithWarnings",
            &[]
        ),
        "{}",
        shown[0].title
    );
    assert_eq!(
        shown[0].description,
        Some(dom.in_runtime(|| tr(&Msg::new("test.recoveryNotVerified"))))
    );
}

/// Spec §7.8 #19: a failed cancellation is reported and the page stops reading as cancelling
/// (the backend still says connecting).
#[tokio::test]
async fn cancel_failure_is_reported() {
    let (mut dom, probe) = mount(state(connecting()));
    let gate = gate_cancel(&probe);
    act(&dom, &probe, Dash::cancel_transition);
    gate.send(Err(AppError::new(ErrorKind::Network)))
        .expect("cancel pending");
    settle(&mut dom, 4, 40).await;
    let shown = toasts(&dom, &probe);
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].kind, ToastKind::Error);
    assert!(
        renders(&dom, &shown[0].title, "dashboard.cancelFailed", &[]),
        "{}",
        shown[0].title
    );
    assert!(!act(&dom, &probe, Dash::conn).cancelling);
}

/// AT-00-007 (spec §7.8 #5, #10): cancelling a server switch is acknowledged without a toast;
/// the backend keeps «Отменяем…» until the previous server is back.
#[tokio::test]
async fn switch_cancel_is_silent() {
    let switching = ConnView {
        transition: Some(Transition::Reconnecting),
        switching: Some("Norway".into()),
        ..connected()
    };
    let (mut dom, probe) = mount(state(switching));
    let conn = act(&dom, &probe, Dash::conn);
    assert_eq!(
        cancel_label(&conn).map(|m| m.key),
        Some("dashboard.cancelServerSwitch".into())
    );
    let gate = gate_cancel(&probe);
    act(&dom, &probe, Dash::cancel_transition);
    gate.send(Ok(None)).expect("cancel pending");
    settle(&mut dom, 4, 40).await;
    assert_eq!(calls(&probe), ["cancel"]);
    assert!(toasts(&dom, &probe).is_empty());
}

/// `shown` is the text of `key`: its translation, or the bare key when the process-wide catalogs
/// were not loaded yet at render time (other tests load them concurrently; the first load wins).
fn renders(dom: &VirtualDom, shown: &str, key: &str, vars: &[(&str, String)]) -> bool {
    shown == key || shown == dom.in_runtime(|| translate(key, vars, None))
}

/// Owner, 12.11.2026 (no confirmation for an action the next press undoes): with protection on
/// a press disconnects at once; a second press while that command runs does nothing.
#[tokio::test]
async fn power_disconnects_at_once() {
    let (mut dom, probe) = mount(state(connected()));
    act(&dom, &probe, Dash::press_power);
    act(&dom, &probe, Dash::press_power);
    settle(&mut dom, 3, 40).await;
    assert_eq!(calls(&probe), ["disconnect"]);
    assert!(toasts(&dom, &probe).is_empty());
}

/// Spec §3.5: the Smart RU toggle saves the opposite of the current setting.
#[tokio::test]
async fn smart_toggle_saves_the_opposite() {
    let (mut dom, probe) = mount(state(ConnView::default()));
    act(&dom, &probe, Dash::toggle_smart);
    settle(&mut dom, 3, 40).await;
    assert_eq!(calls(&probe), ["smart false"]);
    assert!(toasts(&dom, &probe).is_empty());
}

/// Spec §3.1 runDiagnostics: a check that produced no verdict is reported, not hidden.
#[tokio::test]
async fn failed_leak_check_is_reported() {
    let (mut dom, probe) = mount(state(connected()));
    probe
        .api
        .leak
        .replace(Some(Err(AppError::new(ErrorKind::Network))));
    act(&dom, &probe, Dash::check_leaks);
    assert!(act(&dom, &probe, |d| d.leak.running()), "checking at once");
    settle(&mut dom, 3, 40).await;
    assert_eq!(calls(&probe), ["leak"]);
    let shown = toasts(&dom, &probe);
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].kind, ToastKind::Error);
    let message = dom.in_runtime(|| tr(&AppError::new(ErrorKind::Network).user_msg()));
    let vars = [("message", message)];
    assert!(
        renders(&dom, &shown[0].title, "dashboard.routeCheckFailed", &vars),
        "{}",
        shown[0].title
    );
    assert!(!act(&dom, &probe, |d| d.leak.running()));
}

/// AT-03-003 / AT-03-007 (spec §7.8 #9): a failed manual cleanup is reported, never shown as
/// done; the recheck goes to the backend.
#[tokio::test]
async fn kill_switch_banner_actions() {
    let (mut dom, probe) = mount(state(ConnView::default()));
    act(&dom, &probe, Dash::release_kill_switch);
    act(&dom, &probe, Dash::recheck_firewall);
    settle(&mut dom, 3, 40).await;
    assert_eq!(calls(&probe), ["release", "recheck"]);
    let shown = toasts(&dom, &probe);
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].kind, ToastKind::Error);
    assert!(
        renders(&dom, &shown[0].title, "ui.dashboard.releaseFailed", &[]),
        "{}",
        shown[0].title
    );
}

/// Copying the exit address shows «скопировано» only after the clipboard took it, for 1.3 s.
#[tokio::test]
async fn copied_feedback_expires() {
    let (mut dom, probe) = mount(state(connected()));
    let ip: IpAddr = [198, 51, 100, 23].into();
    act(&dom, &probe, |d| d.copy_ip(ip));
    settle(&mut dom, 2, 40).await;
    assert_eq!(calls(&probe), ["copy 198.51.100.23"]);
    assert!(act(&dom, &probe, |d| d.copied.peek().is_some()));
    tokio::time::sleep(Duration::from_millis(COPIED_MS + 100)).await;
    settle(&mut dom, 2, 40).await;
    assert!(act(&dom, &probe, |d| d.copied.peek().is_none()));
}
