//! Port of `Availability.requestLifetime.test.tsx` (ui-pages §7.5, AT-00-003 / AT-00-008):
//! "token" = the run's `CancellationToken`; a late reply has nowhere to go.
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use dioxus::core::{NoOpMutations, ScopeId};
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, Msg};

use super::*;
use crate::availability::model::{AvailabilityState, RoutingVerdict, UrlVerdict};

/// The Russian catalog text of `key`.
fn ru_text(key: &str) -> String {
    crate::test_locales::init_locales();
    vpnte_base::i18n::lookup(vpnte_base::i18n::Lang::Ru, key, &[], None)
}

type Reply<T> = oneshot::Sender<AppResult<T>>;

/// A backend whose every answer the test sends by hand.
struct Script {
    state: watch::Sender<AvailabilityState>,
    checks: RefCell<VecDeque<oneshot::Receiver<AppResult<UrlCheck>>>>,
    routes: RefCell<VecDeque<oneshot::Receiver<AppResult<RoutingReport>>>>,
    tokens: RefCell<Vec<CancellationToken>>,
    inputs: RefCell<Vec<String>>,
    calls: Cell<u32>,
}

impl Script {
    fn new() -> Rc<Self> {
        Rc::new(Self {
            state: watch::Sender::new(AvailabilityState {
                tunnel_running: true,
                ..Default::default()
            }),
            checks: RefCell::default(),
            routes: RefCell::default(),
            tokens: RefCell::default(),
            inputs: RefCell::default(),
            calls: Cell::new(0),
        })
    }
    fn next_check(&self) -> Reply<UrlCheck> {
        let (tx, rx) = oneshot::channel();
        self.checks.borrow_mut().push_back(rx);
        tx
    }
    fn next_route(&self) -> Reply<RoutingReport> {
        let (tx, rx) = oneshot::channel();
        self.routes.borrow_mut().push_back(rx);
        tx
    }
    fn token(&self, i: usize) -> CancellationToken {
        self.tokens.borrow()[i].clone()
    }
}

async fn answer<T>(rx: Option<oneshot::Receiver<AppResult<T>>>) -> AppResult<T> {
    match rx {
        Some(rx) => rx.await.unwrap_or_else(|_| Err(AppError::cancelled())),
        None => Err(AppError::new(ErrorKind::Internal)),
    }
}

#[async_trait::async_trait(?Send)]
impl AvailabilityApi for Script {
    fn state(&self) -> watch::Receiver<AvailabilityState> {
        self.state.subscribe()
    }
    async fn check_url(&self, input: String, cancel: CancellationToken) -> AppResult<UrlCheck> {
        self.calls.set(self.calls.get() + 1);
        self.inputs.borrow_mut().push(input);
        self.tokens.borrow_mut().push(cancel);
        let rx = self.checks.borrow_mut().pop_front();
        answer(rx).await
    }
    async fn routing_test(&self, cancel: CancellationToken) -> AppResult<RoutingReport> {
        self.tokens.borrow_mut().push(cancel);
        let rx = self.routes.borrow_mut().pop_front();
        answer(rx).await
    }
    async fn clear_history(&self) -> AppResult<()> {
        self.state.send_modify(|s| s.history.clear());
        Ok(())
    }
}

/// What the stand-in page hands back: its controller and its mirrored state.
type Mounted = (Controller, Signal<AvailabilityState>);

#[derive(Clone)]
struct Probe {
    api: Rc<Script>,
    show: Rc<Cell<bool>>,
    ctl: Rc<Cell<Option<Mounted>>>,
}

fn root() -> Element {
    let show = use_context::<Probe>().show.get();
    rsx! {
        if show {
            PageStandIn {}
        }
    }
}

/// The page's hooks without its markup.
#[component]
fn PageStandIn() -> Element {
    let probe = use_context::<Probe>();
    let api: Rc<dyn AvailabilityApi> = probe.api.clone();
    let state = crate::hooks::use_watch(|| api.state());
    let ctl = use_controller(api);
    probe.ctl.set(Some((ctl, state)));
    rsx! {}
}

fn mount() -> (VirtualDom, Probe) {
    let probe = Probe {
        api: Script::new(),
        show: Rc::new(Cell::new(true)),
        ctl: Rc::default(),
    };
    let mut dom = VirtualDom::new(root).with_root_context(probe.clone());
    dom.rebuild_in_place();
    (dom, probe)
}

use crate::test_support::settle;

fn ctl(probe: &Probe) -> Controller {
    probe.ctl.get().expect("page mounted").0
}

fn unmount(dom: &mut VirtualDom, probe: &Probe) {
    probe.show.set(false);
    dom.mark_dirty(ScopeId::APP);
    dom.render_immediate(&mut NoOpMutations);
}

fn type_and_check(dom: &VirtualDom, probe: &Probe, text: &str) {
    let ctl = ctl(probe);
    dom.in_runtime(|| {
        let mut input = ctl.input;
        input.set(text.to_owned());
        ctl.check();
    });
}

fn sample(id: &str) -> UrlCheck {
    UrlCheck {
        id: id.into(),
        url: "https://example.com/".into(),
        tested_at: 1,
        tunnel_active: true,
        protected: None,
        direct: None,
        verdict: UrlVerdict::WorksBoth,
        recommendation: Msg::new("ui.tools.demo.reco.both"),
    }
}

/// §7.5 "unmount during a pending check → exactly one cancel, with the check's token; a late
/// success changes nothing".
#[tokio::test]
async fn unmount_cancels_the_check_and_drops_its_late_reply() {
    let (mut dom, probe) = mount();
    let reply = probe.api.next_check();
    type_and_check(&dom, &probe, "  example.com ");
    settle(&mut dom, 4, 30).await;
    assert_eq!(probe.api.inputs.borrow().as_slice(), ["example.com"]);
    let token = probe.api.token(0);
    assert!(!token.is_cancelled());
    unmount(&mut dom, &probe);
    assert!(token.is_cancelled());
    assert!(
        reply.send(Ok(sample("late"))).is_err(),
        "the check's future is gone"
    );
}

/// §7.5 "typed cancellation → no text, nothing left to cancel".
#[tokio::test]
async fn a_cancelled_check_is_silent() {
    let (mut dom, probe) = mount();
    let reply = probe.api.next_check();
    type_and_check(&dom, &probe, "example.com");
    settle(&mut dom, 4, 30).await;
    reply.send(Err(AppError::cancelled())).expect("check alive");
    settle(&mut dom, 4, 30).await;
    let ctl = ctl(&probe);
    dom.in_runtime(|| {
        assert!(!ctl.url_job.running());
        assert_eq!(ctl.check_error(), None);
        assert_eq!(ctl.result(&[]), None);
    });
}

/// §7.5 "success → shows the recommendation" and the pushed history arrives in the page.
#[tokio::test]
async fn a_successful_check_is_shown_and_the_history_follows() {
    let (mut dom, probe) = mount();
    let reply = probe.api.next_check();
    type_and_check(&dom, &probe, "example.com");
    settle(&mut dom, 4, 30).await;
    reply.send(Ok(sample("fresh"))).expect("check alive");
    probe
        .api
        .state
        .send_modify(|s| s.history.insert(0, sample("fresh")));
    settle(&mut dom, 4, 30).await;
    let (ctl, state) = probe.ctl.get().expect("mounted");
    dom.in_runtime(|| {
        assert_eq!(
            ctl.result(&[sample("older")]).map(|c| c.id),
            Some("fresh".into())
        );
        assert_eq!(state.peek().history.len(), 1);
        assert_eq!(ctl.check_error(), None);
    });
}

/// §7.5 "typed permission failure → canonical message; the next click issues a new request
/// with a different token"; validation → the URL hint.
#[tokio::test]
async fn failures_show_their_text_and_a_retry_gets_a_new_token() {
    let (mut dom, probe) = mount();
    let ctl = ctl(&probe);
    probe
        .api
        .next_check()
        .send(Err(AppError::new(ErrorKind::Permission)))
        .expect("queued");
    type_and_check(&dom, &probe, "example.com");
    settle(&mut dom, 4, 30).await;
    let shown = |dom: &VirtualDom| {
        let msg = dom.in_runtime(|| ctl.check_error()).expect("a message");
        ru_text(&msg.key)
    };
    assert_eq!(shown(&dom), "Недостаточно прав для операции");
    probe
        .api
        .next_check()
        .send(Err(AppError::validation(Msg::new("x"))))
        .expect("queued");
    dom.in_runtime(|| ctl.check());
    settle(&mut dom, 4, 30).await;
    assert_ne!(probe.api.token(0), probe.api.token(1));
    let hint =
        "Введите URL вида example.com или https://example.com/path (поддерживаются HTTP и HTTPS).";
    assert_eq!(shown(&dom), hint);
}

/// A blank link is refused on the page, without a call (old `check()`).
#[tokio::test]
async fn a_blank_link_is_refused_without_a_call() {
    let (mut dom, probe) = mount();
    type_and_check(&dom, &probe, "   ");
    settle(&mut dom, 4, 30).await;
    assert_eq!(probe.api.calls.get(), 0);
    let ctl = ctl(&probe);
    let msg = dom.in_runtime(|| ctl.check_error()).expect("a message");
    let hint = "Введите ссылку, например youtube.com или https://www.instagram.com";
    assert_eq!(ru_text(&msg.key), hint);
}

/// §7.5 routing: success shown, failure shown (U-06, the old page only logged it),
/// cancellation quiet; URL check and routing test run with separate tokens and both are
/// cancelled at unmount.
#[tokio::test]
async fn routing_runs_beside_the_check_with_its_own_token() {
    let (mut dom, probe) = mount();
    let ctl = ctl(&probe);
    let report = |verdict| RoutingReport {
        ran_at: 1,
        verdict,
        message: Msg::new("m"),
        vpn_ip: None,
        direct_ip: None,
        smart_ru: false,
        ru_ip: None,
    };
    probe
        .api
        .next_route()
        .send(Ok(report(RoutingVerdict::Ok)))
        .expect("queued");
    dom.in_runtime(|| ctl.run_routing());
    settle(&mut dom, 4, 30).await;
    dom.in_runtime(|| {
        assert!(matches!(ctl.route_job.last(), Some(Ok(r)) if r.verdict == RoutingVerdict::Ok))
    });
    probe
        .api
        .next_route()
        .send(Err(AppError::new(ErrorKind::Network)))
        .expect("queued");
    dom.in_runtime(|| ctl.run_routing());
    settle(&mut dom, 4, 30).await;
    dom.in_runtime(|| {
        assert!(matches!(ctl.route_job.last(), Some(Err(e)) if e.kind == ErrorKind::Network))
    });
    probe
        .api
        .next_route()
        .send(Err(AppError::cancelled()))
        .expect("queued");
    dom.in_runtime(|| ctl.run_routing());
    settle(&mut dom, 4, 30).await;
    dom.in_runtime(|| {
        assert!(matches!(ctl.route_job.last(), Some(Err(e)) if e.kind == ErrorKind::Network))
    });

    let _check = probe.api.next_check();
    let _route = probe.api.next_route();
    type_and_check(&dom, &probe, "example.com");
    dom.in_runtime(|| ctl.run_routing());
    settle(&mut dom, 4, 30).await;
    let (check_token, route_token) = (probe.api.token(3), probe.api.token(4));
    assert_ne!(check_token, route_token);
    unmount(&mut dom, &probe);
    assert!(check_token.is_cancelled() && route_token.is_cancelled());
}
