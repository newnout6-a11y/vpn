//! The start page («Пломба»): banners, the foreign-VPN notice, the facts strip, the status slab
//! (big word, caption, uptime, identity column, cancel block, power button, progress
//! ruler, the mascot) and the panel row.
//!
//! Emits the DOM of the reference start page (classes, attributes, text-node splits) so swiss.css,
//! base.css and utilities.css style it unchanged. State comes from a [`DashboardApi`] in context
//! (`Rc<dyn DashboardApi>`, one [`DashboardView`] snapshot pushed by the app); the panel row and the
//! node line read the `Rc<dyn PanelsApi>` of [`crate::panels`]. [`demo::DemoDashboard`] fakes both
//! with the reference fixtures.
//!
//! The root component is [`Dashboard`]: `registry.register(Page::Dashboard, Dashboard)`.
mod actions;
mod always;
mod banners;
pub mod demo;
mod facts;
mod model;
mod netmode;
mod slab;
#[cfg(test)]
mod tests;

use std::cell::{Cell, RefCell};
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Instant;

use dioxus::prelude::*;
use tokio::sync::watch;
use vpnte_base::types::{Engine, Notice, UnixMs, Verdict};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_view::identity::{ExitIp, HomeIp};
use vpnte_view::labels::FirewallStatus;
use vpnte_view::mascot::MascotEvent;
use vpnte_view::swiss::{self, ConnView, SwissInput};
use vpnte_view::traffic;

use crate::hooks::use_watch;
use crate::lang::tr;
use crate::mascot::MascotBus;
use crate::pages::use_page_active;
use crate::panels::{LocalPings, PanelsApi, SwissPanels};
use crate::widgets::{JobSlot, ToastKind, Toasts, use_job};

/// Everything the start page shows besides the panel row, as the app pushes it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DashboardView {
    /// Projection of the tunnel lifecycle snapshot.
    pub conn: ConnView,
    /// The public / exit address as the IP monitor reports it (geo keyed by address).
    pub exit: ExitIp,
    /// ISO 3166-1 alpha-2 code of `exit.geo`'s country (the flag coin of the geo line).
    pub exit_country: Option<String>,
    /// Kill-switch read-back.
    pub firewall: FirewallStatus,
    /// Summary of the last leak check; `NotChecked` = none (every transition clears it).
    pub leak: Verdict,
    /// Routing mode setting: Soft (applies on the next connect).
    pub soft_mode: bool,
    /// Smart RU setting (applies on the next connect).
    pub smart_ru: bool,
    /// Adapter description of another VPN found while ours is down (`happ-tun (172.18.0.1)`).
    pub foreign_vpn: Option<String>,
    /// The engine that carries the running session and why (`None` while nothing runs).
    pub engine: Option<EngineLine>,
    /// What the automatic server choice is doing (`None` while it does nothing).
    pub autopick: Option<PickLine>,
    /// «Интернет на паузе»: the VPN dropped by itself and the kill switch holds (`None`: not
    /// paused).
    pub pause: Option<PauseLine>,
    /// Another VPN carries the default route (its label): the kill switch does not pause the
    /// running session.
    pub no_pause_vpn: Option<String>,
    /// Another program took over the system proxy our proxy-mode session set: one calm
    /// line with «Вернуть» (ks-b).
    pub proxy_taken: bool,
    /// The connect in flight is proving its exit (its engine runs, nothing is claimed yet):
    /// the caption says «Проверяем выход…» (lab F-4).
    pub proving_exit: bool,
    /// The exit equals the address without our VPN while another VPN works on this PC: one calm
    /// line instead of a leak (the address check proves nothing then).
    pub other_vpn_exit: bool,
}

/// The paused state's line: the next automatic attempt and whether the user must act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PauseLine {
    /// Unix ms of the next automatic attempt; `None` while one runs or none is scheduled.
    pub next_attempt: Option<UnixMs>,
    /// Nothing retries by itself (auto-restart is off): only «Подключить» does.
    pub manual: bool,
    /// The server rejected the key: reconnecting will not help until the user acts.
    pub key_rejected: bool,
}

/// The automatic server choice's step (connecting at start, checking a stalled session, the
/// retries after every server failed) and, during the retries, what traffic does meanwhile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickLine {
    pub title: Msg,
    pub body: Option<Msg>,
}

/// The identity column's engine caption («Xray · REALITY»): never a silent choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineLine {
    pub engine: Engine,
    /// Why it was chosen (`engine.xray.reason.*`); `None` when nothing was chosen (a local
    /// upstream proxy behind sing-box).
    pub reason: Option<Msg>,
}

/// Data and actions of the start page.
///
/// Implementations publish state changes through [`DashboardApi::state`] before a call returns
/// (a cancel publishes `conn.cancelling` at once) and run state-changing work in their own task,
/// so it completes even when the page goes away while a call is pending.
#[async_trait::async_trait(?Send)]
pub trait DashboardApi: 'static {
    /// The page snapshot.
    fn state(&self) -> watch::Receiver<DashboardView>;
    /// Turns protection on with the current settings; returns when the attempt is over.
    async fn connect(&self) -> AppResult<()>;
    /// Turns protection off; `Ok(Some(w))` = off, but recovery reported a warning.
    async fn disconnect(&self) -> AppResult<Option<Msg>>;
    /// Cancels the connect or server switch in flight; `Ok(Some(w))` = cancelled with a warning.
    async fn cancel(&self) -> AppResult<Option<Msg>>;
    /// «Отменить» on the automatic choice's strip: the choice stops and leaves the session that
    /// runs alone until the user acts again; the session itself is never stopped by it.
    async fn end_autopick(&self) -> AppResult<()>;
    /// Saves the Smart RU setting (applies on the next connect).
    async fn set_smart_ru(&self, on: bool) -> AppResult<()>;
    /// Runs the route / leak check; the verdict also lands in [`DashboardView::leak`].
    async fn run_leak_check(&self) -> AppResult<Verdict>;
    /// Puts the exit address on the clipboard.
    async fn copy_ip(&self, ip: IpAddr) -> AppResult<()>;
    /// Reads the kill-switch state back again (published through `firewall`).
    async fn recheck_firewall(&self) -> AppResult<()>;
    /// Removes our kill-switch filters after a failed or ended session.
    async fn release_kill_switch(&self) -> AppResult<()>;
    /// «Подключить» in the paused state: the paused session retries at once.
    async fn retry_now(&self) -> AppResult<()>;
    /// «Вернуть»: points the system proxy at our session again after another program took
    /// it over (the line then goes away with the next snapshot).
    async fn reclaim_proxy(&self) -> AppResult<()>;
}

thread_local! {
    /// The real address: memory only and app-wide, so a remounted page still knows it.
    static HOME: RefCell<HomeIp> = RefCell::new(HomeIp::new());
}

fn observe_home(view: &DashboardView) -> Option<IpAddr> {
    HOME.with(|home| home.borrow_mut().observe(&view.conn, &view.exit))
}

/// The page snapshot, plus the real address observed from every snapshot received (renders
/// coalesce; the home-IP rule needs the settled-off frames).
fn use_view(api: &Rc<dyn DashboardApi>) -> (Signal<DashboardView>, Signal<Option<IpAddr>>) {
    let rx = use_hook(|| api.state());
    let mut home = use_signal(|| observe_home(&rx.borrow()));
    let mut view = use_signal(|| rx.borrow().clone());
    use_future(move || {
        let mut rx = rx.clone();
        async move {
            while rx.changed().await.is_ok() {
                let next = rx.borrow_and_update().clone();
                let ip = observe_home(&next);
                if *home.peek() != ip {
                    home.set(ip);
                }
                if *view.peek() != next {
                    view.set(next);
                }
            }
        }
    });
    (view, home)
}

/// The page's shared handles: snapshot, commands in flight and local UI state (context of the
/// page's components).
#[derive(Clone)]
struct Dash {
    api: Rc<dyn DashboardApi>,
    view: Signal<DashboardView>,
    home: Signal<Option<IpAddr>>,
    toasts: Toasts,
    bus: MascotBus,
    /// Connect or disconnect in flight.
    command: JobSlot<()>,
    cancel: JobSlot<()>,
    smart: JobSlot<()>,
    leak: JobSlot<()>,
    recheck: JobSlot<()>,
    release: JobSlot<()>,
    /// «Вернуть» of the system-proxy line in flight.
    reclaim: JobSlot<()>,
    /// When the exit address was last copied (shows «скопировано» for [`COPIED_MS`]).
    copied: Signal<Option<Instant>>,
    /// The `role=status` caption: the power button's description (D-02).
    caption_id: String,
}

impl Dash {
    /// The snapshot as the page shows it: a cancel request reads as cancelling from the click on,
    /// before the backend's frame arrives (subscribes the caller).
    fn snapshot(&self) -> DashboardView {
        let mut view = self.view.read().clone();
        view.conn.cancelling |= self.cancel.running();
        view
    }

    /// [`Dash::snapshot`]'s connection.
    fn conn(&self) -> ConnView {
        self.snapshot().conn
    }

    /// Shows a failed command; a cancellation is not a failure.
    fn fail(&self, title: String, err: &AppError) {
        if err.kind == ErrorKind::Cancelled {
            return;
        }
        tracing::warn!(error = %err, "start page command failed");
        self.toasts.error(title, Some(tr(&err.user_msg())));
    }
}

/// The page's state and command slots, provided to its components as context. Uses the
/// [`MascotBus`] in context, or provides one.
fn use_dash() -> Dash {
    let api = use_context::<Rc<dyn DashboardApi>>();
    let toasts = Toasts::use_context();
    let bus = use_hook(|| {
        try_consume_context::<MascotBus>().unwrap_or_else(|| provide_context(MascotBus::new()))
    });
    let (view, home) = use_view(&api);
    let (command, cancel, smart) = (use_job(), use_job(), use_job());
    let (leak, recheck, release) = (use_job(), use_job(), use_job());
    let reclaim = use_job();
    let copied = use_signal(|| None);
    let caption_id = crate::widgets::use_dom_id("dash-status");
    use_context_provider(|| Dash {
        api,
        view,
        home,
        toasts,
        bus,
        command,
        cancel,
        smart,
        leak,
        recheck,
        release,
        reclaim,
        copied,
        caption_id,
    })
}

/// The start page (`registry.register(Page::Dashboard, Dashboard)`). Needs `Rc<dyn DashboardApi>`,
/// `Rc<dyn PanelsApi>` and the toast queue ([`Toasts::use_provider`]) from an ancestor. Uses the
/// [`MascotBus`] in context (or provides its own), feeds it, and hosts the mascot overlay inside
/// the slab like the reference (render no second [`crate::mascot::MascotHost`]).
#[component]
pub fn Dashboard() -> Element {
    let panels = use_context::<Rc<dyn PanelsApi>>();
    let dash = use_dash();
    let servers = use_watch(|| panels.servers());
    let sample = use_watch(|| panels.traffic());
    let local_pings = use_signal(LocalPings::default);
    let active = use_page_active();
    use_mascot_feed(&dash, active, sample);
    let (bus, toasts) = (dash.bus.clone(), dash.toasts);
    // Hooks, not `EventHandler::new` in the body: that would add a box to this scope per render.
    let on_mascot = use_callback(move |ev: MascotEvent| bus.send(ev));
    let on_notice = use_callback(move |notice: Notice| {
        let description = notice.body.as_ref().map(tr);
        toasts.push(
            ToastKind::from(notice.level),
            tr(&notice.title),
            description,
        );
    });
    rsx! {
        div { class: "c-swiss swiss-skin",
            div { class: "space-y-6",
                // The old page's own toast container. Toasts live in the shell now (D-18); the
                // empty box stays first so `space-y-6` still puts 24 px above the first block.
                div { class: "c-swiss fixed z-[100] flex flex-col gap-2 top-[52px] right-4" }
                banners::Banners {}
                facts::FactsStrip {}
                slab::Slab { servers, local_pings }
                SwissPanels {
                    local_pings: Some(local_pings),
                    active: Some(active),
                    on_mascot: Some(on_mascot),
                    on_notice: Some(on_notice),
                }
            }
        }
    }
}

/// Feeds the mascot bus: the slab's phase, the session start, page activity, the speed band, and
/// a reaction to every new error / warning / success toast.
fn use_mascot_feed(dash: &Dash, active: Memo<bool>, sample: Signal<traffic::TrafficSample>) {
    let feed = dash.clone();
    use_effect(move || {
        let view = feed.snapshot();
        let state = swiss::derive_swiss_state(&SwissInput::new(&view.conn, &view.exit));
        feed.bus
            .phase(swiss::swiss_phase(state, view.conn.swiss_busy()));
        feed.bus.session_started(view.conn.tun_started_at());
        feed.bus.page_active(active());
    });
    let bus = dash.bus.clone();
    use_effect(move || bus.speed_band(traffic::speed_band(sample.read().down_bps())));
    let (bus, toasts) = (dash.bus.clone(), dash.toasts);
    // Toasts already queued when the page mounts are not news.
    let seen = use_hook(|| Rc::new(Cell::new(None::<u64>)));
    use_effect(move || {
        let list = toasts.list();
        if let Some(last) = seen.get() {
            for toast in list.iter().filter(|t| t.id > last) {
                match toast.kind {
                    ToastKind::Error => bus.send(MascotEvent::NoticeError),
                    ToastKind::Warning => bus.send(MascotEvent::NoticeWarn),
                    ToastKind::Success => bus.send(MascotEvent::NoticeOk),
                    ToastKind::Info => {}
                }
            }
        }
        let max = list.iter().map(|t| t.id).max().or(Some(0));
        seen.set(seen.get().max(max));
    });
}
