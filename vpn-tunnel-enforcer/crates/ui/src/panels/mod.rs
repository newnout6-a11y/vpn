//! The panel row under the status slab («Пломба»): traffic · servers · external proxies.
//!
//! Emits the DOM of the reference `.swiss-panels` subtree (classes, `data-perch` attributes,
//! text-node splits), so swiss.css styles it unchanged. Data and actions come from a
//! [`PanelsApi`] in context (`Rc<dyn PanelsApi>`); the app implements it over the backend,
//! [`demo::DemoPanels`] fakes it with the reference fixtures.
pub mod demo;
pub(crate) mod icons;
mod model;
mod picker;
mod proxies;
mod rules;
mod servers;
#[cfg(test)]
mod tests;
mod traffic;

use std::rc::Rc;

use crate::hooks::use_watch;
use dioxus::prelude::*;
use tokio::sync::watch;
use vpnte_base::AppResult;
use vpnte_base::types::Notice;
use vpnte_view::mascot::MascotEvent;
use vpnte_view::traffic::{TrafficHistory, TrafficSample};

pub use icons::Flag;
pub use model::{
    ProxiesView, ProxyChoice, ProxyHealth, ProxyRowView, Selected, ServerRowView, ServersView,
};
pub use rules::{
    CountrySummary, HEALTHY_REFRESH, IDLE_REFRESH, Indicator, LocalPings, ServerLine,
    UNSTABLE_REFRESH, choice_label, country_summary, first_free_slot, keep_selection,
    refresh_interval, server_lines,
};

/// Data and actions of the panel row.
///
/// Implementations run state-changing work (select, proxy start / stop) in their own task, so
/// it completes even when the panel unmounts while a call is pending. An action publishes the
/// state it changed through the receivers before it returns: the panels render only what the
/// receivers deliver (plus the measurements [`PanelsApi::ping_one`] returns).
#[async_trait::async_trait(?Send)]
pub trait PanelsApi: 'static {
    /// Traffic samples, once a second while the engine runs (the bars assume that cadence).
    fn traffic(&self) -> watch::Receiver<TrafficSample>;
    /// The server list with the active server.
    fn servers(&self) -> watch::Receiver<ServersView>;
    /// The external proxy slots and the picker's servers.
    fn proxies(&self) -> watch::Receiver<ProxiesView>;
    /// Measures one server's round trip now; `Ok(None)` = no answer.
    async fn ping_one(&self, id: &str) -> AppResult<Option<u32>>;
    /// Pings every server; the stored pings arrive through [`PanelsApi::servers`].
    async fn ping_all(&self) -> AppResult<()>;
    /// Makes `id` the active server (a live direct-VPN connection switches over).
    async fn select_server(&self, id: &str) -> AppResult<Selected>;
    /// Starts server `profile_id` as an external proxy in `slot`; returns the published state
    /// (the panel reads the slot's row from it for the feedback).
    async fn proxy_start(&self, slot: u16, profile_id: &str) -> AppResult<ProxiesView>;
    /// Stops the proxy in `slot`; returns the published state.
    async fn proxy_stop(&self, slot: u16) -> AppResult<ProxiesView>;
    /// Restarts `slot` on the next server; returns the published state.
    async fn proxy_rotate(&self, slot: u16) -> AppResult<ProxiesView>;
    /// Stops every external proxy; returns the published state.
    async fn proxy_stop_all(&self) -> AppResult<ProxiesView>;
    /// Re-reads the slots' health now; called on [`refresh_interval`]'s cadence while the
    /// column is shown. Results arrive through [`PanelsApi::proxies`].
    async fn proxy_refresh(&self) -> AppResult<()>;
}

/// The traffic channel: every received sample feeds the 48-bar history here, in the pump,
/// because renders coalesce and a sample seen only by a render could be skipped.
fn use_traffic(api: &Rc<dyn PanelsApi>) -> (Signal<TrafficSample>, Signal<TrafficHistory>) {
    let rx = use_hook(|| api.traffic());
    let mut sample = use_signal(|| *rx.borrow());
    let mut history = use_signal(|| {
        let mut h = TrafficHistory::new();
        h.observe(&sample.peek());
        h
    });
    use_future(move || {
        let mut rx = rx.clone();
        async move {
            while rx.changed().await.is_ok() {
                let next = *rx.borrow_and_update();
                history.write().observe(&next);
                sample.set(next);
            }
        }
    });
    (sample, history)
}

/// The panel row: traffic, servers, external proxies.
///
/// `local_pings`: pass the dashboard's signal to share the panel's ping measurements with the
/// slab's node line (otherwise the row keeps its own). `active`: while it reads false (the page is
/// not shown, the window is hidden) the proxy column's health refresh pauses; without it the
/// refresh always runs. `on_mascot` receives the proxy column's mascot nudges, `on_notice` the user
/// feedback for the toast queue.
#[component]
pub fn SwissPanels(
    #[props(default)] local_pings: Option<Signal<LocalPings>>,
    #[props(default)] active: Option<Memo<bool>>,
    #[props(default)] on_mascot: Option<EventHandler<MascotEvent>>,
    #[props(default)] on_notice: Option<EventHandler<Notice>>,
) -> Element {
    let api = use_context::<Rc<dyn PanelsApi>>();
    let own_pings = use_signal(LocalPings::default);
    let local = local_pings.unwrap_or(own_pings);
    let (sample, history) = use_traffic(&api);
    let servers = use_watch(|| api.servers());
    let proxies = use_watch(|| api.proxies());
    rsx! {
        div { class: "swiss-panels",
            traffic::TrafficPanel { sample, history }
            servers::ServersPanel { view: servers, local, on_notice }
            proxies::ProxiesPanel { view: proxies, active, on_mascot, on_notice }
        }
    }
}

/// Head of a panel: the ink title, a perch for the mascot, and the panel's action.
#[component]
fn PanelHead(title: String, perch: &'static str, children: Element) -> Element {
    rsx! {
        header {
            class: "swiss-panel-head",
            "data-perch": perch,
            "data-perch-y": "bottom",
            "data-perch-scale": "0.32",
            "data-perch-fit": "gap",
            span { class: "swiss-label swiss-label-ink", "{title}" }
            {children}
        }
    }
}

/// Sends `notice` to the optional handler.
fn notify(handler: Option<EventHandler<Notice>>, notice: Notice) {
    if let Some(h) = handler {
        h.call(notice);
    }
}
