//! The Traffic page («Трафик»): the domains seen through the tunnel with connection counts,
//! bytes and optional site names; search, refresh and a confirmed clear (ui-pages §3.15, U-18,
//! U-29). The domains come from the engine's live connections (forensics owns the history).
//!
//! Data and actions come from a [`TrafficHistoryApi`] in context
//! (`Rc<dyn TrafficHistoryApi>`); the app implements it over the domain history,
//! [`demo::DemoTrafficHistory`] fakes it. Register the page with
//! `registry.register(Page::TrafficHistory, TrafficHistoryPage)`; it is an active-only page, so
//! the search resets on every visit, as before.
pub mod demo;
mod model;
mod page;
#[cfg(test)]
mod tests;

use std::rc::Rc;
use std::time::Duration;

use dioxus::prelude::*;
use tokio::sync::watch;

pub use model::{
    DomainRow, MAX_RENDERED, Moment, SiteInfo, TrafficHistoryApi, TrafficSnapshot, by_day,
    day_heading, filter, moment, month_key, seen_line, site_url, totals,
};
pub use page::TrafficHistoryPage;

/// Changes are taken at most this often. Site names can arrive in a burst (one per domain); the
/// app already paces the page's feed to this cadence (`vpnte-app` `api_dashboard::pace`, the
/// first change at once), so a paced push is never held back and an unpaced source (the demo)
/// still renders at most twice a second.
pub const COALESCE: Duration = Duration::from_millis(500);

/// The API from context.
fn use_api() -> Rc<dyn TrafficHistoryApi> {
    use_context::<Rc<dyn TrafficHistoryApi>>()
}

/// A signal that follows the API's watch channel: a change is taken at once, later ones at the
/// end of the [`COALESCE`] window that follows (the latest value), so a burst re-renders the list
/// at most twice a second.
fn use_coalesced<T: Clone + PartialEq + 'static>(
    subscribe: impl FnOnce() -> watch::Receiver<T>,
) -> Signal<T> {
    let rx = use_hook(subscribe);
    let mut value = use_signal(|| rx.borrow().clone());
    use_future(move || {
        let mut rx = rx.clone();
        async move {
            while rx.changed().await.is_ok() {
                let next = rx.borrow_and_update().clone();
                if *value.peek() != next {
                    value.set(next);
                }
                tokio::time::sleep(COALESCE).await;
            }
        }
    });
    value
}
