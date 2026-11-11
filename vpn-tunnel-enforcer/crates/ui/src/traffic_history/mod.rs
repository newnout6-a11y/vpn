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

use crate::lang::tr_now;
use dioxus::prelude::*;
use tokio::sync::watch;

pub use model::{
    DomainRow, MAX_RENDERED, Moment, SiteInfo, TrafficHistoryApi, TrafficSnapshot, by_day,
    day_heading, filter, moment, month_key, seen_line, site_url, totals,
};
pub use page::TrafficHistoryPage;

/// Site names can arrive in a burst (one per domain): changes are taken at most this often.
pub const COALESCE: Duration = Duration::from_millis(250);

/// The API from context.
fn use_api() -> Rc<dyn TrafficHistoryApi> {
    use_context::<Rc<dyn TrafficHistoryApi>>()
}

/// A signal that follows the API's watch channel; after a change it waits [`COALESCE`] and
/// takes the latest value, so a burst re-renders the list once.
fn use_coalesced<T: Clone + PartialEq + 'static>(
    subscribe: impl FnOnce() -> watch::Receiver<T>,
) -> Signal<T> {
    let rx = use_hook(subscribe);
    let mut value = use_signal(|| rx.borrow().clone());
    use_future(move || {
        let mut rx = rx.clone();
        async move {
            while rx.changed().await.is_ok() {
                tokio::time::sleep(COALESCE).await;
                let next = rx.borrow_and_update().clone();
                if *value.peek() != next {
                    value.set(next);
                }
            }
        }
    });
    value
}
