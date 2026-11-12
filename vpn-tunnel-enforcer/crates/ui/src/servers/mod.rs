//! Servers page in the «Пломба» language: groups with subscription facts and refresh, server rows
//! (flag, name, protocol, ping, health, country), the add dialog with an import report,
//! select / switch with cancel, pings, key health, key copy / export, remove, the server detail
//! with the live check, and the batch comparison.
//!
//! The page renders only [`ServersView`] snapshots and calls [`ServersApi`]; the app implements
//! the trait over the backend, [`DemoServersApi`] fakes it with realistic data.
mod actions;
mod add;
mod api;
mod batch;
mod demo;
mod demo_data;
mod detail;
mod facts;
mod group;
mod live;
mod live_model;
mod live_present;
mod menu;
mod model;
mod page;
mod present;
mod report;
mod request;
mod row;
mod state;
#[cfg(test)]
mod tests;
mod verdict;

pub use api::{ServersApi, use_servers_api};
pub use demo::{DemoScene, DemoServersApi};
pub use live_model::*;
pub use model::*;
pub use page::ServersPage;
pub use present::{
    BucketKind, DEVICES, GroupBucket, PingState, RowSignal, Unusable, buckets, device_label,
    displayed_ping, engine_name, fingerprint, happ_type, is_deleted, is_removed_from_subscription,
    local_stamp, protocol_sections, proxy_ready, relative_time, row_signal, sort_groups,
    stealth_badge, unusable,
};
