//! The user's server list: groups, subscriptions (fetch and refresh), selection, persistence.

mod common;
#[cfg(test)]
mod test_locales;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package in file-name
/// order, for the app's locale registration at start (after the UI's base layer).
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/servers-parse.ru.json"),
        include_str!("../locales/servers-parse.en.json"),
    ),
    (
        include_str!("../locales/servers-refresh.ru.json"),
        include_str!("../locales/servers-refresh.en.json"),
    ),
    (
        include_str!("../locales/servers-store.ru.json"),
        include_str!("../locales/servers-store.en.json"),
    ),
];

pub mod legacy;
pub mod model;
pub mod parse;
pub mod refresh;
pub mod store;
pub mod subscription;
