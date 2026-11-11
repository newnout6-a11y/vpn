//! The user's server list: groups, subscriptions (fetch and refresh), selection, persistence.

// --- shared by the work packages (each package build uses only part of it) ---
#[cfg(any(feature = "servers-parse", feature = "servers-store"))]
#[cfg_attr(not(feature = "servers-store"), allow(dead_code))]
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

// --- work package `servers-parse` ---
#[cfg(feature = "servers-parse")]
pub mod parse;

// --- work package `servers-refresh` ---
#[cfg(feature = "servers-refresh")]
pub mod refresh;
#[cfg(feature = "servers-refresh")]
pub mod subscription;

// --- work package `servers-store` ---
#[cfg(feature = "servers-store")]
pub mod legacy;
#[cfg(feature = "servers-store")]
pub mod model;
#[cfg(feature = "servers-store")]
pub mod store;
