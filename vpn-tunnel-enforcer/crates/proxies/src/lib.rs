//! External loopback proxy slots and their local control API.

// --- shared by the work packages ---
#[cfg(test)]
mod test_locales;
#[cfg(all(test, feature = "proxies-model"))]
// A build without the manager leaves its fixtures unused.
#[cfg_attr(not(feature = "proxies-manager"), allow(dead_code))]
mod test_support;
#[cfg(feature = "proxies-model")]
mod token;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package in file-name
/// order, for the app's locale registration at start (after the UI's base layer).
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/proxies-control.ru.json"),
        include_str!("../locales/proxies-control.en.json"),
    ),
    (
        include_str!("../locales/proxies-manager.ru.json"),
        include_str!("../locales/proxies-manager.en.json"),
    ),
    (
        include_str!("../locales/proxies-model.ru.json"),
        include_str!("../locales/proxies-model.en.json"),
    ),
];

// --- work package `proxies-control` ---
#[cfg(feature = "proxies-control")]
pub mod control;

// --- work package `proxies-manager` ---
#[cfg(feature = "proxies-manager")]
pub mod health;
#[cfg(feature = "proxies-manager")]
pub mod manager;
#[cfg(feature = "proxies-manager")]
pub mod probe;

// --- work package `proxies-model` ---
#[cfg(feature = "proxies-model")]
pub mod config;
#[cfg(feature = "proxies-model")]
pub mod lease;
#[cfg(feature = "proxies-model")]
pub mod model;
#[cfg(feature = "proxies-model")]
pub mod slot;
