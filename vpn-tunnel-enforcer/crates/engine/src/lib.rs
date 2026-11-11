//! sing-box and Xray: config generation, process supervision, Clash API, routing and DNS rules.

// --- shared by the work packages ---
pub mod slot;
pub mod tags;
// A build with only some package features leaves parts of the test helpers unused.
#[cfg(test)]
#[cfg_attr(
    not(all(
        feature = "engine-config",
        feature = "engine-process",
        feature = "engine-routing",
        feature = "engine-xray-config"
    )),
    allow(dead_code)
)]
mod test_locales;
#[cfg(test)]
#[cfg_attr(
    not(all(
        feature = "engine-config",
        feature = "engine-process",
        feature = "engine-routing",
        feature = "engine-xray-config"
    )),
    allow(dead_code)
)]
mod test_support;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package in file-name
/// order, for the app's locale registration at start (after the UI's base layer).
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/engine-config.ru.json"),
        include_str!("../locales/engine-config.en.json"),
    ),
    (
        include_str!("../locales/engine-process.ru.json"),
        include_str!("../locales/engine-process.en.json"),
    ),
    (
        include_str!("../locales/engine-routing.ru.json"),
        include_str!("../locales/engine-routing.en.json"),
    ),
    (
        include_str!("../locales/engine-xray-config.ru.json"),
        include_str!("../locales/engine-xray-config.en.json"),
    ),
];

// --- work package `engine-config` (also the home of `RoutingParts`, built by `routing`) ---
#[cfg(any(feature = "engine-config", feature = "engine-routing"))]
pub mod singbox_config;

// --- work package `engine-process` ---
#[cfg(feature = "engine-process")]
pub mod clash_api;
#[cfg(feature = "engine-process")]
pub mod ports;
#[cfg(feature = "engine-process")]
pub mod singbox_process;
#[cfg(feature = "engine-process")]
pub mod xray_process;

// --- work package `engine-routing` ---
#[cfg(feature = "engine-routing")]
pub mod apps;
#[cfg(feature = "engine-routing")]
pub mod routing;

// --- work package `engine-xray-config` ---
#[cfg(feature = "engine-xray-config")]
pub mod xray_config;
