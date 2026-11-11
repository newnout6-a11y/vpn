//! Measurements: public IP and leak checks, diagnostics, availability, speed test, pings, country verification, key health and live server checks.

// The list is complete only when every package is built (a package build alone may already
// have fragments of packages written in parallel).
#[cfg(all(
    test,
    feature = "probes-diag",
    feature = "probes-ip",
    feature = "probes-live",
    feature = "probes-live-stages",
    feature = "probes-servers",
    feature = "probes-web"
))]
mod test_locales;
#[cfg(test)]
mod test_support;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package sorted by
/// package name, for the app's locale registration at start (after the UI's base layer).
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/probes-diag.ru.json"),
        include_str!("../locales/probes-diag.en.json"),
    ),
    (
        include_str!("../locales/probes-ip.ru.json"),
        include_str!("../locales/probes-ip.en.json"),
    ),
    (
        include_str!("../locales/probes-live.ru.json"),
        include_str!("../locales/probes-live.en.json"),
    ),
    (
        include_str!("../locales/probes-live-stages.ru.json"),
        include_str!("../locales/probes-live-stages.en.json"),
    ),
    (
        include_str!("../locales/probes-servers.ru.json"),
        include_str!("../locales/probes-servers.en.json"),
    ),
    (
        include_str!("../locales/probes-web.ru.json"),
        include_str!("../locales/probes-web.en.json"),
    ),
];

// --- shared by several work packages ---
#[cfg(any(feature = "probes-diag", feature = "probes-ip"))]
pub mod curl;
#[cfg(any(feature = "probes-ip", feature = "probes-servers"))]
mod ip_echo;
#[cfg(any(
    feature = "probes-live-stages",
    feature = "probes-servers",
    feature = "probes-web"
))]
mod tls_client;

// --- work package `probes-diag` ---
#[cfg(feature = "probes-diag")]
pub mod diagnostics;
#[cfg(feature = "probes-diag")]
pub mod local_proxy;

// --- work package `probes-ip` ---
#[cfg(feature = "probes-ip")]
pub mod ip_monitor;
#[cfg(feature = "probes-ip")]
pub mod leak;
#[cfg(feature = "probes-ip")]
pub mod public_ip;

// --- work package `probes-live` ---
#[cfg(feature = "probes-live")]
pub mod live;

// --- work package `probes-live-stages` ---
#[cfg(feature = "probes-live-stages")]
pub mod live_stages;

// --- work package `probes-servers` ---
#[cfg(feature = "probes-servers")]
pub mod egress;
#[cfg(feature = "probes-servers")]
pub mod geo;
#[cfg(feature = "probes-servers")]
pub mod key_health;
#[cfg(feature = "probes-servers")]
pub mod ping;

// --- work package `probes-web` ---
#[cfg(feature = "probes-web")]
pub mod availability;
#[cfg(feature = "probes-web")]
pub mod speedtest;
