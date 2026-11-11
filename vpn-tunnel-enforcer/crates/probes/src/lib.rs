//! Measurements: public IP and leak checks, diagnostics, availability, speed test, pings, country verification, key health and live server checks.

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package in file-name
/// order (`probes-live-stages.*` sorts before `probes-live.*`), for the app's locale registration
/// at start (after the UI's base layer).
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
        include_str!("../locales/probes-live-stages.ru.json"),
        include_str!("../locales/probes-live-stages.en.json"),
    ),
    (
        include_str!("../locales/probes-live.ru.json"),
        include_str!("../locales/probes-live.en.json"),
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

mod ip_echo;
#[cfg(test)]
mod test_locales;
#[cfg(test)]
mod test_support;
mod tls_client;

pub mod availability;
pub mod curl;
pub mod diagnostics;
pub mod egress;
pub mod geo;
pub mod ip_monitor;
pub mod key_health;
pub mod leak;
pub mod live;
pub mod live_stages;
pub mod local_proxy;
pub mod ping;
pub mod public_ip;
pub mod speedtest;
