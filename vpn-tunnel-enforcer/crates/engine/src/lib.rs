//! sing-box and Xray: config generation, process supervision, Clash API, routing and DNS rules.

#[cfg(test)]
mod test_locales;
#[cfg(test)]
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

pub mod apps;
pub mod clash_api;
pub mod ports;
pub mod routing;
pub mod singbox_config;
pub mod singbox_process;
pub mod slot;
pub mod tags;
pub mod xray_config;
pub mod xray_process;
