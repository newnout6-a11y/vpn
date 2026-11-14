//! External loopback proxy slots and their local control API.

#[cfg(test)]
mod test_locales;
#[cfg(test)]
mod test_support;
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

pub mod config;
pub mod control;
pub mod health;
pub mod manager;
pub mod model;
pub mod probe;
pub mod slot;
