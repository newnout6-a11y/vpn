//! Dioxus desktop UI: window frame, shell, the start page in the Plomba design, the mascot and every other page. Talks to the backend only through view models and API traits.

// --- shared by the work packages ---
pub mod hooks;
#[cfg(all(test, feature = "ui-frame"))]
mod test_locales;
#[cfg(test)]
mod test_support;
pub mod units;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package in file-name
/// order. [`lang::init_locales`] registers them after the old app's catalog; the app passes the
/// backend crates' `LOCALES` as its extra layers.
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/ui-dashboard.ru.json"),
        include_str!("../locales/ui-dashboard.en.json"),
    ),
    (
        include_str!("../locales/ui-frame.ru.json"),
        include_str!("../locales/ui-frame.en.json"),
    ),
    (
        include_str!("../locales/ui-lists.ru.json"),
        include_str!("../locales/ui-lists.en.json"),
    ),
    (
        include_str!("../locales/ui-logs.ru.json"),
        include_str!("../locales/ui-logs.en.json"),
    ),
    (
        include_str!("../locales/ui-maintenance.ru.json"),
        include_str!("../locales/ui-maintenance.en.json"),
    ),
    (
        include_str!("../locales/ui-mascot.ru.json"),
        include_str!("../locales/ui-mascot.en.json"),
    ),
    (
        include_str!("../locales/ui-panels.ru.json"),
        include_str!("../locales/ui-panels.en.json"),
    ),
    (
        include_str!("../locales/ui-servers.ru.json"),
        include_str!("../locales/ui-servers.en.json"),
    ),
    (
        include_str!("../locales/ui-settings.ru.json"),
        include_str!("../locales/ui-settings.en.json"),
    ),
    (
        include_str!("../locales/ui-shell.ru.json"),
        include_str!("../locales/ui-shell.en.json"),
    ),
    (
        include_str!("../locales/ui-tools.ru.json"),
        include_str!("../locales/ui-tools.en.json"),
    ),
    (
        include_str!("../locales/ui-tray.ru.json"),
        include_str!("../locales/ui-tray.en.json"),
    ),
    (
        include_str!("../locales/ui-widgets.ru.json"),
        include_str!("../locales/ui-widgets.en.json"),
    ),
    (
        include_str!("../locales/ui-wizard.ru.json"),
        include_str!("../locales/ui-wizard.en.json"),
    ),
];

// --- work package `ui-dashboard` ---
#[cfg(feature = "ui-dashboard")]
pub mod dashboard;

// --- work package `ui-frame` ---
#[cfg(feature = "ui-frame")]
pub mod assets;
#[cfg(feature = "ui-frame")]
pub mod lang;
#[cfg(feature = "ui-frame")]
pub mod launch;
#[cfg(feature = "ui-frame")]
pub mod theme;

// --- work package `ui-lists` ---
#[cfg(feature = "ui-lists")]
pub mod schedule;
#[cfg(feature = "ui-lists")]
pub mod split_tunnel;
#[cfg(feature = "ui-lists")]
pub mod traffic_history;

// --- work package `ui-logs` ---
#[cfg(feature = "ui-logs")]
pub mod logs;

// --- work package `ui-maintenance` ---
#[cfg(feature = "ui-maintenance")]
pub mod maintenance;

// --- work package `ui-mascot` ---
#[cfg(feature = "ui-mascot")]
pub mod mascot;

// --- work package `ui-panels` ---
#[cfg(feature = "ui-panels")]
pub mod panels;

// --- work package `ui-servers` ---
#[cfg(feature = "ui-servers")]
pub mod servers;

// --- work package `ui-settings` ---
#[cfg(feature = "ui-settings")]
pub mod settings;

// --- work package `ui-shell` ---
#[cfg(feature = "ui-shell")]
pub mod pages;
#[cfg(feature = "ui-shell")]
pub mod shell;

// --- work package `ui-tools` ---
#[cfg(feature = "ui-tools")]
pub mod availability;
#[cfg(feature = "ui-tools")]
pub mod speedtest;

// --- work package `ui-tray` ---
#[cfg(feature = "ui-tray")]
pub mod tray;

// --- work package `ui-widgets` ---
#[cfg(feature = "ui-widgets")]
pub mod widgets;

// --- work package `ui-wizard` ---
#[cfg(feature = "ui-wizard")]
pub mod wizard;
