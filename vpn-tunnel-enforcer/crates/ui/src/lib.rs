//! Dioxus desktop UI: window frame, shell, the start page in the Plomba design, the mascot and every other page. Talks to the backend only through view models and API traits.

#[cfg(test)]
mod test_locales;
#[cfg(test)]
mod test_support;

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
    // Lab texts (WP-12): shown only by a `lab` build, kept here so the key checks see one catalog.
    (
        include_str!("../locales/w7-mihomo.ru.json"),
        include_str!("../locales/w7-mihomo.en.json"),
    ),
];

pub mod assets;
pub mod availability;
pub mod dashboard;
pub mod hooks;
pub mod lang;
pub mod launch;
pub mod logs;
pub mod maintenance;
pub mod mascot;
pub mod pages;
pub mod panels;
pub mod schedule;
pub mod servers;
pub mod settings;
pub mod shell;
pub mod speedtest;
pub mod split_tunnel;
pub mod theme;
pub mod traffic_history;
pub mod tray;
pub mod units;
pub mod widgets;
pub mod wizard;
