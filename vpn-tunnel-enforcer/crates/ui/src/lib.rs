//! Dioxus desktop UI: window frame, shell, the start page in the Plomba design, the mascot and every other page. Talks to the backend only through view models and API traits.

// --- work package `ui-dashboard` ---
#[cfg(feature = "ui-dashboard")]
pub mod dashboard;

// --- work package `ui-frame` ---
#[cfg(feature = "ui-frame")]
pub mod assets;
#[cfg(feature = "ui-frame")]
pub mod lang;
#[cfg(feature = "ui-frame")]
pub mod theme;
#[cfg(feature = "ui-frame")]
pub mod launch;

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
pub mod shell;
#[cfg(feature = "ui-shell")]
pub mod pages;

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
