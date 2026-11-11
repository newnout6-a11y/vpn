//! VPN Tunnel Enforcer application: builds the backend out of the library crates, implements the
//! UI's API traits over it and runs the Dioxus shell.

// --- written by the lead ---
pub mod args;
pub mod import;
pub mod setup;

// --- work package `app-base` ---
#[cfg(feature = "app-base")]
pub mod services;
#[cfg(feature = "app-base")]
pub mod svc_core;

// --- work package `app-dashboard` ---
#[cfg(feature = "app-dashboard")]
pub mod api_dashboard;

// --- work package `app-servers` ---
#[cfg(feature = "app-servers")]
pub mod api_servers;

// --- work package `app-settings` ---
#[cfg(feature = "app-settings")]
pub mod api_logs;
#[cfg(feature = "app-settings")]
pub mod api_settings;

// --- work package `app-tunnel` ---
#[cfg(feature = "app-tunnel")]
pub mod svc_tunnel;

// --- work package `app-main` ---
#[cfg(feature = "app-main")]
pub mod boot;
#[cfg(feature = "app-main")]
pub mod root;

// --- work package `app-import` ---

// --- work package `app-setup` ---
