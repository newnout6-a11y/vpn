//! sing-box and Xray: config generation, process supervision, Clash API, routing and DNS rules.

// --- work package `engine-config` ---
pub mod singbox_config;

// --- work package `engine-xray-config` ---
pub mod xray_config;

// --- work package `engine-routing` ---
pub mod routing;

// --- work package `engine-process` ---
pub mod singbox_process;
pub mod xray_process;
pub mod clash_api;
pub mod ports;
