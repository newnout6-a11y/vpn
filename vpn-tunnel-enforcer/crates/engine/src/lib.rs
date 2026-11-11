//! sing-box and Xray: config generation, process supervision, Clash API, routing and DNS rules.

// --- work package `engine-config` ---
#[cfg(feature = "engine-config")]
pub mod singbox_config;

// --- work package `engine-process` ---
#[cfg(feature = "engine-process")]
pub mod singbox_process;
#[cfg(feature = "engine-process")]
pub mod xray_process;
#[cfg(feature = "engine-process")]
pub mod clash_api;
#[cfg(feature = "engine-process")]
pub mod ports;

// --- work package `engine-routing` ---
#[cfg(feature = "engine-routing")]
pub mod routing;
#[cfg(feature = "engine-routing")]
pub mod apps;

// --- work package `engine-xray-config` ---
#[cfg(feature = "engine-xray-config")]
pub mod xray_config;
