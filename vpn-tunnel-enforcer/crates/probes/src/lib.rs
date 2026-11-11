//! Measurements: public IP and leak checks, diagnostics, availability, speed test, pings, country verification, key health and live server checks.

// --- work package `probes-diag` ---
#[cfg(feature = "probes-diag")]
pub mod diagnostics;
#[cfg(feature = "probes-diag")]
pub mod local_proxy;

// --- work package `probes-ip` ---
#[cfg(feature = "probes-ip")]
pub mod public_ip;
#[cfg(feature = "probes-ip")]
pub mod ip_monitor;
#[cfg(feature = "probes-ip")]
pub mod leak;

// --- work package `probes-live` ---
#[cfg(feature = "probes-live")]
pub mod live;

// --- work package `probes-live-stages` ---
#[cfg(feature = "probes-live-stages")]
pub mod live_stages;

// --- work package `probes-servers` ---
#[cfg(feature = "probes-servers")]
pub mod ping;
#[cfg(feature = "probes-servers")]
pub mod geo;
#[cfg(feature = "probes-servers")]
pub mod key_health;
#[cfg(feature = "probes-servers")]
pub mod egress;

// --- work package `probes-web` ---
#[cfg(feature = "probes-web")]
pub mod availability;
#[cfg(feature = "probes-web")]
pub mod speedtest;
