//! Measurements: public IP and leak checks, diagnostics, availability, speed test, pings, country verification, key health and live server checks.

// --- work package `probes-ip` ---
pub mod public_ip;
pub mod ip_monitor;
pub mod leak;

// --- work package `probes-diag` ---
pub mod diagnostics;
pub mod local_proxy;

// --- work package `probes-web` ---
pub mod availability;
pub mod speedtest;

// --- work package `probes-servers` ---
pub mod ping;
pub mod geo;
pub mod key_health;
pub mod egress;

// --- work package `probes-live-stages` ---
pub mod live_stages;

// --- work package `probes-live` ---
pub mod live;
