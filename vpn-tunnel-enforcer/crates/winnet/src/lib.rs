//! Windows system layer: adapters and routes, processes and jobs, counters, ICMP, WFP protection, registry, environment, elevation, autostart, single instance, clipboard, power events, toasts.

// --- work package `winnet-adapters` ---
pub mod adapters;

// --- work package `winnet-process` ---
pub mod process;
pub mod counters;
pub mod icmp;

// --- work package `winnet-shell` ---
pub mod elevation;
pub mod single_instance;
pub mod shell;
pub mod toast;
pub mod power;

// --- work package `winnet-system` ---
pub mod registry;
pub mod env;
pub mod autostart;
pub mod clipboard;

// --- work package `winnet-wfp` ---
pub mod wfp;

// --- work package `winnet-legacy` ---
pub mod legacy_cleanup;
