//! Windows system layer: adapters and routes, processes and jobs, counters, ICMP, WFP protection, registry, environment, elevation, autostart, single instance, clipboard, power events, toasts.

// --- work package `winnet-adapters` ---
#[cfg(feature = "winnet-adapters")]
pub mod adapters;

// --- work package `winnet-process` ---
#[cfg(feature = "winnet-process")]
pub mod process;
#[cfg(feature = "winnet-process")]
pub mod counters;
#[cfg(feature = "winnet-process")]
pub mod icmp;

// --- work package `winnet-shell` ---
#[cfg(feature = "winnet-shell")]
pub mod elevation;
#[cfg(feature = "winnet-shell")]
pub mod single_instance;
#[cfg(feature = "winnet-shell")]
pub mod shell;
#[cfg(feature = "winnet-shell")]
pub mod toast;
#[cfg(feature = "winnet-shell")]
pub mod power;

// --- work package `winnet-system` ---
#[cfg(feature = "winnet-system")]
pub mod registry;
#[cfg(feature = "winnet-system")]
pub mod env;
#[cfg(feature = "winnet-system")]
pub mod autostart;
#[cfg(feature = "winnet-system")]
pub mod clipboard;

// --- work package `winnet-wfp` ---
#[cfg(feature = "winnet-wfp")]
pub mod wfp;
