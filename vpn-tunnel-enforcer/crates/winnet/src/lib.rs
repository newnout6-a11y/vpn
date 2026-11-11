//! Windows system layer: adapters and routes, processes and jobs, counters, ICMP, WFP protection, registry, environment, elevation, autostart, single instance, clipboard, power events, toasts.

// --- shared by the work packages ---
// A build with only some package features leaves parts of the shared helpers unused.
#[cfg(test)]
#[cfg_attr(
    not(all(
        feature = "winnet-wfp",
        feature = "winnet-adapters",
        feature = "winnet-process",
        feature = "winnet-system",
        feature = "winnet-shell"
    )),
    allow(dead_code)
)]
mod test_support;
#[cfg_attr(
    not(all(
        feature = "winnet-wfp",
        feature = "winnet-adapters",
        feature = "winnet-process",
        feature = "winnet-system",
        feature = "winnet-shell"
    )),
    allow(dead_code)
)]
mod win;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package, for the
/// app's locale registration (after the UI's base layer).
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/winnet-adapters.ru.json"),
        include_str!("../locales/winnet-adapters.en.json"),
    ),
    (
        include_str!("../locales/winnet-process.ru.json"),
        include_str!("../locales/winnet-process.en.json"),
    ),
    (
        include_str!("../locales/winnet-shell.ru.json"),
        include_str!("../locales/winnet-shell.en.json"),
    ),
    (
        include_str!("../locales/winnet-system.ru.json"),
        include_str!("../locales/winnet-system.en.json"),
    ),
    (
        include_str!("../locales/winnet-wfp.ru.json"),
        include_str!("../locales/winnet-wfp.en.json"),
    ),
];

// --- work package `winnet-adapters` ---
#[cfg(feature = "winnet-adapters")]
pub mod adapters;

// --- work package `winnet-process` (`counters` is also read by `adapters`) ---
#[cfg(any(feature = "winnet-process", feature = "winnet-adapters"))]
pub mod counters;
#[cfg(feature = "winnet-process")]
pub mod icmp;
#[cfg(feature = "winnet-process")]
pub mod process;

// --- work package `winnet-shell` ---
#[cfg(feature = "winnet-shell")]
pub mod elevation;
#[cfg(feature = "winnet-shell")]
pub mod power;
#[cfg(feature = "winnet-shell")]
pub mod shell;
#[cfg(feature = "winnet-shell")]
pub mod single_instance;
#[cfg(feature = "winnet-shell")]
pub mod toast;

// --- work package `winnet-system` (`registry` also serves `adapters`, `toast` and `power`) ---
#[cfg(feature = "winnet-system")]
pub mod autostart;
#[cfg(feature = "winnet-system")]
pub mod clipboard;
#[cfg(feature = "winnet-system")]
pub mod env;
#[cfg(any(
    feature = "winnet-system",
    feature = "winnet-adapters",
    feature = "winnet-shell"
))]
pub mod registry;

// --- work package `winnet-wfp` ---
#[cfg(feature = "winnet-wfp")]
pub mod wfp;
