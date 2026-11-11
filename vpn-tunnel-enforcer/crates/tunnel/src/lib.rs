//! Connection runtime and lifecycle: start, stop, switch, state machine and session history.

// --- shared by the work packages ---
// A build with only some package features leaves parts of the test helpers unused.
#[cfg(test)]
#[cfg_attr(
    not(all(
        feature = "tunnel-fsm",
        feature = "tunnel-history",
        feature = "tunnel-lifecycle",
        feature = "tunnel-runtime"
    )),
    allow(dead_code)
)]
mod test_locales;
#[cfg(test)]
#[cfg_attr(
    not(all(feature = "tunnel-history", feature = "tunnel-lifecycle")),
    allow(dead_code)
)]
mod test_support;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package in file-name
/// order, for the app's locale registration at start (after the UI's base layer).
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/tunnel-fsm.ru.json"),
        include_str!("../locales/tunnel-fsm.en.json"),
    ),
    (
        include_str!("../locales/tunnel-history.ru.json"),
        include_str!("../locales/tunnel-history.en.json"),
    ),
    (
        include_str!("../locales/tunnel-lifecycle.ru.json"),
        include_str!("../locales/tunnel-lifecycle.en.json"),
    ),
    (
        include_str!("../locales/tunnel-runtime.ru.json"),
        include_str!("../locales/tunnel-runtime.en.json"),
    ),
];

// --- work package `tunnel-fsm` ---
#[cfg(feature = "tunnel-fsm")]
pub mod api;
#[cfg(feature = "tunnel-fsm")]
pub mod fsm;

// --- work package `tunnel-history` ---
#[cfg(feature = "tunnel-history")]
pub mod history;
#[cfg(feature = "tunnel-history")]
pub mod outcome;

// --- work package `tunnel-lifecycle` ---
#[cfg(feature = "tunnel-lifecycle")]
pub mod lifecycle;

// --- work package `tunnel-runtime` ---
#[cfg(feature = "tunnel-runtime")]
pub mod runtime;
#[cfg(feature = "tunnel-runtime")]
pub mod switch;
