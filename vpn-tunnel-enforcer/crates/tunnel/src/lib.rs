//! Connection runtime and lifecycle: start, stop, switch, state machine and session history.

#[cfg(test)]
mod test_locales;
#[cfg(test)]
mod test_support;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package in file-name
/// order, for the app's locale registration at start (after the UI's base layer).
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/noadmin-tunnel.ru.json"),
        include_str!("../locales/noadmin-tunnel.en.json"),
    ),
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

pub mod api;
pub mod fsm;
pub mod history;
pub mod lifecycle;
pub mod outcome;
pub mod runtime;
pub mod switch;
