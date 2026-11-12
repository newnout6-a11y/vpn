//! Windows system layer: adapters and routes, processes and jobs, counters, ICMP, WFP protection, registry, environment, elevation, autostart, single instance, clipboard, power events, toasts.

#[cfg(test)]
mod test_support;
mod win;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package, for the
/// app's locale registration (after the UI's base layer).
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/noadmin-system.ru.json"),
        include_str!("../locales/noadmin-system.en.json"),
    ),
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

pub mod adapters;
pub mod autostart;
pub mod clipboard;
pub mod counters;
pub mod elevation;
pub mod env;
pub mod icmp;
pub mod power;
pub mod process;
pub mod registry;
pub mod shell;
pub mod single_instance;
pub mod sysproxy;
pub mod toast;
pub mod wfp;
