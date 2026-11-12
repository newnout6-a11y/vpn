//! Scheduler, profile rotation, AutoPilot, adaptive bypass and reversible soft-mode system tweaks.

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package in file-name
/// order, for the app's locale registration at start (after the UI's base layer).
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/automation-adaptive.ru.json"),
        include_str!("../locales/automation-adaptive.en.json"),
    ),
    (
        include_str!("../locales/automation-hardening.ru.json"),
        include_str!("../locales/automation-hardening.en.json"),
    ),
    (
        include_str!("../locales/automation-sched.ru.json"),
        include_str!("../locales/automation-sched.en.json"),
    ),
    (
        include_str!("../locales/automation-tweaks.ru.json"),
        include_str!("../locales/automation-tweaks.en.json"),
    ),
    (
        include_str!("../locales/noadmin-system.ru.json"),
        include_str!("../locales/noadmin-system.en.json"),
    ),
];

mod lenient;
#[cfg(test)]
mod test_support;

pub mod adaptive;
pub mod autopilot;
pub mod coordinator;
pub mod hardening;
pub mod rotation;
pub mod schedule;
pub mod scheduler;
pub mod tweaks;
