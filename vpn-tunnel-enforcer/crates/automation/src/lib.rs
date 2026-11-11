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

// --- shared by the work packages ---
#[cfg(any(feature = "automation-sched", feature = "automation-tweaks"))]
mod lenient;

// A build with only some package features leaves parts of the test helpers unused.
#[cfg(test)]
#[cfg_attr(
    not(all(
        feature = "automation-sched",
        feature = "automation-adaptive",
        feature = "automation-tweaks",
        feature = "automation-hardening"
    )),
    allow(dead_code)
)]
mod test_support;

// --- work package `automation-adaptive` ---
#[cfg(feature = "automation-adaptive")]
pub mod adaptive;
#[cfg(feature = "automation-adaptive")]
pub mod autopilot;

// --- work package `automation-hardening` ---
#[cfg(feature = "automation-hardening")]
pub mod hardening;

// --- work package `automation-sched` ---
#[cfg(feature = "automation-sched")]
pub mod coordinator;
#[cfg(feature = "automation-sched")]
pub mod rotation;
#[cfg(feature = "automation-sched")]
pub mod schedule;
#[cfg(feature = "automation-sched")]
pub mod scheduler;

// --- work package `automation-tweaks` ---
#[cfg(feature = "automation-tweaks")]
pub mod tweaks;
