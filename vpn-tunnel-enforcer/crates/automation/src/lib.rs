//! Scheduler, profile rotation, AutoPilot, adaptive bypass and reversible soft-mode system tweaks.

// --- work package `automation-adaptive` ---
#[cfg(feature = "automation-adaptive")]
pub mod autopilot;
#[cfg(feature = "automation-adaptive")]
pub mod adaptive;

// --- work package `automation-hardening` ---
#[cfg(feature = "automation-hardening")]
pub mod hardening;

// --- work package `automation-sched` ---
#[cfg(feature = "automation-sched")]
pub mod coordinator;
#[cfg(feature = "automation-sched")]
pub mod schedule;
#[cfg(feature = "automation-sched")]
pub mod scheduler;
#[cfg(feature = "automation-sched")]
pub mod rotation;

// --- work package `automation-tweaks` ---
#[cfg(feature = "automation-tweaks")]
pub mod tweaks;
