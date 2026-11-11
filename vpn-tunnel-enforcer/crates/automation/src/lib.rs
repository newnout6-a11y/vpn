//! Scheduler, profile rotation, AutoPilot, adaptive bypass and reversible soft-mode system tweaks.

// --- work package `automation-sched` ---
pub mod schedule;
pub mod scheduler;
pub mod rotation;

// --- work package `automation-adaptive` ---
pub mod autopilot;
pub mod adaptive;

// --- work package `automation-tweaks` ---
pub mod tweaks;

// --- work package `automation-hardening` ---
pub mod hardening;
