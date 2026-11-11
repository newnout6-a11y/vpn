//! Traffic statistics, domain history, packet capture, ETW events and the diagnostics export.

// --- work package `forensics-capture` ---
#[cfg(feature = "forensics-capture")]
pub mod capture;
#[cfg(feature = "forensics-capture")]
pub mod etw;

// --- work package `forensics-export` ---
#[cfg(feature = "forensics-export")]
pub mod summary;
#[cfg(feature = "forensics-export")]
pub mod export;

// --- work package `forensics-traffic` ---
#[cfg(feature = "forensics-traffic")]
pub mod traffic;
#[cfg(feature = "forensics-traffic")]
pub mod connections;
#[cfg(feature = "forensics-traffic")]
pub mod domains;
#[cfg(feature = "forensics-traffic")]
pub mod enrichment;
