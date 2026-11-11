//! One-shot removal of what the old Electron app left in the system: firewall rules, legacy WFP objects, scheduled tasks, adapter leftovers, orphaned runtime processes.

// --- work package `cleanup-legacy` ---
#[cfg(feature = "cleanup-legacy")]
pub mod legacy;
