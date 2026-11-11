//! One-shot removal of what the old Electron app left in the system: firewall rules, legacy WFP objects, scheduled tasks, adapter leftovers, orphaned runtime processes.

// --- shared by the work packages ---
#[cfg(test)]
#[cfg_attr(not(feature = "cleanup-legacy"), allow(dead_code))]
mod test_support;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package, for the
/// app's locale registration (`vpnte_base::i18n::init`, after the UI's base layer).
pub const LOCALES: &[(&str, &str)] = &[(
    include_str!("../locales/cleanup-legacy.ru.json"),
    include_str!("../locales/cleanup-legacy.en.json"),
)];

// --- work package `cleanup-legacy` ---
#[cfg(feature = "cleanup-legacy")]
pub mod legacy;
