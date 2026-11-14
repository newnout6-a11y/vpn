//! Browser and Windows privacy hardening through registry values, journalled in the shared tweak
//! journal ([`crate::tweaks::Journal`]) and rolled back value by value:
//!
//! - **browsers** ([`browser::Browsers`]): machine policies (`HKLM\SOFTWARE\Policies\…`) for the
//!   verified Chromium browsers Chrome, Edge, Brave and Yandex: WebRTC may use UDP only through a
//!   proxy, and the browser's own DNS-over-HTTPS resolver is off so its lookups reach the tunnel's
//!   DNS. Other browsers are detected and reported as not checked, never touched (owner decision
//!   10.2-B);
//! - **location privacy** ([`location::Location`]): the user's Windows location consent (per user,
//!   no elevation), denied for the duration of a protected session.
//!
//! Every value goes through `vpnte_winnet::registry`; nothing is ever exported to or imported from
//! a `.reg` file. The old app ran `reg import` on user-writable backups from an elevated process,
//! a privilege escalation (spec B1/L1); here the journal only acts on records that [`admit`]
//! accepts, so a doctored `tweaks.json` cannot steer an elevated write anywhere else.

pub mod browser;
pub mod legacy;
pub mod location;
pub mod system;

#[cfg(test)]
mod fake;

pub use browser::{Browser, BrowserDirs, BrowserEntry, BrowserReport, BrowserState, Browsers};
pub use location::{Location, LocationStatus};
pub use system::{System, WinSystem};

use vpnte_base::{AppError, ErrorKind, Msg};

use crate::tweaks::journal::{RegHive, Target, Val};

/// Admission of registry records for [`crate::tweaks::Journal::open`] (a
/// [`crate::tweaks::journal::RegAdmit`]): exactly the values this package writes, each with its
/// type. Names and keys compare ASCII case-insensitively, like the registry itself.
pub fn admit(hive: RegHive, key: &str, name: &str, value: &Val) -> bool {
    browser::admits(hive, key, name, value) || location::admits(hive, key, name, value)
}

/// [`admit`] for a target and one of its values.
fn admissible(target: &Target, value: &Val) -> bool {
    match target {
        Target::Reg { hive, key, name } => admit(*hive, key, name, value),
        _ => false,
    }
}

/// Machine policies need an elevated process (NOADMIN §0: shown as unavailable otherwise).
fn needs_admin() -> AppError {
    AppError::msg(
        ErrorKind::Permission,
        Msg::new("automation.hardening.needsAdmin"),
    )
}

/// A string value we may write back as a baseline: short and free of control characters.
fn short_text(value: &Val) -> bool {
    match value {
        Val::Absent => true,
        Val::Sz(s) => s.len() <= 256 && !s.chars().any(char::is_control),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
