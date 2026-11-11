//! WireGuard `.conf` importer.
use crate::model::{Profile, SkipReason};

// Signature fixed by the lead; the body is written by the owning work package.
/// `None` when the text is not a WireGuard config.
pub fn parse_wg_ini(_text: &str) -> Option<Result<Profile, SkipReason>> {
    None
}
