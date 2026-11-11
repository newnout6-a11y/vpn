//! Share-link importer: one `scheme://…` line -> [`Profile`].
use crate::model::{Profile, SkipReason};

// Signature fixed by the lead; the body is written by the owning work package.
pub fn parse_uri(line: &str) -> Result<Profile, SkipReason> {
    Err(SkipReason::UnknownScheme(line.split(':').next().unwrap_or_default().to_owned()))
}
