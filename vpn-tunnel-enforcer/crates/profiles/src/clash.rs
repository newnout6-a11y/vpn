//! Clash / mihomo YAML importer.
use crate::model::ParseReport;

// Signature fixed by the lead; the body is written by the owning work package.
/// `None` when the text is not a Clash document.
pub fn parse_clash(_text: &str) -> Option<ParseReport> {
    None
}
