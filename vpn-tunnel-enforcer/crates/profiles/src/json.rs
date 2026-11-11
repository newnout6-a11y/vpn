//! JSON importer: sing-box and Xray documents (outbounds, endpoints, wrappers) -> profiles.
use crate::model::ParseReport;

// Signature fixed by the lead; the body is written by the owning work package.
pub fn parse_json(_value: &serde_json::Value) -> ParseReport {
    ParseReport::default()
}
