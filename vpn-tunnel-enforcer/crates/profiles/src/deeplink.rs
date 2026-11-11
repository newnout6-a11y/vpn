//! App deep links (`happ://`, `mantaray://`, …) unwrapped to the text or URL they carry.

/// Why a deep link could not be unwrapped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeepLinkError {
    #[error("encrypted {app} link ({variant})")]
    Encrypted { app: &'static str, variant: String },
    #[error("routing profile link")]
    RoutingProfile,
    #[error("unrecognised add payload")]
    AddPayloadUnrecognised,
    #[error("unknown deep link host {0}")]
    UnknownHost(String),
}

// Signature fixed by the lead; the body is written by the owning work package.
/// `Ok(None)` when the input is not a deep link.
pub fn unwrap_deeplink(_input: &str) -> Result<Option<String>, DeepLinkError> {
    Ok(None)
}
