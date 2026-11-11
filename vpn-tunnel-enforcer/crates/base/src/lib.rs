//! Frozen cross-crate contract: errors, user messages, shared enums, i18n lookup, HTTP/TLS defaults.

// --- work package `lead` ---
pub mod error;
pub mod http;
pub mod i18n;
pub mod msg;
pub mod types;

pub use error::{AppError, AppResult, ErrorKind};
pub use msg::Msg;
