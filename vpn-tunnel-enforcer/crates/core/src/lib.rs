//! Foundation services: data directories, JSON stores, DPAPI secrets, settings, redaction, logging, net helpers, SOCKS5 client, operation registry, legacy-data primitives.

// --- work package `core-legacy` ---
#[cfg(feature = "core-legacy")]
pub mod legacy;

// --- work package `core-log` ---
#[cfg(feature = "core-log")]
pub mod redact;
#[cfg(feature = "core-log")]
pub mod logging;

// --- work package `core-net` ---
#[cfg(feature = "core-net")]
pub mod net;
#[cfg(feature = "core-net")]
pub mod socks5;
#[cfg(feature = "core-net")]
pub mod resolve;

// --- work package `core-ops` ---
#[cfg(feature = "core-ops")]
pub mod ops;

// --- work package `core-store` ---
#[cfg(feature = "core-store")]
pub mod paths;
#[cfg(feature = "core-store")]
pub mod store;
#[cfg(feature = "core-store")]
pub mod secret;
#[cfg(feature = "core-store")]
pub mod settings;
