//! Foundation services: data directories, JSON stores, DPAPI secrets, settings, redaction, logging, net helpers, SOCKS5 client, operation registry, legacy-data primitives.

// --- work package `core-store` ---
pub mod paths;
pub mod store;
pub mod secret;
pub mod settings;

// --- work package `core-net` ---
pub mod net;
pub mod socks5;
pub mod resolve;

// --- work package `core-ops` ---
pub mod ops;

// --- work package `core-log` ---
pub mod redact;
pub mod logging;

// --- work package `core-legacy` ---
pub mod legacy;
