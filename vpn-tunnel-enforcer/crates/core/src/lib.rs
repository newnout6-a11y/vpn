//! Foundation services: data directories, JSON stores, DPAPI secrets, settings, redaction, logging, net helpers, SOCKS5 client, operation registry, legacy-data primitives.

// --- shared by the work packages ---
#[cfg(any(feature = "core-store", feature = "core-legacy"))]
mod dpapi;
#[cfg(test)]
#[cfg_attr(
    not(all(
        feature = "core-store",
        feature = "core-net",
        feature = "core-ops",
        feature = "core-log",
        feature = "core-legacy"
    )),
    allow(dead_code)
)]
mod test_support;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package, for the
/// app's locale registration (`vpnte_base::i18n::init`, after the UI's base layer).
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/core-legacy.ru.json"),
        include_str!("../locales/core-legacy.en.json"),
    ),
    (
        include_str!("../locales/core-log.ru.json"),
        include_str!("../locales/core-log.en.json"),
    ),
    (
        include_str!("../locales/core-net.ru.json"),
        include_str!("../locales/core-net.en.json"),
    ),
    (
        include_str!("../locales/core-ops.ru.json"),
        include_str!("../locales/core-ops.en.json"),
    ),
    (
        include_str!("../locales/core-store.ru.json"),
        include_str!("../locales/core-store.en.json"),
    ),
];

// --- work package `core-legacy` ---
#[cfg(feature = "core-legacy")]
pub mod legacy;

// --- work package `core-log` ---
#[cfg(feature = "core-log")]
pub mod logging;
#[cfg(feature = "core-log")]
pub mod redact;

// --- work package `core-net` ---
// Also the host grammar of `settings::ProxyOverride` (core-store).
#[cfg(any(feature = "core-net", feature = "core-store"))]
pub mod net;
#[cfg(feature = "core-net")]
pub mod resolve;
#[cfg(feature = "core-net")]
pub mod socks5;

// --- work package `core-ops` ---
#[cfg(feature = "core-ops")]
pub mod ops;

// --- work package `core-store` ---
#[cfg(feature = "core-store")]
pub mod paths;
#[cfg(feature = "core-store")]
pub mod secret;
#[cfg(feature = "core-store")]
pub mod settings;
#[cfg(feature = "core-store")]
pub mod store;
