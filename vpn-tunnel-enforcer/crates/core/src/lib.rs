//! Foundation services: data directories, JSON stores, DPAPI secrets, settings, redaction, logging, net helpers, SOCKS5 client, operation registry, legacy-data primitives.

mod dpapi;
#[cfg(test)]
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

pub mod legacy;
pub mod logging;
pub mod net;
pub mod ops;
pub mod paths;
pub mod redact;
pub mod resolve;
pub mod secret;
pub mod settings;
pub mod socks5;
pub mod store;
