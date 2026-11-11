//! VPN profiles: the typed model, importers (URI, JSON, Clash, WireGuard, deep links), the sing-box emitter and exporters.

mod common;
#[cfg(test)]
mod test_locales;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package in file-name
/// order, for the app's locale registration at start (after the UI's base layer).
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/profiles-clash.ru.json"),
        include_str!("../locales/profiles-clash.en.json"),
    ),
    (
        include_str!("../locales/profiles-emit.ru.json"),
        include_str!("../locales/profiles-emit.en.json"),
    ),
    (
        include_str!("../locales/profiles-export.ru.json"),
        include_str!("../locales/profiles-export.en.json"),
    ),
    (
        include_str!("../locales/profiles-json.ru.json"),
        include_str!("../locales/profiles-json.en.json"),
    ),
    (
        include_str!("../locales/profiles-native.ru.json"),
        include_str!("../locales/profiles-native.en.json"),
    ),
    (
        include_str!("../locales/profiles-text.ru.json"),
        include_str!("../locales/profiles-text.en.json"),
    ),
    (
        include_str!("../locales/profiles-uri.ru.json"),
        include_str!("../locales/profiles-uri.en.json"),
    ),
];

pub mod caps;
pub mod clash;
pub mod countries;
pub mod deeplink;
pub mod device;
pub mod emit_singbox;
pub mod export;
pub mod identity;
pub mod json;
pub mod legacy;
pub mod model;
pub mod text;
pub mod uri;
pub mod wg_ini;
pub mod xray_native;
