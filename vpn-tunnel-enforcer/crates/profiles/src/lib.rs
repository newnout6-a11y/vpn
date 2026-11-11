//! VPN profiles: the typed model, importers (URI, JSON, Clash, WireGuard, deep links), the sing-box emitter and exporters.

// --- written by the lead (cross-package contract) ---
pub mod model;

// --- shared by the work packages (each package build uses only part of it) ---
#[cfg_attr(
    not(all(
        feature = "profiles-emit",
        feature = "profiles-uri",
        feature = "profiles-json",
        feature = "profiles-native",
        feature = "profiles-text",
        feature = "profiles-export",
        feature = "profiles-clash"
    )),
    allow(dead_code)
)]
mod common;
#[cfg(test)]
#[cfg_attr(
    not(all(
        feature = "profiles-text",
        feature = "profiles-native",
        feature = "profiles-export"
    )),
    allow(dead_code)
)]
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

// --- work package `profiles-clash` ---
#[cfg(feature = "profiles-clash")]
pub mod clash;
#[cfg(feature = "profiles-clash")]
pub mod wg_ini;

// --- work package `profiles-emit` ---
#[cfg(feature = "profiles-emit")]
pub mod emit_singbox;

// --- work package `profiles-export` ---
#[cfg(feature = "profiles-export")]
pub mod export;
#[cfg(feature = "profiles-export")]
pub mod identity;

// --- work package `profiles-json` ---
#[cfg(feature = "profiles-json")]
pub mod json;
#[cfg(feature = "profiles-json")]
pub mod legacy;

// --- work package `profiles-native` ---
// `xray_native` also serves the emitter (the graph's UDP/443 mux rule).
#[cfg(feature = "profiles-native")]
pub mod deeplink;
#[cfg(any(feature = "profiles-native", feature = "profiles-emit"))]
pub mod xray_native;

// --- work package `profiles-text` ---
// `text` also serves the JSON importer and the deep-link unwrapper (share-link finding).
#[cfg(feature = "profiles-text")]
pub mod caps;
#[cfg(feature = "profiles-text")]
pub mod countries;
#[cfg(feature = "profiles-text")]
pub mod device;
#[cfg(any(
    feature = "profiles-text",
    feature = "profiles-json",
    feature = "profiles-native"
))]
pub mod text;

// --- work package `profiles-uri` ---
#[cfg(feature = "profiles-uri")]
pub mod uri;
