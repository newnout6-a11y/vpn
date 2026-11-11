//! VPN profiles: the typed model, importers (URI, JSON, Clash, WireGuard, deep links), the sing-box emitter and exporters.

// --- written by the lead (cross-package contract) ---
pub mod model;

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
#[cfg(feature = "profiles-native")]
pub mod xray_native;
#[cfg(feature = "profiles-native")]
pub mod deeplink;

// --- work package `profiles-text` ---
#[cfg(feature = "profiles-text")]
pub mod text;
#[cfg(feature = "profiles-text")]
pub mod device;
#[cfg(feature = "profiles-text")]
pub mod countries;
#[cfg(feature = "profiles-text")]
pub mod caps;

// --- work package `profiles-uri` ---
#[cfg(feature = "profiles-uri")]
pub mod uri;
