//! VPN profiles: the typed model, importers (URI, JSON, Clash, WireGuard, deep links), the sing-box emitter and exporters.

// --- work package `lead` ---
pub mod model;

// --- work package `profiles-text` ---
pub mod text;
pub mod device;
pub mod countries;
pub mod caps;

// --- work package `profiles-uri` ---
pub mod uri;

// --- work package `profiles-export` ---
pub mod export;

// --- work package `profiles-json` ---
pub mod json;
pub mod legacy;

// --- work package `profiles-native` ---
pub mod xray_native;
pub mod deeplink;

// --- work package `profiles-clash` ---
pub mod clash;
pub mod wg_ini;

// --- work package `profiles-emit` ---
pub mod emit_singbox;
