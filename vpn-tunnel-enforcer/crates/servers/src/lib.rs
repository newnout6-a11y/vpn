//! The user's server list: groups, subscriptions (fetch and refresh), selection, persistence.

// --- work package `servers-parse` ---
#[cfg(feature = "servers-parse")]
pub mod parse;

// --- work package `servers-refresh` ---
#[cfg(feature = "servers-refresh")]
pub mod subscription;
#[cfg(feature = "servers-refresh")]
pub mod refresh;

// --- work package `servers-store` ---
#[cfg(feature = "servers-store")]
pub mod model;
#[cfg(feature = "servers-store")]
pub mod store;
#[cfg(feature = "servers-store")]
pub mod legacy;
