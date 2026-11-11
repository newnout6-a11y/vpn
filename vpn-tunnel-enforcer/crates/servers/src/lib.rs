//! The user's server list: groups, subscriptions (fetch and refresh), selection, persistence.

// --- work package `servers-store` ---
pub mod model;
pub mod store;
pub mod legacy;

// --- work package `servers-refresh` ---
pub mod subscription;
pub mod refresh;
