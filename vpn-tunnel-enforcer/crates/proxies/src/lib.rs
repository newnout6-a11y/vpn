//! External loopback proxy slots and their local control API.

// --- work package `proxies-control` ---
#[cfg(feature = "proxies-control")]
pub mod control;

// --- work package `proxies-manager` ---
#[cfg(feature = "proxies-manager")]
pub mod probe;
#[cfg(feature = "proxies-manager")]
pub mod health;
#[cfg(feature = "proxies-manager")]
pub mod manager;

// --- work package `proxies-model` ---
#[cfg(feature = "proxies-model")]
pub mod slot;
#[cfg(feature = "proxies-model")]
pub mod model;
#[cfg(feature = "proxies-model")]
pub mod config;
#[cfg(feature = "proxies-model")]
pub mod lease;
