//! External loopback proxy slots and their local control API.

// --- work package `proxies-model` ---
pub mod slot;
pub mod model;
pub mod config;
pub mod lease;

// --- work package `proxies-manager` ---
pub mod probe;
pub mod health;
pub mod manager;

// --- work package `proxies-control` ---
pub mod control;
