//! Connection runtime and lifecycle: start, stop, switch, state machine and session history.

// --- work package `tunnel-fsm` ---
#[cfg(feature = "tunnel-fsm")]
pub mod api;
#[cfg(feature = "tunnel-fsm")]
pub mod fsm;

// --- work package `tunnel-history` ---
#[cfg(feature = "tunnel-history")]
pub mod outcome;
#[cfg(feature = "tunnel-history")]
pub mod history;

// --- work package `tunnel-lifecycle` ---
#[cfg(feature = "tunnel-lifecycle")]
pub mod lifecycle;

// --- work package `tunnel-runtime` ---
#[cfg(feature = "tunnel-runtime")]
pub mod runtime;
#[cfg(feature = "tunnel-runtime")]
pub mod switch;
