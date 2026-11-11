//! Connection runtime and lifecycle: start, stop, switch, state machine and session history.

// --- work package `tunnel-fsm` ---
pub mod fsm;

// --- work package `tunnel-history` ---
pub mod outcome;
pub mod history;

// --- work package `tunnel-switch` ---
pub mod switch;

// --- work package `tunnel-runtime` ---
pub mod runtime;

// --- work package `tunnel-lifecycle` ---
pub mod lifecycle;
