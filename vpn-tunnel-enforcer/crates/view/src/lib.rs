//! Pure UI logic without a webview: start-page state derivation, labels, identity column rules, traffic maths and the mascot's behaviour machine.

// --- work package `view-logic` ---
#[cfg(feature = "view-logic")]
pub mod swiss;
#[cfg(feature = "view-logic")]
pub mod labels;
#[cfg(feature = "view-logic")]
pub mod identity;
#[cfg(feature = "view-logic")]
pub mod traffic;
#[cfg(feature = "view-logic")]
pub mod fmt;

// --- work package `view-mascot` ---
#[cfg(feature = "view-mascot")]
pub mod mascot;
