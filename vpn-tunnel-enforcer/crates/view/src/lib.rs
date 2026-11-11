//! Pure UI logic without a webview: start-page state derivation, labels, identity column rules, traffic maths and the mascot's behaviour machine.

// --- shared by the work packages ---
mod phase;
pub use phase::MascotPhase;
#[cfg(test)]
mod test_locales;

/// This crate's locale fragments as `(ru_json, en_json)` layers, one per work package, to register
/// after the UI's base layer: `vpnte_ui::lang::init_locales(vpnte_view::LOCALES)`.
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/view-logic.ru.json"),
        include_str!("../locales/view-logic.en.json"),
    ),
    (
        include_str!("../locales/view-mascot.ru.json"),
        include_str!("../locales/view-mascot.en.json"),
    ),
];

// --- work package `view-logic` ---
#[cfg(feature = "view-logic")]
pub mod fmt;
#[cfg(feature = "view-logic")]
pub mod identity;
#[cfg(feature = "view-logic")]
pub mod labels;
#[cfg(feature = "view-logic")]
pub mod swiss;
#[cfg(feature = "view-logic")]
pub mod traffic;

// --- work package `view-mascot` ---
#[cfg(feature = "view-mascot")]
pub mod mascot;
