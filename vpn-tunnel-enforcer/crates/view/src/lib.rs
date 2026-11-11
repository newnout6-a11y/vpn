//! Pure UI logic without a webview: start-page state derivation, labels, identity column rules, traffic maths and the mascot's behaviour machine.

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

pub mod fmt;
pub mod identity;
pub mod labels;
pub mod mascot;
pub mod swiss;
pub mod traffic;
