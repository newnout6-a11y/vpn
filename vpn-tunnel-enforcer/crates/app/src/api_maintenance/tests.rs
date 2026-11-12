//! Tests of the Maintenance page's backend: pure mappings, the repair's honesty rules over fake
//! hosts (no real process is ever scanned or stopped), the transition guard, the old data
//! directory's guards in throw-away folders, and the locale fragment.
mod flows;
mod locales;
mod network;
mod views;
