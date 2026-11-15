//! AmneziaWG parameters: reading them from `.conf`, links and mihomo YAML, the checks every
//! AmneziaWG profile passes before import and before any start (AT-12-003 step 1), and the
//! generation they imply.
//!
//! Bounds are those of the implementations (amneziawg-go v3 and the legacy 1.x / 2.0 code that
//! mihomo carries), not the MTU-1280 recommendations of the kernel README: a config that works
//! somewhere is never refused here.
mod check;
mod field;
mod read;
mod tags;
mod write;

pub use check::{implied_generation, validate};
pub use field::{AwgField, AwgInvalid};
pub(crate) use read::AwgReader;
pub(crate) use write::{AwgValue, pairs};

#[cfg(test)]
mod tests;
