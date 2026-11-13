//! The helper service's own updates through the signed feed (p-svc-update; owner answer 7: our
//! own minisign key, no code signing). One key set: everything is verified with the keys compiled
//! into `vpnte_update::policy` (`feed::verify`), as the app does, so the owner creates keys once;
//! without them (`keys_ready()` false) the service never checks.
//!
//! The service fetches the feed and the files itself, directly over HTTPS (through the TUN while a
//! session runs), never from a file a client hands over, and takes only what verifies: engines for
//! Tunnel mode from `feed.engine(id)` entries inside the compiled ranges, checked member by member
//! into a version folder of `<install>\engines` ([`engines`]); its own exe from `feed.service`,
//! staged in the admin-only `<install>\update\` and swapped in when no session runs, at its next
//! start, or right before the app's installer asks for it ([`swap`]).
use async_trait::async_trait;

use crate::proto::{ServiceUpdateWire, UpdateAsk};

pub mod checks;
mod desk;
pub mod engines;
pub mod source;
pub mod swap;

pub use desk::{Updates, UpdatesDeps};

#[cfg(test)]
mod testkit;

/// The service's exit code when it stops for the SCM to start the exe now in place (a swapped-in
/// update, or the previous exe after a failed trial): non-zero, so the recovery restarts it.
pub const RESTART_EXIT: u32 = 10;

/// The pipe's `Update` requests (implemented by the service's updater; the host only routes).
#[async_trait]
pub trait UpdateDesk: Send + Sync {
    /// The answer to `ask`; `may_restart`: no session runs, or it is the caller's own, so a
    /// `Take` may restart the service at once.
    async fn answer(&self, ask: UpdateAsk, may_restart: bool) -> ServiceUpdateWire;
}
