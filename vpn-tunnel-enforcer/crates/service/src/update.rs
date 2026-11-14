//! The helper service's own updates through the signed feed (p-svc-update; owner answer 7: our
//! own minisign key, no code signing). One key set: everything is verified with the keys compiled
//! into `vpnte_update::policy` (`feed::verify`), as the app does, so the owner creates keys once;
//! without them (`keys_ready()` false) the service never checks.
//!
//! The service updates when an app asks, never on a schedule of its own (owner decisions 19 and
//! 28: updates go in on the user's button; review svcupd-b4): the app's `Take` right before a
//! release's installer runs. It then fetches the feed and the files itself, directly over HTTPS
//! (through the TUN while a session runs; never while the kill switch blocks the machine with no
//! tunnel, svcupd-b7), never from a file a client hands over, and takes only what verifies:
//! the release's engines for Tunnel mode from `feed.engine(id)` entries inside the compiled
//! ranges, checked member by member into a version folder of `<install>\engines` ([`engines`]),
//! and its own exe from `feed.service`, staged in the admin-only `<install>\update\` and swapped
//! in when the asker's restart may end nothing but the asker's own session, else once no session
//! runs or at the service's next start ([`swap`]).
use std::sync::Arc;

use async_trait::async_trait;

use crate::proto::{ServiceUpdateWire, UpdateAsk};

pub mod checks;
mod desk;
pub mod engines;
pub mod in_flight;
pub mod source;
pub mod swap;
pub mod trial;

pub use desk::{Updates, UpdatesDeps, accepted_seq, staged_release};

#[cfg(test)]
mod testkit;

/// The service's exit code when it stops for the SCM to start the exe now in place (a swapped-in
/// update, or the previous exe after a failed trial): non-zero, so the recovery restarts it.
pub const RESTART_EXIT: u32 = 10;

/// Whether the session the service holds now (running or its filters held) is the asking user's
/// own. The host judges it at every call: another user may start a session between an ask and
/// the swap it allows (svcupd-a2).
pub type OwnSession = Arc<dyn Fn() -> bool + Send + Sync>;

/// The pipe's `Update` requests (implemented by the service's updater; the host only routes).
#[async_trait]
pub trait UpdateDesk: Send + Sync {
    /// The answer to `ask`. A `Take` may restart the service while nothing runs or is held, or
    /// while `own` says the session is the asker's: judged when it arrives, again right before
    /// the swap and again right before the restart.
    async fn answer(&self, ask: UpdateAsk, own: OwnSession) -> ServiceUpdateWire;
}
