//! Reversible soft-mode tweaks: user-level settings that point applications at the local proxy
//! (the per-user system proxy, per-user environment variables, and opt-in Git / Gradle / Android
//! Studio targets), recorded in one journal so that exactly our own values are rolled back.
//!
//! Rules carried over from the field (spec automation-soft §3.5-3.6, §4, §6.8):
//! - every original value is read before anything is written; an unreadable one aborts the apply
//!   with no change at all;
//! - the journal entry (value before our first change + value we wrote) is persisted before the
//!   write, so a crash in between leaves an obligation, never an orphaned proxy setting;
//! - rollback restores a value only while it still holds ours: a later change by the user or
//!   another program is kept (F-121, AT-09-001);
//! - the registry API keeps the original value type and has no length limit (F-117, AT-09-003).
//!
//! The journal ([`journal::Journal`]) is shared with browser hardening and location privacy
//! (package `automation-hardening`), which bring their own [`journal::Backend`].

use vpnte_base::{AppError, AppResult};

pub mod block;
pub mod endpoint;
pub mod env;
pub mod git;
pub mod journal;
pub mod legacy;
pub mod soft;
pub mod studio;
pub mod sysproxy;
pub mod user;

#[cfg(test)]
mod test_support;

pub use journal::{
    Backend, Feature, Journal, Record, RollbackReport, Target, TweakError, TweakState, Val,
};
pub use soft::{DevTargets, ProxyOwner, Soft, SoftReport, SoftStatus, SoftSystem};
pub use sysproxy::{SystemProxy, WinInet};

/// Runs blocking tweak work (registry, files, `git`) on tokio's blocking pool; the async facades of
/// Soft mode, browser hardening and location privacy go through it.
pub(crate) async fn run_blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> AppResult<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(AppError::internal)
}
