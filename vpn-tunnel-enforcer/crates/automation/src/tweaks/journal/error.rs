//! Why an apply did not happen or was undone, with its user-facing message.
use std::io;

use vpnte_base::{AppError, ErrorKind, Msg};

use super::model::{Feature, tool_name};

/// Why an apply did not happen or was undone.
#[derive(Debug, thiserror::Error)]
pub enum TweakError {
    /// A current value could not be read; nothing was written.
    #[error("{0} is unreadable")]
    Unreadable(String, #[source] io::Error),
    /// A write failed (the call's earlier writes were undone).
    #[error("writing {0} failed")]
    Write(String, #[source] io::Error),
    /// A write did not read back as written (the call's writes were undone).
    #[error("{0} did not read back as written")]
    NotVerified(String),
    /// The journal could not be saved, so nothing was written.
    #[error("tweak journal not saved")]
    Journal(#[source] AppError),
    /// The tool is not installed: nothing to configure (and nothing created).
    #[error("{0:?} not detected")]
    NotDetected(Feature),
    /// The app runs as another account than the signed-in user (over-the-shoulder elevation):
    /// user settings would land in the wrong profile (spec E3).
    #[error("process user differs from the session user")]
    OtherUser,
}

impl From<TweakError> for AppError {
    fn from(err: TweakError) -> Self {
        match err {
            TweakError::Journal(inner) => inner,
            other => {
                let (kind, msg) = other.describe();
                AppError::msg(kind, msg).with_source(other)
            }
        }
    }
}

impl TweakError {
    /// Category and user-facing message.
    pub fn describe(&self) -> (ErrorKind, Msg) {
        let io_kind = |e: &io::Error| match e.kind() {
            io::ErrorKind::PermissionDenied => ErrorKind::Permission,
            _ => ErrorKind::Internal,
        };
        match self {
            TweakError::Unreadable(t, e) => (
                io_kind(e),
                Msg::new("automation.tweaks.unreadable").arg("target", t),
            ),
            TweakError::Write(t, e) => (
                io_kind(e),
                Msg::new("automation.tweaks.writeFailed").arg("target", t),
            ),
            TweakError::NotVerified(t) => (
                ErrorKind::Internal,
                Msg::new("automation.tweaks.notVerified").arg("target", t),
            ),
            TweakError::NotDetected(f) => (
                ErrorKind::Validation,
                Msg::new("automation.tweaks.notDetected").arg("tool", tool_name(*f)),
            ),
            TweakError::OtherUser => (
                ErrorKind::Permission,
                Msg::new("automation.tweaks.otherUser"),
            ),
            TweakError::Journal(e) => (e.kind, e.user_msg()),
        }
    }
}
