//! Helpers every page shares. None needs administrator rights (NOADMIN): [`files`] asks the user
//! which file to open or where an export goes through the native dialogs, [`clipboard`] reads the
//! text for «add key from clipboard», and the task helpers below run backend work so that a page
//! going away never stops it half-way.
//!
//! The dialogs and the clipboard act only on a click of the user and both block (the dialog until
//! it is closed, the clipboard while another program holds it): their `async` wrappers run them
//! on tokio's blocking pool, never on the UI thread.
use std::future::Future;

use tokio::sync::watch;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

pub mod clipboard;
pub mod files;

#[cfg(test)]
mod tests;

/// Runs `work` as a backend task and waits for it: dropping the caller's future (the page
/// unmounted) does not stop a change half-way.
pub(crate) async fn detached<T, Fut>(work: Fut) -> AppResult<T>
where
    T: Send + 'static,
    Fut: Future<Output = AppResult<T>> + Send + 'static,
{
    joined(tokio::spawn(work).await)
}

/// Blocking file / registry / COM / DPAPI work on the blocking pool (it finishes even when the
/// caller is dropped).
pub(crate) async fn blocking<T, F>(work: F) -> AppResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> AppResult<T> + Send + 'static,
{
    joined(tokio::task::spawn_blocking(work).await)
}

/// A task's end as the caller's result: cancelled (runtime shutdown) is `Cancelled`, a panic is
/// `Internal`.
pub(crate) fn joined<T>(result: Result<AppResult<T>, tokio::task::JoinError>) -> AppResult<T> {
    result.unwrap_or_else(|err| {
        if err.is_cancelled() {
            Err(AppError::cancelled())
        } else {
            Err(AppError::internal(anyhow::anyhow!(
                "backend task panicked: {err}"
            )))
        }
    })
}

/// A feature this build does not wire: `Conflict` with its own message, never a fake result.
pub(crate) fn unavailable(key: &'static str) -> AppError {
    AppError::msg(ErrorKind::Conflict, Msg::new(key))
}

/// Resolves on the next change of `rx`; never once it is closed (a closed channel would wake a
/// `select!` loop at once, forever).
pub(crate) async fn changed<T>(rx: &mut watch::Receiver<T>) {
    if rx.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// [`changed`] of an optional receiver; never while there is none.
pub(crate) async fn changed_opt<T>(rx: &mut Option<watch::Receiver<T>>) {
    match rx {
        Some(rx) => changed(rx).await,
        None => std::future::pending().await,
    }
}
