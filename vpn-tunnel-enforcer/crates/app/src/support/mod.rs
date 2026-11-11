//! Helpers the remaining pages share (work package `app-clickjack`). Neither needs administrator
//! rights (NOADMIN): [`files`] asks the user where an export goes through the native Save dialog,
//! [`clipboard`] reads the text for «add key from clipboard».
//!
//! Both act only on a click of the user and both block (the dialog until it is closed, the
//! clipboard while another program holds it): the `async` wrappers run them on tokio's blocking
//! pool, never on the UI thread.
use vpnte_base::{AppError, AppResult};

pub mod clipboard;
pub mod files;

#[cfg(test)]
mod tests;

/// Runs the blocking `f` on tokio's blocking pool.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> AppResult<T> + Send + 'static,
) -> AppResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(AppError::internal)?
}
