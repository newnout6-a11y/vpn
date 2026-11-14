//! Where the updater gets the feed and the files: the compiled mirrors, directly over HTTPS. While
//! a TUN session runs the request goes through it like any other traffic of the machine (the
//! service's own exe is permitted by the kill switch); there is no other way in: no client hands
//! the service a file.
use std::path::Path;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use vpnte_update::download::{DownloadError, Verified, Wanted, download};
use vpnte_update::feed::PublicKey;
use vpnte_update::fetch::{FetchError, Fetched, fetch_feed};
use vpnte_update::net::Way;
use vpnte_update::policy::FEED_BASES;

/// The feed and the files it lists (the real mirrors; tests serve them from memory).
#[async_trait]
pub trait Source: Send + Sync {
    /// The newest feed that verifies with `keys`, not older than `max_seq`.
    async fn feed(&self, keys: &[PublicKey], max_seq: u64) -> Result<Fetched, FetchError>;
    /// `wanted` into `dir`, checked against the size and SHA-256 the signed feed gave; ends at
    /// once with `cancel` (the service's stop, or a kill-switch block that began: svcfix-a3).
    async fn download(
        &self,
        wanted: &Wanted<'_>,
        dir: &Path,
        cancel: &CancellationToken,
    ) -> Result<Verified, DownloadError>;
}

/// The compiled mirrors, directly.
pub struct Mirrors;

#[async_trait]
impl Source for Mirrors {
    async fn feed(&self, keys: &[PublicKey], max_seq: u64) -> Result<Fetched, FetchError> {
        fetch_feed(&FEED_BASES, &[Way::direct()], keys, max_seq).await
    }

    async fn download(
        &self,
        wanted: &Wanted<'_>,
        dir: &Path,
        cancel: &CancellationToken,
    ) -> Result<Verified, DownloadError> {
        // Admin-only, re-created when users could change it: the files staged here are run as
        // SYSTEM later.
        crate::paths::secure_dir(dir)?;
        download(wanted, &[Way::direct()], dir, None, cancel).await
    }
}
