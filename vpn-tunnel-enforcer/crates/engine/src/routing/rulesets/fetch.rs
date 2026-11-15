//! HTTPS download of one rule-set file through the configured routes.
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_core::net::Route;

use super::{MAX_FILE_BYTES, RouteKind};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(45);

/// The body of `url` through the first route that works, and that route.
pub(super) async fn download(
    url: &'static str,
    routes: &[(RouteKind, Route)],
    cancel: &CancellationToken,
) -> Option<(Vec<u8>, RouteKind)> {
    for (kind, route) in routes {
        let result = tokio::select! {
            r = fetch_https(url, route) => r,
            () = cancel.cancelled() => return None,
        };
        match result {
            Ok(body) => return Some((body, *kind)),
            Err(err) => {
                tracing::warn!(route = %route.label(), %err, "rule-set download attempt failed")
            }
        }
    }
    None
}

#[derive(Debug, thiserror::Error)]
pub(super) enum FetchError {
    #[error("not an https URL")]
    NotHttps,
    #[error("HTTP client setup failed")]
    Setup,
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("body larger than the limit")]
    TooLarge,
    #[error("empty body")]
    Empty,
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

/// HTTPS only, redirects included; 15 s to connect, 45 s in total.
pub(super) async fn fetch_https(url: &str, route: &Route) -> Result<Vec<u8>, FetchError> {
    let url = reqwest::Url::parse(url).map_err(|_| FetchError::NotHttps)?;
    if url.scheme() != "https" {
        return Err(FetchError::NotHttps);
    }
    let policy = reqwest::redirect::Policy::custom(|a| {
        if a.url().scheme() != "https" || a.previous().len() >= 5 {
            a.stop()
        } else {
            a.follow()
        }
    });
    let client = vpnte_core::net::builder_for(route, TOTAL_TIMEOUT)
        .map_err(|_| FetchError::Setup)?
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(policy)
        .build()?;
    fetch_body(&client, url, MAX_FILE_BYTES).await
}

/// GET with a size cap; a non-success status or an empty body is an error.
pub(super) async fn fetch_body(
    client: &reqwest::Client,
    url: reqwest::Url,
    cap: usize,
) -> Result<Vec<u8>, FetchError> {
    let mut resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(FetchError::Status(resp.status().as_u16()));
    }
    if resp.content_length().is_some_and(|n| n > cap as u64) {
        return Err(FetchError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > cap {
            return Err(FetchError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    if body.is_empty() {
        Err(FetchError::Empty)
    } else {
        Ok(body)
    }
}
