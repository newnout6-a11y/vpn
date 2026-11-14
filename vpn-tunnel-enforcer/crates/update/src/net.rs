//! How our update requests leave the machine (research §4.6): through the running session first
//! (the engine's authenticated `live-check-in` inbound, which leads to `proxy-out`, so GitHub is
//! reached through the VPN server and past Smart RU), then directly (in TUN mode through the
//! engine's `mixed-direct-in`, otherwise the request would be captured by the tunnel anyway).
use std::time::Duration;

use reqwest::redirect::Policy;
use vpnte_base::AppResult;
use vpnte_core::net::{Route, builder_for};

/// Which way a request went, for the line «откуда пришла лента».
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Via {
    /// Through the running VPN session.
    Session,
    /// Without the VPN.
    Direct,
}

/// One way out: the route and what to call it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Way {
    pub route: Route,
    pub via: Via,
}

impl Way {
    /// No session: the plain direct route (our requests never use the system proxy implicitly).
    pub fn direct() -> Self {
        Self {
            route: Route::Direct,
            via: Via::Direct,
        }
    }
}

/// The feed must arrive within this time per mirror and way (research §4.6).
pub const FEED_TIMEOUT: Duration = Duration::from_secs(20);
/// A download that receives nothing for this long moves on to the next way or mirror.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound of one download attempt (a 45 MB installer at a slow 100 KB/s takes ~8 min).
const DOWNLOAD_BUDGET: Duration = Duration::from_secs(3600);
const MAX_REDIRECTS: usize = 5;

/// A client for the feed (short total deadline).
pub(crate) fn feed_client(way: &Way) -> AppResult<reqwest::Client> {
    build(builder_for(&way.route, FEED_TIMEOUT)?)
}

/// A client for a download: a long total budget, but an idle deadline per read.
pub(crate) fn download_client(way: &Way) -> AppResult<reqwest::Client> {
    build(builder_for(&way.route, DOWNLOAD_BUDGET)?.read_timeout(IDLE_TIMEOUT))
}

/// GitHub release downloads answer with a redirect to their asset host, so redirects are
/// followed — a few, and never from https down to http.
fn build(builder: reqwest::ClientBuilder) -> AppResult<reqwest::Client> {
    let policy = Policy::custom(|attempt| {
        let downgrade = attempt
            .previous()
            .last()
            .is_some_and(|prev| prev.scheme() == "https" && attempt.url().scheme() != "https");
        if downgrade || attempt.previous().len() >= MAX_REDIRECTS {
            attempt.stop()
        } else {
            attempt.follow()
        }
    });
    builder
        .redirect(policy)
        .build()
        .map_err(|err| vpnte_base::AppError::internal(err.without_url()))
}
