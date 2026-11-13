//! Fetching the feed (research §4.4): every mirror in order, each through the session first and
//! then directly; the first fresh feed whose signature verifies wins. A mirror that serves an
//! older `seq` than we already accepted is skipped (a stale cache, or a replay); a feed past
//! [`MAX_FEED_AGE`] is kept only as the "stale" answer when nothing fresher exists.
use futures_util::StreamExt;
use jiff::Timestamp;
use minisign_verify::PublicKey;
use serde::{Deserialize, Serialize};

use crate::feed::{FEED_FILE, Feed, FeedError, SIG_FILE, verify};
use crate::net::{Via, Way, feed_client};
use crate::policy::MAX_FEED_AGE;

/// A feed is a few KB; anything far larger is not ours.
const FEED_CAP: usize = 1 << 20;
const SIG_CAP: usize = 4096;

/// Where an accepted feed came from: the mirror's host and the way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub host: String,
    pub via: Via,
}

/// A verified feed with the exact signed bytes (kept next to what it installs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub feed: Feed,
    pub bytes: Vec<u8>,
    pub sig: String,
    pub source: Source,
    /// Issued more than [`MAX_FEED_AGE`] ago: never report "up to date" from it.
    pub stale: bool,
}

/// Why no feed was taken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// No mirror answered on any way.
    #[error("no feed mirror answered")]
    Unreachable,
    /// A mirror answered, but nothing it served verified.
    #[error(transparent)]
    Refused(#[from] FeedError),
    /// Every answer was older than the feed already accepted: nothing new.
    #[error("every mirror serves an older feed than the one accepted")]
    Older,
}

/// How a verified feed compares with what we know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    /// `seq` below the remembered maximum.
    Older,
    /// Issued too long ago (or its date is unreadable).
    Stale,
}

/// `seq` first (a replay is never used), then the age of `issued`.
pub fn freshness(feed: &Feed, max_seq: u64, now: Timestamp) -> Freshness {
    if feed.seq < max_seq {
        return Freshness::Older;
    }
    let issued = feed.issued.parse::<Timestamp>().ok();
    let max_age = jiff::SignedDuration::try_from(MAX_FEED_AGE).unwrap_or(jiff::SignedDuration::MAX);
    match issued {
        Some(at) if now.duration_since(at) <= max_age => Freshness::Fresh,
        _ => Freshness::Stale,
    }
}

/// Tries `bases` (feed folder URLs ending in `/`) through `ways`; see the module docs.
pub async fn fetch_feed(
    bases: &[&str],
    ways: &[Way],
    keys: &[PublicKey],
    max_seq: u64,
) -> Result<Fetched, FetchError> {
    let mut stale: Option<Fetched> = None;
    let mut error = FetchError::Unreachable;
    for base in bases {
        for way in ways {
            let Some((bytes, sig)) = get_pair(way, base).await else {
                continue;
            };
            let feed = match verify(&bytes, &sig, keys) {
                Ok(feed) => feed,
                Err(err) => {
                    tracing::warn!(%err, via = ?way.via, mirror = host(base), "feed refused");
                    error = FetchError::Refused(err);
                    // A different way may avoid whoever altered it.
                    continue;
                }
            };
            let fresh = freshness(&feed, max_seq, Timestamp::now());
            let fetched = Fetched {
                feed,
                bytes,
                sig,
                source: Source {
                    host: host(base),
                    via: way.via,
                },
                stale: fresh == Freshness::Stale,
            };
            match fresh {
                Freshness::Fresh => return Ok(fetched),
                Freshness::Older => {
                    if error == FetchError::Unreachable {
                        error = FetchError::Older;
                    }
                }
                Freshness::Stale => {
                    if stale.as_ref().is_none_or(|s| s.feed.seq < fetched.feed.seq) {
                        stale = Some(fetched);
                    }
                }
            }
            // The same mirror serves the same file on the other way: next mirror.
            break;
        }
    }
    stale.ok_or(error)
}

/// `update.json` and its signature from `base`, or `None` on any network or HTTP failure.
async fn get_pair(way: &Way, base: &str) -> Option<(Vec<u8>, String)> {
    let client = feed_client(way).ok()?;
    let bytes = get(&client, &format!("{base}{FEED_FILE}"), FEED_CAP).await?;
    let sig = get(&client, &format!("{base}{SIG_FILE}"), SIG_CAP).await?;
    Some((bytes, String::from_utf8(sig).ok()?))
}

async fn get(client: &reqwest::Client, url: &str, cap: usize) -> Option<Vec<u8>> {
    let response = client.get(url).send().await.ok()?.error_for_status().ok()?;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk.ok()?);
        if body.len() > cap {
            return None;
        }
    }
    Some(body)
}

/// The host of a feed base, for the source line (never a path or query).
fn host(base: &str) -> String {
    reqwest::Url::parse(base)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
