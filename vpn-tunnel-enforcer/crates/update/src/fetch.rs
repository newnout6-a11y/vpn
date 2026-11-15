//! Fetching the feed (research §4.4): the mirrors in order, each through the session first and
//! then directly; the first fresh feed whose signature verifies wins. A mirror that has not
//! answered within [`HEAD_START`] no longer holds up the next one (ops5), so a frozen mirror costs
//! seconds, not [`crate::net::FEED_TIMEOUT`] per way. A mirror that serves an older `seq` than we
//! already accepted is passed over (a stale cache, or a replay); a feed past [`MAX_FEED_AGE`] is
//! kept only as the "stale" answer when nothing fresher exists.
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use jiff::Timestamp;
use minisign_verify::PublicKey;
use serde::{Deserialize, Serialize};

use crate::feed::{FEED_FILE, Feed, FeedError, SIG_FILE, verify};
use crate::net::{Via, Way, feed_client};
use crate::policy::MAX_FEED_AGE;

/// A feed is a few KB; anything far larger is not ours.
const FEED_CAP: usize = 1 << 20;
/// How long the next mirror waits for the ones before it. Was a whole [`crate::net::FEED_TIMEOUT`]
/// (20 s) per mirror and way in turn: a hanging raw.githubusercontent.com cost 40 s, the worst
/// case 120 s.
const HEAD_START: Duration = Duration::from_secs(3);
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
    let mut verdict = Verdict::default();
    let mut pending = bases.iter();
    let mut running = FuturesUnordered::new();
    let mut start = true;
    loop {
        if std::mem::take(&mut start)
            && let Some(base) = pending.next()
        {
            running.push(mirror(base, ways, keys, max_seq));
        }
        if running.is_empty() {
            return verdict.finish();
        }
        tokio::select! {
            Some(answer) = running.next() => {
                if let Some(fresh) = verdict.add(answer) {
                    return Ok(fresh);
                }
                // An answer without a fresh feed: the next mirror need not wait.
                start = true;
            }
            () = tokio::time::sleep(HEAD_START), if pending.len() > 0 => start = true,
        }
    }
}

/// How one mirror ended.
enum Answer {
    Fresh(Fetched),
    Stale(Fetched),
    Older,
    Refused(FeedError),
    Unreachable,
}

/// What the mirrors that ended said: the newest stale feed and the strongest error (refused >
/// older > unreachable).
#[derive(Default)]
struct Verdict {
    stale: Option<Fetched>,
    refused: Option<FeedError>,
    older: bool,
}

impl Verdict {
    /// Takes `answer` in; a fresh feed is handed back at once.
    fn add(&mut self, answer: Answer) -> Option<Fetched> {
        match answer {
            Answer::Fresh(fetched) => return Some(fetched),
            Answer::Stale(fetched) => {
                if self
                    .stale
                    .as_ref()
                    .is_none_or(|s| s.feed.seq < fetched.feed.seq)
                {
                    self.stale = Some(fetched);
                }
            }
            Answer::Older => self.older = true,
            Answer::Refused(err) => {
                self.refused.get_or_insert(err);
            }
            Answer::Unreachable => {}
        }
        None
    }

    fn finish(self) -> Result<Fetched, FetchError> {
        match (self.stale, self.refused) {
            (Some(stale), _) => Ok(stale),
            (None, Some(err)) => Err(FetchError::Refused(err)),
            (None, None) if self.older => Err(FetchError::Older),
            (None, None) => Err(FetchError::Unreachable),
        }
    }
}

/// One mirror through `ways` in order (the session first). A refused signature tries the next
/// way; any verified feed ends the mirror, which serves the same file on every way.
async fn mirror(base: &str, ways: &[Way], keys: &[PublicKey], max_seq: u64) -> Answer {
    let mut answer = Answer::Unreachable;
    for way in ways {
        let Some((bytes, sig)) = get_pair(way, base).await else {
            continue;
        };
        let feed = match verify(&bytes, &sig, keys) {
            Ok(feed) => feed,
            Err(err) => {
                tracing::warn!(%err, via = ?way.via, mirror = host(base), "feed refused");
                // A different way may avoid whoever altered it.
                answer = Answer::Refused(err);
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
        return match fresh {
            Freshness::Fresh => Answer::Fresh(fetched),
            Freshness::Older => Answer::Older,
            Freshness::Stale => Answer::Stale(fetched),
        };
    }
    answer
}

/// `update.json` and its signature from `base`, fetched together (one round trip less), or
/// `None` on any network or HTTP failure.
async fn get_pair(way: &Way, base: &str) -> Option<(Vec<u8>, String)> {
    let client = feed_client(way).ok()?;
    let (feed, sig) = (format!("{base}{FEED_FILE}"), format!("{base}{SIG_FILE}"));
    let (bytes, sig) = tokio::join!(get(&client, &feed, FEED_CAP), get(&client, &sig, SIG_CAP));
    Some((bytes?, String::from_utf8(sig?).ok()?))
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
