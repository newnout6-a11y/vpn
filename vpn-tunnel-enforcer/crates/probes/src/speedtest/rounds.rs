//! Transfers of the speed test: latency pings and time-boxed download / upload rounds.
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use futures_util::future::try_join_all;
use reqwest::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use tokio::sync::Notify;
use url::Url;

use super::{DownloadTarget, Plan, Round, maths};

/// Upload chunk handed to the HTTP client per pull.
const CHUNK: usize = 64 * 1024;
/// How often a running round reports its progress.
const TICK: Duration = Duration::from_millis(100);

/// Why a round produced no figure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RoundError {
    /// No byte moved within the setup timeout.
    NoData,
    /// A stream ended before its byte budget (captive portal, truncated answer).
    Short,
    /// A non-2xx status.
    Status(u16),
    /// The transfer failed in the network.
    Transport,
    /// Too little data for a meaningful figure (B-ST-2).
    TooSmall,
}

/// Bytes moved by a round and when the first one moved.
#[derive(Debug, Default)]
struct Meter {
    bytes: AtomicU64,
    first: OnceLock<Instant>,
    started: Notify,
}

impl Meter {
    fn add(&self, n: u64) {
        self.bytes.fetch_add(n, Ordering::Relaxed);
        if self.first.get().is_none() && self.first.set(Instant::now()).is_ok() {
            self.started.notify_one();
        }
    }

    fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Share of the round done: by bytes or by time, whichever is further.
    fn ratio(&self, round: &Round) -> f64 {
        let total = round
            .bytes_per_stream
            .saturating_mul(round.streams as u64)
            .max(1);
        let by_bytes = self.bytes() as f64 / total as f64;
        let by_time = self.first.get().map_or(0.0, |first| {
            first.elapsed().as_secs_f64() / round.time_box.as_secs_f64().max(0.001)
        });
        by_bytes.max(by_time).min(1.0)
    }
}

/// Runs the streams of a round until they all finish or the time box (counted from the first
/// byte) closes; dropping the transfers aborts every open request. Returns Mbps.
async fn run_round(
    transfers: impl Future<Output = Result<(), RoundError>>,
    meter: &Meter,
    round: &Round,
    plan: &Plan,
    report: &(dyn Fn(f64) + Sync),
) -> Result<f64, RoundError> {
    let time_box = async {
        tokio::time::timeout(plan.setup_timeout, meter.started.notified())
            .await
            .map_err(|_| RoundError::NoData)?;
        let end = tokio::time::Instant::now() + round.time_box;
        let mut ticks = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                () = tokio::time::sleep_until(end) => return Ok(()),
                _ = ticks.tick() => report(meter.ratio(round)),
            }
        }
    };
    let time_boxed = tokio::select! {
        done = transfers => { done?; false }
        closed = time_box => { closed?; true }
    };
    let end = Instant::now();
    let bytes = meter.bytes();
    let Some(first) = meter.first.get().copied() else {
        return Err(RoundError::NoData);
    };
    // A round cut by its time box is a slow but live link; one that ended on its own must have
    // moved a meaningful amount. A figure that rounds to zero is no figure (old `probe <= 0`).
    let mbps = maths::mbps(bytes, end - first);
    if (!time_boxed && bytes < plan.min_round_bytes) || mbps <= 0.0 {
        return Err(RoundError::TooSmall);
    }
    report(1.0);
    Ok(mbps)
}

/// URL of one download stream: sized servers get the byte count, static files a cache-buster.
pub(super) fn stream_url(target: &DownloadTarget, bytes: u64, run: &str, index: usize) -> Url {
    let mut url = target.url.clone();
    if target.sized {
        url.query_pairs_mut()
            .append_pair("bytes", &bytes.to_string())
            .append_pair("run", run)
            .append_pair("stream", &index.to_string());
    } else {
        url.query_pairs_mut()
            .append_pair("cb", &format!("{run}{index}"));
    }
    url
}

async fn download_stream(
    client: &reqwest::Client,
    url: Url,
    budget: u64,
    meter: &Meter,
) -> Result<(), RoundError> {
    let mut resp = client
        .get(url)
        .header(CACHE_CONTROL, "no-cache")
        .send()
        .await
        .map_err(|_| RoundError::Transport)?;
    if !resp.status().is_success() {
        return Err(RoundError::Status(resp.status().as_u16()));
    }
    let mut got = 0u64;
    while got < budget {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                got += chunk.len() as u64;
                meter.add(chunk.len() as u64);
            }
            Ok(None) => return Err(RoundError::Short),
            Err(_) => return Err(RoundError::Transport),
        }
    }
    Ok(())
}

/// One download round against `target`; Mbps.
pub(super) async fn download_round(
    client: &reqwest::Client,
    target: &DownloadTarget,
    round: &Round,
    plan: &Plan,
    report: &(dyn Fn(f64) + Sync),
) -> Result<f64, RoundError> {
    let meter = Meter::default();
    let run = uuid::Uuid::new_v4().simple().to_string();
    let streams = (0..round.streams).map(|index| {
        let url = stream_url(target, round.bytes_per_stream, &run, index);
        download_stream(client, url, round.bytes_per_stream, &meter)
    });
    let transfers = async { try_join_all(streams).await.map(drop) };
    run_round(transfers, &meter, round, plan, report).await
}

/// Random upload payload, generated once per run and shared by every stream (B-ST-6). Random,
/// not zeros: a compressing hop would otherwise carry fewer bytes than we count.
pub(super) fn payload(len: u64) -> Arc<[u8]> {
    let mut bytes = vec![0u8; usize::try_from(len).unwrap_or(CHUNK).max(1)];
    fastrand::fill(&mut bytes);
    bytes.into()
}

/// Request body of `len` bytes cut from `payload` (wrapping around); a byte counts as sent
/// when the HTTP client pulls it, as in the old app (buffered, not acknowledged).
fn upload_body(payload: Arc<[u8]>, len: u64, meter: Arc<Meter>) -> reqwest::Body {
    let chunks = futures_util::stream::unfold(0u64, move |sent| {
        let (payload, meter) = (payload.clone(), meter.clone());
        async move {
            if sent >= len {
                return None;
            }
            // `payload` is never empty, so the offset is in bounds and `n` is at least 1.
            let offset = usize::try_from(sent % payload.len() as u64).unwrap_or(0);
            let left = usize::try_from(len - sent).unwrap_or(usize::MAX);
            let n = left.min(CHUNK).min(payload.len() - offset);
            meter.add(n as u64);
            let chunk = payload[offset..offset + n].to_vec();
            Some((Ok::<_, io::Error>(chunk), sent + n as u64))
        }
    });
    reqwest::Body::wrap_stream(chunks)
}

async fn upload_stream(
    client: &reqwest::Client,
    url: Url,
    len: u64,
    body: reqwest::Body,
) -> Result<(), RoundError> {
    let resp = client
        .post(url)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, len)
        .body(body)
        .send()
        .await
        .map_err(|_| RoundError::Transport)?;
    match resp.status() {
        status if status.is_success() => Ok(()),
        status => Err(RoundError::Status(status.as_u16())),
    }
}

/// One upload round; Mbps from the bytes the HTTP client actually took.
pub(super) async fn upload_round(
    client: &reqwest::Client,
    url: &Url,
    round: &Round,
    plan: &Plan,
    payload: &Arc<[u8]>,
    report: &(dyn Fn(f64) + Sync),
) -> Result<f64, RoundError> {
    let meter = Arc::new(Meter::default());
    let streams = (0..round.streams).map(|_| {
        let body = upload_body(payload.clone(), round.bytes_per_stream, meter.clone());
        upload_stream(client, url.clone(), round.bytes_per_stream, body)
    });
    let transfers = async { try_join_all(streams).await.map(drop) };
    run_round(transfers, &meter, round, plan, report).await
}

/// Latency: per URL in order, one discarded warm-up (cold DNS / handshake), then five timed
/// requests; the first URL with samples gives the trimmed median. A URL whose warm-up fails is
/// skipped (its timed requests would fail the same way). Any HTTP answer is a round trip.
pub(super) async fn latency(client: &reqwest::Client, plan: &Plan) -> Option<u32> {
    let deadline = Instant::now() + plan.latency_budget;
    for url in &plan.latency_urls {
        if ping(client, url, plan.latency_timeout, deadline)
            .await
            .is_none()
        {
            continue;
        }
        let mut samples = Vec::with_capacity(5);
        for _ in 0..5 {
            if let Some(ms) = ping(client, url, plan.latency_timeout, deadline).await {
                samples.push(ms);
            }
        }
        if let Some(ms) = maths::latency_ms(samples) {
            return Some(ms);
        }
    }
    None
}

async fn ping(
    client: &reqwest::Client,
    url: &Url,
    limit: Duration,
    deadline: Instant,
) -> Option<u32> {
    let start = Instant::now();
    let left = deadline.saturating_duration_since(start);
    if left.is_zero() {
        return None;
    }
    let request = async {
        let resp = client
            .get(url.clone())
            .header(CACHE_CONTROL, "no-cache")
            .send()
            .await
            .ok()?;
        // Read the (tiny) body so the connection can be reused by the next sample.
        resp.bytes().await.ok()
    };
    tokio::time::timeout(limit.min(left), request)
        .await
        .ok()??;
    Some(u32::try_from(start.elapsed().as_millis()).unwrap_or(u32::MAX))
}
