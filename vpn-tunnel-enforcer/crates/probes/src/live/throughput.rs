//! Throughput through the profile (live-probe §3.16-§3.17 with B-10, B-11, B-35): three
//! sequential 4 MiB downloads from speed.cloudflare.com through the probe inbound, each under one
//! 8 s deadline covering dial, TLS, request and body. The median is the headline; min / max,
//! stalls and the longest pause expose shaping that an average hides (DPI throttling shows as
//! stalls or a sawtooth).
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::{Loopback, now_ms};

use super::model::{EngineRoute, Throughput, ThroughputSample, ThroughputStatus};
use super::ms;
use super::wire::{Wire, exchange_head};
use crate::live_stages::CANCELLED;

/// `throughput.endpoint` label.
pub(crate) const ENDPOINT: &str = "speed.cloudflare.com/__down";
const HOST: &str = "speed.cloudflare.com";
/// Bytes requested per sample.
pub(crate) const SAMPLE_BYTES: u64 = 4 * 1024 * 1024;
/// Samples per check.
pub(crate) const SAMPLES: u32 = 3;
/// One sample: dial + TLS + request + body.
pub(crate) const SAMPLE_DEADLINE: Duration = Duration::from_secs(8);
/// A pause between body chunks this long counts as a stall.
pub(crate) const STALL_GAP_MS: u64 = 750;
/// Min-max spread (in % of the median) from which the speed counts as unstable.
const UNSTABLE_SPREAD_PCT: u32 = 40;

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// Summary of the samples (§3.16). Incomplete samples count with their bytes (B-11) and make
/// the result a warning, like an error does.
pub fn summarize_throughput(
    samples: Vec<ThroughputSample>,
    endpoint: &str,
    duration_ms: u64,
    error: Option<String>,
) -> Throughput {
    let base = Throughput {
        duration_ms,
        endpoint: Some(endpoint.to_owned()),
        ..Throughput::default()
    };
    if samples.is_empty() {
        let status = if error.is_some() {
            ThroughputStatus::Error
        } else {
            ThroughputStatus::Skipped
        };
        return Throughput {
            status,
            error,
            ..base
        };
    }
    let mut speeds: Vec<f64> = samples
        .iter()
        .map(|s| s.throughput_mbps)
        .filter(|v| v.is_finite())
        .collect();
    if speeds.is_empty() {
        return Throughput {
            status: ThroughputStatus::Error,
            samples,
            error: error.or_else(|| Some("no sample has a numeric speed".into())),
            ..base
        };
    }
    speeds.sort_by(f64::total_cmp);
    let mid = speeds.len() / 2;
    let median = if speeds.len().is_multiple_of(2) {
        (speeds[mid - 1] + speeds[mid]) / 2.0
    } else {
        speeds[mid]
    };
    let (min, max) = (speeds[0], speeds[speeds.len() - 1]);
    let spread = if median > 0.0 {
        ((max - min) / median * 100.0).round() as u32
    } else {
        0
    };
    let stalls: u32 = samples.iter().map(|s| s.stall_count).sum();
    let max_gap = samples
        .iter()
        .map(|s| s.max_inter_chunk_gap_ms)
        .max()
        .unwrap_or(0);
    let partial = error.is_some() || samples.iter().any(|s| !s.complete);
    let unstable =
        partial || spread >= UNSTABLE_SPREAD_PCT || stalls > 0 || max_gap >= STALL_GAP_MS;
    let detail = match (unstable, partial) {
        (false, _) => Msg::new("probes.live.throughput.stable"),
        (true, false) => Msg::new("probes.live.throughput.unstable"),
        (true, true) => Msg::new("probes.live.throughput.partial").arg(
            "error",
            error.clone().unwrap_or_else(|| "incomplete sample".into()),
        ),
    };
    Throughput {
        status: if unstable {
            ThroughputStatus::Warning
        } else {
            ThroughputStatus::Ok
        },
        samples,
        median_mbps: Some(round2(median)),
        min_mbps: Some(round2(min)),
        max_mbps: Some(round2(max)),
        variability_pct: Some(spread),
        stall_count: Some(stalls),
        max_inter_chunk_gap_ms: Some(max_gap),
        detail: Some(detail.into()),
        error,
        ..base
    }
}

/// Timing of one sample's body; survives a timed-out transfer so partial data is kept (B-11).
#[derive(Debug, Clone)]
pub(crate) struct Meter {
    t0: Instant,
    first: Option<Instant>,
    last: Option<Instant>,
    bytes: u64,
    stalls: u32,
    max_gap: u64,
}

impl Meter {
    pub(crate) fn new(t0: Instant) -> Self {
        Meter {
            t0,
            first: None,
            last: None,
            bytes: 0,
            stalls: 0,
            max_gap: 0,
        }
    }

    /// `n` body bytes arrived at `at`.
    pub(crate) fn chunk_at(&mut self, n: usize, at: Instant) {
        if n == 0 {
            return;
        }
        if let Some(last) = self.last {
            let gap = ms(at.saturating_duration_since(last));
            self.max_gap = self.max_gap.max(gap);
            if gap >= STALL_GAP_MS {
                self.stalls += 1;
            }
        }
        self.first.get_or_insert(at);
        self.last = Some(at);
        self.bytes = (self.bytes + n as u64).min(SAMPLE_BYTES);
    }

    /// The sample as measured so far (`None` without body bytes). The rate is taken over the
    /// body window, so dial, TLS and request round trips do not halve it on a slow path (B-10).
    pub(crate) fn sample(
        &self,
        index: u32,
        complete: bool,
        now: Instant,
    ) -> Option<ThroughputSample> {
        let (first, last) = (self.first?, self.last?);
        let window = ms(last.saturating_duration_since(first)).max(1);
        Some(ThroughputSample {
            index,
            bytes: self.bytes,
            duration_ms: ms(now.saturating_duration_since(self.t0)).max(1),
            throughput_mbps: round2(self.bytes as f64 * 8.0 / window as f64 / 1000.0),
            ttfb_ms: Some(ms(first.saturating_duration_since(self.t0))),
            stall_count: self.stalls,
            max_inter_chunk_gap_ms: self.max_gap,
            complete,
        })
    }
}

/// Downloads one sample through `proxy`, recording body chunks into `meter`.
async fn transfer(
    wire: &Wire,
    proxy: &Loopback,
    index: u32,
    meter: &mut Meter,
) -> Result<(), String> {
    let (mut stream, _) = wire
        .open(proxy, HOST, 443, HOST)
        .await
        .map_err(|e| e.text())?;
    // The cache-buster keeps an intermediate cache from serving a stored body.
    let request = format!(
        "GET /__down?bytes={SAMPLE_BYTES}&vpnte_probe={index}-{} HTTP/1.1\r\nHost: {HOST}\r\n\
         Accept: application/octet-stream\r\nAccept-Encoding: identity\r\nCache-Control: no-cache\r\n\
         Connection: close\r\n\r\n",
        now_ms()
    );
    let (head, first) = exchange_head(&mut stream, &request)
        .await
        .map_err(|e| format!("throughput probe: {}", e.text()))?;
    if !(200..300).contains(&head.status) {
        return Err(format!("throughput probe HTTP status {}", head.status));
    }
    meter.chunk_at(first.len(), Instant::now());
    let mut buf = vec![0u8; 64 * 1024];
    while meter.bytes < SAMPLE_BYTES {
        let n = match stream.read(&mut buf).await {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => {
                return Err(format!(
                    "throughput connection failed: {}",
                    super::wire::io_text(&e)
                ));
            }
        };
        if n == 0 {
            return Err(format!(
                "throughput probe ended after {} of {SAMPLE_BYTES} bytes",
                meter.bytes
            ));
        }
        meter.chunk_at(n, Instant::now());
    }
    Ok(())
}

/// One sample under its deadline: `Ok` when complete, else the error and what arrived.
async fn sample(
    wire: &Wire,
    proxy: &Loopback,
    index: u32,
    cancel: &CancellationToken,
) -> (Option<ThroughputSample>, Option<String>) {
    let mut meter = Meter::new(Instant::now());
    let outcome = tokio::select! {
        biased;
        () = cancel.cancelled() => Err(CANCELLED.to_owned()),
        r = tokio::time::timeout(SAMPLE_DEADLINE, transfer(wire, proxy, index, &mut meter)) => {
            r.unwrap_or_else(|_| Err("throughput probe timeout".into()))
        }
    };
    let sample = meter.sample(index, outcome.is_ok(), Instant::now());
    (sample, outcome.err())
}

/// Three sequential samples (the second starts after the first connection is closed).
pub(crate) async fn probe_throughput(
    wire: &Wire,
    proxy: &Loopback,
    route: EngineRoute,
    cancel: &CancellationToken,
) -> Throughput {
    let start = Instant::now();
    let mut samples = Vec::new();
    let mut last_error = None;
    for index in 0..SAMPLES {
        if cancel.is_cancelled() {
            break;
        }
        let (sample, error) = sample(wire, proxy, index, cancel).await;
        samples.extend(sample);
        if error.as_deref() == Some(CANCELLED) {
            break;
        }
        if error.is_some() {
            last_error = error;
        }
    }
    let mut t = summarize_throughput(samples, ENDPOINT, ms(start.elapsed()), last_error);
    t.route = Some(route);
    t
}
