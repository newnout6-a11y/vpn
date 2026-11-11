//! 1 Hz speed sampler of the TUN adapter: raw and smoothed rates, burstiness, session and adapter
//! totals, peaks, published on a `watch` channel for the dashboard, tray, mascot and watchdog.
//!
//! The counters come from `GetIfEntry2` on the TUN's LUID (`vpnte_winnet::counters`), never from
//! an alias lookup: a physical NIC auto-named like our disguised alias must not be sampled.
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_winnet::counters::{self, IfCounters};

/// Time between the end of one counters read and the start of the next.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// EMA weight of a new sample in the smoothed rate.
pub const SMOOTHING_ALPHA: f64 = 0.35;
/// Number of recent raw rates the burstiness is computed over (5 s at 1 Hz).
pub const BURSTINESS_WINDOW: usize = 5;
/// A rate above this many bytes per second counts as live traffic (proxy-down recovery, watchdog).
pub const LIVE_TRAFFIC_BPS: f64 = 1024.0;
/// Longest adapter alias Windows accepts (`IF_MAX_STRING_SIZE`).
const MAX_ALIAS_CHARS: usize = 256;

/// The TUN interface to sample: its alias (display only) and its LUID (what is actually read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunIf {
    pub alias: String,
    pub luid: u64,
}

impl TunIf {
    /// Validates the alias (non-empty after trim, at most 256 characters, no control characters)
    /// before anything reaches the OS (AT-07-009).
    pub fn new(alias: &str, luid: u64) -> AppResult<Self> {
        let valid = !alias.trim().is_empty()
            && alias.chars().count() <= MAX_ALIAS_CHARS
            && !alias.chars().any(|c| c < '\u{20}');
        if !valid {
            return Err(AppError::validation(Msg::new(
                "forensics.traffic.invalidAdapter",
            )));
        }
        Ok(Self {
            alias: alias.to_owned(),
            luid,
        })
    }
}

/// One published speed sample. Rates are bytes per second; burstiness is 0..=999 %.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficStats {
    pub ts_ms: UnixMs,
    /// The sampler is on (protection session active), whether or not the last read succeeded.
    pub running: bool,
    pub adapter: String,
    pub adapter_found: bool,
    pub down_bps: f64,
    pub up_bps: f64,
    pub smooth_down_bps: f64,
    pub smooth_up_bps: f64,
    pub down_burst_pct: u16,
    pub up_burst_pct: u16,
    /// Adapter counters since the adapter was created.
    pub total_down: u64,
    pub total_up: u64,
    /// Bytes since the sampler started; survives an engine restart that recreates the adapter.
    pub session_down: u64,
    pub session_up: u64,
    pub peak_down_bps: f64,
    pub peak_up_bps: f64,
    pub started_at_ms: Option<UnixMs>,
}

impl TrafficStats {
    /// The idle value: everything zero, not running.
    pub fn empty(adapter: &str, now: UnixMs) -> Self {
        Self {
            ts_ms: now,
            adapter: adapter.to_owned(),
            ..Self::default()
        }
    }

    /// Proxy-down recovery rule: running and the smoothed (else raw) rate of either direction
    /// above [`LIVE_TRAFFIC_BPS`].
    pub fn shows_live_traffic(&self) -> bool {
        let pick = |smooth: f64, raw: f64| if smooth > 0.0 { smooth } else { raw };
        self.running
            && (pick(self.smooth_down_bps, self.down_bps) > LIVE_TRAFFIC_BPS
                || pick(self.smooth_up_bps, self.up_bps) > LIVE_TRAFFIC_BPS)
    }
}

/// Watchdog confirmation from traffic alone: bytes moved within `max_age_ms` (`last_traffic_ms`
/// from [`RateSampler::last_traffic_ms`], 0 = never), or the sampler is running and the raw rate
/// of either direction is above [`LIVE_TRAFFIC_BPS`]. The public-IP and probe confirmations are
/// the watchdog's own inputs.
pub fn recent_traffic(
    stats: &TrafficStats,
    last_traffic_ms: UnixMs,
    now: UnixMs,
    max_age_ms: i64,
) -> bool {
    (last_traffic_ms > 0 && now - last_traffic_ms <= max_age_ms)
        || (stats.running && (stats.down_bps > LIVE_TRAFFIC_BPS || stats.up_bps > LIVE_TRAFFIC_BPS))
}

/// Exponential smoothing that resists a single buffered burst; the first sample sets the level.
pub fn smooth(prev: f64, cur: f64, alpha: f64) -> f64 {
    if !prev.is_finite() || prev <= 0.0 {
        return cur.max(0.0);
    }
    let alpha = alpha.clamp(0.01, 1.0);
    (prev + alpha * (cur - prev)).max(0.0)
}

/// Relative population standard deviation of `xs` in percent, capped at 999; fewer than two
/// usable values, or a zero mean, give 0.
pub fn burstiness(xs: &[f64]) -> u16 {
    let usable: Vec<f64> = xs
        .iter()
        .copied()
        .filter(|x| x.is_finite() && *x >= 0.0)
        .collect();
    if usable.len() < 2 {
        return 0;
    }
    let n = usable.len() as f64;
    let mean = usable.iter().sum::<f64>() / n;
    if mean <= 0.0 {
        return 0;
    }
    let variance = usable.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    (variance.sqrt() / mean * 100.0).min(999.0).round() as u16
}

/// One good counters read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sample {
    identity: u128,
    rx: u64,
    tx: u64,
    /// Monotonic milliseconds of the read: a wall-clock step (time sync after resume) must not
    /// turn into a rate spike.
    mono: i64,
}

/// The sampler's arithmetic, free of I/O and clocks so the vectors can be replayed exactly.
#[derive(Debug, Default)]
struct RateState {
    /// The last good sample: the delta base. A failed read leaves it alone, so the first good
    /// sample after a gap measures the delta over the whole gap.
    prev: Option<Sample>,
    smooth_down: f64,
    smooth_up: f64,
    win_down: VecDeque<f64>,
    win_up: VecDeque<f64>,
    last_traffic: UnixMs,
    /// Last published value: start time, totals, session bytes and peaks carry over.
    last: TrafficStats,
}

impl RateState {
    fn started(adapter: &str, now: UnixMs) -> Self {
        let last = TrafficStats {
            running: true,
            started_at_ms: Some(now),
            ..TrafficStats::empty(adapter, now)
        };
        Self {
            last,
            ..Self::default()
        }
    }

    /// Folds one read into the state and returns the stats to publish. `None` = no sample (read
    /// failed, adapter absent): rates and smoothing drop to zero, the sampler stays running.
    /// `now` stamps the stats; `mono` (monotonic ms) measures the time between reads.
    fn on_sample(
        &mut self,
        read: Option<(u128, u64, u64)>,
        adapter: &str,
        now: UnixMs,
        mono: i64,
    ) -> TrafficStats {
        let Some((identity, rx, tx)) = read else {
            self.reset_smoothing();
            return self.publish(TrafficStats {
                ts_ms: now,
                adapter: adapter.to_owned(),
                adapter_found: false,
                ..self.zero_rates()
            });
        };
        let cur = Sample {
            identity,
            rx,
            tx,
            mono,
        };
        let base = match self.prev {
            Some(prev) if prev.identity == identity && rx >= prev.rx && tx >= prev.tx => prev,
            // First sample, adapter recreated by an engine restart, or counters reset: a new
            // baseline. Session bytes and peaks continue (B-25).
            _ => {
                self.prev = Some(cur);
                self.reset_smoothing();
                return self.publish(TrafficStats {
                    ts_ms: now,
                    adapter: adapter.to_owned(),
                    adapter_found: true,
                    total_down: rx,
                    total_up: tx,
                    ..self.zero_rates()
                });
            }
        };
        let dt = ((mono - base.mono) as f64 / 1000.0).max(0.001);
        // Subtract as u64 first: counters above 2^53 lose precision as f64, deltas do not.
        let (d_rx, d_tx) = (rx - base.rx, tx - base.tx);
        let (down, up) = (d_rx as f64 / dt, d_tx as f64 / dt);
        if d_rx > 0 || d_tx > 0 {
            self.last_traffic = now;
        }
        self.smooth_down = smooth(self.smooth_down, down, SMOOTHING_ALPHA);
        self.smooth_up = smooth(self.smooth_up, up, SMOOTHING_ALPHA);
        push_window(&mut self.win_down, down);
        push_window(&mut self.win_up, up);
        self.prev = Some(cur);
        let last = &self.last;
        let stats = TrafficStats {
            ts_ms: now,
            adapter: adapter.to_owned(),
            adapter_found: true,
            down_bps: down,
            up_bps: up,
            smooth_down_bps: self.smooth_down,
            smooth_up_bps: self.smooth_up,
            down_burst_pct: burstiness(self.win_down.make_contiguous()),
            up_burst_pct: burstiness(self.win_up.make_contiguous()),
            total_down: rx,
            total_up: tx,
            session_down: last.session_down.saturating_add(d_rx),
            session_up: last.session_up.saturating_add(d_tx),
            peak_down_bps: last.peak_down_bps.max(down),
            peak_up_bps: last.peak_up_bps.max(up),
            ..last.clone()
        };
        self.publish(stats)
    }

    /// The last published stats with every rate at zero.
    fn zero_rates(&self) -> TrafficStats {
        TrafficStats {
            down_bps: 0.0,
            up_bps: 0.0,
            smooth_down_bps: 0.0,
            smooth_up_bps: 0.0,
            down_burst_pct: 0,
            up_burst_pct: 0,
            ..self.last.clone()
        }
    }

    fn reset_smoothing(&mut self) {
        self.smooth_down = 0.0;
        self.smooth_up = 0.0;
        self.win_down.clear();
        self.win_up.clear();
    }

    fn publish(&mut self, stats: TrafficStats) -> TrafficStats {
        self.last = stats.clone();
        stats
    }
}

fn push_window(window: &mut VecDeque<f64>, rate: f64) {
    if window.len() == BURSTINESS_WINDOW {
        window.pop_front();
    }
    window.push_back(rate);
}

/// Reads the counters of the interface with a LUID; `Ok(None)` = no such interface.
type Reader = Arc<dyn Fn(u64) -> windows::core::Result<Option<IfCounters>> + Send + Sync>;

#[derive(Default)]
struct Shared {
    /// Bumped by every start and stop: a read that settles after either is dropped.
    generation: u64,
    running: bool,
    adapter: String,
    state: RateState,
    cancel: Option<CancellationToken>,
}

/// The speed sampler. Its lifetime follows the protection session (start on `running` /
/// `proxy-down`, stop otherwise), not the engine process: after an engine restart the tunnel
/// publishes the new [`TunIf`] and the identity rule starts a new baseline.
pub struct RateSampler {
    tx: watch::Sender<TrafficStats>,
    shared: Arc<Mutex<Shared>>,
    reader: Reader,
    interval: Duration,
}

impl Default for RateSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl RateSampler {
    /// A stopped sampler reading `GetIfEntry2` counters.
    pub fn new() -> Self {
        Self::with_reader(Arc::new(counters::read), SAMPLE_INTERVAL)
    }

    fn with_reader(reader: Reader, interval: Duration) -> Self {
        Self {
            tx: watch::Sender::new(TrafficStats::empty("", now_ms())),
            shared: Arc::default(),
            reader,
            interval,
        }
    }

    /// Stats stream; the current value is the latest sample.
    pub fn subscribe(&self) -> watch::Receiver<TrafficStats> {
        self.tx.subscribe()
    }

    /// The latest published stats. Read the ending session's numbers before [`Self::stop`].
    pub fn current(&self) -> TrafficStats {
        self.tx.borrow().clone()
    }

    /// Whether the sampler is on.
    pub fn is_running(&self) -> bool {
        self.shared.lock().running
    }

    /// Time of the last sample that moved bytes, 0 when none since the start.
    pub fn last_traffic_ms(&self) -> UnixMs {
        self.shared.lock().state.last_traffic
    }

    /// Starts sampling the TUN published on `tun` once per second (inside a tokio runtime).
    /// Idempotent: a running sampler ignores the call.
    pub fn start(&self, tun: watch::Receiver<Option<TunIf>>) {
        let mut shared = self.shared.lock();
        if shared.running {
            return;
        }
        if let Some(t) = tun.borrow().as_ref() {
            shared.adapter.clone_from(&t.alias);
        }
        shared.generation += 1;
        shared.running = true;
        shared.state = RateState::started(&shared.adapter, now_ms());
        self.tx.send_replace(shared.state.last.clone());
        let cancel = CancellationToken::new();
        shared.cancel = Some(cancel.clone());
        tokio::spawn(sample_loop(
            shared.generation,
            tun,
            self.shared.clone(),
            self.tx.clone(),
            self.reader.clone(),
            self.interval,
            cancel,
        ));
    }

    /// Stops sampling, resets every number and publishes the idle value.
    pub fn stop(&self) {
        let mut shared = self.shared.lock();
        shared.generation += 1;
        shared.running = false;
        if let Some(cancel) = shared.cancel.take() {
            cancel.cancel();
        }
        shared.state = RateState::default();
        self.tx
            .send_replace(TrafficStats::empty(&shared.adapter, now_ms()));
    }
}

impl Drop for RateSampler {
    fn drop(&mut self) {
        if let Some(cancel) = self.shared.lock().cancel.take() {
            cancel.cancel();
        }
    }
}

/// One run: read, publish, sleep a full interval after the read settled (reads never overlap).
async fn sample_loop(
    generation: u64,
    tun: watch::Receiver<Option<TunIf>>,
    shared: Arc<Mutex<Shared>>,
    tx: watch::Sender<TrafficStats>,
    reader: Reader,
    interval: Duration,
    cancel: CancellationToken,
) {
    let mut failing = false;
    let epoch = Instant::now();
    loop {
        let target = tun.borrow().clone();
        let read = match &target {
            None => Ok(None),
            Some(t) => {
                let (reader, luid) = (reader.clone(), t.luid);
                match tokio::task::spawn_blocking(move || reader(luid)).await {
                    Ok(read) => read.map_err(|err| err.to_string()),
                    Err(err) => Err(err.to_string()),
                }
            }
        };
        let mono = i64::try_from(epoch.elapsed().as_millis()).unwrap_or(i64::MAX);
        let sample = match read {
            Ok(found) => {
                failing = false;
                found.map(|c| (c.guid, c.in_octets, c.out_octets))
            }
            Err(err) => {
                if !failing {
                    tracing::warn!(error = %err, "traffic counter sample unavailable");
                    failing = true;
                }
                None
            }
        };
        {
            let mut guard = shared.lock();
            let s = &mut *guard;
            if s.generation != generation || !s.running {
                return;
            }
            if let Some(t) = &target {
                s.adapter.clone_from(&t.alias);
            }
            let stats = s.state.on_sample(sample, &s.adapter, now_ms(), mono);
            tx.send_replace(stats);
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(interval) => {}
        }
    }
}

#[cfg(test)]
mod tests;
