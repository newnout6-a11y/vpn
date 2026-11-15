//! Traffic statistics shared by the dashboard, tray and mascot: the published sample and the
//! smoothing / burstiness maths. The app samples the engine's Clash API totals once per second for
//! both captures (a Soft session has no TUN adapter whose counters could be read).
use std::time::Duration;

use serde::Serialize;
use vpnte_base::types::UnixMs;

/// Time between two samples.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// EMA weight of a new sample in the smoothed rate.
pub const SMOOTHING_ALPHA: f64 = 0.35;
/// Number of recent raw rates the burstiness is computed over (5 s at 1 Hz).
pub const BURSTINESS_WINDOW: usize = 5;

/// One published speed sample. Rates are bytes per second; burstiness is 0..=999 %.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficStats {
    pub ts_ms: UnixMs,
    /// A protection session is active, whether or not the last read succeeded.
    pub running: bool,
    pub adapter: String,
    /// The last read succeeded.
    pub adapter_found: bool,
    pub down_bps: f64,
    pub up_bps: f64,
    pub smooth_down_bps: f64,
    pub smooth_up_bps: f64,
    pub down_burst_pct: u16,
    pub up_burst_pct: u16,
    /// Totals of the current source (one engine run).
    pub total_down: u64,
    pub total_up: u64,
    /// Bytes since the session started; survive an engine restart.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// trafficMonitor.test.ts 'smooths an isolated burst' / 'reports relative variation'.
    #[test]
    fn smoothing_and_burstiness_vectors() {
        assert!((smooth(10.0, 100.0, 0.35) - 41.5).abs() < 1e-9);
        assert_eq!(smooth(0.0, 100.0, 0.35), 100.0);
        assert_eq!(smooth(f64::NAN, -5.0, 0.35), 0.0);
        assert_eq!(burstiness(&[100.0, 100.0, 100.0]), 0);
        assert_eq!(burstiness(&[50.0, 100.0, 150.0]), 41);
        assert_eq!(burstiness(&[0.0, 0.0]), 0);
        assert_eq!(burstiness(&[5.0]), 0);
        assert_eq!(burstiness(&[f64::NAN, 10.0, -1.0, 30.0]), 50);
    }
}
