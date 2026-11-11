//! Traffic panel maths: Mbit/s conversion, the 48-sample history behind the bars, bar heights,
//! session gigabytes and the mascot's speed band.
use std::collections::VecDeque;

use vpnte_base::Msg;
use vpnte_base::types::UnixMs;

use crate::fmt::to_fixed;

/// Number of bars. The hover read-out says "N s ago" for bar `HISTORY - 1 - N`, which is true only
/// because the backend samples traffic once a second.
pub const HISTORY: usize = 48;
/// The y-scale never drops below 10 Mbit/s, so an idle running link shows a row of short stubs.
pub const SCALE_FLOOR_MBPS: f64 = 10.0;
/// Shortest bar, percent of the chart height.
pub const MIN_BAR_PCT: f64 = 4.0;

/// One traffic sample as the backend pushes it (once a second while the engine runs).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct TrafficSample {
    /// Sample time: every new sample has a new `ts`.
    pub ts: UnixMs,
    pub running: bool,
    pub download_bps: f64,
    pub upload_bps: f64,
    pub smoothed_download_bps: f64,
    pub smoothed_upload_bps: f64,
    pub session_download_bytes: u64,
    /// Start of the traffic session; a new value starts a fresh chart.
    pub started_at: Option<UnixMs>,
}

impl TrafficSample {
    /// Download rate in bytes/s: the smoothed rate, or the raw one while smoothing has nothing.
    pub fn down_bps(&self) -> f64 {
        prefer(self.smoothed_download_bps, self.download_bps)
    }

    /// Upload rate in bytes/s, chosen like [`Self::down_bps`].
    pub fn up_bps(&self) -> f64 {
        prefer(self.smoothed_upload_bps, self.upload_bps)
    }

    /// Download rate in Mbit/s (the big figure).
    pub fn down_mbps(&self) -> f64 {
        to_mbps(self.down_bps())
    }

    /// Upload rate in Mbit/s.
    pub fn up_mbps(&self) -> f64 {
        to_mbps(self.up_bps())
    }

    /// Session volume in GiB (labelled «ГБ»); download bytes only, as the old panel showed.
    pub fn session_gb(&self) -> f64 {
        self.session_download_bytes as f64 / 1_073_741_824.0
    }
}

// JS `smoothed || raw`: zero (or NaN) falls back to the raw rate.
fn prefer(smoothed: f64, raw: f64) -> f64 {
    if smoothed != 0.0 && !smoothed.is_nan() {
        smoothed
    } else {
        raw
    }
}

/// Bytes per second to Mbit/s; negative rates read as zero.
pub fn to_mbps(bps: f64) -> f64 {
    bps.max(0.0) * 8.0 / 1_000_000.0
}

/// The mascot's speed band for a download rate in bytes/s (pass [`TrafficSample::down_bps`]):
/// fast (≥ 75 Mbit/s) in 10 Mbit/s buckets ("Летим!"), slow (0.3–3 Mbit/s) in 0.5 Mbit/s buckets
/// ("Тащимся…"), otherwise 0 (idle or ordinary: nothing to say). The mascot re-renders only when
/// the band changes.
pub fn speed_band(down_bps: f64) -> f32 {
    let mbps = to_mbps(down_bps);
    let band = if mbps >= 75.0 {
        (mbps / 10.0).round() * 10.0
    } else if (0.3..3.0).contains(&mbps) {
        ((mbps * 2.0).floor() / 2.0).max(0.5)
    } else {
        0.0
    };
    band as f32
}

/// One bar of the chart.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bar {
    /// Height in percent of the chart (`style="height: {height_pct}%"`).
    pub height_pct: f64,
    /// Not running: the bars keep their values but render `.is-off`.
    pub off: bool,
    /// The hovered bar, or the newest one (`.is-hot`).
    pub hot: bool,
    /// Another bar is hovered (`.is-faded`).
    pub faded: bool,
}

/// The last [`HISTORY`] download rates (Mbit/s), oldest first; starts as zeros.
#[derive(Debug, Clone, PartialEq)]
pub struct TrafficHistory {
    samples: VecDeque<f64>,
    /// `(ts, running, rate bits)` of the last sample seen, to push one bar per sample.
    last: Option<(UnixMs, bool, u64)>,
    session: Option<UnixMs>,
}

impl Default for TrafficHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficHistory {
    /// An empty chart: [`HISTORY`] zero samples.
    pub fn new() -> Self {
        Self {
            samples: VecDeque::from(vec![0.0; HISTORY]),
            last: None,
            session: None,
        }
    }

    /// Feeds a sample: one bar per new sample while running (the false → true edge pushes a bar at
    /// once); stopping keeps the bars. A new session start clears the chart, so a reconnect does
    /// not begin with the previous session's tail (D-25). Returns whether the bars changed.
    pub fn observe(&mut self, s: &TrafficSample) -> bool {
        let mut changed = false;
        if s.started_at.is_some() && s.started_at != self.session {
            self.session = s.started_at;
            if self.samples.iter().any(|&v| v != 0.0) {
                self.samples.iter_mut().for_each(|v| *v = 0.0);
                changed = true;
            }
        }
        let down = s.down_mbps();
        let key = (s.ts, s.running, down.to_bits());
        if self.last != Some(key) {
            self.last = Some(key);
            if s.running {
                self.samples.pop_front();
                self.samples.push_back(down);
                changed = true;
            }
        }
        changed
    }

    /// Rates in Mbit/s, oldest first.
    pub fn samples(&self) -> impl ExactSizeIterator<Item = f64> + '_ {
        self.samples.iter().copied()
    }

    /// Top of the y-scale: the largest rate, at least [`SCALE_FLOOR_MBPS`].
    pub fn scale_max(&self) -> f64 {
        self.samples.iter().fold(SCALE_FLOOR_MBPS, |m, &v| m.max(v))
    }

    /// The bars, oldest first, for the current run state and hovered bar.
    pub fn bars(&self, running: bool, hover: Option<usize>) -> Vec<Bar> {
        let max = self.scale_max();
        self.samples
            .iter()
            .enumerate()
            .map(|(i, &v)| Bar {
                height_pct: (v / max * 100.0).max(MIN_BAR_PCT),
                off: !running,
                hot: running && (hover == Some(i) || i == HISTORY - 1),
                faded: running && hover.is_some_and(|h| h != i),
            })
            .collect()
    }

    /// Read-out for the hovered bar: «{mbps} Мбит/с · {n} с назад».
    pub fn hover_msg(&self, i: usize) -> Option<Msg> {
        let v = *self.samples.get(i)?;
        Some(
            Msg::new("view.traffic.hover")
                .arg("mbps", to_fixed(v, 1))
                .arg("n", HISTORY - 1 - i),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ts: UnixMs, running: bool, down_bps: f64) -> TrafficSample {
        TrafficSample {
            ts,
            running,
            download_bps: down_bps,
            started_at: running.then_some(1_000),
            ..TrafficSample::default()
        }
    }

    #[test]
    fn rates_prefer_the_smoothed_value() {
        assert_eq!(to_mbps(125_000.0), 1.0);
        assert_eq!(to_mbps(-5.0), 0.0);
        let mut s = sample(1, true, 250_000.0);
        assert_eq!(s.down_mbps(), 2.0);
        s.smoothed_download_bps = 125_000.0;
        assert_eq!(s.down_mbps(), 1.0);
        s.upload_bps = 31_250.0;
        assert_eq!(s.up_mbps(), 0.25);
        s.session_download_bytes = 3 * 1_073_741_824 / 2;
        assert_eq!(s.session_gb(), 1.5);
    }

    /// ui-dashboard §3.6 (`SwissMascot.tsx:21-35`): speed buckets for the mascot.
    #[test]
    fn speed_bands() {
        let mbps = |m: f64| m * 1_000_000.0 / 8.0;
        let cases: [(f64, f32); 11] = [
            (0.0, 0.0),
            (0.29, 0.0),
            (0.3, 0.5),
            (0.99, 0.5),
            (1.5, 1.5),
            (2.99, 2.5),
            (3.0, 0.0),
            (74.9, 0.0),
            (75.0, 80.0),
            (80.0, 80.0),
            (123.0, 120.0),
        ];
        for (m, band) in cases {
            assert_eq!(speed_band(mbps(m)), band, "{m} Mbit/s");
        }
    }

    /// ui-dashboard §2.5 (`SwissPanels.tsx:41-99`): one bar per sample, 10 Mbit/s scale floor,
    /// 4 % stubs, bars kept (but off) after a stop.
    #[test]
    fn history_pushes_one_bar_per_sample() {
        let mut h = TrafficHistory::new();
        assert_eq!(h.samples().len(), HISTORY);
        assert_eq!(h.scale_max(), 10.0);
        assert!(
            h.bars(false, None)
                .iter()
                .all(|b| b.height_pct == 4.0 && b.off)
        );
        assert!(!h.observe(&sample(1, false, 0.0)));
        assert!(h.observe(&sample(2, true, 625_000.0))); // 5 Mbit/s
        assert!(!h.observe(&sample(2, true, 625_000.0)));
        assert!(h.observe(&sample(3, true, 2_500_000.0))); // 20 Mbit/s
        let rates: Vec<f64> = h.samples().collect();
        assert_eq!(rates[HISTORY - 2..], [5.0, 20.0]);
        assert_eq!(h.scale_max(), 20.0);
        let bars = h.bars(true, None);
        assert_eq!(bars[HISTORY - 1].height_pct, 100.0);
        assert_eq!(bars[HISTORY - 2].height_pct, 25.0);
        assert!(bars[HISTORY - 1].hot && !bars[0].hot && !bars[0].faded);
        let hovered = h.bars(true, Some(HISTORY - 2));
        assert!(hovered[HISTORY - 2].hot && !hovered[HISTORY - 2].faded);
        assert!(hovered[HISTORY - 1].hot && hovered[HISTORY - 1].faded);
        assert!(hovered[0].faded);
        // A stop keeps the bars.
        let stopped = TrafficSample {
            started_at: Some(1_000),
            ..sample(4, false, 0.0)
        };
        assert!(!h.observe(&stopped));
        assert_eq!(h.scale_max(), 20.0);
        // The running edge pushes at once even without a new timestamp.
        let resumed = sample(4, true, 0.0);
        assert!(h.observe(&resumed));
        assert_eq!(h.samples().last(), Some(0.0));
    }

    /// D-25: a new session starts with an empty chart.
    #[test]
    fn a_new_session_clears_the_chart() {
        let mut h = TrafficHistory::new();
        h.observe(&sample(1, true, 625_000.0));
        let next = TrafficSample {
            started_at: Some(9_000),
            ..sample(9_001, true, 125_000.0)
        };
        assert!(h.observe(&next));
        let rates: Vec<f64> = h.samples().collect();
        assert_eq!(rates.iter().filter(|&&v| v != 0.0).count(), 1);
        assert_eq!(rates[HISTORY - 1], 1.0);
    }

    #[test]
    fn hover_read_out() {
        let mut h = TrafficHistory::new();
        h.observe(&sample(1, true, 31_250.0)); // 0.25 Mbit/s prints like the old toFixed
        let msg = h.hover_msg(HISTORY - 1).unwrap();
        assert_eq!(msg.key, "view.traffic.hover");
        assert_eq!(
            msg,
            Msg::new("view.traffic.hover")
                .arg("mbps", "0.3")
                .arg("n", 0)
        );
        assert_eq!(h.hover_msg(0).unwrap().args[1].1, "47");
        assert_eq!(h.hover_msg(HISTORY), None);
    }
}
