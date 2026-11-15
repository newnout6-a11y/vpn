//! Pure arithmetic of the speed test: throughput, latency median, progress percent, egress
//! comparison.
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vpnte_base::Msg;
use vpnte_core::net::unmap;

use super::SpeedPhase;

/// Megabits per second, rounded to 2 decimals; the window is at least 1 ms.
pub fn mbps(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64().max(0.001);
    let mbps = bytes as f64 * 8.0 / secs / 1_000_000.0;
    (mbps * 100.0).round() / 100.0
}

/// Latency from timed samples: with three or more, the min and max are dropped and the middle
/// of the rest is taken; with one or two, the middle (upper) sample. `None` without samples.
pub fn latency_ms(mut samples: Vec<u32>) -> Option<u32> {
    samples.sort_unstable();
    let pool = if samples.len() >= 3 {
        &samples[1..samples.len() - 1]
    } else {
        &samples[..]
    };
    pool.get(pool.len() / 2).copied()
}

/// Progress percent of a phase at `ratio` (0..=1) of its work: download 5..=50, upload
/// 50..=100, latency 0, complete 100, error 0.
pub fn percent(phase: SpeedPhase, ratio: f64) -> u8 {
    let ratio = if ratio.is_finite() {
        ratio.clamp(0.0, 1.0)
    } else {
        0.0
    };
    match phase {
        SpeedPhase::Latency | SpeedPhase::Error => 0,
        SpeedPhase::Download => 5 + (ratio * 45.0).round() as u8,
        SpeedPhase::Upload => 50 + (ratio * 50.0).round() as u8,
        SpeedPhase::Complete => 100,
    }
}

/// What the tunnel's exit looked like during the test (B-ST-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Egress {
    /// Every sample equals the adopted VPN exit.
    Match,
    /// A sample differs from the VPN exit (`seen: None` for imported old rows); a warning only,
    /// the figures are kept (owner decision §10.5 row 5).
    Changed { seen: Option<IpAddr> },
    /// A sample equals the user's real ISP address: the test bypassed the tunnel.
    Direct { seen: IpAddr },
    /// No sample, or nothing to compare with.
    #[default]
    NotChecked,
}

impl Egress {
    /// What the egress check means for the user (`probes.speed.egress.*`).
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            Egress::Match => "probes.speed.egress.match",
            Egress::Changed { .. } => "probes.speed.egress.changed",
            Egress::Direct { .. } => "probes.speed.egress.direct",
            Egress::NotChecked => "probes.speed.egress.notChecked",
        })
    }
}

/// The reference addresses of the egress comparison.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EgressRef {
    /// The adopted VPN exit address of the current connection.
    pub baseline: Option<IpAddr>,
    /// The user's real address (measured through the engine's direct path).
    pub real_ip: Option<IpAddr>,
}

/// Compares the samples taken before the download and after the upload with the references.
pub fn egress_verdict(samples: &[Option<IpAddr>], reference: EgressRef) -> Egress {
    let seen: Vec<IpAddr> = samples.iter().flatten().map(|ip| unmap(*ip)).collect();
    if let Some(real) = reference.real_ip.map(unmap)
        && seen.contains(&real)
    {
        return Egress::Direct { seen: real };
    }
    let Some(baseline) = reference.baseline.map(unmap) else {
        return Egress::NotChecked;
    };
    match seen.iter().find(|ip| **ip != baseline) {
        Some(other) => Egress::Changed { seen: Some(*other) },
        None if seen.is_empty() => Egress::NotChecked,
        None => Egress::Match,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mbps_is_rounded_and_floored() {
        assert_eq!(mbps(1_250_000, Duration::from_secs(1)), 10.0);
        assert_eq!(mbps(1_000, Duration::from_secs(3)), 0.0);
        assert_eq!(mbps(123_456, Duration::from_millis(1000)), 0.99);
        // Zero elapsed counts as 1 ms.
        assert_eq!(mbps(125, Duration::ZERO), 1.0);
    }

    #[test]
    fn latency_drops_extremes() {
        assert_eq!(latency_ms(vec![50, 10, 30, 20, 40]), Some(30));
        assert_eq!(latency_ms(vec![100, 1, 7]), Some(7));
        assert_eq!(latency_ms(vec![9, 3]), Some(9));
        assert_eq!(latency_ms(vec![4]), Some(4));
        assert_eq!(latency_ms(Vec::new()), None);
    }

    #[test]
    fn percent_mapping() {
        assert_eq!(percent(SpeedPhase::Download, 0.0), 5);
        assert_eq!(percent(SpeedPhase::Download, 0.5), 28);
        assert_eq!(percent(SpeedPhase::Download, 2.0), 50);
        assert_eq!(percent(SpeedPhase::Upload, 0.0), 50);
        assert_eq!(percent(SpeedPhase::Upload, 1.0), 100);
        assert_eq!(percent(SpeedPhase::Upload, f64::NAN), 50);
        assert_eq!(percent(SpeedPhase::Complete, 0.0), 100);
    }

    /// speedTest.test.ts (F-010, AT-00-007): egress vs the monitor's addresses.
    #[test]
    fn egress_vectors() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let reference = EgressRef {
            baseline: Some(ip("198.51.100.9")),
            real_ip: Some(ip("192.0.2.44")),
        };
        assert_eq!(
            egress_verdict(&[Some(ip("203.0.113.7"))], reference),
            Egress::Changed {
                seen: Some(ip("203.0.113.7"))
            }
        );
        assert_eq!(
            egress_verdict(&[Some(ip("198.51.100.9")), None], reference),
            Egress::Match
        );
        assert_eq!(egress_verdict(&[None, None], reference), Egress::NotChecked);
        assert_eq!(
            egress_verdict(
                &[Some(ip("198.51.100.9")), Some(ip("::ffff:192.0.2.44"))],
                reference
            ),
            Egress::Direct {
                seen: ip("192.0.2.44")
            }
        );
        let no_baseline = EgressRef {
            baseline: None,
            ..reference
        };
        assert_eq!(
            egress_verdict(&[Some(ip("203.0.113.7"))], no_baseline),
            Egress::NotChecked
        );
        let json = serde_json::to_string(&Egress::Changed { seen: None }).unwrap();
        assert_eq!(json, r#"{"kind":"changed","seen":null}"#);
        assert_eq!(
            serde_json::from_str::<Egress>(r#"{"kind":"match"}"#).unwrap(),
            Egress::Match
        );
    }
}
