//! Text formatting for the start page: JS-compatible fixed decimals, uptime and ages.
use std::time::Duration;

use vpnte_base::types::UnixMs;

/// `Number.prototype.toFixed` (for |v| < 1e21): the nearest decimal with `digits` fraction
/// digits, exact binary ties rounded away from zero. Rust's `{:.N}` rounds exact ties to even, so
/// 31 250 B/s (exactly 0.25 Mbit/s) would read "0.2" where the old UI printed "0.3".
pub fn to_fixed(v: f64, digits: usize) -> String {
    if !v.is_finite() {
        return v.to_string();
    }
    let abs = v.abs();
    // A tie terminates right after the rounding digit; any other double has a non-zero digit
    // within the next few dozen places, so 80 extra digits always reveal it.
    let exact = format!("{abs:.prec$}", prec = digits + 80);
    let tail = exact.split_once('.').map_or("", |(_, frac)| frac);
    let tie =
        tail.as_bytes().get(digits) == Some(&b'5') && tail[digits + 1..].bytes().all(|b| b == b'0');
    let rounded = if tie { abs.next_up() } else { abs };
    let text = format!("{rounded:.digits$}");
    if v < 0.0 { format!("-{text}") } else { text }
}

/// `HH:MM:SS`, each part zero-padded; hours are not wrapped (100 h → `100:00:00`).
pub fn format_uptime(d: Duration) -> String {
    let total = d.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        total / 3600,
        total % 3600 / 60,
        total % 60
    )
}

/// Time from `since` to `now`; a clock that went backwards reads as zero.
pub fn elapsed(since: UnixMs, now: UnixMs) -> Duration {
    Duration::from_millis(u64::try_from(now.saturating_sub(since)).unwrap_or(0))
}

/// Whole minutes since `ts` (rounded, never negative); `None` when never checked. A zero stamp
/// counts as never checked, as in the old documents.
pub fn minutes_ago(ts: Option<UnixMs>, now: UnixMs) -> Option<u64> {
    let ts = ts.filter(|&t| t != 0)?;
    let minutes = (now.saturating_sub(ts) as f64 / 60_000.0).round();
    Some(minutes.max(0.0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// JS `toFixed` parity, including exact binary ties (0.25, 1.125, 2.5) and values whose
    /// decimal looks like a tie but is not (1.005 is 1.00499…).
    #[test]
    fn to_fixed_matches_javascript() {
        let cases: [(f64, usize, &str); 14] = [
            (0.25, 1, "0.3"),
            (0.35, 1, "0.3"), // 0.34999…
            (1.125, 2, "1.13"),
            (1.005, 2, "1.00"),
            (2.5, 0, "3"),
            (0.0, 1, "0.0"),
            (-0.0, 1, "0.0"),
            (147.0, 1, "147.0"),
            (12.34, 1, "12.3"),
            (99.96, 1, "100.0"),
            (0.044, 2, "0.04"),
            (1.0 / 3.0, 2, "0.33"),
            (-1.25, 1, "-1.3"),
            (-0.04, 1, "-0.0"),
        ];
        for (v, digits, expected) in cases {
            assert_eq!(to_fixed(v, digits), expected, "{v}.toFixed({digits})");
        }
    }

    /// ui-dashboard §3.1 (`Dashboard.tsx:26-53`).
    #[test]
    fn uptime_is_hh_mm_ss_with_uncapped_hours() {
        assert_eq!(format_uptime(Duration::ZERO), "00:00:00");
        assert_eq!(format_uptime(Duration::from_millis(9_999)), "00:00:09");
        assert_eq!(format_uptime(Duration::from_secs(3_725)), "01:02:05");
        assert_eq!(format_uptime(Duration::from_secs(100 * 3600)), "100:00:00");
        assert_eq!(elapsed(1_000, 10_999), Duration::from_millis(9_999));
        assert_eq!(elapsed(10_000, 1_000), Duration::ZERO);
    }

    /// ui-dashboard §2.5 (`SwissPanels.tsx:101-103`): `max(0, round((now - ts) / 60000))`.
    #[test]
    fn minutes_ago_rounds_and_never_goes_negative() {
        let now = 10_000_000;
        assert_eq!(minutes_ago(None, now), None);
        assert_eq!(minutes_ago(Some(0), now), None);
        assert_eq!(minutes_ago(Some(now), now), Some(0));
        assert_eq!(minutes_ago(Some(now - 29_999), now), Some(0));
        assert_eq!(minutes_ago(Some(now - 30_000), now), Some(1));
        assert_eq!(minutes_ago(Some(now - 5 * 60_000), now), Some(5));
        assert_eq!(minutes_ago(Some(now + 120_000), now), Some(0));
    }
}
