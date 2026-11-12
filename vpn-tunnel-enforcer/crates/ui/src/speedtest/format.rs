//! Pure text rules of the Speed test page; the page passes the `Lang` it read from `LANG`.
use jiff::tz::TimeZone;
use vpnte_base::i18n::Lang;
use vpnte_base::types::UnixMs;

use super::model::{Egress, SpeedPhase};
use crate::availability::{text, text_with};
use crate::widgets::Tone;

/// A speed for display, three significant figures: two decimals below 10 Mbit/s, one below 100,
/// none above, trailing zeros kept so a column of results reads in one format («5.10», «76.0»,
/// «87.4», «413»). Not finite or negative reads as «0».
pub fn fmt_mbps(mbps: f64) -> String {
    if !mbps.is_finite() || mbps <= 0.0 {
        return "0".to_owned();
    }
    let decimals = if mbps < 10.0 {
        2
    } else if mbps < 100.0 {
        1
    } else {
        0
    };
    format!("{mbps:.decimals$}")
}

/// «11 нояб., 12:09» / «Nov 11, 12:09» in `tz` (the old `toLocaleString` with month short, day,
/// hour, minute; 24-hour clock in both languages).
pub fn format_date_time(lang: Lang, ts: UnixMs, tz: &TimeZone) -> String {
    let Ok(at) = jiff::Timestamp::from_millisecond(ts) else {
        return "—".to_owned();
    };
    let at = at.to_zoned(tz.clone());
    let months = text(lang, "ui.speedTest.months");
    let month = usize::try_from(at.month() - 1)
        .ok()
        .and_then(|i| months.split(' ').nth(i))
        .unwrap_or_default()
        .to_owned();
    let time = format!("{:02}:{:02}", at.hour(), at.minute());
    text_with(
        lang,
        "ui.speedTest.dateTime",
        &[
            ("day", at.day().to_string()),
            ("month", month),
            ("time", time),
        ],
    )
}

/// Label key of a running phase.
pub fn phase_key(phase: SpeedPhase) -> &'static str {
    match phase {
        SpeedPhase::Latency => "speedTest.phaseLatency",
        SpeedPhase::Download => "speedTest.phaseDownload",
        SpeedPhase::Upload => "speedTest.phaseUpload",
        SpeedPhase::Complete => "speedTest.phaseComplete",
    }
}

/// What the result says about the exit IP: sentence key, short history mark key and tone.
/// `Match` says nothing (the figures describe the tunnel).
pub fn egress_look(egress: Egress) -> Option<(&'static str, &'static str, Tone)> {
    match egress {
        Egress::Match => None,
        Egress::Changed { .. } => Some((
            "speedTest.egressMismatch",
            "ui.speedTest.markChanged",
            Tone::Warn,
        )),
        Egress::Direct { .. } => Some((
            "ui.speedTest.egressDirect",
            "ui.speedTest.markDirect",
            Tone::Fail,
        )),
        Egress::NotChecked => Some((
            "ui.speedTest.egressNotChecked",
            "ui.speedTest.markNotChecked",
            Tone::Unknown,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One format per magnitude (unslop: numbers in one format): «76.0» next to «87.4», not «76».
    #[test]
    fn speeds_keep_meaningful_digits() {
        assert_eq!(fmt_mbps(87.4), "87.4");
        assert_eq!(fmt_mbps(76.0), "76.0");
        assert_eq!(fmt_mbps(92.13), "92.1");
        assert_eq!(fmt_mbps(5.10), "5.10");
        assert_eq!(fmt_mbps(0.456), "0.46");
        assert_eq!(fmt_mbps(412.7), "413");
        assert_eq!(fmt_mbps(f64::NAN), "0");
        assert_eq!(fmt_mbps(-1.0), "0");
    }

    /// The old `toLocaleString({month:'short', day:'numeric', hour, minute})` shape per language.
    #[test]
    fn date_time_is_short_and_local() {
        crate::test_locales::init_locales();
        let (ru, en) = (Lang::Ru, Lang::En);
        // 2026-11-11 09:05:00 UTC
        let ts = 1_794_387_900_000;
        assert_eq!(format_date_time(ru, ts, &TimeZone::UTC), "11 нояб., 09:05");
        assert_eq!(format_date_time(en, ts, &TimeZone::UTC), "Nov 11, 09:05");
        let msk = TimeZone::fixed(jiff::tz::offset(3));
        assert_eq!(format_date_time(ru, ts, &msk), "11 нояб., 12:05");
        assert_eq!(
            format_date_time(ru, 1_778_198_400_000, &TimeZone::UTC),
            "8 мая, 00:00"
        );
    }

    /// Owner §10.5 B: a changed exit is a warning, a test past the tunnel is a failure mark, an
    /// unchecked exit is "not checked" (never silence that reads as fine), a match says nothing.
    #[test]
    fn egress_marks() {
        use std::net::{IpAddr, Ipv4Addr};
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        assert_eq!(egress_look(Egress::Match), None);
        assert_eq!(
            egress_look(Egress::Changed { seen: None }).map(|l| l.2),
            Some(Tone::Warn)
        );
        assert_eq!(
            egress_look(Egress::Direct { seen: ip }).map(|l| l.2),
            Some(Tone::Fail)
        );
        assert_eq!(
            egress_look(Egress::NotChecked).map(|l| l.2),
            Some(Tone::Unknown)
        );
        assert_eq!(
            egress_look(Egress::Changed { seen: Some(ip) }).map(|l| l.0),
            Some("speedTest.egressMismatch")
        );
    }
}
