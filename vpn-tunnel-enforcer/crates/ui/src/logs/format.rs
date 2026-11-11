//! Display formats of the page: durations, local dates and times (ui-pages §3.18); sizes use the
//! shared [`crate::units::format_bytes`]. Unit words of durations and month names come from the
//! catalog.
use jiff::Timestamp;
use jiff::tz::TimeZone;
use vpnte_base::Msg;
use vpnte_base::types::UnixMs;

/// `1h 5m` / `3m 0s` / `59s` as a message (`logs.duration.{hm,ms,s}`); `None` for zero, shown
/// as «—».
pub fn duration_msg(ms: u64) -> Option<Msg> {
    if ms == 0 {
        return None;
    }
    let total = ms / 1000;
    let (h, m, s) = (total / 3600, total / 60 % 60, total % 60);
    Some(if h > 0 {
        Msg::new("logs.duration.hm").arg("h", h).arg("m", m)
    } else if m > 0 {
        Msg::new("logs.duration.ms").arg("m", m).arg("s", s)
    } else {
        Msg::new("logs.duration.s").arg("s", s)
    })
}

/// A moment split for display in `tz`: day of month, month 1–12, `HH:MM`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DateParts {
    pub day: i8,
    pub month: i8,
    pub time: String,
}

/// Local day, month and `HH:MM` of `ms` in `tz` (the old `toLocaleString(month short, day,
/// hour, minute)`; 24-hour clock in both languages, like the shell clock).
pub fn date_parts(ms: UnixMs, tz: &TimeZone) -> Option<DateParts> {
    let zoned = Timestamp::from_millisecond(ms).ok()?.to_zoned(tz.clone());
    Some(DateParts {
        day: zoned.day(),
        month: zoned.month(),
        time: format!("{:02}:{:02}", zoned.hour(), zoned.minute()),
    })
}

/// `HH:MM:SS` of `ms` in `tz` (journal lines).
pub fn local_time(ms: UnixMs, tz: &TimeZone) -> Option<String> {
    let zoned = Timestamp::from_millisecond(ms).ok()?.to_zoned(tz.clone());
    Some(format!(
        "{:02}:{:02}:{:02}",
        zoned.hour(),
        zoned.minute(),
        zoned.second()
    ))
}

/// The local calendar date of `ms` in `tz` (export file name).
pub fn local_date(ms: UnixMs, tz: &TimeZone) -> Option<jiff::civil::Date> {
    Some(
        Timestamp::from_millisecond(ms)
            .ok()?
            .to_zoned(tz.clone())
            .date(),
    )
}

/// `2026-11-11T08:00:00.000Z` (copied diagnostics; the old `toISOString()`).
pub fn iso_utc(ms: UnixMs) -> String {
    Timestamp::from_millisecond(ms).map_or_else(
        |_| ms.to_string(),
        |ts| ts.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
    )
}
