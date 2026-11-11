//! Weekly schedule windows: pure algebra over local wall-clock times.
//!
//! Every function takes the zone explicitly (`&TimeZone`), so tests pin New York / Lord Howe /
//! Moscow independent of the host. Local times map to instants with jiff's `Compatible`
//! disambiguation, the JavaScript `Date` behaviour of the old app: a time inside a DST gap moves
//! forward by the gap, a repeated time takes the earlier instant.
use std::fmt;
use std::str::FromStr;

use jiff::Timestamp;
use jiff::ToSpan;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Local time of day, minutes since midnight (`0..=1439`); text form `HH:MM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HhMm(u16);

impl HhMm {
    /// `None` unless `hour <= 23` and `minute <= 59`.
    pub const fn new(hour: u8, minute: u8) -> Option<Self> {
        if hour <= 23 && minute <= 59 {
            Some(HhMm(hour as u16 * 60 + minute as u16))
        } else {
            None
        }
    }

    /// Minutes since midnight.
    pub const fn minutes(self) -> u16 {
        self.0
    }

    /// Hour of day, 0..=23.
    pub const fn hour(self) -> i8 {
        (self.0 / 60) as i8
    }

    /// Minute of the hour, 0..=59.
    pub const fn minute(self) -> i8 {
        (self.0 % 60) as i8
    }

    /// The old app's parser (`split(':')` + `parseInt` per part), kept for stored and imported
    /// values only: `"9:5"` → 09:05, `"09:30abc"` → 09:30, `" 9:05"`, `"-0:00"`, `"1e1:00"` → 01:00.
    pub fn parse_lenient(text: &str) -> Option<Self> {
        let (h, m) = text.split_once(':')?;
        if m.contains(':') {
            return None;
        }
        let hour = u8::try_from(js_parse_int(h)?).ok()?;
        let minute = u8::try_from(js_parse_int(m)?).ok()?;
        Self::new(hour, minute)
    }
}

/// JavaScript `parseInt(s, 10)`: leading whitespace, optional sign, the longest digit prefix.
fn js_parse_int(text: &str) -> Option<i64> {
    let text = text.trim_start();
    let (negative, rest) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    // Saturate: anything this large is out of range for a time anyway.
    let value = rest[..digits].parse::<i64>().unwrap_or(i64::MAX);
    Some(if negative { -value } else { value })
}

/// Strict input form `^([01]?\d|2[0-3]):([0-5]\d)$` (fix S7): `"9:05"` is accepted, `"9:5"`,
/// `"09:30abc"`, `" 9:05"` and `"24:00"` are not.
impl FromStr for HhMm {
    type Err = InvalidTime;

    fn from_str(text: &str) -> Result<Self, InvalidTime> {
        let (h, m) = text.split_once(':').ok_or(InvalidTime)?;
        let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !(1..=2).contains(&h.len()) || m.len() != 2 || !all_digits(h) || !all_digits(m) {
            return Err(InvalidTime);
        }
        let hour = h.parse::<u8>().map_err(|_| InvalidTime)?;
        let minute = m.parse::<u8>().map_err(|_| InvalidTime)?;
        HhMm::new(hour, minute).ok_or(InvalidTime)
    }
}

/// A time of day that is not `H:MM` / `HH:MM` within `00:00..=23:59`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid time of day")]
pub struct InvalidTime;

impl fmt::Display for HhMm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}:{:02}", self.hour(), self.minute())
    }
}

impl Serialize for HhMm {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// Stored values are read with the old lenient rules (a superset of the strict form with the same
/// result for strict input), so a hand-edited `"9:5"` loads as 09:05 instead of failing the file.
impl<'de> Deserialize<'de> for HhMm {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        HhMm::parse_lenient(&text)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid time of day {text:?}")))
    }
}

/// What a schedule turns on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScheduleMode {
    /// Hard TUN through the local proxy.
    Hard,
    /// Soft mode (user-level proxy variables).
    Soft,
    /// Direct VPN through `profile_id`.
    Direct,
}

/// One weekly window: on each of `days` from `start_time` to `end_time` (overnight when
/// `end_time < start_time`, 24 hours when they are equal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleEntry {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// Weekdays of the window's START, 0 = Sunday … 6 = Saturday; sorted, no duplicates.
    pub days: Vec<u8>,
    pub start_time: HhMm,
    pub end_time: HhMm,
    /// Server profile; used only by `Direct` schedules (fix S6).
    #[serde(default)]
    pub profile_id: String,
    pub mode: ScheduleMode,
}

/// One concrete occurrence of an entry: `[start, stop)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub start: Timestamp,
    pub stop: Timestamp,
    /// Index of the entry in the slice it came from.
    pub entry: usize,
}

/// Overlapping or adjacent windows of all entries merged into one protected period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub start: Timestamp,
    pub stop: Timestamp,
    /// Entry of the earliest window (the one that starts the run).
    pub first: usize,
    /// Entry of the window that ends last (the one that ends the run).
    pub last: usize,
}

impl Run {
    /// `start <= t < stop`.
    pub fn contains(&self, t: Timestamp) -> bool {
        self.start <= t && t < self.stop
    }
}

/// The next boundary of the merged runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextEvent {
    Start { at: Timestamp, entry: usize },
    Stop { at: Timestamp, entry: usize },
}

impl NextEvent {
    /// When the boundary happens.
    pub fn at(&self) -> Timestamp {
        match *self {
            NextEvent::Start { at, .. } | NextEvent::Stop { at, .. } => at,
        }
    }
}

/// Days looked at around today when merging runs. Back: a run that started days ago (24-hour
/// windows chained over several days) keeps its real start. Ahead: the old 8-day look-ahead, so
/// truncation at the weekly horizon never invents a stop.
const DAYS_BACK: i32 = 8;
const DAYS_AHEAD: i32 = 8;

/// Windows of `e` that start on the local days `today - 1 ..= today + days_ahead`. Yesterday is
/// included because an overnight window opened yesterday may still be active this morning (F-193).
pub fn windows(
    e: &ScheduleEntry,
    idx: usize,
    tz: &TimeZone,
    now: Timestamp,
    days_ahead: i32,
) -> Vec<Window> {
    windows_between(e, idx, tz, local_date(now, tz), -1, days_ahead)
}

fn windows_between(
    e: &ScheduleEntry,
    idx: usize,
    tz: &TimeZone,
    today: Date,
    from: i32,
    to: i32,
) -> Vec<Window> {
    if !e.enabled || e.days.is_empty() {
        return Vec::new();
    }
    // Equal times mean a 24-hour window (fix S3): the end is the same local time on the next day.
    let ends_next_day = e.start_time >= e.end_time;
    let mut out = Vec::new();
    for offset in from..=to {
        let Ok(day) = today.checked_add(offset.days()) else {
            continue;
        };
        let weekday = u8::try_from(day.weekday().to_sunday_zero_offset());
        if !weekday.is_ok_and(|w| e.days.contains(&w)) {
            continue;
        }
        let stop_day = if ends_next_day {
            day.tomorrow().ok()
        } else {
            Some(day)
        };
        // The end is resolved on its own calendar day: after a DST gap an overnight end keeps
        // its wall-clock time.
        let (Some(start), Some(stop)) = (
            instant(tz, day, e.start_time),
            stop_day.and_then(|d| instant(tz, d, e.end_time)),
        ) else {
            continue;
        };
        if stop > start {
            out.push(Window {
                start,
                stop,
                entry: idx,
            });
        } else {
            tracing::debug!(entry = idx, %day, "schedule window collapsed by a DST change, skipped");
        }
    }
    out
}

fn local_date(t: Timestamp, tz: &TimeZone) -> Date {
    t.to_zoned(tz.clone()).date()
}

fn instant(tz: &TimeZone, day: Date, time: HhMm) -> Option<Timestamp> {
    tz.to_timestamp(day.at(time.hour(), time.minute(), 0, 0))
        .ok()
}

/// `e` has a window containing `t` (`[start, stop)`).
pub fn is_active(e: &ScheduleEntry, tz: &TimeZone, t: Timestamp) -> bool {
    windows(e, 0, tz, t, 0)
        .iter()
        .any(|w| w.start <= t && t < w.stop)
}

/// Indices of the entries active at `t`, in slice order.
pub fn active_entries(entries: &[ScheduleEntry], tz: &TimeZone, t: Timestamp) -> Vec<usize> {
    (0..entries.len())
        .filter(|&i| is_active(&entries[i], tz, t))
        .collect()
}

/// All windows around `now`, sorted by start (stable: entry order, then day), merged while the
/// next window starts at or before the run's stop (overlap and adjacency merge; a gap does not).
fn runs(entries: &[ScheduleEntry], tz: &TimeZone, now: Timestamp) -> Vec<Run> {
    let today = local_date(now, tz);
    let mut all: Vec<Window> = entries
        .iter()
        .enumerate()
        .flat_map(|(i, e)| windows_between(e, i, tz, today, -DAYS_BACK, DAYS_AHEAD))
        .collect();
    all.sort_by_key(|w| w.start);
    let mut out: Vec<Run> = Vec::new();
    for w in all {
        match out.last_mut() {
            Some(run) if w.start <= run.stop => {
                // Strictly later only: on equal stops the earlier window keeps the run's end.
                if w.stop > run.stop {
                    run.stop = w.stop;
                    run.last = w.entry;
                }
            }
            _ => out.push(Run {
                start: w.start,
                stop: w.stop,
                first: w.entry,
                last: w.entry,
            }),
        }
    }
    out
}

/// The merged run containing `now`, if any.
pub fn active_run(entries: &[ScheduleEntry], tz: &TimeZone, now: Timestamp) -> Option<Run> {
    runs(entries, tz, now).into_iter().find(|r| r.contains(now))
}

/// The next start or stop strictly after `now` and before local midnight of today + 8 days.
pub fn next_event(entries: &[ScheduleEntry], tz: &TimeZone, now: Timestamp) -> Option<NextEvent> {
    let horizon_day = local_date(now, tz).checked_add(DAYS_AHEAD.days()).ok()?;
    let horizon = instant(tz, horizon_day, HhMm(0))?;
    for run in runs(entries, tz, now) {
        if run.start > now && run.start < horizon {
            return Some(NextEvent::Start {
                at: run.start,
                entry: run.first,
            });
        }
        if run.stop > now && run.stop < horizon {
            return Some(NextEvent::Stop {
                at: run.stop,
                entry: run.last,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests;
