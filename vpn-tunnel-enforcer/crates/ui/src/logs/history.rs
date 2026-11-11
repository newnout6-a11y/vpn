//! Pure history logic of the page: what counts as a session, the outcome shown for old rows,
//! filters with local-day bounds, sorting, period stats (ui-pages §3.9, lifecycle-app §3.23).
use std::cmp::Ordering;
use std::collections::BTreeSet;

use jiff::civil::Date;
use jiff::tz::TimeZone;
use vpnte_base::types::UnixMs;

use super::model::{DisconnectReason, OutcomeKind, SessionRow, Text};
use crate::lang::Lang;

/// A session shorter than this, without traffic and ended by an error, never came up (rows
/// written before outcomes existed have no `start-failed` kind).
pub const START_FAILURE_MAX_MS: u64 = 1000;

/// Elapsed time of an ended session: the monotonic duration when recorded, else end − start
/// ("calendar dates may jump"); 0 while running.
pub fn connection_duration_ms(row: &SessionRow) -> u64 {
    match row.ended_at {
        None => 0,
        Some(end) => row
            .duration_ms
            .unwrap_or_else(|| u64::try_from(end.saturating_sub(row.started_at)).unwrap_or(0)),
    }
}

/// An attempt that never reached a working tunnel: listed apart from the sessions.
pub fn is_start_failure(row: &SessionRow) -> bool {
    if let Some(outcome) = &row.outcome {
        return outcome.kind == OutcomeKind::StartFailed;
    }
    row.ended_at.is_some()
        && connection_duration_ms(row) < START_FAILURE_MAX_MS
        && row.bytes_down == 0
        && row.bytes_up == 0
        && row.reason == DisconnectReason::Error
}

/// Outcome kind shown for a row without an outcome.
pub fn legacy_kind(reason: DisconnectReason) -> OutcomeKind {
    match reason {
        DisconnectReason::User => OutcomeKind::UserStop,
        DisconnectReason::Rotation => OutcomeKind::Rotation,
        DisconnectReason::Schedule => OutcomeKind::Schedule,
        DisconnectReason::Crash => OutcomeKind::Killswitch,
        DisconnectReason::Error => OutcomeKind::Unknown,
    }
}

/// The outcome kind of the chip.
pub fn shown_kind(row: &SessionRow) -> OutcomeKind {
    row.outcome
        .as_ref()
        .map_or_else(|| legacy_kind(row.reason), |o| o.kind)
}

/// The chip of a row: none while a session without an outcome is still running (the old table
/// showed «Вы отключили» on the live row).
pub fn chip_kind(row: &SessionRow) -> Option<OutcomeKind> {
    (row.ended_at.is_some() || row.outcome.is_some()).then(|| shown_kind(row))
}

/// The headline: the outcome's, else the stored message, else the chip label.
pub fn shown_headline(row: &SessionRow) -> Text {
    if let Some(outcome) = &row.outcome {
        return outcome.headline.clone();
    }
    match non_empty(row.error_message.as_deref()) {
        Some(message) => Text::Plain(message.to_owned()),
        None => Text::Msg(legacy_kind(row.reason).label()),
    }
}

/// The stored technical message, when it says more than the headline (the old detail never
/// showed it for rows with an outcome).
pub fn extra_message<'a>(row: &'a SessionRow, headline: &str) -> Option<&'a str> {
    non_empty(row.error_message.as_deref()).filter(|m| m.trim() != headline.trim())
}

pub(crate) fn non_empty(text: Option<&str>) -> Option<&str> {
    text.filter(|t| !t.trim().is_empty())
}

/// Sessions and start failures, each in the given order.
pub fn split<'a>(
    rows: impl IntoIterator<Item = &'a SessionRow>,
) -> (Vec<&'a SessionRow>, Vec<&'a SessionRow>) {
    rows.into_iter().partition(|row| !is_start_failure(row))
}

/// The on-screen filters (the export ignores them).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Filters {
    /// Empty = every reason.
    pub reasons: BTreeSet<DisconnectReason>,
    /// First local day, inclusive.
    pub from: Option<Date>,
    /// Last local day, inclusive.
    pub to: Option<Date>,
    pub text: String,
}

impl Filters {
    pub fn is_empty(&self) -> bool {
        self.reasons.is_empty()
            && self.from.is_none()
            && self.to.is_none()
            && self.text.trim().is_empty()
    }
}

/// Start of local day `day` in `tz`, in Unix ms (fixes the old UTC-midnight parse, U-11).
pub fn day_start(day: Date, tz: &TimeZone) -> Option<UnixMs> {
    day.to_zoned(tz.clone())
        .ok()
        .map(|z| z.timestamp().as_millisecond())
}

/// Last millisecond of local day `day` in `tz`.
pub fn day_end(day: Date, tz: &TimeZone) -> Option<UnixMs> {
    let next = day.tomorrow().ok()?;
    day_start(next, tz).map(|start| start - 1)
}

/// [`Filters`] resolved for matching: local-day bounds in ms, the lower-cased search text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    reasons: BTreeSet<DisconnectReason>,
    from: Option<UnixMs>,
    to: Option<UnixMs>,
    text: String,
    lang: Lang,
}

impl Query {
    pub fn new(filters: &Filters, tz: &TimeZone, lang: Lang) -> Self {
        Self {
            reasons: filters.reasons.clone(),
            from: filters.from.and_then(|d| day_start(d, tz)),
            to: filters.to.and_then(|d| day_end(d, tz)),
            text: filters.text.trim().to_lowercase(),
            lang,
        }
    }

    /// AND of reason ∈ reasons, start ≥ from, start ≤ to, and the text found in what the row
    /// shows: profile, mode, reason, stored message, outcome kind, chip label, headline.
    pub fn matches(&self, row: &SessionRow) -> bool {
        if !self.reasons.is_empty() && !self.reasons.contains(&row.reason) {
            return false;
        }
        if self.from.is_some_and(|from| row.started_at < from)
            || self.to.is_some_and(|to| row.started_at > to)
        {
            return false;
        }
        if self.text.is_empty() {
            return true;
        }
        let (kind, label, headline) = match chip_kind(row) {
            Some(kind) => (
                kind.key(),
                kind.label().render(self.lang),
                shown_headline(row).render(self.lang),
            ),
            None => ("", String::new(), String::new()),
        };
        let haystack = [
            row.profile_name.as_str(),
            row.mode.key(),
            row.reason.key(),
            row.error_message.as_deref().unwrap_or(""),
            kind,
            &label,
            &headline,
        ]
        .join(" ")
        .to_lowercase();
        haystack.contains(&self.text)
    }
}

/// A sortable column of the history table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    Profile,
    Mode,
    Started,
    Ended,
    Duration,
    Traffic,
    /// The outcome chip (sorted by its label as shown).
    Outcome,
}

/// Column and direction; `descending` first for every column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortState {
    pub field: SortField,
    pub descending: bool,
}

impl Default for SortState {
    fn default() -> Self {
        Self {
            field: SortField::Started,
            descending: true,
        }
    }
}

impl SortState {
    /// The same header flips the direction; another header sorts by it, descending.
    pub fn toggle(self, field: SortField) -> Self {
        if self.field == field {
            Self {
                field,
                descending: !self.descending,
            }
        } else {
            Self {
                field,
                descending: true,
            }
        }
    }
}

/// Sorts rows by `sort`; ties keep the newest first.
pub fn sort_rows(rows: &mut [&SessionRow], sort: SortState, lang: Lang) {
    let text = |a: &str, b: &str| a.to_lowercase().cmp(&b.to_lowercase());
    rows.sort_by(|a, b| {
        let primary = match sort.field {
            SortField::Profile => text(&a.profile_name, &b.profile_name),
            SortField::Mode => a.mode.key().cmp(b.mode.key()),
            SortField::Started => a.started_at.cmp(&b.started_at),
            SortField::Ended => a.ended_at.unwrap_or(0).cmp(&b.ended_at.unwrap_or(0)),
            SortField::Duration => connection_duration_ms(a).cmp(&connection_duration_ms(b)),
            SortField::Traffic => traffic(a).cmp(&traffic(b)),
            SortField::Outcome => text(&chip_label(a, lang), &chip_label(b, lang)),
        };
        let primary = if sort.descending {
            primary.reverse()
        } else {
            primary
        };
        primary
            .then_with(|| b.started_at.cmp(&a.started_at))
            .then_with(|| a.id.cmp(&b.id))
    });
}

fn chip_label(row: &SessionRow, lang: Lang) -> String {
    chip_kind(row)
        .map(|k| k.label().render(lang))
        .unwrap_or_default()
}

fn traffic(row: &SessionRow) -> u64 {
    row.bytes_down.saturating_add(row.bytes_up)
}

/// Window of the stats card, back from now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Period {
    #[default]
    Day,
    Week,
    Month,
}

impl Period {
    pub const ALL: [Period; 3] = [Period::Day, Period::Week, Period::Month];
    pub fn window_ms(self) -> i64 {
        const DAY: i64 = 86_400_000;
        match self {
            Period::Day => DAY,
            Period::Week => 7 * DAY,
            Period::Month => 30 * DAY,
        }
    }
    pub fn label_key(self) -> &'static str {
        match self {
            Period::Day => "logs.periodDay",
            Period::Week => "logs.periodWeek",
            Period::Month => "logs.periodMonth",
        }
    }
}

/// Totals of the stats card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Σ elapsed time of the ended sessions.
    pub total_time_ms: u64,
    pub bytes_down: u64,
    pub bytes_up: u64,
    pub sessions: usize,
}

/// Stats of the sessions started within `period` before `now`. Start failures are not
/// connections and are left out, by the same rule as the table (the old card only dropped
/// `start-failed`, so old "never came up" rows still counted there).
pub fn stats(rows: &[SessionRow], period: Period, now: UnixMs) -> Stats {
    let since = now - period.window_ms();
    rows.iter()
        .filter(|row| row.started_at >= since && !is_start_failure(row))
        .fold(Stats::default(), |mut acc, row| {
            if row.ended_at.is_some() {
                acc.total_time_ms += connection_duration_ms(row);
            }
            acc.bytes_down = acc.bytes_down.saturating_add(row.bytes_down);
            acc.bytes_up = acc.bytes_up.saturating_add(row.bytes_up);
            acc.sessions += 1;
            acc
        })
}

/// Total order helper for callers that sort failures the same way as sessions.
pub fn newest_first(a: &&SessionRow, b: &&SessionRow) -> Ordering {
    b.started_at
        .cmp(&a.started_at)
        .then_with(|| a.id.cmp(&b.id))
}
