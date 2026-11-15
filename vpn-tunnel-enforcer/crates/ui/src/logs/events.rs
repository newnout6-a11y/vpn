//! The «События» tab's model and rules: one timeline of what happened, in the user's language
//! (the app's event journal: notices, session starts and ends, warnings that passed silently).
use jiff::civil::Date;
use jiff::tz::TimeZone;
use vpnte_base::Msg;
use vpnte_base::types::{Engine, UnixMs};

use super::format::{duration_msg, local_date, local_time};
use super::model::{Mode, OutcomeKind, Text};
use crate::servers::engine_name;

/// Events rendered at most (the newest that match); the journal itself keeps more.
pub const EVENTS_SHOWN: usize = 500;

/// What an event is about (the filter chips).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Topic {
    Connection,
    Protection,
    Automation,
    Update,
    Other,
}

/// The status dot of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventLevel {
    Ok,
    Info,
    Warn,
    Error,
}

impl EventLevel {
    /// Wire name (`ok`): the dot's `data-level`.
    pub fn key(self) -> &'static str {
        match self {
            EventLevel::Ok => "ok",
            EventLevel::Info => "info",
            EventLevel::Warn => "warn",
            EventLevel::Error => "error",
        }
    }
}

/// Facts of a session start or end, shown on expand.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionFacts {
    pub profile: String,
    pub mode: Mode,
    /// `None` on a start.
    pub duration_ms: Option<u64>,
    pub bytes_down: u64,
    pub bytes_up: u64,
    pub engine: Option<Engine>,
    /// How it ended (`None` on a start).
    pub outcome: Option<OutcomeKind>,
}

/// One event of the journal.
#[derive(Debug, Clone, PartialEq)]
pub struct EventRow {
    /// Stable key (the journal's sequence number).
    pub id: u64,
    pub at: UnixMs,
    pub topic: Topic,
    pub level: EventLevel,
    /// The one line.
    pub title: Text,
    /// More of it, on expand.
    pub body: Option<Text>,
    pub session: Option<SessionFacts>,
}

/// The filter chips: a topic, or every error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum EventFilter {
    #[default]
    All,
    Connections,
    Protection,
    Automation,
    Updates,
    Errors,
}

impl EventFilter {
    pub const ALL: [EventFilter; 6] = [
        EventFilter::All,
        EventFilter::Connections,
        EventFilter::Protection,
        EventFilter::Automation,
        EventFilter::Updates,
        EventFilter::Errors,
    ];

    /// Chip label key (`logs.events.filter.all`).
    pub fn label_key(self) -> &'static str {
        match self {
            EventFilter::All => "logs.events.filter.all",
            EventFilter::Connections => "logs.events.filter.connections",
            EventFilter::Protection => "logs.events.filter.protection",
            EventFilter::Automation => "logs.events.filter.automation",
            EventFilter::Updates => "logs.events.filter.updates",
            EventFilter::Errors => "logs.events.filter.errors",
        }
    }

    pub fn keeps(self, row: &EventRow) -> bool {
        match self {
            EventFilter::All => true,
            EventFilter::Connections => row.topic == Topic::Connection,
            EventFilter::Protection => row.topic == Topic::Protection,
            EventFilter::Automation => row.topic == Topic::Automation,
            EventFilter::Updates => row.topic == Topic::Update,
            EventFilter::Errors => row.level == EventLevel::Error,
        }
    }
}

/// The tab's chip and search (kept across visits of the page).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventQuery {
    pub filter: EventFilter,
    pub text: String,
}

impl EventQuery {
    /// The chip keeps the row and the search (case-insensitive) finds it in the shown title,
    /// details or profile name; `tr` renders catalog messages.
    pub fn matches(&self, row: &EventRow, tr: &dyn Fn(&Msg) -> String) -> bool {
        if !self.filter.keeps(row) {
            return false;
        }
        let needle = self.text.trim().to_lowercase();
        if needle.is_empty() {
            return true;
        }
        let mut hay = row.title.render_with(tr);
        if let Some(body) = &row.body {
            hay.push(' ');
            hay.push_str(&body.render_with(tr));
        }
        if let Some(session) = &row.session {
            hay.push(' ');
            hay.push_str(&session.profile);
        }
        hay.to_lowercase().contains(&needle)
    }
}

/// The matching rows, newest first, at most [`EVENTS_SHOWN`]; `true` when more matched.
pub fn shown_events<'a>(
    rows: &'a [EventRow],
    query: &EventQuery,
    tr: &dyn Fn(&Msg) -> String,
) -> (Vec<&'a EventRow>, bool) {
    let mut matched: Vec<&EventRow> = rows.iter().filter(|r| query.matches(r, tr)).collect();
    matched.sort_by(|a, b| b.at.cmp(&a.at).then(b.id.cmp(&a.id)));
    let more = matched.len() > EVENTS_SHOWN;
    matched.truncate(EVENTS_SHOWN);
    (matched, more)
}

/// The header of a day group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Day {
    Today,
    Yesterday,
    On(Date),
}

impl Day {
    /// The local day of `at` as seen at `now` in `tz`.
    pub fn of(at: UnixMs, now: UnixMs, tz: &TimeZone) -> Day {
        let day = local_date(at, tz).unwrap_or_default();
        let today = local_date(now, tz).unwrap_or_default();
        if day == today {
            Day::Today
        } else if today.yesterday().is_ok_and(|y| y == day) {
            Day::Yesterday
        } else {
            Day::On(day)
        }
    }

    /// «Сегодня», «Вчера», «12 нояб.» (`tr` renders catalog messages).
    pub fn label(self, tr: &dyn Fn(&Msg) -> String) -> String {
        match self {
            Day::Today => tr(&Msg::new("logs.events.today")),
            Day::Yesterday => tr(&Msg::new("logs.events.yesterday")),
            Day::On(date) => {
                let month = tr(&Msg::new(format!("logs.month.{}", date.month())));
                tr(&Msg::new("logs.events.day")
                    .arg("day", date.day())
                    .arg("month", month))
            }
        }
    }
}

/// Rows (newest first) split into day groups, in the same order.
pub fn by_day<'a>(
    rows: Vec<&'a EventRow>,
    now: UnixMs,
    tz: &TimeZone,
) -> Vec<(Day, Vec<&'a EventRow>)> {
    let mut groups: Vec<(Day, Vec<&EventRow>)> = Vec::new();
    for row in rows {
        let day = Day::of(row.at, now, tz);
        match groups.last_mut() {
            Some((last, members)) if *last == day => members.push(row),
            _ => groups.push((day, vec![row])),
        }
    }
    groups
}

/// The facts of a session event as shown lines (mode, duration, traffic, engine, outcome);
/// `bytes` formats a size (the page passes `units::format_bytes`).
pub fn facts(
    session: &SessionFacts,
    tr: &dyn Fn(&Msg) -> String,
    bytes: &dyn Fn(u64) -> String,
) -> Vec<String> {
    let mut lines = vec![tr(&Msg::new("logs.events.fact.mode")
        .arg("profile", &session.profile)
        .arg("mode", tr(&Msg::new(session.mode.label_key()))))];
    if let Some(duration) = session.duration_ms.and_then(duration_msg) {
        lines.push(tr(
            &Msg::new("logs.events.fact.duration").arg("duration", tr(&duration))
        ));
    }
    if session.duration_ms.is_some() {
        lines.push(tr(&Msg::new("logs.events.fact.traffic")
            .arg("down", bytes(session.bytes_down))
            .arg("up", bytes(session.bytes_up))));
    }
    if let Some(engine) = session.engine {
        lines.push(tr(
            &Msg::new("logs.events.fact.engine").arg("engine", engine_name(engine))
        ));
    }
    if let Some(kind) = session.outcome {
        lines.push(tr(
            &Msg::new("logs.events.fact.outcome").arg("outcome", tr(&kind.label()))
        ));
    }
    lines
}

/// The event's one line: its title, and for a session end how it ended («Отключено ·
/// Нидерланды — Сервер недоступен»).
pub fn line_text(row: &EventRow, tr: &dyn Fn(&Msg) -> String) -> String {
    let title = row.title.render_with(tr);
    match row.session.as_ref().and_then(|s| s.outcome) {
        Some(kind) if kind != OutcomeKind::StartFailed => {
            format!("{title} — {}", tr(&kind.label()))
        }
        _ => title,
    }
}

/// The copied text of one event: local date and time, the line, then its details.
pub fn event_text(
    row: &EventRow,
    tz: &TimeZone,
    tr: &dyn Fn(&Msg) -> String,
    bytes: &dyn Fn(u64) -> String,
) -> String {
    let date = local_date(row.at, tz)
        .map(|d| d.to_string())
        .unwrap_or_default();
    let time = local_time(row.at, tz).unwrap_or_default();
    let mut lines = vec![format!("{date} {time} · {}", line_text(row, tr))];
    if let Some(body) = &row.body {
        lines.push(body.render_with(tr));
    }
    if let Some(session) = &row.session {
        lines.extend(facts(session, tr, bytes));
    }
    lines.join("\n")
}
