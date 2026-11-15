//! Journal records -> the page's `EventRow` (display data only).
use vpnte_ui::logs::{EventLevel, EventRow, SessionFacts, Topic};

use super::rows;
use crate::svc_journal::{Record, Tone, Topic as RecordTopic};

/// One event as the «События» tab shows it. Messages stay messages (re-rendered on a
/// language switch); verbatim text stays text.
pub fn row(r: &Record) -> EventRow {
    EventRow {
        id: r.seq,
        at: r.at,
        topic: match r.topic {
            RecordTopic::Connection => Topic::Connection,
            RecordTopic::Protection => Topic::Protection,
            RecordTopic::Automation => Topic::Automation,
            RecordTopic::Update => Topic::Update,
            RecordTopic::Other => Topic::Other,
        },
        level: match r.tone {
            Tone::Ok => EventLevel::Ok,
            Tone::Info => EventLevel::Info,
            Tone::Warn => EventLevel::Warn,
            Tone::Error => EventLevel::Error,
        },
        title: rows::text(&r.title),
        body: r.body.as_ref().map(rows::text),
        session: r.session.as_ref().map(|s| SessionFacts {
            profile: s.profile.clone(),
            mode: rows::mode(s.mode),
            duration_ms: s.duration_ms,
            bytes_down: s.bytes_down,
            bytes_up: s.bytes_up,
            engine: s.engine,
            outcome: s.outcome.map(rows::kind),
        }),
    }
}
