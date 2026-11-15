//! Queries and exports over the rows: filter, period statistics, CSV and JSON.
use super::*;

/// What the history page asks for; every set condition must hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// Coarse reasons to show; empty = all.
    pub levels: Vec<DisconnectReason>,
    /// Inclusive bounds on `started_at`.
    pub date_from: Option<UnixMs>,
    pub date_to: Option<UnixMs>,
    /// Case-insensitive substring of profile name, mode, reason, kind and the rendered messages.
    pub text: Option<String>,
}

/// Rows matching `filter`, in order. Messages are searched as the user reads them (`lang`).
pub fn filter<'a>(
    entries: impl IntoIterator<Item = &'a Entry>,
    filter: &Filter,
    lang: Lang,
) -> Vec<Entry> {
    let needle = filter
        .text
        .as_deref()
        .filter(|t| !t.is_empty())
        .map(str::to_lowercase);
    entries
        .into_iter()
        .filter(|e| filter.levels.is_empty() || filter.levels.contains(&e.disconnect_reason))
        .filter(|e| filter.date_from.is_none_or(|from| e.started_at >= from))
        .filter(|e| filter.date_to.is_none_or(|to| e.started_at <= to))
        .filter(|e| {
            needle
                .as_deref()
                .is_none_or(|needle| haystack(e, lang).contains(needle))
        })
        .cloned()
        .collect()
}

fn haystack(e: &Entry, lang: Lang) -> String {
    let message = |m: Option<&Msg>| m.map(|m| outcome::render(m, lang)).unwrap_or_default();
    let outcome = e.outcome.as_ref();
    [
        e.profile_name.clone(),
        e.mode.as_str().to_owned(),
        e.disconnect_reason.as_str().to_owned(),
        message(e.error_message.as_ref()),
        outcome.map_or("", |o| o.kind.as_str()).to_owned(),
        message(outcome.map(|o| &o.headline)),
    ]
    .join(" ")
    .to_lowercase()
}

/// Statistics window, back from "now" on `started_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Period {
    Day,
    Week,
    Month,
}

impl Period {
    /// Window length: 1, 7 or 30 days.
    pub fn window_ms(self) -> i64 {
        const DAY: i64 = 86_400_000;
        match self {
            Period::Day => DAY,
            Period::Week => 7 * DAY,
            Period::Month => 30 * DAY,
        }
    }
}

/// Totals over the connections of one period.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    /// Sum of the durations of finished sessions.
    pub total_time_ms: u64,
    pub total_bytes_down: u64,
    pub total_bytes_up: u64,
    pub entry_count: usize,
}

/// Totals of the rows started within `period` before `now`. Starts that never came up are not
/// connections and stay out (zero-duration noise).
pub fn stats<'a>(
    entries: impl IntoIterator<Item = &'a Entry>,
    period: Period,
    now: UnixMs,
) -> Stats {
    let cutoff = now.saturating_sub(period.window_ms());
    entries
        .into_iter()
        .filter(|e| e.started_at >= cutoff)
        .filter(|e| !e.outcome.as_ref().is_some_and(|o| o.kind.never_connected()))
        .fold(Stats::default(), |mut s, e| {
            s.total_time_ms = s.total_time_ms.saturating_add(e.connection_ms());
            s.total_bytes_down = s.total_bytes_down.saturating_add(e.bytes_down);
            s.total_bytes_up = s.total_bytes_up.saturating_add(e.bytes_up);
            s.entry_count += 1;
            s
        })
}

/// Header line of the CSV export (18 columns, the Electron order).
pub const CSV_HEADER: &str = "id,startedAt,endedAt,profileName,profileId,mode,bytesDown,bytesUp,\
disconnectReason,errorMessage,outcomeKind,outcomeHeadline,correlationId,source,owner,route,\
confidence,durationMs";

/// The rows as CSV: header, then one line per row joined with `\n` (no trailing newline).
/// Messages are rendered in `lang`.
pub fn to_csv<'a>(entries: impl IntoIterator<Item = &'a Entry>, lang: Lang) -> String {
    let mut out = String::from(CSV_HEADER);
    for e in entries {
        let message = |m: Option<&Msg>| m.map(|m| outcome::render(m, lang)).unwrap_or_default();
        let kind = e.outcome.as_ref().map(|o| o.kind.as_str());
        let prov = e.provenance.as_ref();
        let cells = [
            cell(&e.id),
            e.started_at.to_string(),
            e.ended_at.map(|t| t.to_string()).unwrap_or_default(),
            cell(&e.profile_name),
            cell(&e.profile_id),
            e.mode.as_str().to_owned(),
            e.bytes_down.to_string(),
            e.bytes_up.to_string(),
            e.disconnect_reason.as_str().to_owned(),
            cell(&message(e.error_message.as_ref())),
            cell(kind.unwrap_or_default()),
            cell(&message(e.outcome.as_ref().map(|o| &o.headline))),
            cell(e.correlation_id.as_ref().map_or("", CorrelationId::as_str)),
            prov.map_or("", |p| source_str(p.source)).to_owned(),
            prov.map_or("", |p| owner_str(p.owner)).to_owned(),
            prov.map_or("", |p| p.route.as_str()).to_owned(),
            prov.map_or("", |p| p.confidence.as_str()).to_owned(),
            e.duration_ms.map(|d| d.to_string()).unwrap_or_default(),
        ];
        out.push('\n');
        out.push_str(&cells.join(","));
    }
    out
}

/// A text cell. Provider-chosen names and engine text reach spreadsheets: a leading `=`, `+`,
/// `-`, `@`, TAB or CR would start a formula, so it gets a `'` (OWASP CSV-injection rule, L-19).
/// Values with `,`, `"`, CR or LF are quoted with inner quotes doubled.
pub(super) fn cell(value: &str) -> String {
    let value: Cow<'_, str> = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}").into()
    } else {
        value.into()
    };
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.into_owned()
    }
}

/// The rows as pretty JSON in the Electron export shape: messages become text in `lang`, so the
/// file reads without the app and imports back through the same reader.
pub fn to_json<'a>(entries: impl IntoIterator<Item = &'a Entry>, lang: Lang) -> AppResult<String> {
    let text = |m: &Msg| Value::String(outcome::render(m, lang));
    let mut rows = Vec::new();
    for e in entries {
        let mut row = serde_json::to_value(e).map_err(AppError::internal)?;
        let mut set = |pointer: &str, value: Value| {
            if let Some(slot) = row.pointer_mut(pointer) {
                *slot = value;
            }
        };
        if let Some(m) = &e.error_message {
            set("/errorMessage", text(m));
        }
        if let Some(o) = &e.outcome {
            set("/outcome/headline", text(&o.headline));
            if let Some(hint) = &o.evidence.hint {
                set("/outcome/evidence/hint", text(hint));
            }
        }
        rows.push(row);
    }
    serde_json::to_string_pretty(&rows).map_err(AppError::internal)
}
