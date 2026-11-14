//! The «Журнал» page (owner, 13.11.2026: «бесполезный раздел, логи без логов»): three tabs.
//! «События» — one timeline of what happened, in the user's language (the app's event journal);
//! «Подключения» — the sessions table with filters, stats and the CSV / JSON export;
//! «Технический» — the app, engine and helper-service logs for support. Each tab has its own
//! «Очистить»; «Сохранить для поддержки» packs the Maintenance page's diagnostics ZIP.
//!
//! Data and actions come from a [`LogsApi`] in context (`Rc<dyn LogsApi>`); the app implements
//! it over the backend, [`demo::DemoLogs`] fakes it. Register the page with
//! `registry.register(Page::Logs, LogsPage)`. It is an active-only page; the tab and the filters
//! are remembered across visits ([`PageState`]).
mod clear;
mod connections;
pub mod demo;
mod events;
mod events_view;
mod format;
mod history;
mod journal;
mod model;
mod page;
mod report;
mod state;
mod table;
#[cfg(test)]
mod tests;
mod viewer;

use std::rc::Rc;

use crate::hooks::use_watch;
use crate::lang::tr_now;
use dioxus::prelude::*;

pub use events::{
    Day, EVENTS_SHOWN, EventFilter, EventLevel, EventQuery, EventRow, SessionFacts, Topic, by_day,
    event_text, facts, line_text, shown_events,
};
pub use format::{DateParts, date_parts, duration_msg, iso_utc, local_date, local_time};
pub use history::{
    Filters, Period, Query, START_FAILURE_MAX_MS, SortField, SortState, Stats, chip_kind,
    connection_duration_ms, day_end, day_start, extra_message, is_start_failure, legacy_kind,
    shown_headline, shown_kind, sort_rows, split, stats,
};
pub use journal::{
    JournalLine, LevelFilter, LineLevel, MAX_LINE_CHARS, TAIL_LINES, journal, parse_line,
};
pub use model::{
    ArtifactReport, DisconnectReason, Evidence, EvidenceKey, EvidenceValue, ExportFormat,
    LogSource, LogTail, LogsApi, LogsSnapshot, Mode, Outcome, OutcomeKind, OutcomeTone, SessionRow,
    TailLine, TailNote, Text,
};
pub use page::LogsPage;
pub use report::{
    ClearSummary, diagnostics_text, evidence_items, evidence_text, export_file_name, fault_key,
    fault_label, headline_text,
};
pub use state::{PageState, Tab, TechQuery};

/// Re-read period of the technical tab while the page is visible and following.
pub const JOURNAL_REFRESH: std::time::Duration = std::time::Duration::from_secs(5);
/// How long «Скопировано» replaces a copy button's label.
pub const COPIED_FLASH: std::time::Duration = std::time::Duration::from_millis(1500);

/// The API from context.
fn use_api() -> Rc<dyn LogsApi> {
    use_context::<Rc<dyn LogsApi>>()
}
