//! The Logs page («Логи»): connection history with explained outcomes (filters, sort, period
//! stats, expandable evidence, start failures apart), CSV / JSON export, full cleanup behind a
//! confirmation, and the journal viewer for the app and engine logs (ui-pages §3.9 / §6.5).
//!
//! Data and actions come from a [`LogsApi`] in context (`Rc<dyn LogsApi>`); the app implements
//! it over the backend, [`demo::DemoLogs`] fakes it. Register the page with
//! `registry.register(Page::Logs, LogsPage)`; it is an active-only page, so its filters, sort and
//! expanded row reset on every visit, as before.
pub mod demo;
mod format;
mod history;
mod journal;
mod model;
mod page;
mod report;
mod table;
#[cfg(test)]
mod tests;
mod viewer;

use std::rc::Rc;

use crate::hooks::use_watch;
use crate::lang::tr_now;
use dioxus::prelude::*;

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
    ArtifactReport, ClearReport, DisconnectReason, Evidence, EvidenceKey, EvidenceValue,
    ExportFormat, LogSource, LogTail, LogsApi, LogsSnapshot, Mode, Outcome, OutcomeKind,
    OutcomeTone, SessionRow, Text,
};
pub use page::LogsPage;
pub use report::{
    ClearSummary, diagnostics_text, evidence_items, evidence_text, export_file_name, fault_key,
    fault_label, headline_text,
};

/// Auto-refresh period of the journal while the page is visible and «Следить» is on (the old
/// panel polled app.log every 10 s; a tail should follow closer).
pub const JOURNAL_REFRESH: std::time::Duration = std::time::Duration::from_secs(5);
/// How long «Скопировано» replaces the copy button's label.
pub const COPIED_FLASH: std::time::Duration = std::time::Duration::from_millis(1500);

/// The API from context.
fn use_api() -> Rc<dyn LogsApi> {
    use_context::<Rc<dyn LogsApi>>()
}
