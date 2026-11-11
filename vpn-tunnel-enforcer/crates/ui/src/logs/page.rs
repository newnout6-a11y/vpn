//! The page root and the history half: header actions, filters, stats, the sessions table with
//! expandable evidence, the start failures; the cleanup confirmation.
use std::rc::Rc;
use std::sync::Arc;

use dioxus::prelude::*;
use jiff::tz::TimeZone;
use vpnte_base::ErrorKind;
use vpnte_base::types::now_ms;

use super::format::local_date;
use super::history::{Filters, Period, Query, SortState, newest_first, sort_rows, split, stats};
use super::model::{ExportFormat, LogsApi, SessionRow};
use super::report::{ClearSummary, export_file_name};
use super::table::{FiltersPanel, PageTz, StatsPanel, failures_panel, history_panel, use_tz};
use super::viewer::JournalPanel;
use super::{tr_now, use_api, use_watch};
use crate::lang::translate_now;
use crate::lang::{LANG, tr};
use crate::pages::{Page, nav_number};
use crate::t;
use crate::widgets::{
    Button, ButtonKind, ConfirmDialog, JobSlot, Load, LoadError, Loading, Panel, SectionHeader,
    Toasts, use_job,
};

/// The Logs page (register as `Page::Logs`). Needs `Rc<dyn LogsApi>` and the [`Toasts`]
/// provider in context.
#[component]
pub fn LogsPage() -> Element {
    let api = use_api();
    let snapshot = use_watch({
        let api = api.clone();
        move || api.history()
    });
    let mut confirm_open = use_signal(|| false);
    let journal_reload = use_signal(|| 0u64);
    let tz = use_hook(TimeZone::system);
    use_context_provider(|| PageTz(tz.clone()));
    let toasts = Toasts::use_context();
    let clear_job = use_job::<()>();
    let export_job = use_job::<()>();
    let mut exporting = use_signal(|| None::<ExportFormat>);

    let history = snapshot.read().history.clone();

    let export = {
        let api = api.clone();
        let tz = tz.clone();
        move |format: ExportFormat| {
            let (api, tz) = (api.clone(), tz.clone());
            exporting.set(Some(format));
            export_job.start(move |_token| async move {
                let date = local_date(now_ms(), &tz).unwrap_or_default();
                let result = api
                    .export_history(format, export_file_name(format, date))
                    .await;
                match result {
                    Ok(file) => {
                        toasts.success(translate_now("logs.exportDone", &[]), Some(file));
                    }
                    Err(err) if err.kind == ErrorKind::Cancelled => {}
                    Err(err) => {
                        tracing::warn!(error = %err, "history export failed");
                        toasts.error(
                            translate_now("logs.exportFailed", &[]),
                            Some(tr_now(&err.user_msg())),
                        );
                    }
                }
                Ok(())
            });
        }
    };
    let mut export_csv = export.clone();
    let mut export_json = export;

    let start_clear = {
        let api = api.clone();
        move |()| clear(api.clone(), clear_job, toasts, confirm_open, journal_reload)
    };

    let exporting_now = if export_job.running() {
        exporting()
    } else {
        None
    };
    rsx! {
        div { class: "c-swiss swiss-skin lg",
            SectionHeader {
                title: t!("logs.title"),
                number: nav_number(Page::ALL.iter().position(|p| *p == Page::Logs).unwrap_or(7)),
                description: t!("logs.description"),
                Button {
                    kind: ButtonKind::Ghost,
                    small: true,
                    busy: exporting_now == Some(ExportFormat::Csv),
                    disabled: exporting_now.is_some(),
                    onclick: move |_| export_csv(ExportFormat::Csv),
                    {t!("logs.exportCsv")}
                }
                Button {
                    kind: ButtonKind::Ghost,
                    small: true,
                    busy: exporting_now == Some(ExportFormat::Json),
                    disabled: exporting_now.is_some(),
                    onclick: move |_| export_json(ExportFormat::Json),
                    {t!("logs.exportJson")}
                }
                Button {
                    kind: ButtonKind::Danger,
                    small: true,
                    busy: clear_job.running(),
                    onclick: move |_| confirm_open.set(true),
                    {t!("logs.clear")}
                }
            }
            HistoryHalf { history }
            JournalPanel { reload: journal_reload }
            ConfirmDialog {
                open: confirm_open,
                title: t!("logs.cleanup.title"),
                message: t!("logs.cleanup.confirm"),
                confirm_label: t!("logs.cleanup.action"),
                cancel_label: t!("common.cancel"),
                danger: true,
                busy: clear_job.running(),
                on_confirm: start_clear,
                on_cancel: move |()| confirm_open.set(false),
            }
        }
    }
}

/// Runs the cleanup in the page's slot: the toast appears only after every part settled, and
/// not at all when the page was left meanwhile (the slot's future is dropped; the app finishes
/// the cleanup in its own task).
pub(super) fn clear(
    api: Rc<dyn LogsApi>,
    job: JobSlot<()>,
    toasts: Toasts,
    mut confirm_open: Signal<bool>,
    mut journal_reload: Signal<u64>,
) {
    job.start(move |_token| async move {
        let result = api.clear_all().await;
        confirm_open.set(false);
        match result {
            Ok(report) => {
                let summary = ClearSummary::of(&report);
                let (title, body) = summary.toast(&tr_now);
                if summary.is_success() {
                    toasts.success(title, Some(body));
                } else {
                    tracing::warn!(failed = summary.failed, "logs cleanup incomplete");
                    toasts.error(title, Some(body));
                }
            }
            Err(err) if err.kind == ErrorKind::Cancelled => {}
            Err(err) => {
                tracing::warn!(error = %err, "logs cleanup failed");
                toasts.error(
                    translate_now("logs.cleanup.partialTitle", &[]),
                    Some(tr_now(&err.user_msg())),
                );
            }
        }
        // App and engine logs are among the artifacts: show what is left of them.
        *journal_reload.write() += 1;
        Ok(())
    });
}

/// Filters, stats, the sessions table and the start failures over the pushed history.
#[component]
fn HistoryHalf(history: Load<Arc<[SessionRow]>>) -> Element {
    let api = use_api();
    let filters = use_signal(Filters::default);
    let sort = use_signal(SortState::default);
    let period = use_signal(Period::default);
    let expanded = use_signal(|| None::<String>);
    let failures_open = use_signal(|| false);
    let tz = use_tz();
    let lang = *LANG.read();

    let rows = match &history {
        Load::Loading => {
            return rsx! {
                Panel { title: t!("logs.connectionHistory"),
                    Loading { label: t!("common.loading") }
                }
            };
        }
        Load::Failed(err) => {
            let retry = move |()| {
                let api = api.clone();
                spawn(async move {
                    if let Err(err) = api.reload_history().await {
                        tracing::warn!(error = %err, "history reload failed");
                    }
                });
            };
            return rsx! {
                Panel { title: t!("logs.connectionHistory"),
                    LoadError { text: tr(&err.msg), retry_label: t!("common.retry"), on_retry: retry }
                }
            };
        }
        Load::Ready(rows) => rows.clone(),
    };

    let query = Query::new(&filters.read(), &tz, lang);
    let (mut sessions, mut failures) = split(rows.iter().filter(|row| query.matches(row)));
    sort_rows(&mut sessions, sort(), lang);
    failures.sort_by(newest_first);
    let totals = stats(&rows, period(), now_ms());
    let filtered = !filters.read().is_empty();
    rsx! {
        div { class: "lg-top",
            FiltersPanel { filters }
            StatsPanel { stats: totals, period }
        }
        {history_panel(&sessions, filtered, sort, expanded, filters)}
        {failures_panel(&failures, failures_open)}
    }
}
