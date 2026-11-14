//! «Подключения»: the sessions table with its filters, period stats, start failures and the
//! CSV / JSON export of the whole history (same behaviour as the old page; the filters, sort
//! and period are remembered across visits).
use std::sync::Arc;

use dioxus::prelude::*;
use vpnte_base::ErrorKind;
use vpnte_base::types::now_ms;

use super::clear::{ClearButton, ClearTarget};
use super::format::local_date;
use super::history::{Query, newest_first, sort_rows, split, stats};
use super::model::{ExportFormat, SessionRow};
use super::report::export_file_name;
use super::state::use_remembered;
use super::table::{FiltersPanel, StatsPanel, failures_panel, history_panel, use_tz};
use super::{tr_now, use_api};
use crate::lang::{LANG, tr, translate_now};
use crate::t;
use crate::widgets::{Button, ButtonKind, Load, LoadError, Loading, Panel, Toasts, use_job};

/// The tab: its actions, then the history half.
#[component]
pub(super) fn ConnectionsTab(history: Load<Arc<[SessionRow]>>) -> Element {
    let api = use_api();
    let toasts = Toasts::use_context();
    let tz = use_tz();
    let export_job = use_job::<()>();
    let mut exporting = use_signal(|| None::<ExportFormat>);
    let export = move |format: ExportFormat| {
        let (api, tz) = (api.clone(), tz.clone());
        exporting.set(Some(format));
        export_job.start(move |_token| async move {
            let date = local_date(now_ms(), &tz).unwrap_or_default();
            match api
                .export_history(format, export_file_name(format, date))
                .await
            {
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
    };
    let mut export_csv = export.clone();
    let mut export_json = export;
    let busy = if export_job.running() {
        exporting()
    } else {
        None
    };
    rsx! {
        div { class: "lg-tab-bar",
            Button {
                kind: ButtonKind::Ghost,
                small: true,
                busy: busy == Some(ExportFormat::Csv),
                disabled: busy.is_some(),
                onclick: move |_| export_csv(ExportFormat::Csv),
                {t!("logs.exportCsv")}
            }
            Button {
                kind: ButtonKind::Ghost,
                small: true,
                busy: busy == Some(ExportFormat::Json),
                disabled: busy.is_some(),
                onclick: move |_| export_json(ExportFormat::Json),
                {t!("logs.exportJson")}
            }
            ClearButton { target: ClearTarget::History }
        }
        HistoryHalf { history }
    }
}

/// Filters, stats, the sessions table and the start failures over the pushed history.
#[component]
fn HistoryHalf(history: Load<Arc<[SessionRow]>>) -> Element {
    let api = use_api();
    let filters = use_remembered(|s| s.filters.clone(), |s, v| s.filters = v);
    let sort = use_remembered(|s| s.sort, |s, v| s.sort = v);
    let period = use_remembered(|s| s.period, |s, v| s.period = v);
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
