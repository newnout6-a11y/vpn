//! «События»: the timeline grouped by day (Сегодня, Вчера, a date), the topic chips and a
//! search, one line per event (time, status dot, text), details on expand, «Скопировать».
use std::sync::Arc;

use dioxus::prelude::*;
use vpnte_base::types::now_ms;

use super::clear::{ClearButton, ClearTarget};
use super::events::{
    EventFilter, EventQuery, EventRow, by_day, event_text, facts, line_text, shown_events,
};
use super::format::local_time;
use super::state::use_remembered;
use super::table::use_tz;
use super::{COPIED_FLASH, use_api};
use crate::lang::{LANG, tr};
use crate::t;
use crate::units::format_bytes;
use crate::widgets::{
    Button, ButtonKind, EmptyState, Load, LoadError, Loading, TextInput, TextKind,
};

/// The tab: chips, search and «Очистить», then the days.
#[component]
pub(super) fn EventsTab(events: Load<Arc<[EventRow]>>) -> Element {
    let api = use_api();
    let mut query = use_remembered(|s| s.events.clone(), |s, v| s.events = v);
    let current = query.read().clone();
    let chips: Vec<(EventFilter, String)> = EventFilter::ALL
        .iter()
        .map(|f| (*f, t!(f.label_key())))
        .collect();
    let body = match events {
        Load::Loading => rsx! {
            Loading { label: t!("common.loading") }
        },
        Load::Failed(err) => {
            let retry = move |()| {
                let api = api.clone();
                spawn(async move {
                    if let Err(err) = api.reload_history().await {
                        tracing::warn!(error = %err, "events reload failed");
                    }
                });
            };
            rsx! {
                LoadError { text: tr(&err.msg), retry_label: t!("common.retry"), on_retry: retry }
            }
        }
        Load::Ready(rows) if rows.is_empty() => rsx! {
            EmptyState { title: t!("logs.events.empty"), detail: t!("logs.events.emptyHint") }
        },
        Load::Ready(rows) => rsx! {
            Timeline { rows, query: current.clone() }
        },
    };
    rsx! {
        div { class: "lg-tab-bar",
            div { class: "lg-chips", role: "group", aria_label: t!("logs.events.filterLabel"),
                for (filter, label) in chips {
                    button {
                        r#type: "button",
                        class: "lg-chip",
                        aria_pressed: if current.filter == filter { "true" } else { "false" },
                        onclick: move |_| query.write().filter = filter,
                        {label}
                    }
                }
            }
            div { class: "lg-search",
                TextInput {
                    kind: TextKind::Search,
                    value: current.text.clone(),
                    oninput: move |v| query.write().text = v,
                    placeholder: t!("logs.events.search"),
                    aria_label: t!("logs.events.search"),
                }
            }
            ClearButton { target: ClearTarget::Events }
        }
        {body}
    }
}

/// The matching events, newest first, under their day headers.
#[component]
fn Timeline(rows: Arc<[EventRow]>, query: EventQuery) -> Element {
    let tz = use_tz();
    let _lang = LANG.read();
    let expanded = use_signal(|| None::<u64>);
    let (shown, more) = shown_events(&rows, &query, &tr);
    if shown.is_empty() {
        return rsx! {
            EmptyState { title: t!("logs.events.noMatches") }
        };
    }
    let groups = by_day(shown, now_ms(), &tz);
    rsx! {
        div { class: "lg-days",
            for (day, members) in groups {
                section { class: "lg-day", key: "{day:?}",
                    h3 { class: "lg-day-title", {day.label(&tr)} }
                    ol { class: "lg-events",
                        for row in members {
                            EventLine {
                                key: "{row.id}",
                                row: row.clone(),
                                open: expanded() == Some(row.id),
                                expanded,
                            }
                        }
                    }
                }
            }
            if more {
                p { class: "lg-hint", {t!("logs.events.more", count = super::EVENTS_SHOWN)} }
            }
        }
    }
}

/// One event: time, dot, text; a click (or Enter) shows its details and «Скопировать».
#[component]
fn EventLine(row: EventRow, open: bool, mut expanded: Signal<Option<u64>>) -> Element {
    let api = use_api();
    let tz = use_tz();
    let mut copied = use_signal(|| false);
    let id = row.id;
    let time = local_time(row.at, &tz)
        .and_then(|t| t.get(..5).map(str::to_owned))
        .unwrap_or_default();
    let title = line_text(&row, &tr);
    let detail_id = format!("lg-event-{id}");
    let copy = {
        let (row, tz) = (row.clone(), tz.clone());
        move |_| {
            let (api, text) = (api.clone(), event_text(&row, &tz, &tr, &format_bytes));
            spawn(async move {
                if api.copy_text(text).await.is_ok() {
                    copied.set(true);
                    tokio::time::sleep(COPIED_FLASH).await;
                    copied.set(false);
                }
            });
        }
    };
    rsx! {
        li { class: "lg-event", "data-level": row.level.key(),
            button {
                r#type: "button",
                class: "lg-event-head",
                aria_expanded: if open { "true" } else { "false" },
                aria_controls: "{detail_id}",
                onclick: move |_| expanded.set(if open { None } else { Some(id) }),
                span { class: "lg-event-time swiss-mono", "{time}" }
                span { class: "lg-dot", "data-level": row.level.key(), aria_hidden: "true" }
                span { class: "lg-event-title", "{title}" }
            }
            if open {
                div { class: "lg-event-detail", id: "{detail_id}",
                    if let Some(body) = &row.body {
                        p { class: "lg-event-body", {body.render_with(&tr)} }
                    }
                    if let Some(session) = &row.session {
                        ul { class: "lg-facts",
                            for line in facts(session, &tr, &format_bytes) {
                                li { "{line}" }
                            }
                        }
                    }
                    Button { kind: ButtonKind::Link, onclick: copy,
                        if copied() {
                            {t!("logs.copied")}
                        } else {
                            {t!("logs.events.copy")}
                        }
                    }
                }
            }
        }
    }
}
