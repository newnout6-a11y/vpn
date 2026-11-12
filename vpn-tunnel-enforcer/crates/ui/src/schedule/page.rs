//! The page: header, next-event strip, the create / edit form and the schedule list.
use std::time::Duration;

use dioxus::prelude::*;
use jiff::tz::TimeZone;
use vpnte_base::Msg;
use vpnte_base::types::now_ms;

use super::editor::FormPanel;
use super::form::{
    ScheduleForm, days_keys, local_hhmm, server_label, time_until, until_next_change, window_hint,
};
use super::model::{NextAction, NextEvent, ScheduleEntry, ServerChoice};
use super::{use_api, use_watch};
use crate::lang::tr;
use crate::pages::{Page, nav_number, use_page_active};
use crate::t;
use crate::widgets::{
    Badge, Button, EmptyState, IconButton, IconGlyph, Load, LoadError, Loading, Panel,
    SectionHeader, Switch, Toasts, use_job,
};

/// The time zone the page shows local times in (read when the page mounts; it stays mounted).
#[derive(Clone)]
struct PageTz(TimeZone);

/// The Schedule page (register as `Page::Schedule`). Needs `Rc<dyn ScheduleApi>` and the
/// [`Toasts`] provider in context.
#[component]
pub fn SchedulePage() -> Element {
    let api = use_api();
    let state = use_watch({
        let api = api.clone();
        move || api.state()
    });
    let mut form = use_signal(|| None::<ScheduleForm>);
    use_context_provider(|| PageTz(TimeZone::system()));
    let reload_job = use_job::<()>();
    let reload = move |()| {
        let api = api.clone();
        reload_job.start(move |_| async move { api.reload().await });
    };

    let snapshot = state.read().clone();
    let number = Page::ALL
        .iter()
        .position(|p| *p == Page::Schedule)
        .unwrap_or(6);
    let creating = form.read().as_ref().is_some_and(|f| f.editing.is_none());
    rsx! {
        div { class: "c-swiss swiss-skin sched",
            SectionHeader {
                title: t!("schedule.title"),
                number: nav_number(number),
                description: t!("schedule.description"),
                Button {
                    small: true,
                    disabled: creating,
                    onclick: move |_| form.set(Some(ScheduleForm::default())),
                    {t!("schedule.create")}
                }
            }
            if let Some(next) = snapshot.next.clone() {
                NextEventStrip { event: next }
            }
            if form.read().is_some() {
                FormPanel {
                    form,
                    servers: snapshot.servers.clone(),
                    tun_available: snapshot.tun_available,
                }
            }
            match snapshot.schedules {
                Load::Loading => rsx! {
                    Panel {
                        Loading { label: t!("common.loading") }
                    }
                },
                Load::Failed(err) => rsx! {
                    Panel {
                        LoadError {
                            text: tr(&err.msg),
                            retry_label: t!("common.retry"),
                            on_retry: reload,
                        }
                    }
                },
                Load::Ready(list) if list.is_empty() => rsx! {
                    if form.read().is_none() {
                        Panel {
                            EmptyState {
                                title: t!("schedule.noSchedules"),
                                detail: t!("schedule.emptyHint"),
                            }
                        }
                    }
                },
                Load::Ready(list) => rsx! {
                    Panel { flush: true,
                        ul { class: "sched-list", aria_label: t!("schedule.title"),
                            for entry in list {
                                ScheduleCard {
                                    key: "{entry.id}",
                                    entry: entry.clone(),
                                    servers: snapshot.servers.clone(),
                                    form,
                                }
                            }
                        }
                    }
                },
            }
        }
    }
}

/// «Следующее событие: <name>» with «Отключить в 19:00 (через 6 ч 24 мин)»; the countdown
/// re-renders when its minute changes, only while the page is visible.
#[component]
fn NextEventStrip(event: NextEvent) -> Element {
    let tz = use_context::<PageTz>().0;
    let active = use_page_active();
    let mut tick = use_signal(|| 0u64);
    // The ticker reads the moment through a signal, so a new next event retimes it.
    let mut moment = use_signal(|| event.at);
    if *moment.peek() != event.at {
        moment.set(event.at);
    }
    use_future(move || async move {
        loop {
            let wait = if *active.peek() {
                until_next_change(*moment.peek(), now_ms())
            } else {
                None
            };
            tokio::time::sleep(wait.unwrap_or(Duration::from_secs(30))).await;
            // a hidden page is not re-rendered; showing it again re-renders (`active` below)
            if *active.peek() {
                tick += 1;
            }
        }
    });
    tick.read();
    active.read();
    let at = event.at;
    let (action_key, mark) = match event.action {
        NextAction::Start => ("dashboardWidgets.scheduleConnect", "is-start"),
        NextAction::Stop => ("dashboardWidgets.scheduleDisconnect", "is-stop"),
    };
    let detail = tr(&Msg::new("dashboardWidgets.scheduleAt")
        .arg("action", t!(action_key))
        .arg("time", local_hhmm(at, &tz).unwrap_or_default())
        .arg("until", tr(&time_until(at, now_ms()))));
    let title = format!("{}: {}", t!("schedule.nextEvent"), event.name);
    rsx! {
        section { class: "sched-next", role: "status",
            span { class: "sched-next-mark {mark}", aria_hidden: "true" }
            div { class: "sched-next-text",
                p { class: "sched-next-title", "{title}" }
                p { class: "sched-next-detail swiss-mono", "{detail}" }
            }
        }
    }
}

/// One schedule: on/off switch, name, days (Monday first), window, capture and upstream; edit
/// and delete (one click, no confirmation: a single row, U-29). Failures are toasts with the
/// canonical text.
#[component]
fn ScheduleCard(
    entry: ScheduleEntry,
    servers: Vec<ServerChoice>,
    form: Signal<Option<ScheduleForm>>,
) -> Element {
    let api = use_api();
    let toasts = Toasts::use_context();
    let toggle_job = use_job::<()>();
    let delete_job = use_job::<()>();
    let days: Vec<String> = days_keys(&entry.days).into_iter().map(|k| t!(k)).collect();
    let days = days.join(", ");
    let hint = window_hint(entry.start, entry.end).map(|m| tr(&m));
    // Two separate choices (NOADMIN §2): how the traffic is taken, and where it goes.
    let capture = t!(entry.capture.label_key());
    let upstream = t!(entry.upstream.label_key());
    // The server is a name, not a choice: plain text next to the badges (a badge sets its text in
    // upper case); a deleted server is marked.
    let server = server_label(&entry, &servers);
    let editing = form.read().as_ref().and_then(|f| f.editing.clone()) == Some(entry.id.clone());

    let toggle = {
        let (api, id) = (api.clone(), entry.id.clone());
        move |on: bool| {
            let (api, id) = (api.clone(), id.clone());
            toggle_job.start(move |_| async move {
                if let Err(err) = api.set_enabled(id, on).await {
                    toasts.failed(&Msg::new("schedule.toggleFailed"), &err);
                }
                Ok(())
            });
        }
    };
    let delete = {
        let (api, id) = (api.clone(), entry.id.clone());
        move |_| {
            let (api, id) = (api.clone(), id.clone());
            delete_job.start(move |_| async move {
                match api.delete(id.clone()).await {
                    Ok(()) => {
                        let open = form.peek().as_ref().and_then(|f| f.editing.clone());
                        if open == Some(id) {
                            form.set(None);
                        }
                    }
                    Err(err) => toasts.failed(&Msg::new("schedule.deleteFailed"), &err),
                }
                Ok(())
            });
        }
    };
    let edit = {
        let entry = entry.clone();
        move |_| form.set(Some(ScheduleForm::edit(&entry)))
    };
    rsx! {
        li {
            class: "sched-item",
            class: if !entry.enabled { "is-off" },
            class: if editing { "is-editing" },
            Switch {
                label: entry.name.clone(),
                hide_label: true,
                checked: entry.enabled,
                busy: toggle_job.running(),
                on_change: toggle,
            }
            div { class: "sched-item-text",
                p { class: "sched-item-name", "{entry.name}" }
                p { class: "sched-item-meta",
                    span { "{days}" }
                    span { class: "swiss-mono", "{entry.start} – {entry.end}" }
                    if let Some(hint) = hint {
                        span { class: "sched-item-hint", "{hint}" }
                    }
                    Badge { "{capture}" }
                    Badge { "{upstream}" }
                    match server {
                        Some(Ok(name)) => rsx! {
                            span { class: "sched-item-server", "{name}" }
                        },
                        Some(Err(missing)) => rsx! {
                            span { class: "sched-item-server is-missing", {tr(&missing)} }
                        },
                        None => rsx! {},
                    }
                }
            }
            div { class: "sched-item-actions",
                IconButton {
                    glyph: IconGlyph::Edit,
                    label: t!("schedule.editItem", name = entry.name),
                    pressed: editing,
                    onclick: edit,
                }
                IconButton {
                    glyph: IconGlyph::Trash,
                    label: t!("schedule.deleteItem", name = entry.name),
                    danger: true,
                    busy: delete_job.running(),
                    onclick: delete,
                }
            }
        }
    }
}
