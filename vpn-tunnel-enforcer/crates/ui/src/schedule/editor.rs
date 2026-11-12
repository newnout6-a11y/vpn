//! The create / edit form of the Schedule page.
use dioxus::prelude::*;
use vpnte_base::{ErrorKind, Msg};

use super::form::{DISPLAY_ORDER, ScheduleForm, day_key};
use super::model::{Capture, ServerChoice, Upstream};
use super::use_api;
use crate::lang::tr;
use crate::t;
use crate::widgets::{
    Button, ButtonKind, Field, FieldCtx, Panel, Segmented, Select, SelectOption, Switch, TextInput,
    use_dom_id, use_job,
};

/// The form. Save stays disabled (with the reason as its title) until the form is valid; a
/// failed save keeps the form open and says why inline.
#[component]
pub(super) fn FormPanel(
    form: Signal<Option<ScheduleForm>>,
    servers: Vec<ServerChoice>,
    tun_available: bool,
) -> Element {
    let api = use_api();
    let save_job = use_job::<()>();
    let mut failure = use_signal(|| None::<Msg>);
    let days_label = use_dom_id("sched-days");
    // The form is drawn above the list: on open (and on switching to another schedule) move the
    // focus, and with it the view, to the name field. `initial_focus` alone acts in dialogs only.
    // Switching also forgets the previous schedule's save: its late success must not close the
    // form now open for another one, nor its error show there.
    let editing_id = use_memo(move || form.read().as_ref().and_then(|f| f.editing.clone()));
    use_effect(move || {
        editing_id.read();
        save_job.cancel();
        failure.set(None);
        let _ = document::eval("document.querySelector('.sched-form [data-w-autofocus]')?.focus()");
    });
    let Some(draft) = form.read().clone() else {
        return rsx! {};
    };
    let checked = draft.input(&servers);
    let problem = checked.as_ref().err().map(|p| t!(p.msg_key()));
    let editing = draft.editing.clone();
    let save = move |_| {
        let Ok(input) = checked.clone() else {
            return;
        };
        let (api, id) = (api.clone(), editing.clone());
        failure.set(None);
        save_job.start(move |_| async move {
            let result = match id {
                Some(id) => api.update(id, input).await,
                None => api.create(input).await,
            };
            match result {
                Ok(()) => form.set(None),
                Err(err) if err.kind == ErrorKind::Cancelled => {}
                Err(err) => {
                    tracing::warn!(error = %err, "schedule save failed");
                    failure.set(Some(err.user_msg()));
                }
            }
            Ok(())
        });
    };
    let mut server_options = vec![SelectOption::new(
        String::new(),
        t!("schedule.currentServer"),
    )];
    server_options.extend(
        servers
            .iter()
            .map(|s| SelectOption::new(s.id.clone(), format!("{} ({})", s.name, s.protocol))),
    );
    let captures: Vec<(Capture, String)> = Capture::ALL
        .iter()
        .map(|&c| (c, t!(c.label_key())))
        .collect();
    let upstreams: Vec<(Upstream, String)> = Upstream::ALL
        .iter()
        .map(|&u| (u, t!(u.label_key())))
        .collect();
    let title = if draft.editing.is_some() {
        t!("schedule.edit")
    } else {
        t!("schedule.create")
    };
    // NOADMIN §0: the TUN needs the app started as administrator; said, never hidden.
    let capture_hint = if draft.capture == Capture::Tun && !tun_available {
        t!("schedule.tunUnavailable")
    } else {
        t!("schedule.captureHint")
    };
    let upstream_hint = if draft.upstream.uses_profile() {
        t!("schedule.serverHint")
    } else {
        t!("schedule.localHint")
    };
    rsx! {
        Panel { title,
            div { class: "sched-form",
                Field { label: t!("schedule.name"),
                    TextInput {
                        value: draft.name.clone(),
                        maxlength: 200,
                        initial_focus: true,
                        oninput: move |v: String| {
                            if let Some(f) = form.write().as_mut() {
                                f.name = v;
                            }
                        },
                    }
                }
                div { class: "sched-field",
                    span { class: "w-field-label", id: "{days_label}", {t!("schedule.days")} }
                    div { class: "sched-days", role: "group", aria_labelledby: "{days_label}",
                        for day in DISPLAY_ORDER {
                            button {
                                key: "{day}",
                                r#type: "button",
                                class: "sched-day",
                                aria_pressed: if draft.days[usize::from(day)] { "true" } else { "false" },
                                onclick: move |_| {
                                    if let Some(f) = form.write().as_mut() {
                                        f.toggle_day(day);
                                    }
                                },
                                {t!(day_key(day))}
                            }
                        }
                    }
                }
                div { class: "sched-times",
                    Field { label: t!("schedule.startTime"),
                        TimeInput {
                            value: draft.start.clone(),
                            oninput: move |v: String| {
                                if let Some(f) = form.write().as_mut() {
                                    f.start = v;
                                }
                            },
                        }
                    }
                    Field { label: t!("schedule.endTime"),
                        TimeInput {
                            value: draft.end.clone(),
                            oninput: move |v: String| {
                                if let Some(f) = form.write().as_mut() {
                                    f.end = v;
                                }
                            },
                        }
                    }
                    if let Some(hint) = draft.hint() {
                        p { class: "sched-hint", {tr(&hint)} }
                    }
                }
                div { class: "sched-field",
                    span { class: "w-field-label", {t!("schedule.capture")} }
                    Segmented {
                        options: captures,
                        value: draft.capture,
                        label: t!("schedule.capture"),
                        on_change: move |c| {
                            if let Some(f) = form.write().as_mut() {
                                f.capture = c;
                            }
                        },
                    }
                    p { class: "w-field-hint", "{capture_hint}" }
                }
                div { class: "sched-field",
                    span { class: "w-field-label", {t!("schedule.upstream")} }
                    Segmented {
                        options: upstreams,
                        value: draft.upstream,
                        label: t!("schedule.upstream"),
                        on_change: move |u| {
                            if let Some(f) = form.write().as_mut() {
                                f.upstream = u;
                            }
                        },
                    }
                    p { class: "w-field-hint", "{upstream_hint}" }
                }
                if draft.upstream.uses_profile() {
                    Field { label: t!("schedule.server"),
                        Select {
                            options: server_options,
                            value: Some(draft.profile_id.clone()),
                            placeholder: t!("ui.widgets.choose"),
                            on_change: move |id: String| {
                                if let Some(f) = form.write().as_mut() {
                                    f.profile_id = id;
                                }
                            },
                        }
                    }
                }
                Switch {
                    label: t!("schedule.enabled"),
                    checked: draft.enabled,
                    on_change: move |on| {
                        if let Some(f) = form.write().as_mut() {
                            f.enabled = on;
                        }
                    },
                }
                if let Some(msg) = failure() {
                    p { class: "sched-form-error", role: "alert",
                        {t!("schedule.saveFailed", error = tr(&msg))}
                    }
                }
                div { class: "sched-form-actions",
                    Button {
                        busy: save_job.running(),
                        disabled: problem.is_some(),
                        disabled_reason: problem,
                        onclick: save,
                        {t!("schedule.save")}
                    }
                    Button {
                        kind: ButtonKind::Ghost,
                        onclick: move |_| {
                            save_job.cancel();
                            form.set(None);
                        },
                        {t!("common.cancel")}
                    }
                }
            }
        }
    }
}

/// A native time box (`HH:MM`, a 24-hour value whatever the clock format) wired to the
/// [`Field`] around it.
#[component]
fn TimeInput(value: String, oninput: EventHandler<String>) -> Element {
    let field = try_use_context::<FieldCtx>();
    rsx! {
        input {
            class: "w-input sched-time swiss-mono",
            r#type: "time",
            required: true,
            id: field.map(|f| f.id()),
            aria_describedby: field.and_then(|f| f.described_by()),
            value: "{value}",
            oninput: move |evt| oninput.call(evt.value()),
        }
    }
}
