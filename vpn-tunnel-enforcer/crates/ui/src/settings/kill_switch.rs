//! «Kill switch»: three choices with one line each (research killswitch 5.2), applied and
//! verified by the backend (U-04 shows «Применяем…», the failure reason and an unconfirmed
//! state), a Details panel for what concerns few people, and the exceptions editor. "Always" is
//! offered only where the helper service keeps it safe; until then it shows disabled with one
//! calm line and a stored "Always" works as "If the VPN drops" (owner decision 12.11.2026).
use dioxus::prelude::*;

use super::model::{ExceptionKind, KillSwitchLevel, ProtectionStatus, RoutingMode};
use super::{ActionError, use_api, use_ctx};
use crate::lang::tr;
use crate::t;
use crate::widgets::{
    Badge, Button, ButtonKind, Field, IconButton, IconGlyph, Panel, Segmented, Spinner, TextInput,
    Tone, UiError, use_job,
};

/// The choices in page order.
const LEVELS: [KillSwitchLevel; 3] = [
    KillSwitchLevel::Off,
    KillSwitchLevel::Standard,
    KillSwitchLevel::Strict,
];

/// Name and one line of a choice. In proxy mode "If the VPN drops" gets its one neutral
/// addition (the hold is the system proxy), nothing else.
pub(super) fn choice_keys(
    level: KillSwitchLevel,
    routing: RoutingMode,
) -> [Option<&'static str>; 3] {
    match level {
        KillSwitchLevel::Off => [
            Some("ui.settings.killSwitch.off"),
            Some("ui.settings.killSwitch.offLine"),
            None,
        ],
        KillSwitchLevel::Standard => [
            Some("ui.settings.killSwitch.onDrop"),
            Some("ui.settings.killSwitch.onDropLine"),
            (routing == RoutingMode::Soft).then_some("ui.settings.killSwitch.onDropProxy"),
        ],
        KillSwitchLevel::Strict => [
            Some("ui.settings.killSwitch.always"),
            Some("ui.settings.killSwitch.alwaysLine"),
            None,
        ],
    }
}

/// Short badge of an exception's kind.
fn kind_label(kind: ExceptionKind) -> String {
    match kind {
        ExceptionKind::App => t!("ui.settings.killSwitch.kindApp"),
        ExceptionKind::Ip => t!("ui.settings.killSwitch.kindIp"),
    }
}

/// Badge of the verified protection state.
fn status_badge(status: &ProtectionStatus) -> (Tone, String) {
    match status {
        ProtectionStatus::Off => (Tone::Neutral, t!("ui.settings.killSwitch.statusOff")),
        ProtectionStatus::Armed => (Tone::Neutral, t!("ui.settings.killSwitch.statusArmed")),
        ProtectionStatus::Engaged => (Tone::Ok, t!("ui.settings.killSwitch.statusEngaged")),
        ProtectionStatus::Blocking => (Tone::Warn, t!("ui.settings.killSwitch.statusBlocking")),
        ProtectionStatus::Unconfirmed(_) => {
            (Tone::Fail, t!("ui.settings.killSwitch.statusUnconfirmed"))
        }
    }
}

#[component]
pub(super) fn KillSwitch() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let job = use_job::<()>();
    let mut pending = use_signal(|| None::<KillSwitchLevel>);
    let kill = ctx.kill.read().clone();
    let routing = ctx.view().routing_mode;
    let applying = job.running();
    let shown = pending().filter(|_| applying).unwrap_or(kill.level);
    let set_level = use_callback(move |level: KillSwitchLevel| {
        if level == ctx.kill.peek().level {
            return;
        }
        pending.set(Some(level));
        let api = api.clone();
        job.start(move |_| async move {
            let result = api.set_kill_switch_level(level).await;
            match &result {
                Ok(()) => tracing::info!(target: "ui", ?level, "kill-switch level set"),
                Err(err) => tracing::warn!(target: "ui", ?level, error = %err, "kill-switch level not changed"),
            }
            result
        });
    });
    let error = match job.last() {
        Some(Err(err)) => Some(UiError {
            kind: err.kind,
            msg: vpnte_base::Msg::new("ui.settings.killSwitch.levelFailed")
                .arg("reason", tr(&err.msg)),
        }),
        _ => None,
    };
    let (tone, status_text) = status_badge(&kill.status);
    let details = kill.firewall_blocks_outbound || kill.hyperv_unfiltered;
    rsx! {
        Panel { title: t!("settings.killSwitch"), id: "set-kill-switch",
            div { class: "set-choices", role: "radiogroup", aria_label: t!("settings.killSwitch"),
                for level in LEVELS {
                    Choice {
                        key: "{level:?}",
                        level,
                        routing,
                        checked: shown == level,
                        // Never offered where it cannot be kept safe; a stored one stays shown.
                        unavailable: level == KillSwitchLevel::Strict && !kill.always_available,
                        disabled: applying,
                        on_pick: set_level,
                    }
                }
                if applying {
                    span { class: "set-applying", role: "status", Spinner {} {t!("ui.settings.killSwitch.applying")} }
                }
            }
            ActionError { error }
            div { class: "set-status-line",
                span { class: "set-status-label", {t!("ui.settings.killSwitch.status")} }
                Badge { tone, "{status_text}" }
                if let ProtectionStatus::Unconfirmed(reason) = &kill.status {
                    span { class: "set-hint", {tr(reason)} }
                }
            }
            if details {
                details { class: "set-details",
                    summary { {t!("ui.settings.killSwitch.details")} }
                    if kill.firewall_blocks_outbound {
                        p { class: "set-hint", {t!("ui.settings.killSwitch.firewallBlock")} }
                    }
                    if kill.hyperv_unfiltered {
                        p { class: "set-hint", {t!("ui.settings.killSwitch.hyperv")} }
                    }
                }
            }
            Exceptions {}
        }
    }
}

/// One choice: a native radio (keyboard and screen readers for free), its name and line.
#[component]
fn Choice(
    level: KillSwitchLevel,
    routing: RoutingMode,
    checked: bool,
    unavailable: bool,
    disabled: bool,
    on_pick: EventHandler<KillSwitchLevel>,
) -> Element {
    let [name, line, extra] = choice_keys(level, routing);
    // A stored "Always" without the service: it runs as "If the VPN drops" meanwhile.
    let note = match (unavailable, checked) {
        (true, true) => Some("ui.settings.killSwitch.alwaysAsOnDrop"),
        (true, false) => Some("ui.settings.killSwitch.needsService"),
        _ => None,
    };
    rsx! {
        label { class: "set-choice", class: if unavailable { "is-unavailable" },
            input {
                r#type: "radio",
                name: "kill-switch-level",
                checked,
                disabled: disabled || unavailable,
                onchange: move |_| on_pick.call(level),
            }
            span { class: "set-choice-text",
                span { class: "set-choice-name", {name.map(|k| t!(k))} }
                span { class: "set-choice-line",
                    {line.map(|k| t!(k))}
                    if let Some(extra) = extra {
                        {format!(" {}", t!(extra))}
                    }
                }
                if let Some(note) = note {
                    span { class: "set-choice-note", {t!(note)} }
                }
            }
        }
    }
}

#[component]
fn Exceptions() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let remove_job = use_job::<()>();
    let exceptions = ctx.kill.read().exceptions.clone();
    let remove_error = match remove_job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    rsx! {
        div { class: "set-subgroup", role: "group", aria_label: t!("killSwitch.exceptions"),
            p { class: "set-subgroup-title", {t!("killSwitch.exceptions")} }
            p { class: "set-hint", {t!("killSwitch.exceptionsDescription")} }
            if exceptions.is_empty() {
                p { class: "set-empty", {t!("killSwitch.noExceptions")} }
            } else {
                ul { class: "set-list",
                    for item in exceptions {
                        li { key: "{item.id}", class: "set-list-row",
                            Badge { tone: Tone::Neutral, {kind_label(item.kind)} }
                            div { class: "set-list-text",
                                span { class: "set-list-title", "{item.label}" }
                                span { class: "set-list-sub swiss-mono", title: "{item.value}", "{item.value}" }
                                // A broad network is allowed: a quiet hint, no dialog (research 5.8).
                                if item.broad {
                                    span { class: "set-hint", {t!("ui.settings.killSwitch.broadHint")} }
                                }
                            }
                            IconButton {
                                glyph: IconGlyph::Trash,
                                label: format!("{} {}", t!("common.remove"), item.label),
                                danger: true,
                                disabled: remove_job.running(),
                                onclick: {
                                    let api = api.clone();
                                    let id = item.id.clone();
                                    move |_| {
                                        let (api, id) = (api.clone(), id.clone());
                                        remove_job.start(move |_| async move { api.remove_exception(id).await });
                                    }
                                },
                            }
                        }
                    }
                }
            }
            ActionError { error: remove_error }
            AddException {}
        }
    }
}

/// The add form: type, value (+ «Выбрать приложение» for apps), label. A rejected exception
/// shows the backend's reason under the form (strict validation, U-04).
#[component]
fn AddException() -> Element {
    let api = use_api();
    let add_job = use_job::<()>();
    let browse_job = use_job::<()>();
    let mut kind = use_signal(|| ExceptionKind::App);
    let mut value = use_signal(String::new);
    let mut label = use_signal(String::new);
    let browse_api = api.clone();
    let browse = move |_| {
        let api = browse_api.clone();
        browse_job.start(move |_| async move {
            if let Some(app) = api.pick_app().await? {
                value.set(app.path);
                if label.peek().trim().is_empty() {
                    label.set(app.name);
                }
            }
            Ok(())
        });
    };
    let submit = use_callback(move |()| {
        let v = value.peek().trim().to_owned();
        if v.is_empty() || add_job.running() {
            return;
        }
        let l = match label.peek().trim() {
            "" => v.clone(),
            l => l.to_owned(),
        };
        let (api, k) = (api.clone(), *kind.peek());
        add_job.start(move |_| async move {
            api.add_exception(k, v, l).await?;
            value.set(String::new());
            label.set(String::new());
            Ok(())
        });
    });
    let error = match (add_job.last(), browse_job.last()) {
        (Some(Err(err)), _) | (_, Some(Err(err))) => Some(err),
        _ => None,
    };
    let placeholder = match kind() {
        ExceptionKind::App => t!("killSwitch.valuePlaceholderApp"),
        ExceptionKind::Ip => t!("killSwitch.valuePlaceholderIp"),
    };
    rsx! {
        div { class: "set-form", role: "group", aria_label: t!("killSwitch.addException"),
            p { class: "set-form-title", {t!("killSwitch.addException")} }
            div { class: "set-form-grid",
                div { class: "w-field",
                    span { class: "w-field-label", {t!("killSwitch.exceptionType")} }
                    Segmented {
                        label: t!("killSwitch.exceptionType"),
                        options: vec![
                            (ExceptionKind::App, t!("killSwitch.typeApp")),
                            (ExceptionKind::Ip, t!("killSwitch.typeIp")),
                        ],
                        value: kind(),
                        on_change: move |k| {
                            kind.set(k);
                            add_job.clear();
                        },
                    }
                }
                Field { label: t!("killSwitch.exceptionValue"),
                    div { class: "set-input-with",
                        TextInput {
                            value: value(),
                            oninput: move |v| {
                                value.set(v);
                                add_job.clear();
                            },
                            placeholder,
                            mono: true,
                            maxlength: 2048u32,
                            on_enter: move |()| submit.call(()),
                        }
                        if kind() == ExceptionKind::App {
                            Button { kind: ButtonKind::Ghost, busy: browse_job.running(), onclick: browse,
                                {t!("killSwitch.browseApp")}
                            }
                        }
                    }
                }
                Field { label: t!("killSwitch.exceptionLabel"),
                    TextInput {
                        value: label(),
                        oninput: move |v| label.set(v),
                        placeholder: t!("killSwitch.labelPlaceholder"),
                        maxlength: 200u32,
                        on_enter: move |()| submit.call(()),
                    }
                }
            }
            ActionError { error }
            div { class: "set-form-actions",
                Button {
                    kind: ButtonKind::Primary,
                    small: true,
                    busy: add_job.running(),
                    disabled: value().trim().is_empty(),
                    onclick: move |_| submit.call(()),
                    {t!("common.add")}
                }
            }
        }
    }
}
