//! «Kill switch»: level (instant, applied and verified by the backend; U-04 shows «Применяем…»,
//! the failure reason and an unconfirmed state) and the exceptions editor.
use dioxus::prelude::*;

use super::model::{ExceptionKind, KillSwitchLevel, ProtectionStatus, RoutingMode};
use super::{ActionError, use_api, use_ctx};
use crate::lang::tr;
use crate::t;
use crate::widgets::{
    Badge, Button, ButtonKind, Field, IconButton, IconGlyph, Panel, Segmented, Spinner, TextInput,
    Tone, UiError, use_job,
};

/// What `level` does in `routing`: in Proxy mode the hold is the system proxy left on the
/// engine's port, and strict needs the Tunnel (WFP), so the Tunnel texts would promise too much.
pub(super) fn level_desc_key(level: KillSwitchLevel, routing: RoutingMode) -> &'static str {
    match (level, routing) {
        (KillSwitchLevel::Off, _) => "onboarding.killSwitchOffDesc",
        (KillSwitchLevel::Standard, RoutingMode::Hard) => "onboarding.killSwitchStandardDesc",
        (KillSwitchLevel::Strict, RoutingMode::Hard) => "onboarding.killSwitchStrictDesc",
        (KillSwitchLevel::Standard, RoutingMode::Soft) => "ui.wizard.protection.standardSoft",
        (KillSwitchLevel::Strict, RoutingMode::Soft) => "ui.wizard.protection.strictSoft",
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
    let applying = job.running();
    let shown = pending().filter(|_| applying).unwrap_or(kill.level);
    let set_level = move |level: KillSwitchLevel| {
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
    };
    let error = match job.last() {
        Some(Err(err)) => Some(UiError {
            kind: err.kind,
            msg: vpnte_base::Msg::new("ui.settings.killSwitch.levelFailed")
                .arg("reason", tr(&err.msg)),
        }),
        _ => None,
    };
    let (tone, status_text) = status_badge(&kill.status);
    rsx! {
        Panel { title: t!("settings.killSwitch"), id: "set-kill-switch",
            div { class: "w-row",
                div { class: "w-row-text",
                    span { class: "w-row-label", {t!("settings.killSwitchDescription")} }
                    p { class: "w-row-hint", {t!(level_desc_key(shown, ctx.view().routing_mode))} }
                }
                div { class: "w-row-control",
                    if applying {
                        span { class: "set-applying", role: "status", Spinner {} {t!("ui.settings.killSwitch.applying")} }
                    }
                    Segmented {
                        label: t!("settings.killSwitch"),
                        options: vec![
                            (KillSwitchLevel::Off, t!("settings.killSwitchOff")),
                            (KillSwitchLevel::Standard, t!("settings.killSwitchStandard")),
                            (KillSwitchLevel::Strict, t!("settings.killSwitchStrict")),
                        ],
                        value: shown,
                        disabled: applying,
                        on_change: set_level,
                    }
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
            if kill.firewall_blocks_outbound {
                p { class: "set-result is-warn", role: "alert", {t!("ui.settings.killSwitch.firewallBlock")} }
            }
            Exceptions {}
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
                            }
                            if item.broad {
                                Badge { tone: Tone::Warn, title: t!("ui.settings.killSwitch.broadHint"),
                                    {t!("ui.settings.killSwitch.broad")}
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
