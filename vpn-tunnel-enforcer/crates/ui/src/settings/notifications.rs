//! «Уведомления» (instant): the master switch (old «Уведомления Windows» row), the six events,
//! the delivery method, sound, and the Windows block state with its repair (U-07: one OS-state
//! value, re-read on window focus and after a reset).
use std::time::Duration;

use dioxus::prelude::*;
use vpnte_base::Msg;

use super::model::{NotificationChange, NotifyEvent, NotifyMethod, OsNotifications, ResetReport};
use super::{ActionError, Line, use_api, use_ctx};
use crate::lang::tr;
use crate::shell::WindowState;
use crate::t;
use crate::widgets::{Button, ButtonKind, Panel, Segmented, Switch, use_job};

/// The banner of a partial reset: the head line and the distinct reasons (`None` = all cleared).
pub(super) fn reset_banner(report: &ResetReport) -> Option<(Msg, Vec<Msg>)> {
    if report.errors.is_empty() {
        return None;
    }
    let mut reasons: Vec<Msg> = Vec::new();
    for reason in &report.errors {
        if !reasons.contains(reason) {
            reasons.push(reason.clone());
        }
    }
    let head = Msg::new("notifications.resetPartial")
        .arg("cleared", report.cleared)
        .arg("failed", report.errors.len());
    Some((head, reasons))
}

#[component]
pub(super) fn Notifications() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let set_job = use_job::<()>();
    let view = ctx.notifications.read().clone();
    let window = try_use_context::<WindowState>();
    let focus_api = api.clone();
    // "The user may have fixed it in Windows Settings without restarting the app."
    use_effect(move || {
        let focused = window.is_none_or(|w| w.focused());
        if focused {
            let api = focus_api.clone();
            spawn(async move {
                let _ = api.check_os_notifications().await;
            });
        }
    });
    let change = use_callback(move |change: NotificationChange| {
        let api = api.clone();
        set_job.start(move |_| async move { api.set_notification(change).await });
    });
    let error = match set_job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    let off = !view.enabled;
    rsx! {
        Panel { title: t!("notifications.title"), id: "set-notifications",
            Switch {
                label: t!("ui.settings.notifications.master"),
                hint: t!("ui.settings.notifications.masterHint"),
                checked: view.enabled,
                on_change: move |on| change.call(NotificationChange::Enabled(on)),
            }
            OsState { method: view.method }
            div { class: "set-subgroup", role: "group", aria_label: t!("ui.settings.notifications.events"),
                p { class: "set-subgroup-title", {t!("ui.settings.notifications.events")} }
                for event in NotifyEvent::ALL {
                    Switch {
                        key: "{event.key()}",
                        label: t!(&format!("notifications.{}", event.key())),
                        checked: view.event(event),
                        disabled: off,
                        disabled_reason: t!("ui.settings.notifications.masterOff"),
                        on_change: move |on| change.call(NotificationChange::Event(event, on)),
                    }
                }
            }
            Line { label: t!("notifications.method"),
                Segmented {
                    label: t!("notifications.method"),
                    options: vec![
                        (NotifyMethod::System, t!("notifications.methodSystem")),
                        (NotifyMethod::InApp, t!("notifications.methodInapp")),
                        (NotifyMethod::Both, t!("notifications.methodBoth")),
                    ],
                    value: view.method,
                    disabled: off,
                    on_change: move |m| change.call(NotificationChange::Method(m)),
                }
            }
            Switch {
                label: t!("notifications.soundEnabled"),
                checked: view.sound,
                disabled: off,
                disabled_reason: t!("ui.settings.notifications.masterOff"),
                on_change: move |on| change.call(NotificationChange::Sound(on)),
            }
            ActionError { error }
        }
    }
}

/// The Windows block state: the blocked banner with its two repairs, or a failed check with
/// «Повторить».
#[component]
fn OsState(method: NotifyMethod) -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let reset_job = use_job::<ResetReport>();
    let open_job = use_job::<()>();
    let check_job = use_job::<()>();
    let os = ctx.notifications.read().os.clone();
    let reset_api = api.clone();
    let reset = move |_| {
        let api = reset_api.clone();
        reset_job.start(move |_| async move {
            let report = api.reset_os_notification_block().await?;
            // Windows may apply the change a moment later: read once now and once after 1 s.
            let _ = api.check_os_notifications().await;
            let again = api.clone();
            spawn(async move {
                tokio::time::sleep(Duration::from_millis(1000)).await;
                let _ = again.check_os_notifications().await;
            });
            Ok(report)
        });
    };
    let open_api = api.clone();
    let open = move |_| {
        let api = open_api.clone();
        open_job.start(move |_| async move { api.open_windows_notification_settings().await });
    };
    let retry = move |_| {
        let api = api.clone();
        check_job.start(move |_| async move { api.check_os_notifications().await });
    };
    let partial = match reset_job.last() {
        Some(Ok(report)) => reset_banner(&report),
        _ => None,
    };
    let action_error = match (reset_job.last(), open_job.last(), check_job.last()) {
        (Some(Err(err)), _, _) | (_, Some(Err(err)), _) | (_, _, Some(Err(err))) => Some(err),
        _ => None,
    };
    rsx! {
        match os {
            OsNotifications::Blocked => rsx! {
                div { class: "set-note is-warn", role: "alert",
                    p { class: "set-note-title", {t!("notifications.osBlockedWarning")} }
                    p { {t!("notifications.osBlockedExplanation")} }
                    if matches!(method, NotifyMethod::System | NotifyMethod::Both) {
                        p { class: "set-hint", {t!("notifications.osBlockedHint")} }
                    }
                    div { class: "set-form-actions",
                        Button { kind: ButtonKind::Primary, small: true, busy: reset_job.running(), onclick: reset,
                            {t!("notifications.resetWindowsBlock")}
                        }
                        Button { kind: ButtonKind::Ghost, small: true, busy: open_job.running(), onclick: open,
                            {t!("notifications.openWindowsSettings")}
                        }
                    }
                }
            },
            OsNotifications::CheckFailed(reason) => rsx! {
                div { class: "set-status-line is-warn",
                    p { class: "set-status-text", role: "status",
                        {t!("notifications.osCheckError")} ": " {tr(&reason)}
                    }
                    div { class: "set-status-actions",
                        Button { kind: ButtonKind::Link, busy: check_job.running(), onclick: retry, {t!("common.retry")} }
                    }
                }
            },
            OsNotifications::Allowed | OsNotifications::Unknown => rsx! {},
        }
        if let Some((head, reasons)) = partial {
            p { class: "set-error", role: "alert",
                {tr(&head)} ": "
                {reasons.iter().map(tr).collect::<Vec<_>>().join("; ")}
            }
        }
        ActionError { error: action_error }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ui-pages §7.11 Notifications: a partial reset names the counts and the distinct
    /// canonical reasons; a full reset shows nothing.
    #[test]
    fn partial_reset_banner() {
        assert_eq!(
            reset_banner(&ResetReport {
                cleared: 2,
                errors: vec![]
            }),
            None
        );
        let report = ResetReport {
            cleared: 1,
            errors: vec![Msg::new("errors.permission"), Msg::new("errors.permission")],
        };
        let (head, reasons) = reset_banner(&report).expect("partial");
        assert_eq!(
            head,
            Msg::new("notifications.resetPartial")
                .arg("cleared", 1)
                .arg("failed", 2)
        );
        assert_eq!(reasons, [Msg::new("errors.permission")]);
    }
}
