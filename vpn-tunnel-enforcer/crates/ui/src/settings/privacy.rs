//! Instant privacy actions of «Защита»: Windows location privacy (§3.1.4) and the re-homed
//! browser WebRTC protection (§6.4). Each shows its own outcome; neither touches the draft.
use dioxus::prelude::*;

use super::model::{BrowserStatus, BrowserView, LocationOutcome};
use super::{ActionError, toast, use_api, use_ctx};
use crate::lang::tr;
use crate::t;
use crate::widgets::{Badge, Button, ButtonKind, Switch, ToastKind, Tone, use_job};

/// Toast of a location-privacy outcome: (kind, title key, body key).
pub(super) fn location_toast(
    outcome: LocationOutcome,
    on: bool,
) -> (ToastKind, &'static str, &'static str) {
    match (outcome, on) {
        (LocationOutcome::Applied, true) => (
            ToastKind::Success,
            "ui.settings.location.hidden",
            "ui.settings.location.hiddenBody",
        ),
        (LocationOutcome::Applied, false) => (
            ToastKind::Success,
            "ui.settings.location.restored",
            "ui.settings.location.restoredBody",
        ),
        (LocationOutcome::Stored, true) => (
            ToastKind::Info,
            "ui.settings.location.willHide",
            "ui.settings.location.nextConnect",
        ),
        (LocationOutcome::Stored, false) => (
            ToastKind::Info,
            "ui.settings.location.wontHide",
            "ui.settings.location.storedBody",
        ),
        (LocationOutcome::NotApplied, _) => (
            ToastKind::Warning,
            "ui.settings.location.notApplied",
            "ui.settings.location.notAppliedBody",
        ),
    }
}

#[component]
pub(super) fn LocationPrivacy() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let job = use_job::<()>();
    let on = ctx.state.read().location_privacy;
    let toggle = move |next: bool| {
        let api = api.clone();
        job.start(move |_| async move {
            match api.set_location_privacy(next).await {
                Ok(outcome) => {
                    tracing::info!(target: "ui", on = next, ?outcome, "location privacy switched");
                    let (kind, title, body) = location_toast(outcome, next);
                    toast(kind, t!(title), Some(t!(body)));
                    Ok(())
                }
                Err(err) => {
                    if err.kind != vpnte_base::ErrorKind::Cancelled {
                        tracing::error!(target: "ui", error = %err, "location privacy switch failed");
                        toast(
                            ToastKind::Error,
                            t!("ui.settings.location.failed"),
                            Some(tr(&err.user_msg())),
                        );
                    }
                    Err(err)
                }
            }
        });
    };
    let error = match job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    rsx! {
        Switch {
            label: t!("ui.settings.location.label"),
            hint: t!("ui.settings.location.hint"),
            checked: on,
            busy: job.running(),
            on_change: toggle,
        }
        ActionError { error }
    }
}

fn status_badge(status: &BrowserStatus) -> (Tone, String, Option<String>) {
    match status {
        BrowserStatus::Protected => (Tone::Ok, t!("ui.settings.browser.protected"), None),
        BrowserStatus::NotProtected => (Tone::Warn, t!("ui.settings.browser.notProtected"), None),
        BrowserStatus::NotInstalled => {
            (Tone::Neutral, t!("ui.settings.browser.notInstalled"), None)
        }
        BrowserStatus::NotChecked => (Tone::Unknown, t!("ui.widgets.notChecked"), None),
        BrowserStatus::Failed(reason) => (
            Tone::Fail,
            t!("ui.settings.browser.failed"),
            Some(tr(reason)),
        ),
    }
}

#[component]
pub(super) fn BrowserProtection() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let job = use_job::<BrowserView>();
    let browser = ctx.state.read().browser.clone();
    let apply_api = api.clone();
    let apply = move |_| {
        let api = apply_api.clone();
        job.start(move |_| async move { api.apply_browser_protection().await });
    };
    let rollback = move |_| {
        let api = api.clone();
        job.start(move |_| async move { api.rollback_browser_protection().await });
    };
    let error = match job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    rsx! {
        div { class: "w-row set-browser",
            div { class: "w-row-text",
                span { class: "w-row-label", {t!("ui.settings.browser.label")} }
                p { class: "w-row-hint", {t!("ui.settings.browser.hint")} }
                if !browser.browsers.is_empty() {
                    ul { class: "set-browser-list",
                        for item in browser.browsers.iter() {
                            li { key: "{item.name}",
                                span { class: "set-browser-name", "{item.name}" }
                                {
                                    let (tone, text, reason) = status_badge(&item.status);
                                    rsx! {
                                        Badge { tone, title: reason.clone(), "{text}" }
                                        if let Some(reason) = reason {
                                            span { class: "set-hint", "{reason}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if browser.restart_required {
                    p { class: "set-result is-warn", role: "status", {t!("ui.settings.browser.restart")} }
                }
                ActionError { error }
            }
            div { class: "w-row-control",
                Button { kind: ButtonKind::Ghost, small: true, busy: job.running(), onclick: apply,
                    {t!("ui.settings.browser.apply")}
                }
                Button { kind: ButtonKind::Ghost, small: true, disabled: job.running(), onclick: rollback,
                    {t!("ui.settings.browser.rollback")}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ui-pages §7.2 (location toggle) → Rust: applied only with a session; otherwise stored with
    /// «Применится при следующем подключении»; a refusal by Windows is a warning, never success.
    #[test]
    fn location_outcomes_have_their_own_toasts() {
        let (kind, title, body) = location_toast(LocationOutcome::Applied, true);
        assert_eq!(
            (kind, title),
            (ToastKind::Success, "ui.settings.location.hidden")
        );
        assert_eq!(body, "ui.settings.location.hiddenBody");
        let (_, title, _) = location_toast(LocationOutcome::Applied, false);
        assert_eq!(title, "ui.settings.location.restored");
        let (kind, _, body) = location_toast(LocationOutcome::Stored, true);
        assert_eq!(
            (kind, body),
            (ToastKind::Info, "ui.settings.location.nextConnect")
        );
        let (kind, title, _) = location_toast(LocationOutcome::NotApplied, true);
        assert_eq!(
            (kind, title),
            (ToastKind::Warning, "ui.settings.location.notApplied")
        );
    }
}
