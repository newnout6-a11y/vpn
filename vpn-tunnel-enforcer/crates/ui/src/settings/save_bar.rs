//! The save bar: shown while the draft differs from the live settings (ui-pages §3.1.2, §6.4).
//! «Сохранить и применить» sends only the changed fields; «Сбросить» forgets the edits.
use dioxus::prelude::*;

use super::{ActionError, toast, use_api, use_ctx};
use crate::lang::tr;
use crate::t;
use crate::widgets::{Button, ButtonKind, ToastKind, use_job};

#[component]
pub(super) fn SaveBar() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let job = use_job::<()>();
    let changed = {
        let live = &ctx.state.read().settings;
        ctx.draft.read().changed(live).len()
    };
    let saving = job.running();
    let error = match job.last() {
        Some(Err(err)) if changed > 0 => Some(err),
        _ => None,
    };
    if changed == 0 && !saving {
        return rsx! {};
    }
    let save = move |_| {
        let live = ctx.state.peek().settings.clone();
        let patch = ctx.draft.peek().to_save(&live);
        if patch.is_empty() {
            return;
        }
        let api = api.clone();
        let (mut draft, mut state) = (ctx.draft, ctx.state);
        job.start(move |_| async move {
            match api.save(patch.clone()).await {
                Ok(report) => {
                    tracing::info!(target: "ui", fields = ?patch.fields(), "settings saved");
                    draft.write().saved(&patch);
                    state.write().settings = report.settings.clone();
                    let (kind, title, body) = match &report.restart {
                        Some(Ok(())) => {
                            (ToastKind::Success, t!("ui.settings.save.restarted"), None)
                        }
                        Some(Err(reason)) => (
                            ToastKind::Warning,
                            t!("ui.settings.save.restartFailed"),
                            Some(tr(reason)),
                        ),
                        None if report.next_connect => {
                            (ToastKind::Success, t!("ui.settings.save.nextConnect"), None)
                        }
                        None => (ToastKind::Success, t!("ui.settings.save.done"), None),
                    };
                    toast(kind, title, body);
                    Ok(())
                }
                Err(err) => {
                    tracing::error!(target: "ui", error = %err, "settings save failed");
                    toast(
                        ToastKind::Error,
                        t!("ui.settings.save.failed"),
                        Some(tr(&err.user_msg())),
                    );
                    Err(err)
                }
            }
        });
    };
    let reset = move |_| {
        let mut draft = ctx.draft;
        draft.write().reset();
        job.clear();
    };
    rsx! {
        div { class: "set-savebar", role: "region", aria_label: t!("ui.settings.saveBar.title"),
            div { class: "set-savebar-text",
                p { class: "set-savebar-title", {t!("ui.settings.saveBar.title")} }
                p { class: "set-savebar-count",
                    {t!("ui.settings.saveBar.changed", count = changed)}
                    {t!("ui.settings.saveBar.press")}
                }
                ActionError { error }
            }
            div { class: "set-savebar-actions",
                button {
                    r#type: "button",
                    class: "w-btn is-ghost",
                    aria_label: t!("ui.settings.saveBar.resetName"),
                    disabled: saving,
                    onclick: reset,
                    span { class: "w-btn-text", {t!("common.reset")} }
                }
                Button { kind: ButtonKind::Primary, busy: saving, onclick: save,
                    if saving {
                        {t!("ui.settings.saveBar.saving")}
                    } else {
                        {t!("ui.settings.saveBar.save")}
                    }
                }
            }
        }
    }
}
