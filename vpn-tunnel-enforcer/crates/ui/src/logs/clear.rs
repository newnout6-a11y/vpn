//! «Очистить» of each tab: one button and a one-line confirmation that names exactly what goes
//! (the events / the sessions history / the technical logs); nothing else is touched. The call
//! runs in the button's slot: its toast comes after the reply and never after the page was left
//! (the app finishes a clear in its own task).
use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_base::{AppResult, ErrorKind};

use super::model::LogsApi;
use super::report::ClearSummary;
use super::{tr_now, use_api};
use crate::lang::translate_now;
use crate::t;
use crate::widgets::{Button, ButtonKind, ConfirmDialog, JobSlot, Toasts, use_job};

/// What a tab's «Очистить» empties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClearTarget {
    Events,
    History,
    Technical,
}

impl ClearTarget {
    /// Key part of its texts (`logs.erase.events.*`).
    fn key(self) -> &'static str {
        match self {
            ClearTarget::Events => "events",
            ClearTarget::History => "history",
            ClearTarget::Technical => "technical",
        }
    }
}

/// The call, and for the technical logs what happened file by file.
async fn run(api: &dyn LogsApi, target: ClearTarget) -> AppResult<Option<ClearSummary>> {
    match target {
        ClearTarget::Events => api.clear_events().await.map(|()| None),
        ClearTarget::History => api.clear_history().await.map(|()| None),
        ClearTarget::Technical => {
            let report = api.clear_technical().await?;
            Ok(Some(ClearSummary::of(&report)))
        }
    }
}

/// Runs the clear in `job` (single flight: a second start while one runs does nothing). The
/// toast comes after the reply; leaving the page drops the job and with it the toast.
pub(super) fn start(
    api: Rc<dyn LogsApi>,
    target: ClearTarget,
    job: JobSlot<()>,
    toasts: Toasts,
    mut open: Signal<bool>,
    on_done: EventHandler<()>,
) {
    let key = target.key();
    job.start(move |_token| async move {
        let result = run(&*api, target).await;
        open.set(false);
        match result {
            Ok(None) => {
                toasts.success(translate_now(&format!("logs.erase.{key}.done"), &[]), None);
            }
            Ok(Some(summary)) if summary.is_success() => {
                let (title, body) = summary.toast(&tr_now);
                toasts.success(title, Some(body));
            }
            Ok(Some(summary)) => {
                tracing::warn!(failed = summary.failed, "technical logs partly cleared");
                let (title, body) = summary.toast(&tr_now);
                toasts.error(title, Some(body));
            }
            Err(err) if err.kind == ErrorKind::Cancelled => {}
            Err(err) => {
                tracing::warn!(error = %err, target = key, "clear failed");
                toasts.error(
                    translate_now("logs.erase.failed", &[]),
                    Some(tr_now(&err.user_msg())),
                );
            }
        }
        on_done.call(());
        Ok(())
    });
}

/// The tab's «Очистить» with its confirmation; `on_done` after every finished clear.
#[component]
pub(super) fn ClearButton(
    target: ClearTarget,
    #[props(default)] on_done: EventHandler<()>,
) -> Element {
    let api = use_api();
    let toasts = Toasts::use_context();
    let job = use_job::<()>();
    let mut open = use_signal(|| false);
    let key = target.key();
    let confirm = move |()| start(api.clone(), target, job, toasts, open, on_done);
    rsx! {
        Button {
            kind: ButtonKind::Danger,
            small: true,
            busy: job.running(),
            onclick: move |_| open.set(true),
            {t!("logs.erase.action")}
        }
        ConfirmDialog {
            open,
            title: t!(&format!("logs.erase.{key}.title")),
            message: t!(&format!("logs.erase.{key}.confirm")),
            confirm_label: t!("logs.erase.action"),
            cancel_label: t!("common.cancel"),
            danger: true,
            busy: job.running(),
            on_confirm: confirm,
            on_cancel: move |()| open.set(false),
        }
    }
}
