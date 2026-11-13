//! The quiet strip on the start page: the outcome of the last update, a newer app version, newer
//! engine versions and a download in flight — in the start page's own notice style.
use std::rc::Rc;

use dioxus::prelude::*;

use super::UpdatesApi;
use super::format::{day_label, megabytes, notes_for};
use super::model::{AppOffer, EngineOffer, UpdateOutcome, UpdatesView};
use crate::hooks::use_watch;
use crate::lang::{LANG, tr};
use crate::t;
use crate::widgets::{JobSlot, use_job};

/// The update strip; renders nothing without an [`UpdatesApi`] in context.
#[component]
pub fn UpdateBanner() -> Element {
    let provided = try_use_context::<Rc<dyn UpdatesApi>>().is_some();
    rsx! {
        if provided {
            Strips {}
        }
    }
}

/// Runs one API action in `job` (one at a time).
pub(super) fn act<F>(
    job: JobSlot<()>,
    api: &Rc<dyn UpdatesApi>,
    f: impl FnOnce(Rc<dyn UpdatesApi>) -> F,
) where
    F: Future<Output = vpnte_base::AppResult<()>> + 'static,
{
    let call = f(api.clone());
    job.start(move |_| call);
}

#[component]
fn Strips() -> Element {
    let api = use_context::<Rc<dyn UpdatesApi>>();
    let state = use_watch(|| api.state());
    let job = use_job::<()>();
    let view: UpdatesView = state.read().clone();
    let busy = job.running() || view.progress.is_some();
    // A refused click (another download runs, nothing new any more) says why in the same strip.
    let refused = match job.last() {
        Some(Err(err)) => Some(tr(&err.msg)),
        _ => None,
    };
    rsx! {
        if let Some(outcome) = view.outcome.clone() {
            OutcomeStrip { outcome, busy, job }
        }
        if let Some(line) = refused {
            div { class: "overflow-hidden",
                div { class: "c-swiss swiss-notice", role: "alert", id: "upd-refused",
                    p { class: "swiss-notice-body", "{line}" }
                }
            }
        }
        if let Some(progress) = view.progress.clone() {
            div { class: "overflow-hidden",
                div { class: "c-swiss swiss-notice", role: "status", aria_live: "polite", id: "upd-progress",
                    span { class: "swiss-label swiss-notice-tag", {t!("ui.update.downloading", what = progress.what)} }
                    p { class: "swiss-notice-body",
                        {t!("ui.update.progress", done = megabytes(progress.done), total = megabytes(progress.total))}
                    }
                }
            }
        }
        if let Some(offer) = view.app.clone() {
            AppStrip { offer, busy, job }
        }
        for offer in view.engines.iter().cloned() {
            EngineStrip { key: "{offer.id}", offer, busy, job }
        }
        if let Some(note) = view.note.clone() {
            div { class: "overflow-hidden",
                div { class: "c-swiss swiss-notice", role: "status", id: "upd-note",
                    p { class: "swiss-notice-body", {tr(&note.msg)} }
                    div { class: "swiss-confirm-actions",
                        button { r#type: "button", class: "swiss-confirm-no",
                            onclick: move |_| act(job, &api, |a| async move { a.dismiss().await }),
                            {t!("ui.update.dismiss")}
                        }
                    }
                }
            }
        }
    }
}

/// «Обновлено до 2.0.1» once, or «Обновление до 2.0.1 не установилось» with the kept installer.
#[component]
fn OutcomeStrip(outcome: UpdateOutcome, busy: bool, job: JobSlot<()>) -> Element {
    let api = use_context::<Rc<dyn UpdatesApi>>();
    let retry_api = api.clone();
    let (tag, failed) = match &outcome {
        UpdateOutcome::Updated { version } => (t!("ui.update.updated", version = version), false),
        UpdateOutcome::Failed { version } => (t!("ui.update.failed", version = version), true),
    };
    rsx! {
        div { class: "overflow-hidden",
            div { class: "c-swiss swiss-notice", role: "status", id: "upd-outcome",
                span { class: "swiss-label swiss-notice-tag", "{tag}" }
                if failed {
                    p { class: "swiss-notice-body", {t!("ui.update.failedBody")} }
                }
                div { class: "swiss-confirm-actions",
                    if failed {
                        button { r#type: "button", class: "swiss-confirm-yes", disabled: busy,
                            onclick: move |_| act(job, &retry_api, |a| async move { a.retry_installer().await }),
                            {t!("ui.update.retry")}
                        }
                    }
                    button { r#type: "button", class: "swiss-confirm-no",
                        onclick: move |_| act(job, &api, |a| async move { a.dismiss().await }),
                        {t!("ui.update.dismiss")}
                    }
                }
            }
        }
    }
}

/// «Доступна версия 2.0.1 · Что нового · [Обновить] [Позже] [Пропустить эту версию]»; a
/// security update has no «Пропустить» (the tray already said it once).
#[component]
fn AppStrip(offer: AppOffer, busy: bool, job: JobSlot<()>) -> Element {
    let api = use_context::<Rc<dyn UpdatesApi>>();
    let (later_api, skip_api) = (api.clone(), api.clone());
    let lang = *LANG.read();
    let notes = notes_for(&offer.notes, lang).map(str::to_owned);
    let tag = if offer.security {
        t!("ui.update.app.security", version = offer.version)
    } else {
        t!("ui.update.app.available", version = offer.version)
    };
    rsx! {
        div { class: "overflow-hidden",
            div { class: "c-swiss swiss-notice", role: "status", aria_live: "polite", id: "upd-app",
                span { class: "swiss-label swiss-notice-tag", "{tag}" }
                if let Some(notes) = notes {
                    details { class: "swiss-notice-body",
                        summary { {t!("ui.update.whatsNew")} }
                        p { "{notes}" }
                    }
                }
                div { class: "swiss-confirm-actions",
                    button { r#type: "button", class: "swiss-confirm-yes", id: "upd-app-go", disabled: busy,
                        onclick: move |_| act(job, &api, |a| async move { a.update_app().await }),
                        {t!("ui.update.app.update")}
                    }
                    button { r#type: "button", class: "swiss-confirm-no", disabled: busy,
                        onclick: move |_| act(job, &later_api, |a| async move { a.later_app().await }),
                        {t!("ui.update.later")}
                    }
                    if offer.can_skip {
                        button { r#type: "button", class: "swiss-confirm-no", disabled: busy,
                            onclick: move |_| act(job, &skip_api, |a| async move { a.skip_app().await }),
                            {t!("ui.update.app.skip")}
                        }
                    }
                }
            }
        }
    }
}

/// «sing-box 1.14.4 → 1.14.5 (проверено нами 12.11) · [Установить] [Позже]».
#[component]
fn EngineStrip(offer: EngineOffer, busy: bool, job: JobSlot<()>) -> Element {
    let api = use_context::<Rc<dyn UpdatesApi>>();
    let later_api = api.clone();
    let lang = *LANG.read();
    let notes = notes_for(&offer.notes, lang).map(str::to_owned);
    let tag = match &offer.tested_on {
        Some(day) => t!(
            "ui.update.engine.offerTested",
            name = offer.name,
            from = offer.from,
            to = offer.to,
            day = day_label(day, lang)
        ),
        None => t!(
            "ui.update.engine.offer",
            name = offer.name,
            from = offer.from,
            to = offer.to
        ),
    };
    let (id, later_id) = (offer.id.clone(), offer.id.clone());
    rsx! {
        div { class: "overflow-hidden",
            div { class: "c-swiss swiss-notice", role: "status", id: "upd-engine-{offer.id}",
                span { class: "swiss-label swiss-notice-tag", "{tag}" }
                if let Some(notes) = notes {
                    details { class: "swiss-notice-body",
                        summary { {t!("ui.update.whatsNew")} }
                        p { "{notes}" }
                    }
                }
                p { class: "swiss-notice-body", {t!("ui.update.engine.when")} }
                div { class: "swiss-confirm-actions",
                    button { r#type: "button", class: "swiss-confirm-yes", disabled: busy,
                        onclick: move |_| {
                            let id = id.clone();
                            act(job, &api, |a| async move { a.install_engine(id).await })
                        },
                        {t!("ui.update.engine.install")}
                    }
                    button { r#type: "button", class: "swiss-confirm-no", disabled: busy,
                        onclick: move |_| {
                            let id = later_id.clone();
                            act(job, &later_api, |a| async move { a.later_engine(id).await })
                        },
                        {t!("ui.update.later")}
                    }
                }
            }
        }
    }
}
