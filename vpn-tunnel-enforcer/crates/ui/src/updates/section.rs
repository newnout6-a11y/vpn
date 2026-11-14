//! Settings → «Обновления»: automatic checks, downloading ahead, skipped versions, the last check
//! and where the feed came from, «Проверить сейчас», the rollback offer; and the «Движки» block:
//! each engine's version and origin with «Вернуть предыдущую» / «Вернуть встроенную».
use std::rc::Rc;

use dioxus::prelude::*;

use super::UpdatesApi;
use super::banner::act;
use super::format::{day_label, time_label};
use super::model::{CheckLine, CheckResult, EngineRow, ServiceLine, ServiceState};
use crate::hooks::use_watch;
use crate::lang::{LANG, tr};
use crate::t;
use crate::widgets::{Button, ButtonKind, JobSlot, Panel, Switch, use_job};

/// The section; renders nothing without an [`UpdatesApi`] in context.
#[component]
pub fn UpdatesSection() -> Element {
    let provided = try_use_context::<Rc<dyn UpdatesApi>>().is_some();
    rsx! {
        if provided {
            Updates {}
            Engines {}
        }
    }
}

#[component]
fn Updates() -> Element {
    let api = use_context::<Rc<dyn UpdatesApi>>();
    let state = use_watch(|| api.state());
    let job = use_job::<()>();
    let view = state.read().clone();
    let busy = job.running();
    let refused = match job.last() {
        Some(Err(err)) => Some(tr(&err.msg)),
        _ => None,
    };
    let off = !view.ready;
    let not_ready = off.then(|| t!("ui.update.notReady"));
    let (auto_api, ahead_api, check_api, reset_api, back_api) = (
        api.clone(),
        api.clone(),
        api.clone(),
        api.clone(),
        api.clone(),
    );
    rsx! {
        Panel { title: t!("ui.update.title"), id: "set-updates",
            if let Some(line) = refused {
                p { class: "set-error", id: "upd-refused", role: "alert", "{line}" }
            }
            if let Some(line) = not_ready.clone() {
                p { class: "set-hint", id: "upd-not-ready", "{line}" }
            }
            Switch {
                label: t!("ui.update.auto"),
                hint: t!("ui.update.autoHint"),
                checked: view.auto_check && view.ready,
                disabled: off || busy,
                disabled_reason: not_ready.clone(),
                on_change: move |on| act(job, &auto_api, |a| async move { a.set_auto_check(on).await }),
            }
            Switch {
                label: t!("ui.update.ahead"),
                hint: t!("ui.update.aheadHint"),
                checked: view.download_ahead,
                disabled: off || busy,
                disabled_reason: not_ready,
                on_change: move |on| act(job, &ahead_api, |a| async move { a.set_download_ahead(on).await }),
            }
            if let Some(line) = view.last_check.clone() {
                LastCheck { line }
            }
            if let Some(line) = view.service.clone() {
                Service { line }
            }
            div { class: "set-form-actions",
                Button {
                    id: "upd-check",
                    kind: ButtonKind::Ghost,
                    busy: view.checking,
                    disabled: off || busy,
                    onclick: move |_| act(job, &check_api, |a| async move { a.check_now().await }),
                    {t!("ui.update.checkNow")}
                }
                if let Some(version) = view.rollback_to.clone() {
                    Button {
                        id: "upd-rollback",
                        kind: ButtonKind::Ghost,
                        disabled: busy || view.progress.is_some(),
                        onclick: move |_| act(job, &back_api, |a| async move { a.rollback_app().await }),
                        {t!("ui.update.rollback", version = version)}
                    }
                }
            }
            if !view.skipped.is_empty() {
                div { class: "set-form-actions",
                    p { class: "set-hint", {t!("ui.update.skipped", versions = view.skipped.join(", "))} }
                    Button {
                        id: "upd-reset-skipped",
                        kind: ButtonKind::Ghost,
                        small: true,
                        disabled: busy,
                        onclick: move |_| act(job, &reset_api, |a| async move { a.reset_skipped().await }),
                        {t!("ui.update.resetSkipped")}
                    }
                }
            }
        }
    }
}

/// The helper service in one calm line: its version and its own update (p-svc-update).
#[component]
fn Service(line: ServiceLine) -> Element {
    let version = line.version;
    let text = match line.state {
        ServiceState::Unchecked => t!("ui.update.service.version", version = version),
        ServiceState::Current => t!("ui.update.service.current", version = version),
        ServiceState::Working => t!("ui.update.service.working", version = version),
        ServiceState::Waiting { target } => {
            t!(
                "ui.update.service.waiting",
                version = version,
                target = target
            )
        }
        ServiceState::Restarting { target } => {
            t!(
                "ui.update.service.restarting",
                version = version,
                target = target
            )
        }
        ServiceState::Failed => t!("ui.update.service.failed", version = version),
    };
    rsx! {
        p { class: "set-hint upd-service", id: "upd-service", "{text}" }
    }
}

/// «Последняя проверка: 12.11 14:03 · raw.githubusercontent.com через VPN» and what it found.
#[component]
fn LastCheck(line: CheckLine) -> Element {
    let lang = *LANG.read();
    let at = time_label(line.at, lang);
    let source = match (&line.host, line.via_vpn) {
        (Some(host), true) => Some(t!("ui.update.sourceVpn", host = host)),
        (Some(host), false) => Some(t!("ui.update.sourceDirect", host = host)),
        (None, _) => None,
    };
    let result = match line.result {
        CheckResult::UpToDate => t!("ui.update.result.upToDate"),
        CheckResult::Found => t!("ui.update.result.found"),
        CheckResult::Stale => t!("ui.update.result.stale"),
        CheckResult::Failed => t!("ui.update.result.failed"),
    };
    rsx! {
        p { class: "set-hint", id: "upd-last-check",
            {t!("ui.update.lastCheck", at = at)}
            if let Some(source) = source {
                " · {source}"
            }
            " · {result}"
        }
    }
}

/// «Движки»: version and origin of each engine, and the two ways back.
#[component]
fn Engines() -> Element {
    let api = use_context::<Rc<dyn UpdatesApi>>();
    let state = use_watch(|| api.state());
    let job = use_job::<()>();
    let rows = state.read().installed.clone();
    let refused = match job.last() {
        Some(Err(err)) => Some(tr(&err.msg)),
        _ => None,
    };
    rsx! {
        Panel { title: t!("ui.update.engines.title"), id: "set-engines",
            p { class: "set-hint", {t!("ui.update.engines.hint")} }
            if let Some(line) = refused {
                p { class: "set-error", role: "alert", "{line}" }
            }
            ul { class: "set-list",
                for row in rows {
                    EngineLine { key: "{row.id}", row, job }
                }
            }
        }
    }
}

#[component]
fn EngineLine(row: EngineRow, job: JobSlot<()>) -> Element {
    let api = use_context::<Rc<dyn UpdatesApi>>();
    let bundled_api = api.clone();
    let lang = *LANG.read();
    let origin = match &row.updated_on {
        Some(day) => t!("ui.update.engines.updated", day = day_label(day, lang)),
        None => t!("ui.update.engines.bundled"),
    };
    let busy = job.running();
    let (id, bundled_id) = (row.id.clone(), row.id.clone());
    rsx! {
        li { class: "set-list-row", id: "upd-engine-row-{row.id}",
            div { class: "set-list-text",
                span { class: "set-list-title", "{row.name} {row.version}" }
                span { class: "set-list-sub", "{origin}" }
            }
            div { class: "set-row-tools",
                if let Some(previous) = row.previous.clone() {
                    Button {
                        kind: ButtonKind::Ghost,
                        small: true,
                        disabled: busy,
                        onclick: move |_| {
                            let id = id.clone();
                            act(job, &api, |a| async move { a.revert_previous(id).await })
                        },
                        {t!("ui.update.engines.previous", version = previous)}
                    }
                }
                if row.can_restore_bundled {
                    Button {
                        kind: ButtonKind::Ghost,
                        small: true,
                        disabled: busy,
                        onclick: move |_| {
                            let id = bundled_id.clone();
                            act(job, &bundled_api, |a| async move { a.revert_bundled(id).await })
                        },
                        {t!("ui.update.engines.restoreBundled")}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use vpnte_base::Msg;
    use vpnte_base::i18n::Lang;

    /// p-svc-update: the helper service's line reads calmly in both languages, with its version
    /// and, where one waits, the next one.
    #[test]
    fn the_service_line_reads_calmly() {
        crate::test_locales::init_locales();
        for lang in [Lang::Ru, Lang::En] {
            for key in [
                "version",
                "current",
                "working",
                "waiting",
                "restarting",
                "failed",
            ] {
                let text = Msg::new(format!("ui.update.service.{key}"))
                    .arg("version", "2.0.0")
                    .arg("target", "2.0.1")
                    .render(lang);
                assert!(text.contains("2.0.0"), "{key}: {text}");
                assert!(!text.contains('!') && !text.contains("{{"), "{key}: {text}");
            }
        }
    }
}
