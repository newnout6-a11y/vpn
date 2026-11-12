//! «Умный режим РФ»: the split and maps switches and the rule-list auto update (draft), the list
//! status and «Обновить сейчас» (instant, with the SAVED settings: never saves the draft, U-02).
use dioxus::prelude::*;

use super::model::RuleSource;
use super::{ActionError, use_api, use_ctx};
use crate::lang::{LANG, tr};
use crate::servers::local_stamp;
use crate::t;
use crate::widgets::{Button, ButtonKind, Panel, Switch, use_job};

#[component]
pub(super) fn SmartRu() -> Element {
    let ctx = use_ctx();
    let view = ctx.view();
    rsx! {
        Panel { title: t!("ui.settings.smartRu.title"), id: "set-smart-ru",
            Switch {
                label: t!("ui.settings.smartRu.split"),
                hint: t!("ui.settings.smartRu.splitHint"),
                checked: view.smart_ru_split,
                on_change: move |on| ctx.edit(|p| p.smart_ru_split = Some(on)),
            }
            p { class: "set-hint set-indent", {t!("ui.settings.smartRu.splitNote")} }
            if view.smart_ru_split {
                Switch {
                    label: t!("ui.settings.smartRu.maps"),
                    hint: t!("ui.settings.smartRu.mapsHint"),
                    checked: view.smart_ru_maps_direct,
                    on_change: move |on| ctx.edit(|p| p.smart_ru_maps_direct = Some(on)),
                }
                RuleLists {}
            }
        }
    }
}

#[component]
fn RuleLists() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let job = use_job::<()>();
    let view = ctx.view();
    let (lists, saved_auto) = {
        let state = ctx.state.read();
        (state.rule_sets.clone(), state.settings.smart_ru_auto_update)
    };
    let refreshing = lists.refreshing || job.running();
    let source = if refreshing {
        t!("ui.settings.smartRu.refreshing")
    } else {
        match (lists.active_source, lists.managed_at) {
            (RuleSource::Managed, Some(at)) => {
                t!(
                    "ui.settings.smartRu.usingManaged",
                    when = local_stamp(at, *LANG.read())
                )
            }
            (RuleSource::Managed, None) => t!("ui.settings.smartRu.usingManagedUndated"),
            (RuleSource::Bundled, _) => t!("ui.settings.smartRu.usingBundled"),
        }
    };
    let refresh = move |_| {
        let api = api.clone();
        job.start(move |_| async move { api.refresh_rule_sets().await });
    };
    let error = match job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    rsx! {
        div { class: "set-subgroup", role: "group", aria_label: t!("ui.settings.smartRu.lists"),
            p { class: "set-subgroup-title", {t!("ui.settings.smartRu.lists")} }
            p { class: "set-hint", {t!("ui.settings.smartRu.listsHint")} }
            Switch {
                label: t!("ui.settings.smartRu.autoUpdate"),
                hint: t!("ui.settings.smartRu.autoUpdateHint"),
                checked: view.smart_ru_auto_update,
                on_change: move |on| ctx.edit(|p| p.smart_ru_auto_update = Some(on)),
            }
            div { class: "set-status-line",
                p { class: "set-status-text", role: "status", "{source}" }
                if saved_auto {
                    div { class: "set-status-actions",
                        Button {
                            kind: ButtonKind::Link,
                            busy: refreshing,
                            title: t!("ui.settings.smartRu.refreshTitle"),
                            onclick: refresh,
                            {t!("ui.settings.smartRu.refresh")}
                        }
                    }
                }
            }
            if !saved_auto {
                p { class: "set-hint", {t!("ui.settings.smartRu.refreshNeedsAuto")} }
            }
            if let Some(reason) = lists.last_error.as_ref().filter(|_| !refreshing) {
                p { class: "set-result is-warn", role: "status",
                    {t!("ui.settings.smartRu.refreshFailed", reason = tr(reason))}
                }
            }
            ActionError { error }
        }
    }
}
