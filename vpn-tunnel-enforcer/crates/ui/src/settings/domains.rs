//! «Маршрутизация по доменам» (instant): the rules in priority order with hit counters, add /
//! edit / delete, reorder with ↑ ↓ (keyboard-friendly, no drag library), list import with a
//! preview and one action for all imported domains (routing-dns B-DR-5), and the order in which
//! user rules and Smart RU apply (owner 10.4 B / B-DR-8).
use dioxus::prelude::*;

use super::model::{
    DomainAction, DomainImportPreview, DomainImportReport, DomainRuleView, SmartRoute,
};
use super::{ActionError, use_api, use_ctx};
use crate::lang::tr;
use crate::t;
use crate::widgets::{
    Badge, Button, ButtonKind, IconButton, IconGlyph, Panel, Segmented, Select, SelectOption, Size,
    TextInput, Tone, use_job,
};

fn action_label(action: DomainAction) -> String {
    match action {
        DomainAction::Vpn => t!("domainRouting.actionVpn"),
        DomainAction::Direct => t!("domainRouting.actionDirect"),
        DomainAction::Block => t!("domainRouting.actionBlock"),
    }
}

fn action_tone(action: DomainAction) -> Tone {
    match action {
        DomainAction::Vpn => Tone::Neutral,
        DomainAction::Direct => Tone::Ok,
        DomainAction::Block => Tone::Fail,
    }
}

/// The ids in the new order after moving `index` by `delta` (`None` at the edges).
pub(super) fn moved(rules: &[DomainRuleView], index: usize, delta: isize) -> Option<Vec<String>> {
    let target = index
        .checked_add_signed(delta)
        .filter(|&t| t < rules.len())?;
    let mut ids: Vec<String> = rules.iter().map(|r| r.id.clone()).collect();
    ids.swap(index, target);
    Some(ids)
}

#[component]
pub(super) fn Domains() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let mut adding = use_signal(|| false);
    let mut editing = use_signal(|| None::<String>);
    let row_job = use_job::<()>();
    let import_job = use_job::<Option<DomainImportPreview>>();
    // Each pick gets a fresh preview box: the previous box's import report must not stay over it.
    let mut picks = use_signal(|| 0u32);
    let view = ctx.domains.read().clone();
    let pick_api = api.clone();
    let pick = move |_| {
        let api = pick_api.clone();
        import_job.start(move |_| async move {
            let picked = api.pick_domain_list().await?;
            picks += 1;
            Ok(picked)
        });
    };
    let row_error = match row_job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    let (preview, import_error) = match import_job.last() {
        Some(Ok(preview)) => (preview, None),
        Some(Err(err)) => (None, Some(err)),
        None => (None, None),
    };
    let busy = row_job.running();
    let count = view.rules.len();
    rsx! {
        Panel {
            title: t!("domainRouting.title"),
            id: "set-domains",
            actions: rsx! {
                Button { kind: ButtonKind::Link, busy: import_job.running(), onclick: pick, {t!("domainRouting.import")} }
                Button {
                    kind: ButtonKind::Link,
                    onclick: move |_| {
                        editing.set(None);
                        adding.set(true);
                    },
                    {t!("domainRouting.addRule")}
                }
            },
            p { class: "set-hint", {t!("domainRouting.description")} }
            RuleOrder { smart_ru: view.smart_ru }
            if let Some(preview) = preview {
                ImportPreviewBox { key: "{picks}", preview, on_close: move |()| import_job.clear() }
            }
            ActionError { error: import_error }
            if adding() {
                RuleForm {
                    pattern: String::new(),
                    action: DomainAction::Vpn,
                    on_done: move |()| adding.set(false),
                    edit_id: None,
                }
            }
            if view.rules.is_empty() {
                p { class: "set-empty", {t!("domainRouting.noRules")} }
            } else {
                ol { class: "set-list set-rules",
                    for (index, rule) in view.rules.iter().cloned().enumerate() {
                        if editing().as_deref() == Some(rule.id.as_str()) {
                            li { key: "{rule.id}", class: "set-list-row is-editing",
                                RuleForm {
                                    pattern: rule.pattern.clone(),
                                    action: rule.action,
                                    on_done: move |()| editing.set(None),
                                    edit_id: Some(rule.id.clone()),
                                }
                            }
                        } else {
                            RuleRow {
                                key: "{rule.id}",
                                index,
                                count,
                                rule: rule.clone(),
                                busy,
                                on_edit: move |id: String| {
                                    adding.set(false);
                                    editing.set(Some(id));
                                },
                                on_move: {
                                    let api = api.clone();
                                    move |delta: isize| {
                                        let rules = ctx.domains.peek().rules.clone();
                                        if let Some(ids) = moved(&rules, index, delta) {
                                            let api = api.clone();
                                            row_job.start(move |_| async move { api.reorder_domain_rules(ids).await });
                                        }
                                    }
                                },
                                on_delete: {
                                    let api = api.clone();
                                    move |id: String| {
                                        let api = api.clone();
                                        row_job.start(move |_| async move { api.delete_domain_rule(id).await });
                                    }
                                },
                            }
                        }
                    }
                }
                p { class: "set-hint", {t!("ui.settings.domains.orderHint")} }
            }
            ActionError { error: row_error }
        }
    }
}

/// Which rules win, top to bottom (the routing generator's fixed order: the user's own rules
/// before Smart RU, owner answer 4).
#[component]
fn RuleOrder(smart_ru: bool) -> Element {
    rsx! {
        details { class: "set-order",
            summary { {t!("ui.settings.domains.orderTitle")} }
            ol {
                li { {t!("ui.settings.domains.orderBlock")} }
                li { {t!("ui.settings.domains.orderUser")} }
                if smart_ru {
                    li { {t!("ui.settings.domains.orderSmartPins")} }
                    li { {t!("ui.settings.domains.orderSmartDirect")} }
                    li { {t!("ui.settings.domains.orderGeoip")} }
                }
                li { {t!("ui.settings.domains.orderFinal")} }
            }
        }
    }
}

/// The one line under a rule that overrides Smart RU's own choice for its site.
fn override_note(smart: SmartRoute) -> String {
    match smart {
        SmartRoute::Direct => t!("ui.settings.domains.overridesDirect"),
        SmartRoute::Vpn => t!("ui.settings.domains.overridesVpn"),
    }
}

#[component]
fn RuleRow(
    index: usize,
    count: usize,
    rule: DomainRuleView,
    busy: bool,
    on_edit: EventHandler<String>,
    on_move: EventHandler<isize>,
    on_delete: EventHandler<String>,
) -> Element {
    let (edit_id, delete_id) = (rule.id.clone(), rule.id.clone());
    let position = index + 1;
    rsx! {
        li { class: "set-list-row",
            span { class: "set-rule-num swiss-mono", "#{position}" }
            div { class: "set-list-text",
                span { class: "set-list-title swiss-mono", "{rule.pattern}" }
                if rule.hits > 0 {
                    span { class: "set-list-sub", title: t!("ui.settings.domains.hitsTitle"),
                        {t!("domainRouting.hits", count = rule.hits)}
                    }
                }
                if let Some(smart) = rule.overrides {
                    span { class: "set-list-sub", {override_note(smart)} }
                }
            }
            Badge { tone: action_tone(rule.action), {action_label(rule.action)} }
            div { class: "set-row-tools",
                IconButton {
                    glyph: IconGlyph::ChevronUp,
                    label: t!("ui.settings.domains.moveUp", pattern = rule.pattern.clone()),
                    disabled: busy || index == 0,
                    onclick: move |_| on_move.call(-1),
                }
                IconButton {
                    glyph: IconGlyph::ChevronDown,
                    label: t!("ui.settings.domains.moveDown", pattern = rule.pattern.clone()),
                    disabled: busy || index + 1 >= count,
                    onclick: move |_| on_move.call(1),
                }
                IconButton {
                    glyph: IconGlyph::Edit,
                    label: t!("ui.settings.domains.edit", pattern = rule.pattern.clone()),
                    disabled: busy,
                    onclick: move |_| on_edit.call(edit_id.clone()),
                }
                IconButton {
                    glyph: IconGlyph::Trash,
                    label: t!("ui.settings.domains.delete", pattern = rule.pattern.clone()),
                    danger: true,
                    disabled: busy,
                    onclick: move |_| on_delete.call(delete_id.clone()),
                }
            }
        }
    }
}

/// Add (no `edit_id`) or edit a rule: Enter saves, Escape cancels, the backend's validation
/// message shows under the field (never «[object Object]», U-06).
#[component]
fn RuleForm(
    pattern: String,
    action: DomainAction,
    edit_id: Option<String>,
    on_done: EventHandler<()>,
) -> Element {
    let api = use_api();
    let job = use_job::<()>();
    let mut text = use_signal(move || pattern);
    let mut chosen = use_signal(move || action);
    let mut blank = use_signal(|| false);
    let submit = use_callback(move |()| {
        let value = text.peek().trim().to_owned();
        if value.is_empty() {
            blank.set(true);
            return;
        }
        let (api, act, id) = (api.clone(), *chosen.peek(), edit_id.clone());
        job.start(move |_| async move {
            match id {
                Some(id) => api.update_domain_rule(id, value, act).await?,
                None => api.add_domain_rule(value, act).await?,
            }
            on_done.call(());
            Ok(())
        });
    });
    let error = match job.last() {
        Some(Err(err)) => Some(tr(&err.msg)),
        _ if blank() => Some(t!("ui.settings.domains.patternEmpty")),
        _ => None,
    };
    let options: Vec<_> = DomainAction::ALL
        .into_iter()
        .map(|a| SelectOption::new(a, action_label(a)))
        .collect();
    rsx! {
        div { class: "set-rule-form",
            div { class: "set-rule-fields",
                TextInput {
                    value: text(),
                    oninput: move |v| {
                        text.set(v);
                        blank.set(false);
                        job.clear();
                    },
                    placeholder: t!("domainRouting.patternPlaceholder"),
                    aria_label: t!("domainRouting.pattern"),
                    invalid: error.is_some(),
                    mono: true,
                    maxlength: 253u32,
                    initial_focus: true,
                    on_enter: move |()| submit.call(()),
                    on_escape: move |()| on_done.call(()),
                }
                Select {
                    options,
                    value: Some(chosen()),
                    aria_label: t!("domainRouting.action"),
                    size: Size::Sm,
                    on_change: move |a| chosen.set(a),
                }
                IconButton {
                    glyph: IconGlyph::Check,
                    label: t!("common.save"),
                    busy: job.running(),
                    onclick: move |_| submit.call(()),
                }
                IconButton {
                    glyph: IconGlyph::Close,
                    label: t!("common.cancel"),
                    onclick: move |_| on_done.call(()),
                }
            }
            p { class: "set-hint", {t!("ui.settings.domains.patternHint")} }
            if let Some(error) = error {
                p { class: "set-error", role: "alert", "{error}" }
            }
        }
    }
}

/// A picked domain list: what it holds and one action for all of it (preselected «Напрямую»,
/// the old import's only action).
#[component]
fn ImportPreviewBox(preview: DomainImportPreview, on_close: EventHandler<()>) -> Element {
    let api = use_api();
    let job = use_job::<DomainImportReport>();
    let mut action = use_signal(|| DomainAction::Direct);
    let discard_api = api.clone();
    let close = move |_| {
        let api = discard_api.clone();
        // The box unmounts right away: a task of its own scope would be dropped unpolled.
        dioxus::core::spawn_forever(async move { api.discard_domain_list().await });
        on_close.call(());
    };
    let import = move |_| {
        let (api, act) = (api.clone(), *action.peek());
        job.start(move |_| async move { api.import_domain_list(act).await });
    };
    let options: Vec<_> = DomainAction::ALL
        .into_iter()
        .map(|a| (a, action_label(a)))
        .collect();
    let done = job.last();
    rsx! {
        div { class: "set-note set-import", role: "group", aria_label: t!("domainRouting.import"),
            p { class: "set-note-title",
                {t!("ui.settings.domains.importFile", name = preview.file_name.clone())}
            }
            p { {t!("ui.settings.domains.importNew", count = preview.new_rules)} }
            if preview.duplicates + preview.invalid + preview.over_limit > 0 {
                p { class: "set-hint",
                    {t!("ui.settings.domains.importSkipped",
                        duplicates = preview.duplicates,
                        invalid = preview.invalid,
                        over = preview.over_limit)}
                }
            }
            match done {
                Some(Ok(report)) => rsx! {
                    p { class: "set-result", role: "status", {t!("ui.settings.domains.imported", count = report.added)} }
                    div { class: "set-form-actions",
                        Button { kind: ButtonKind::Ghost, small: true, onclick: move |_| on_close.call(()), {t!("common.close")} }
                    }
                },
                other => rsx! {
                    div { class: "set-form-actions",
                        Segmented {
                            label: t!("domainRouting.action"),
                            options,
                            value: action(),
                            disabled: job.running(),
                            on_change: move |a| action.set(a),
                        }
                        Button {
                            kind: ButtonKind::Primary,
                            small: true,
                            busy: job.running(),
                            disabled: preview.new_rules == 0,
                            onclick: import,
                            {t!("ui.settings.domains.importApply")}
                        }
                        Button { kind: ButtonKind::Ghost, small: true, disabled: job.running(), onclick: close,
                            {t!("common.cancel")}
                        }
                    }
                    if let Some(Err(err)) = other {
                        ActionError { error: Some(err) }
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(n: usize) -> Vec<DomainRuleView> {
        (0..n)
            .map(|i| DomainRuleView {
                id: format!("r{i}"),
                pattern: format!("site{i}.example"),
                action: DomainAction::Vpn,
                hits: 0,
                overrides: None,
            })
            .collect()
    }

    /// Reorder sends the whole new order; the edges do nothing.
    #[test]
    fn moving_swaps_neighbours_inside_the_list() {
        let list = rules(3);
        assert_eq!(moved(&list, 1, -1).unwrap(), ["r1", "r0", "r2"]);
        assert_eq!(moved(&list, 1, 1).unwrap(), ["r0", "r2", "r1"]);
        assert_eq!(moved(&list, 0, -1), None);
        assert_eq!(moved(&list, 2, 1), None);
        assert_eq!(moved(&[], 0, 1), None);
    }
}
