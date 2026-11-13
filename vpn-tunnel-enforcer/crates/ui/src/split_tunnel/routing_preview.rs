//! The preview of a routing profile: the rules it adds, Smart RU, what already works and what is
//! not carried over with the reason; «Добавить в мои правила» and «Отмена».
use dioxus::prelude::*;

use super::routing::{EntryNote, PreviewEntry, PreviewRule, RoutingPreview, SmartRuStep};
use crate::lang::tr;
use crate::t;
use crate::widgets::{Button, ButtonKind};

/// Rows a list shows before «Показать все».
const FOLDED_ROWS: usize = 6;

#[component]
pub(super) fn PreviewView(
    preview: RoutingPreview,
    busy: bool,
    on_import: EventHandler<u64>,
    on_cancel: EventHandler<()>,
) -> Element {
    let title = match &preview.name {
        Some(name) => t!("splitTunneling.routing.profileNamed", name = name),
        None => t!("splitTunneling.routing.profile"),
    };
    let changes = preview.changes();
    let token = preview.token;
    let label = title.clone();
    rsx! {
        section { class: "apps-routing-preview", aria_label: label,
            h3 { class: "apps-routing-name", {title} }
            if preview.off {
                p { class: "apps-routing-line", {t!("splitTunneling.routing.off")} }
            }
            if !preview.add.is_empty() {
                RuleList { rules: preview.add.clone() }
            }
            if let Some(step) = preview.smart_ru.clone() {
                SmartRuLine { step }
            }
            if !preview.covered.is_empty() {
                EntryList {
                    title: t!("splitTunneling.routing.coveredTitle", count = preview.covered.len()),
                    entries: preview.covered.clone(),
                }
            }
            if !preview.skipped.is_empty() || !preview.kept.is_empty() {
                EntryList {
                    title: t!(
                        "splitTunneling.routing.skippedTitle",
                        count = preview.skipped.len() + preview.kept.len()
                    ),
                    entries: preview.skipped.clone(),
                    kept: preview.kept.iter().map(|k| tr(&k.msg())).collect::<Vec<_>>(),
                }
            }
            if !changes && !preview.off {
                p { class: "apps-routing-line", {t!("splitTunneling.routing.nothingToAdd")} }
            }
            div { class: "apps-routing-actions",
                if changes {
                    Button {
                        busy,
                        onclick: move |_| on_import.call(token),
                        {t!("splitTunneling.routing.import")}
                    }
                }
                Button {
                    kind: ButtonKind::Ghost,
                    disabled: busy,
                    onclick: move |_| on_cancel.call(()),
                    {if changes { t!("common.cancel") } else { t!("common.close") }}
                }
            }
        }
    }
}

/// «Будет добавлено в ваши правила (N)»: pattern and route, folded after a few rows.
#[component]
fn RuleList(rules: Vec<PreviewRule>) -> Element {
    let mut all = use_signal(|| false);
    let total = rules.len();
    let shown = if all() { total } else { total.min(FOLDED_ROWS) };
    rsx! {
        div { class: "apps-routing-group",
            p { class: "apps-routing-head", {t!("splitTunneling.routing.addTitle", count = total)} }
            ul { class: "apps-routing-list",
                for rule in rules.into_iter().take(shown) {
                    li { class: "apps-routing-row",
                        span { class: "apps-routing-entry swiss-mono", {rule.pattern} }
                        span { class: "apps-routing-route", "data-route": "{rule.route:?}", {t!(rule.route.label_key())} }
                    }
                }
            }
            if total > shown {
                Button { kind: ButtonKind::Link, small: true, onclick: move |_| all.set(true),
                    {t!("splitTunneling.routing.showAll", count = total)}
                }
            }
        }
    }
}

/// Smart RU: switched on by the import, or on already; the entries that ask for it.
#[component]
fn SmartRuLine(step: SmartRuStep) -> Element {
    let key = if step.turn_on {
        "splitTunneling.routing.smartRuTurnOn"
    } else {
        "splitTunneling.routing.smartRuAlreadyOn"
    };
    rsx! {
        div { class: "apps-routing-group",
            p { class: "apps-routing-line", {t!(key)} }
            p { class: "apps-routing-from swiss-mono", {step.from.join(", ")} }
        }
    }
}

/// Entries with where the profile sends them and the reason they are not added; `kept` are the
/// profile's settings that stay as the user has them, listed after the entries.
#[component]
fn EntryList(
    title: String,
    entries: Vec<PreviewEntry>,
    #[props(default)] kept: Vec<String>,
) -> Element {
    let mut all = use_signal(|| false);
    let total = entries.len() + kept.len();
    let shown = if all() { total } else { total.min(FOLDED_ROWS) };
    let kept_shown = shown.saturating_sub(entries.len());
    rsx! {
        div { class: "apps-routing-group",
            p { class: "apps-routing-head", {title} }
            ul { class: "apps-routing-list",
                for entry in entries.into_iter().take(shown) {
                    li { class: "apps-routing-row",
                        span { class: "apps-routing-entry swiss-mono", {entry.text.clone()} }
                        span { class: "apps-routing-route", "data-route": "{entry.route:?}", {t!(entry.route.label_key())} }
                        span { class: "apps-routing-note", {note_text(entry.note)} }
                    }
                }
                for line in kept.into_iter().take(kept_shown) {
                    li { class: "apps-routing-row is-kept",
                        span { class: "apps-routing-note", {line} }
                    }
                }
            }
            if total > shown {
                Button { kind: ButtonKind::Link, small: true, onclick: move |_| all.set(true),
                    {t!("splitTunneling.routing.showAll", count = total)}
                }
            }
        }
    }
}

/// The reason next to an entry (the user's own rule names its route).
pub(super) fn note_text(note: EntryNote) -> String {
    match note {
        EntryNote::YourRule(route) => t!(note.key(), route = t!(route.label_key())),
        other => t!(other.key()),
    }
}
