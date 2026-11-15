//! Page structure: [`Panel`], [`SectionHeader`], [`Row`], [`EmptyState`], [`Trunc`].
use dioxus::prelude::*;

use super::fields::use_field_ctx;
use super::{title_if_long, use_dom_id};

/// A framed block of a page: hairline frame on paper, an optional 40 px head with a mono caption
/// and actions on the right (the dashboard panel look).
#[component]
pub fn Panel(
    #[props(default)] title: Option<String>,
    /// Header actions, usually `Button { kind: ButtonKind::Link }`s.
    #[props(default)]
    actions: Option<Element>,
    /// No padding in the body (tables and lists draw their own rules).
    #[props(default)]
    flush: bool,
    #[props(default)] id: Option<String>,
    children: Element,
) -> Element {
    let head_id = use_dom_id("w-panel");
    let has_head = title.is_some() || actions.is_some();
    rsx! {
        section {
            class: "w-panel",
            id,
            aria_labelledby: title.is_some().then(|| head_id.clone()),
            if has_head {
                header { class: "w-panel-head",
                    if let Some(title) = &title {
                        h2 { class: "swiss-label w-panel-title", id: "{head_id}", "{title}" }
                    }
                    if let Some(actions) = actions {
                        div { class: "w-panel-actions", {actions} }
                    }
                }
            }
            div { class: "w-panel-body", class: if flush { "is-flush" }, {children} }
        }
    }
}

/// The heading of a page section: an optional index number in signal mono («01»), the title, a
/// description under it, and actions on the right.
#[component]
pub fn SectionHeader(
    title: String,
    #[props(default)] number: Option<String>,
    #[props(default)] description: Option<String>,
    #[props(default)] id: Option<String>,
    #[props(default)] children: Element,
) -> Element {
    rsx! {
        div { class: "w-section-head",
            div { class: "w-section-text",
                h2 { class: "w-section-title", id,
                    if let Some(number) = number {
                        span { class: "w-section-num swiss-mono", "{number}" }
                    }
                    "{title}"
                }
                if let Some(description) = &description {
                    p { class: "w-section-desc", "{description}" }
                }
            }
            div { class: "w-section-actions", {children} }
        }
    }
}

/// A settings line: label and hint on the left, the control on the right, a hairline above.
/// The control inside is labelled by `label` (same mechanism as [`super::Field`]).
#[component]
pub fn Row(
    label: String,
    #[props(default)] hint: Option<String>,
    #[props(default)] error: Option<String>,
    children: Element,
) -> Element {
    let ctx = use_field_ctx(hint.is_some(), error.is_some());
    rsx! {
        div { class: "w-row", class: if error.is_some() { "is-invalid" },
            div { class: "w-row-text",
                label { class: "w-row-label", id: "{ctx.label_id()}", r#for: "{ctx.id()}", "{label}" }
                if let Some(hint) = &hint {
                    p { class: "w-row-hint", id: "{ctx.hint_id()}", "{hint}" }
                }
                if let Some(error) = &error {
                    p { class: "w-field-error", id: "{ctx.error_id()}", role: "alert", "{error}" }
                }
            }
            div { class: "w-row-control", {children} }
        }
    }
}

/// What a list shows when it has nothing (never used for a failed read: that is
/// [`super::LoadError`]).
#[component]
pub fn EmptyState(
    title: String,
    #[props(default)] detail: Option<String>,
    #[props(default)] children: Element,
) -> Element {
    rsx! {
        div { class: "w-empty",
            span { class: "w-empty-mark", aria_hidden: "true" }
            p { class: "w-empty-title", "{title}" }
            if let Some(detail) = detail {
                p { class: "w-empty-detail", "{detail}" }
            }
            div { class: "w-empty-action", {children} }
        }
    }
}

/// One line of text cut with an ellipsis; the full text is the hover title when it is long.
#[component]
pub fn Trunc(
    text: String,
    #[props(default = 32)] max: usize,
    #[props(default)] mono: bool,
) -> Element {
    let title = title_if_long(&text, max);
    rsx! {
        span { class: "w-trunc", class: if mono { "swiss-mono" }, title, "{text}" }
    }
}
