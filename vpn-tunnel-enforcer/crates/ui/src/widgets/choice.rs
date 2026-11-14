//! Choices: [`Switch`] (always labelled), [`Checkbox`], [`Segmented`] (a radio group) and
//! [`Tabs`]; the last two follow the roving-focus keyboard pattern ([`roving_index`]).
use std::rc::Rc;

use dioxus::prelude::*;

use super::feedback::Spinner;
use super::{title_with_reason, use_dom_id};

/// Where arrow keys move the focus in a group of `len` items (wrap-around; Home / End).
/// `None` for keys the group does not handle.
pub fn roving_index(len: usize, current: usize, key: &Key) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let current = current.min(len - 1);
    match key {
        Key::ArrowRight | Key::ArrowDown => Some((current + 1) % len),
        Key::ArrowLeft | Key::ArrowUp => Some((current + len - 1) % len),
        Key::Home => Some(0),
        Key::End => Some(len - 1),
        _ => None,
    }
}

/// An on/off switch with its label on the left (old switches had no accessible name, and the
/// label wrapped the button; ui-pages U-15). `hide_label` keeps the name for assistive
/// technology only, for places where the label is printed elsewhere.
#[component]
pub fn Switch(
    label: String,
    checked: bool,
    on_change: EventHandler<bool>,
    #[props(default)] hint: Option<String>,
    #[props(default)] disabled: bool,
    #[props(default)] disabled_reason: Option<String>,
    /// An apply is in flight: spinner, no clicks.
    #[props(default)]
    busy: bool,
    #[props(default)] hide_label: bool,
) -> Element {
    let id = use_dom_id("w-sw");
    let hint_id = format!("{id}-hint");
    let off = disabled || busy;
    let title = disabled
        .then(|| title_with_reason("", disabled_reason.as_deref()))
        .filter(|t| !t.is_empty());
    rsx! {
        div {
            class: "w-switch-row",
            class: if hide_label { "is-bare" },
            class: if off { "is-disabled" },
            if !hide_label {
                div { class: "w-switch-text",
                    label { class: "w-switch-label", r#for: "{id}", "{label}" }
                    if let Some(hint) = &hint {
                        p { class: "w-switch-hint", id: "{hint_id}", "{hint}" }
                    }
                }
            }
            if busy {
                Spinner {}
            }
            button {
                r#type: "button",
                id: "{id}",
                class: "w-switch",
                class: if checked { "is-on" },
                role: "switch",
                aria_checked: if checked { "true" } else { "false" },
                aria_label: hide_label.then(|| label.clone()),
                aria_describedby: hint.is_some().then(|| hint_id.clone()),
                aria_busy: busy.then_some("true"),
                disabled: off,
                title,
                onclick: move |_| {
                    if !off {
                        on_change.call(!checked);
                    }
                },
                span { class: "w-switch-thumb" }
            }
        }
    }
}

/// A square checkbox with its label to the right (linked by id, not nested).
#[component]
pub fn Checkbox(
    label: String,
    checked: bool,
    on_change: EventHandler<bool>,
    #[props(default)] disabled: bool,
    #[props(default)] hint: Option<String>,
) -> Element {
    let id = use_dom_id("w-cb");
    let hint_id = format!("{id}-hint");
    rsx! {
        div { class: "w-check-row", class: if disabled { "is-disabled" },
            input {
                r#type: "checkbox",
                class: "w-check",
                id: "{id}",
                checked,
                disabled,
                aria_describedby: hint.is_some().then(|| hint_id.clone()),
                onchange: move |evt| on_change.call(evt.checked()),
            }
            div { class: "w-check-text",
                label { class: "w-check-label", r#for: "{id}", "{label}" }
                if let Some(hint) = &hint {
                    p { class: "w-check-hint", id: "{hint_id}", "{hint}" }
                }
            }
        }
    }
}

/// Focus handles of a roving group, filled by `onmounted`.
type Handles = Signal<Vec<Option<Rc<MountedData>>>>;

fn remember(mut handles: Handles, index: usize, data: Rc<MountedData>) {
    let mut list = handles.write();
    if list.len() <= index {
        list.resize(index + 1, None);
    }
    list[index] = Some(data);
}

fn focus(handles: Handles, index: usize) {
    if let Some(Some(el)) = handles.peek().get(index).cloned() {
        spawn(async move {
            let _ = el.set_focus(true).await;
        });
    }
}

/// One choice out of a few, as a row of joined square segments (`role=radiogroup`; the arrow
/// keys move and select, Tab enters at the selected segment).
#[component]
pub fn Segmented<T: Clone + PartialEq + 'static>(
    options: Vec<(T, String)>,
    value: T,
    on_change: EventHandler<T>,
    /// Accessible name of the group.
    label: String,
    #[props(default)] disabled: bool,
) -> Element {
    let handles: Handles = use_signal(Vec::new);
    let selected = options.iter().position(|(v, _)| *v == value);
    let len = options.len();
    let values: Vec<T> = options.iter().map(|(v, _)| v.clone()).collect();
    rsx! {
        div {
            class: "w-seg",
            class: if disabled { "is-disabled" },
            role: "radiogroup",
            aria_label: "{label}",
            onkeydown: move |evt| {
                if disabled {
                    return;
                }
                if let Some(next) = roving_index(len, selected.unwrap_or(0), &evt.key()) {
                    evt.prevent_default();
                    evt.stop_propagation();
                    if Some(next) != selected {
                        on_change.call(values[next].clone());
                    }
                    focus(handles, next);
                }
            },
            for (i , (option , text)) in options.into_iter().enumerate() {
                button {
                    key: "{i}",
                    r#type: "button",
                    class: "w-seg-item",
                    class: if Some(i) == selected { "is-on" },
                    role: "radio",
                    aria_checked: if Some(i) == selected { "true" } else { "false" },
                    tabindex: if Some(i) == selected || (selected.is_none() && i == 0) { "0" } else { "-1" },
                    disabled,
                    onmounted: move |evt| remember(handles, i, evt.data()),
                    onclick: move |_| {
                        if Some(i) != selected {
                            on_change.call(option.clone());
                        }
                    },
                    "{text}"
                }
            }
        }
    }
}

/// A tab strip and the panel of the selected tab (`children`, rendered by the page). Tabs
/// activate on focus (arrow keys, Home / End); the panel is labelled by its tab.
#[component]
pub fn Tabs<T: Clone + PartialEq + 'static>(
    tabs: Vec<(T, String)>,
    value: T,
    on_change: EventHandler<T>,
    /// Accessible name of the tab list.
    label: String,
    children: Element,
) -> Element {
    let base = use_dom_id("w-tabs");
    let handles: Handles = use_signal(Vec::new);
    let selected = tabs.iter().position(|(v, _)| *v == value).unwrap_or(0);
    let len = tabs.len();
    let values: Vec<T> = tabs.iter().map(|(v, _)| v.clone()).collect();
    let panel_id = format!("{base}-panel");
    rsx! {
        div { class: "w-tabs",
            div {
                class: "w-tablist",
                role: "tablist",
                aria_label: "{label}",
                onkeydown: move |evt| {
                    if let Some(next) = roving_index(len, selected, &evt.key()) {
                        evt.prevent_default();
                        evt.stop_propagation();
                        if next != selected {
                            on_change.call(values[next].clone());
                        }
                        focus(handles, next);
                    }
                },
                for (i , (tab , text)) in tabs.into_iter().enumerate() {
                    button {
                        key: "{i}",
                        r#type: "button",
                        id: "{base}-tab-{i}",
                        class: "w-tab",
                        class: if i == selected { "is-on" },
                        role: "tab",
                        aria_selected: if i == selected { "true" } else { "false" },
                        aria_controls: "{panel_id}",
                        tabindex: if i == selected { "0" } else { "-1" },
                        onmounted: move |evt| remember(handles, i, evt.data()),
                        onclick: move |_| {
                            if i != selected {
                                on_change.call(tab.clone());
                            }
                        },
                        "{text}"
                    }
                }
            }
            div {
                class: "w-tabpanel",
                id: "{panel_id}",
                role: "tabpanel",
                aria_labelledby: "{base}-tab-{selected}",
                tabindex: "0",
                {children}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrows_wrap_and_home_end_jump() {
        assert_eq!(roving_index(3, 0, &Key::ArrowRight), Some(1));
        assert_eq!(roving_index(3, 2, &Key::ArrowRight), Some(0));
        assert_eq!(roving_index(3, 0, &Key::ArrowLeft), Some(2));
        assert_eq!(roving_index(3, 1, &Key::ArrowUp), Some(0));
        assert_eq!(roving_index(3, 1, &Key::ArrowDown), Some(2));
        assert_eq!(roving_index(3, 1, &Key::Home), Some(0));
        assert_eq!(roving_index(3, 1, &Key::End), Some(2));
        assert_eq!(roving_index(3, 1, &Key::Enter), None);
        assert_eq!(roving_index(0, 0, &Key::ArrowRight), None);
        assert_eq!(roving_index(2, 9, &Key::ArrowLeft), Some(0));
    }
}
