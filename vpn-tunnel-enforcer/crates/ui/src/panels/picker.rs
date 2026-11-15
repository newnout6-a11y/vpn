//! The proxy picker: a small ARIA combobox with the old MacSelect's markup; its keyboard rules are
//! the shared MacSelect model of [`crate::widgets::select_key`].
//!
//! Focus stays on the trigger while the list is open (`aria-activedescendant`); mousedown in
//! the list keeps it there, so leaving the trigger (click elsewhere, Tab) closes the list. The
//! list escapes the panel's `overflow: hidden` through `css/pages/panels.css` (D-27).
use std::rc::Rc;

use dioxus::prelude::*;

use super::icons::Chevron;
use super::rules::Indicator;
use crate::widgets::{SelectKey, SelectState, initial_active, select_key};

/// One option of the picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PickerOption {
    pub id: String,
    pub label: String,
    pub indicator: Indicator,
    pub indicator_label: String,
    pub disabled: bool,
}

fn indicator_class(indicator: Indicator) -> &'static str {
    match indicator {
        Indicator::Success => {
            "h-2 w-2 flex-shrink-0 rounded-full bg-[var(--color-success)] shadow-[0_0_0_3px_color-mix(in_srgb,var(--color-success)_16%,transparent)]"
        }
        Indicator::Danger => {
            "h-2 w-2 flex-shrink-0 rounded-full bg-[var(--color-danger)] shadow-[0_0_0_3px_color-mix(in_srgb,var(--color-danger)_14%,transparent)]"
        }
        Indicator::Muted => "h-2 w-2 flex-shrink-0 rounded-full bg-[var(--color-text-muted)]",
    }
}

/// Classes of an option row, as the old component produced them after `tailwind-merge`.
fn option_class(selected: bool, active: bool, disabled: bool) -> String {
    let mut class = String::from("px-2 py-1 text-xs");
    if !disabled {
        class.push_str(" cursor-pointer");
    }
    class.push_str(" transition-colors duration-[var(--transition-fast)]");
    match (selected, active) {
        (true, true) => class.push_str(" text-[var(--color-accent)] bg-[var(--color-border)]/50"),
        (true, false) => class.push_str(" bg-[var(--color-accent)]/10 text-[var(--color-accent)]"),
        (false, true) => class.push_str(
            " text-[var(--color-text)] hover:bg-[var(--color-border)]/50 bg-[var(--color-border)]/50",
        ),
        (false, false) => class.push_str(" text-[var(--color-text)] hover:bg-[var(--color-border)]/50"),
    }
    if disabled {
        class.push_str(" opacity-50 cursor-not-allowed");
    }
    class
}

const TRIGGER: &str = "w-full flex items-center justify-between h-8 px-2 text-xs bg-[var(--color-card)] rounded-[var(--radius-sm)] border transition-colors duration-[var(--transition-fast)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)] focus:border-transparent disabled:opacity-50 disabled:cursor-not-allowed";

/// Status dot + truncated label (the old `OptionLabel`).
#[component]
fn OptionLabel(option: PickerOption) -> Element {
    rsx! {
        span { class: "flex min-w-0 items-center gap-2",
            span {
                class: indicator_class(option.indicator),
                role: "img",
                aria_label: "{option.indicator_label}",
                title: "{option.indicator_label}",
            }
            span { class: "truncate", "{option.label}" }
        }
    }
}

/// The combobox. `id` prefixes the element ids; `value` is the chosen option's id.
#[component]
pub(super) fn Picker(
    id: &'static str,
    label: String,
    placeholder: String,
    options: Vec<PickerOption>,
    value: Option<String>,
    disabled: bool,
    on_change: EventHandler<String>,
) -> Element {
    let mut open = use_signal(|| false);
    let mut active = use_signal(|| None::<usize>);
    let mut trigger = use_signal(|| None::<Rc<MountedData>>);
    let can_open = !disabled && !options.is_empty();
    // Disabled (an action runs) or emptied while open: close, so it does not pop up again later.
    use_effect(use_reactive((&can_open,), move |(can_open,)| {
        if !can_open && *open.peek() {
            open.set(false);
        }
    }));
    let is_open = open() && can_open;
    let enabled: Vec<bool> = options.iter().map(|o| !o.disabled).collect();
    let selected = value
        .as_deref()
        .and_then(|v| options.iter().position(|o| o.id == v));
    let active_now = active().filter(|_| is_open);

    let mut show = {
        let enabled = enabled.clone();
        move |at: Option<usize>| {
            open.set(true);
            active.set(at.or_else(|| initial_active(&enabled, selected)));
            if let Some(el) = trigger() {
                spawn(async move {
                    let _ = el.set_focus(true).await;
                });
            }
        }
    };
    let options_for_keys = options.clone();
    let onkeydown = {
        let enabled = enabled.clone();
        let mut show = show.clone();
        move |evt: KeyboardEvent| {
            let Some(key) = SelectKey::from_key(&evt.key()) else {
                return;
            };
            let state = SelectState {
                open: is_open,
                active: active(),
            };
            let Some(action) = select_key(state, key, &enabled, selected) else {
                return;
            };
            if action.consume {
                evt.prevent_default();
            }
            if !can_open {
                return;
            }
            if let Some(o) = action.choose.and_then(|i| options_for_keys.get(i)) {
                on_change.call(o.id.clone());
            }
            if action.state.open {
                show(action.state.active);
            } else {
                open.set(false);
            }
        }
    };
    let current = selected.and_then(|i| options.get(i)).cloned();
    let trigger_class = if is_open {
        format!("{TRIGGER} ring-2 ring-[var(--color-accent)] border-transparent")
    } else {
        format!("{TRIGGER} border-[var(--color-border)]")
    };
    let activedescendant = active_now.map(|i| format!("{id}-listbox-option-{i}"));
    rsx! {
        div {
            class: "relative flex flex-col gap-1.5",
            class: if is_open { "z-[120]" },
            class: "swiss-proxy-select",
            onfocusout: move |_| open.set(false),
            label {
                id: "{id}-label",
                r#for: "{id}-trigger",
                class: "text-sm font-medium text-[var(--color-text)]",
                "{label}"
            }
            div { class: "relative",
                button {
                    id: "{id}-trigger",
                    r#type: "button",
                    disabled: !can_open,
                    class: "{trigger_class}",
                    role: "combobox",
                    aria_labelledby: "{id}-label",
                    aria_expanded: if is_open { "true" } else { "false" },
                    aria_haspopup: "listbox",
                    aria_controls: "{id}-listbox",
                    "aria-activedescendant": activedescendant,
                    onmounted: move |evt| trigger.set(Some(evt.data())),
                    onclick: move |_| {
                        if is_open {
                            open.set(false);
                        } else if can_open {
                            show(None);
                        }
                    },
                    onkeydown,
                    if let Some(option) = current {
                        span { class: "min-w-0 text-[var(--color-text)]",
                            OptionLabel { option }
                        }
                    } else {
                        span { class: "min-w-0 text-[var(--color-text-secondary)]", "{placeholder}" }
                    }
                    Chevron { open: is_open }
                }
                if is_open {
                    ul {
                        class: "absolute z-[130] w-full mt-1 py-1 bg-[var(--color-card)] rounded-[var(--radius-sm)] border border-[var(--color-border)] shadow-[var(--shadow-modal)] max-h-[200px] overflow-y-auto",
                        role: "listbox",
                        id: "{id}-listbox",
                        aria_label: "{label}",
                        // keep focus on the trigger: a click in the list must not close it first
                        onmousedown: move |evt| evt.prevent_default(),
                        for (i , option) in options.iter().cloned().enumerate() {
                            li {
                                key: "{option.id}",
                                id: "{id}-listbox-option-{i}",
                                role: "option",
                                aria_selected: if selected == Some(i) { "true" } else { "false" },
                                class: option_class(selected == Some(i), active_now == Some(i), option.disabled),
                                onmouseenter: move |_| {
                                    if !option.disabled {
                                        active.set(Some(i));
                                    }
                                },
                                onclick: {
                                    let option = option.clone();
                                    move |_| {
                                        if !option.disabled {
                                            on_change.call(option.id.clone());
                                            open.set(false);
                                        }
                                    }
                                },
                                OptionLabel { option: option.clone() }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The active option after `key` with the list open on `from`.
    fn moved(enabled: &[bool], from: Option<usize>, key: SelectKey) -> Option<usize> {
        let open = SelectState {
            open: true,
            active: from,
        };
        select_key(open, key, enabled, None).and_then(|a| a.state.active)
    }

    /// MacSelect keyboard rules (`MacSelect.tsx:136-159`) on the reference picker: moves skip
    /// disabled options and wrap; Home / End jump to the first / last enabled one.
    #[test]
    fn keys_move_among_enabled_options() {
        // the reference picker: three taken servers, then three free ones
        let on = [false, false, false, true, true, true];
        assert_eq!(moved(&on, Some(3), SelectKey::Down), Some(4));
        assert_eq!(moved(&on, Some(5), SelectKey::Down), Some(3));
        assert_eq!(moved(&on, Some(3), SelectKey::Up), Some(5));
        assert_eq!(moved(&on, Some(4), SelectKey::Home), Some(3));
        assert_eq!(moved(&on, None, SelectKey::End), Some(5));
        assert_eq!(moved(&on, None, SelectKey::Down), Some(3));
        assert_eq!(moved(&on, Some(1), SelectKey::Down), Some(3));
        assert_eq!(moved(&[false, false], None, SelectKey::Down), None);
        assert_eq!(moved(&[], Some(0), SelectKey::Home), None);
    }

    /// On open the active option is the selected one if enabled, else the first enabled
    /// (`proxy-picker-open`: `aria-activedescendant` = option 3, Poland); arrows on the closed
    /// picker open it there.
    #[test]
    fn opening_activates_the_selection() {
        let on = [false, false, false, true, true, true];
        assert_eq!(initial_active(&on, Some(3)), Some(3));
        assert_eq!(initial_active(&on, Some(1)), Some(3));
        assert_eq!(initial_active(&on, None), Some(3));
        assert_eq!(initial_active(&on, Some(9)), Some(3));
        let closed = SelectState::default();
        let opened = select_key(closed, SelectKey::Down, &on, Some(4)).map(|a| a.state);
        assert_eq!(
            opened,
            Some(SelectState {
                open: true,
                active: Some(4)
            })
        );
    }

    /// Option classes as `cn()` / tailwind-merge produced them in `proxy-picker-open`.
    #[test]
    fn option_classes_match_the_reference() {
        assert_eq!(
            option_class(false, false, true),
            "px-2 py-1 text-xs transition-colors duration-[var(--transition-fast)] text-[var(--color-text)] hover:bg-[var(--color-border)]/50 opacity-50 cursor-not-allowed"
        );
        assert_eq!(
            option_class(true, true, false),
            "px-2 py-1 text-xs cursor-pointer transition-colors duration-[var(--transition-fast)] text-[var(--color-accent)] bg-[var(--color-border)]/50"
        );
        assert_eq!(
            option_class(false, false, false),
            "px-2 py-1 text-xs cursor-pointer transition-colors duration-[var(--transition-fast)] text-[var(--color-text)] hover:bg-[var(--color-border)]/50"
        );
    }
}
