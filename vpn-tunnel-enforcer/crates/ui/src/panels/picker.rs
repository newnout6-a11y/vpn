//! The proxy picker: a small ARIA combobox with the old MacSelect's markup and keyboard rules.
//!
//! Focus stays on the trigger while the list is open (`aria-activedescendant`); mousedown in
//! the list keeps it there, so leaving the trigger (click elsewhere, Tab) closes the list. The
//! list escapes the panel's `overflow: hidden` through `css/pages/panels.css` (D-27).
use std::rc::Rc;

use dioxus::prelude::*;

use super::icons::Chevron;
use super::rules::Indicator;

/// One option of the picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PickerOption {
    pub id: String,
    pub label: String,
    pub indicator: Indicator,
    pub indicator_label: String,
    pub disabled: bool,
}

/// Where the active option moves on a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Move {
    Next,
    Prev,
    First,
    Last,
}

/// The active option after `mv`, among enabled options only; next / previous wrap around.
fn step(enabled: &[bool], from: Option<usize>, mv: Move) -> Option<usize> {
    let on: Vec<usize> = (0..enabled.len()).filter(|&i| enabled[i]).collect();
    let (first, last) = (*on.first()?, *on.last()?);
    let at = from.and_then(|f| on.iter().position(|&i| i == f));
    Some(match (mv, at) {
        (Move::First, _) | (Move::Next, None) => first,
        (Move::Last, _) | (Move::Prev, None) => last,
        (Move::Next, Some(p)) => on.get(p + 1).copied().unwrap_or(first),
        (Move::Prev, Some(p)) => p.checked_sub(1).map_or(last, |q| on[q]),
    })
}

/// The active option when the list opens: the selected one if enabled, else the first enabled.
fn initial_active(enabled: &[bool], selected: Option<usize>) -> Option<usize> {
    selected
        .filter(|&i| enabled.get(i) == Some(&true))
        .or_else(|| step(enabled, None, Move::First))
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
            let mv = match evt.key() {
                Key::ArrowDown => Some(Move::Next),
                Key::ArrowUp => Some(Move::Prev),
                Key::Home => Some(Move::First),
                Key::End => Some(Move::Last),
                _ => None,
            };
            if let Some(mv) = mv {
                evt.prevent_default();
                if !can_open {
                    return;
                }
                let opened = open();
                let at = match mv {
                    Move::Next | Move::Prev if !opened => initial_active(&enabled, selected),
                    _ => step(&enabled, active(), mv),
                };
                show(at);
                return;
            }
            let commit = evt.key() == Key::Enter || evt.key() == Key::Character(" ".into());
            if commit && is_open {
                evt.prevent_default();
                if let Some(o) = active().and_then(|i| options_for_keys.get(i))
                    && !o.disabled
                {
                    on_change.call(o.id.clone());
                }
                open.set(false);
            } else if evt.key() == Key::Escape && is_open {
                evt.prevent_default();
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
            class: "relative flex flex-col gap-2",
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

    /// MacSelect keyboard rules (`MacSelect.tsx:136-159`): moves skip disabled options and wrap;
    /// Home / End jump to the first / last enabled one.
    #[test]
    fn keys_move_among_enabled_options() {
        // the reference picker: three taken servers, then three free ones
        let on = [false, false, false, true, true, true];
        assert_eq!(step(&on, Some(3), Move::Next), Some(4));
        assert_eq!(step(&on, Some(5), Move::Next), Some(3));
        assert_eq!(step(&on, Some(3), Move::Prev), Some(5));
        assert_eq!(step(&on, Some(4), Move::First), Some(3));
        assert_eq!(step(&on, None, Move::Last), Some(5));
        assert_eq!(step(&on, None, Move::Next), Some(3));
        assert_eq!(step(&on, Some(1), Move::Next), Some(3));
        assert_eq!(step(&[false, false], None, Move::Next), None);
        assert_eq!(step(&[], Some(0), Move::First), None);
    }

    /// On open the active option is the selected one if enabled, else the first enabled
    /// (`proxy-picker-open`: `aria-activedescendant` = option 3, Poland).
    #[test]
    fn opening_activates_the_selection() {
        let on = [false, false, false, true, true, true];
        assert_eq!(initial_active(&on, Some(3)), Some(3));
        assert_eq!(initial_active(&on, Some(1)), Some(3));
        assert_eq!(initial_active(&on, None), Some(3));
        assert_eq!(initial_active(&on, Some(9)), Some(3));
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
