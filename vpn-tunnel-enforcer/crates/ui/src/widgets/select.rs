//! [`Select`]: a single-choice dropdown that keeps the old MacSelect keyboard model (ui-servers
//! §3.21) and fixes its defects (UI-17): the list closes on Tab / blur, `aria-controls` only while
//! open, handled keys never reach a parent dialog, re-picking the current value is ignored. The
//! list is a top-layer popover anchored to the trigger, so no panel can clip it.
use dioxus::prelude::*;

use super::buttons::{Icon, IconGlyph};
use super::fields::FieldCtx;
use super::use_dom_id;

/// Height of a [`Select`] trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Size {
    /// 28 px, for panel heads and table rows.
    Sm,
    /// 36 px, the form height.
    #[default]
    Md,
}

/// Square mark before an option label (server health and similar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indicator {
    Ok,
    Fail,
    Muted,
    Signal,
}

impl Indicator {
    fn class(self) -> &'static str {
        match self {
            Indicator::Ok => "w-dot is-ok",
            Indicator::Fail => "w-dot is-fail",
            Indicator::Muted => "w-dot is-muted",
            Indicator::Signal => "w-dot is-signal",
        }
    }
}

/// One entry of a [`Select`].
#[derive(Debug, Clone, PartialEq)]
pub struct SelectOption<T> {
    pub value: T,
    pub label: String,
    pub disabled: bool,
    /// The mark and its spoken meaning.
    pub indicator: Option<(Indicator, String)>,
}

impl<T> SelectOption<T> {
    pub fn new(value: T, label: impl Into<String>) -> Self {
        Self {
            value,
            label: label.into(),
            disabled: false,
            indicator: None,
        }
    }
    #[must_use]
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }
    #[must_use]
    pub fn indicator(mut self, indicator: Indicator, label: impl Into<String>) -> Self {
        self.indicator = Some((indicator, label.into()));
        self
    }
}

/// Whether the list is open and which option is highlighted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SelectState {
    pub open: bool,
    pub active: Option<usize>,
}

/// Keys of the select keyboard model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectKey {
    Down,
    Up,
    Home,
    End,
    Enter,
    Space,
    Escape,
    Tab,
}

impl SelectKey {
    /// The model's key for a DOM key, if it has one.
    pub fn from_key(key: &Key) -> Option<Self> {
        Some(match key {
            Key::ArrowDown => SelectKey::Down,
            Key::ArrowUp => SelectKey::Up,
            Key::Home => SelectKey::Home,
            Key::End => SelectKey::End,
            Key::Enter => SelectKey::Enter,
            Key::Character(c) if c == " " => SelectKey::Space,
            Key::Escape => SelectKey::Escape,
            Key::Tab => SelectKey::Tab,
            _ => return None,
        })
    }
}

/// Result of a key: the next state, the option to choose, and whether the key is consumed
/// (default action prevented, propagation stopped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectAction {
    pub state: SelectState,
    pub choose: Option<usize>,
    pub consume: bool,
}

fn first_enabled(enabled: &[bool]) -> Option<usize> {
    enabled.iter().position(|&e| e)
}

fn last_enabled(enabled: &[bool]) -> Option<usize> {
    enabled.iter().rposition(|&e| e)
}

/// The next enabled option after `from` in direction `down`, wrapping around.
fn step_enabled(enabled: &[bool], from: Option<usize>, down: bool) -> Option<usize> {
    let len = enabled.len();
    if len == 0 {
        return None;
    }
    let start = match from {
        Some(i) => i.min(len - 1),
        None if down => len - 1,
        None => 0,
    };
    (1..=len)
        .map(|k| {
            if down {
                (start + k) % len
            } else {
                (start + len - k % len) % len
            }
        })
        .find(|&i| enabled[i])
}

/// The option highlighted when the list opens: the selected one if enabled, else the first
/// enabled one.
pub fn initial_active(enabled: &[bool], selected: Option<usize>) -> Option<usize> {
    selected
        .filter(|&i| enabled.get(i).copied().unwrap_or(false))
        .or_else(|| first_enabled(enabled))
}

/// The select keyboard model. `enabled[i]` tells whether option `i` can be chosen; `selected` is
/// the index of the current value. `None` = the key is not handled.
pub fn select_key(
    state: SelectState,
    key: SelectKey,
    enabled: &[bool],
    selected: Option<usize>,
) -> Option<SelectAction> {
    let open = |active| SelectState { open: true, active };
    let closed = SelectState::default();
    let step = |state, choose| SelectAction {
        state,
        choose,
        consume: true,
    };
    Some(match (state.open, key) {
        (false, SelectKey::Down | SelectKey::Up | SelectKey::Enter | SelectKey::Space) => {
            step(open(initial_active(enabled, selected)), None)
        }
        (true, SelectKey::Down) => step(open(step_enabled(enabled, state.active, true)), None),
        (true, SelectKey::Up) => step(open(step_enabled(enabled, state.active, false)), None),
        (_, SelectKey::Home) => step(open(first_enabled(enabled)), None),
        (_, SelectKey::End) => step(open(last_enabled(enabled)), None),
        (true, SelectKey::Enter | SelectKey::Space) => {
            let choose = state
                .active
                .filter(|&i| enabled.get(i).copied().unwrap_or(false));
            step(closed, choose.filter(|&i| Some(i) != selected))
        }
        (true, SelectKey::Escape) => step(closed, None),
        (true, SelectKey::Tab) => SelectAction {
            state: closed,
            choose: None,
            consume: false,
        },
        (false, SelectKey::Escape | SelectKey::Tab) => return None,
    })
}

/// A dropdown of `options`. The trigger is a `combobox` button that keeps the focus; the list is
/// a `listbox` in the top layer (`popover`) anchored under the trigger (above it when there is
/// no room). Inside a [`super::Field`] / [`super::Row`] it is labelled by the field's label.
#[component]
pub fn Select<T: Clone + PartialEq + 'static>(
    options: Vec<SelectOption<T>>,
    value: Option<T>,
    on_change: EventHandler<T>,
    /// Shown while no option is selected.
    #[props(default)]
    placeholder: String,
    /// Accessible name when there is no field label around.
    #[props(default)]
    aria_label: Option<String>,
    #[props(default)] disabled: bool,
    #[props(default)] invalid: bool,
    #[props(default)] size: Size,
    /// Told when the list opens (`true`) and closes (`false`).
    #[props(default)]
    on_open_change: Option<EventHandler<bool>>,
) -> Element {
    let field = try_use_context::<FieldCtx>();
    let own_id = use_dom_id("w-sel");
    let trigger_id = field.map(|f| f.id()).unwrap_or(own_id);
    let list_id = format!("{trigger_id}-listbox");
    let mut state = use_signal(SelectState::default);
    let selected = options
        .iter()
        .position(|o| Some(&o.value) == value.as_ref());
    let enabled: Vec<bool> = options.iter().map(|o| !o.disabled).collect();
    let SelectState { open, active } = state();
    let open = open && !disabled;

    // Every change of the open state goes through here, so `on_open_change` sees each flip once.
    let mut commit = move |next: SelectState, chosen: Option<T>| {
        let was_open = state.peek().open;
        state.set(next);
        if let Some(value) = chosen {
            on_change.call(value);
        }
        if was_open != next.open
            && let Some(cb) = on_open_change
        {
            cb.call(next.open);
        }
    };

    // Keep the highlighted option visible while the arrows move through a long list.
    let active_id = active.map(|i| format!("{list_id}-opt-{i}"));
    let scroll_to = active_id.clone();
    use_effect(use_reactive!(|(open, scroll_to)| {
        if open && let Some(id) = scroll_to {
            let _ = document::eval(&format!(
                "document.getElementById('{id}')?.scrollIntoView({{block:'nearest'}})"
            ));
        }
    }));

    let shown = selected.map(|i| options[i].clone());
    let has_value = shown.is_some();
    let invalid = invalid || field.is_some_and(|f| f.invalid());
    let labelled_by = if aria_label.is_none() {
        field.map(|f| f.label_id())
    } else {
        None
    };
    let (list_label, list_labelled_by) = (aria_label.clone(), labelled_by.clone());
    let values: Vec<T> = options.iter().map(|o| o.value.clone()).collect();
    let enabled_click = enabled.clone();
    let list_js = list_id.clone();
    rsx! {
        div {
            class: "w-select",
            class: if size == Size::Sm { "is-sm" },
            class: if open { "is-open" },
            button {
                r#type: "button",
                id: "{trigger_id}",
                class: "w-select-trigger",
                style: "anchor-name:--{trigger_id}",
                role: "combobox",
                disabled,
                aria_haspopup: "listbox",
                aria_expanded: if open { "true" } else { "false" },
                aria_controls: open.then(|| list_id.clone()),
                aria_activedescendant: if open { active_id.clone() } else { None },
                aria_label: aria_label.clone(),
                aria_labelledby: labelled_by.clone(),
                aria_describedby: field.and_then(|f| f.described_by()),
                aria_invalid: invalid.then_some("true"),
                onclick: move |_| {
                    let next = if state.peek().open {
                        SelectState::default()
                    } else {
                        SelectState { open: true, active: initial_active(&enabled_click, selected) }
                    };
                    commit(next, None);
                },
                onkeydown: move |evt| {
                    let Some(key) = SelectKey::from_key(&evt.key()) else {
                        return;
                    };
                    let current = *state.peek();
                    if let Some(action) = select_key(current, key, &enabled, selected) {
                        if action.consume {
                            evt.prevent_default();
                            evt.stop_propagation();
                        }
                        commit(action.state, action.choose.map(|i| values[i].clone()));
                    }
                },
                onblur: move |_| {
                    if state.peek().open {
                        commit(SelectState::default(), None);
                    }
                },
                span { class: "w-select-value", class: if !has_value { "is-placeholder" },
                    if let Some(option) = shown {
                        if let Some((mark, _)) = option.indicator {
                            span { class: mark.class(), aria_hidden: "true" }
                        }
                        span { class: "w-select-text", "{option.label}" }
                    } else {
                        span { class: "w-select-text", "{placeholder}" }
                    }
                }
                Icon { glyph: IconGlyph::ChevronDown }
            }
            if open {
                div {
                    id: "{list_id}",
                    class: "w-select-pop",
                    class: if size == Size::Sm { "is-sm" },
                    style: "position-anchor:--{trigger_id}",
                    role: "listbox",
                    popover: "manual",
                    aria_label: list_label,
                    aria_labelledby: list_labelled_by,
                    onmounted: move |_| {
                        let _ = document::eval(&format!("document.getElementById('{list_js}')?.showPopover()"));
                    },
                    // Keep the focus on the trigger: a click in the list must not blur it.
                    onmousedown: move |evt| evt.prevent_default(),
                    for (i , option) in options.into_iter().enumerate() {
                        div {
                            key: "{i}",
                            id: "{list_id}-opt-{i}",
                            class: "w-option",
                            class: if active == Some(i) { "is-active" },
                            class: if selected == Some(i) { "is-selected" },
                            role: "option",
                            aria_selected: if selected == Some(i) { "true" } else { "false" },
                            aria_disabled: option.disabled.then_some("true"),
                            onmouseenter: {
                                let on = !option.disabled;
                                move |_| {
                                    if on && state.peek().active != Some(i) {
                                        state.write().active = Some(i);
                                    }
                                }
                            },
                            onclick: {
                                let (on, value) = (!option.disabled, option.value.clone());
                                move |_| {
                                    if on {
                                        let chosen = (Some(i) != selected).then(|| value.clone());
                                        commit(SelectState::default(), chosen);
                                    }
                                }
                            },
                            if let Some((mark, spoken)) = option.indicator {
                                span { class: mark.class(), role: "img", aria_label: "{spoken}" }
                            }
                            span { class: "w-option-label", "{option.label}" }
                            if selected == Some(i) {
                                Icon { glyph: IconGlyph::Check, size: 14 }
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

    const ALL: [bool; 3] = [true, true, true];

    fn open(active: usize) -> SelectState {
        SelectState {
            open: true,
            active: Some(active),
        }
    }

    fn key(
        state: SelectState,
        k: SelectKey,
        enabled: &[bool],
        selected: Option<usize>,
    ) -> SelectAction {
        select_key(state, k, enabled, selected).expect("handled")
    }

    /// MacSelect.test "arrow-key navigation and Enter selection" (options auto / 1 min / 1 hr,
    /// value auto): ArrowDown opens on the selected option, ArrowDown moves to option 1, Enter
    /// chooses it and closes.
    #[test]
    fn arrow_down_opens_moves_and_enter_chooses() {
        let a = key(SelectState::default(), SelectKey::Down, &ALL, Some(0));
        assert_eq!((a.state, a.choose, a.consume), (open(0), None, true));
        let a = key(a.state, SelectKey::Down, &ALL, Some(0));
        assert_eq!(a.state, open(1));
        let a = key(a.state, SelectKey::Enter, &ALL, Some(0));
        assert_eq!((a.state, a.choose), (SelectState::default(), Some(1)));
    }

    #[test]
    fn arrows_wrap_around() {
        assert_eq!(key(open(2), SelectKey::Down, &ALL, None).state, open(0));
        assert_eq!(key(open(0), SelectKey::Up, &ALL, None).state, open(2));
    }

    #[test]
    fn disabled_options_are_skipped_by_arrows_home_and_end() {
        let enabled = [false, true, false, true, false];
        assert_eq!(key(open(1), SelectKey::Down, &enabled, None).state, open(3));
        assert_eq!(key(open(3), SelectKey::Down, &enabled, None).state, open(1));
        assert_eq!(key(open(1), SelectKey::Up, &enabled, None).state, open(3));
        assert_eq!(
            key(SelectState::default(), SelectKey::Home, &enabled, None).state,
            open(1)
        );
        assert_eq!(key(open(1), SelectKey::End, &enabled, None).state, open(3));
        // the selected option is disabled: the list opens on the first enabled one
        assert_eq!(initial_active(&enabled, Some(2)), Some(1));
        assert_eq!(initial_active(&[false, false], None), None);
    }

    #[test]
    fn escape_closes_without_change_and_is_consumed_only_when_open() {
        let a = key(open(1), SelectKey::Escape, &ALL, Some(0));
        assert_eq!(
            (a.state, a.choose, a.consume),
            (SelectState::default(), None, true)
        );
        // closed: the key goes on to the enclosing dialog
        assert_eq!(
            select_key(SelectState::default(), SelectKey::Escape, &ALL, Some(0)),
            None
        );
    }

    /// UI-17: Tab closes the list and still moves the focus.
    #[test]
    fn tab_closes_without_consuming() {
        let a = key(open(1), SelectKey::Tab, &ALL, Some(0));
        assert_eq!(
            (a.state, a.choose, a.consume),
            (SelectState::default(), None, false)
        );
        assert_eq!(
            select_key(SelectState::default(), SelectKey::Tab, &ALL, None),
            None
        );
    }

    /// S-18: re-picking the current value is not a change; a disabled active option is never chosen.
    #[test]
    fn same_value_and_disabled_picks_change_nothing() {
        assert_eq!(key(open(0), SelectKey::Enter, &ALL, Some(0)).choose, None);
        assert_eq!(
            key(open(1), SelectKey::Space, &[true, false], Some(0)).choose,
            None
        );
        assert_eq!(
            key(open(2), SelectKey::Space, &ALL, Some(0)).choose,
            Some(2)
        );
    }

    #[test]
    fn dom_keys_map_to_the_model() {
        assert_eq!(
            SelectKey::from_key(&Key::Character(" ".into())),
            Some(SelectKey::Space)
        );
        assert_eq!(SelectKey::from_key(&Key::ArrowUp), Some(SelectKey::Up));
        assert_eq!(SelectKey::from_key(&Key::Character("a".into())), None);
    }
}
