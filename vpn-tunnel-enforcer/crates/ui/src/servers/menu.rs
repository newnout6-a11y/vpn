//! [`OverflowMenu`]: the «…» row menu (menu-button pattern). Rows keep one primary action; the
//! rest get text labels here, destructive items last after a separator (the old row had seven
//! same-size icons and delete one pixel from routine actions). The panel is a top-layer popover
//! anchored to the trigger, so no clipping row or card can hide it; the keyboard model is the
//! shared select model (arrows, Home / End, Enter / Space, Escape, Tab), the focus stays on the
//! trigger (`aria-activedescendant`) and handled keys never reach a parent dialog.
use dioxus::prelude::*;

use crate::widgets::{
    Icon, IconGlyph, SelectKey, SelectState, Spinner, select_key, title_with_reason, use_dom_id,
};

/// One entry of an [`OverflowMenu`].
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MenuItem {
    pub id: &'static str,
    pub label: String,
    pub disabled: bool,
    /// Why the item is disabled (its hover title).
    pub reason: Option<String>,
    pub destructive: bool,
    /// The action runs (a spinner after the label, the item is disabled).
    pub busy: bool,
}

impl MenuItem {
    pub fn new(id: &'static str, label: String) -> Self {
        Self {
            id,
            label,
            disabled: false,
            reason: None,
            destructive: false,
            busy: false,
        }
    }

    /// Disabled with a reason (`None` reason = enabled).
    #[must_use]
    pub fn blocked(mut self, reason: Option<String>) -> Self {
        self.disabled = reason.is_some();
        self.reason = reason;
        self
    }

    #[must_use]
    pub fn busy(mut self, busy: bool) -> Self {
        self.busy = busy;
        self
    }

    #[must_use]
    pub fn destructive(mut self) -> Self {
        self.destructive = true;
        self
    }

    fn enabled(&self) -> bool {
        !self.disabled && !self.busy
    }
}

/// Routine items first, destructive ones after them (stable within each part).
pub(crate) fn menu_order(items: &[MenuItem]) -> Vec<MenuItem> {
    let mut out: Vec<MenuItem> = items.iter().filter(|i| !i.destructive).cloned().collect();
    out.extend(items.iter().filter(|i| i.destructive).cloned());
    out
}

/// The «…» button and its menu. `label` names the trigger (e.g. «Действия: Riga-2»).
#[component]
pub(crate) fn OverflowMenu(
    label: String,
    items: Vec<MenuItem>,
    on_select: EventHandler<&'static str>,
) -> Element {
    let id = use_dom_id("srv-menu");
    let list_id = format!("{id}-list");
    let mut state = use_signal(SelectState::default);
    let items = menu_order(&items);
    let enabled: Vec<bool> = items.iter().map(MenuItem::enabled).collect();
    let SelectState { open, active } = state();
    let active_id = active.map(|i| format!("{list_id}-{i}"));
    let ids: Vec<&'static str> = items.iter().map(|i| i.id).collect();
    let first_destructive = items.iter().position(|i| i.destructive).filter(|&p| p > 0);
    let list_js = list_id.clone();
    let enabled_click = enabled.clone();
    rsx! {
        div { class: "srv-menu", onclick: move |evt| evt.stop_propagation(),
            button {
                r#type: "button",
                id: "{id}",
                class: "w-icon-btn srv-menu-trigger",
                style: "anchor-name:--{id}",
                aria_label: "{label}",
                title: "{label}",
                aria_haspopup: "menu",
                aria_expanded: if open { "true" } else { "false" },
                aria_controls: open.then(|| list_id.clone()),
                aria_activedescendant: if open { active_id.clone() } else { None },
                onclick: move |_| {
                    let next = if state.peek().open {
                        SelectState::default()
                    } else {
                        SelectState {
                            open: true,
                            active: enabled_click.iter().position(|&e| e),
                        }
                    };
                    state.set(next);
                },
                onkeydown: move |evt| {
                    let Some(key) = SelectKey::from_key(&evt.key()) else {
                        return;
                    };
                    let current = *state.peek();
                    if let Some(action) = select_key(current, key, &enabled, None) {
                        if action.consume {
                            evt.prevent_default();
                            evt.stop_propagation();
                        }
                        state.set(action.state);
                        if let Some(&item) = action.choose.and_then(|i| ids.get(i)) {
                            on_select.call(item);
                        }
                    }
                },
                onblur: move |_| {
                    if state.peek().open {
                        state.set(SelectState::default());
                    }
                },
                Icon { glyph: IconGlyph::More }
            }
            if open {
                div {
                    id: "{list_id}",
                    class: "srv-menu-pop c-swiss",
                    style: "position-anchor:--{id}",
                    role: "menu",
                    popover: "manual",
                    aria_label: "{label}",
                    onmounted: move |_| {
                        let _ = document::eval(&format!("document.getElementById('{list_js}')?.showPopover()"));
                    },
                    // A click in the menu must not blur the trigger (which would close it first).
                    onmousedown: move |evt| evt.prevent_default(),
                    for (i , item) in items.into_iter().enumerate() {
                        div {
                            key: "{item.id}",
                            id: "{list_id}-{i}",
                            class: "srv-menu-item",
                            // destructive items sit below a rule
                            class: if first_destructive == Some(i) { "is-after-rule" },
                            class: if active == Some(i) { "is-active" },
                            class: if item.destructive { "is-danger" },
                            role: "menuitem",
                            aria_disabled: (!item.enabled()).then_some("true"),
                            title: item.reason.as_deref().map(|r| title_with_reason("", Some(r))),
                            onmouseenter: {
                                let on = item.enabled();
                                move |_| {
                                    if on && state.peek().active != Some(i) {
                                        state.write().active = Some(i);
                                    }
                                }
                            },
                            onclick: {
                                let (on, item_id) = (item.enabled(), item.id);
                                move |_| {
                                    if on {
                                        state.set(SelectState::default());
                                        on_select.call(item_id);
                                    }
                                }
                            },
                            span { class: "srv-menu-label", "{item.label}" }
                            if item.busy {
                                Spinner {}
                            }
                        }
                    }
                }
            }
        }
    }
}
