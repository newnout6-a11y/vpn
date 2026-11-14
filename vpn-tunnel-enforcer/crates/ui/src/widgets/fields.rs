//! Form fields: [`Field`] (label / hint / error around a control), [`TextInput`], [`TextArea`],
//! [`NumberInput`] (raw text while typing, parse and clamp on blur or Enter: ui-pages U-05).
use dioxus::prelude::*;

use super::{next_serial, use_dom_id};

/// What a control learns from the [`Field`] or [`super::Row`] around it: its id (the label's
/// `for`), its description ids and whether the field shows an error.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FieldCtx {
    n: u64,
    state: Signal<FieldState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct FieldState {
    hint: bool,
    error: bool,
}

impl FieldCtx {
    /// Id of the control.
    pub fn id(&self) -> String {
        format!("w-f-{}", self.n)
    }
    pub fn label_id(&self) -> String {
        format!("w-f-{}-label", self.n)
    }
    pub fn hint_id(&self) -> String {
        format!("w-f-{}-hint", self.n)
    }
    pub fn error_id(&self) -> String {
        format!("w-f-{}-error", self.n)
    }

    /// `aria-describedby` of the control: the error first, then the hint (subscribes the caller).
    pub fn described_by(&self) -> Option<String> {
        let state = *self.state.read();
        let ids: Vec<String> = [
            state.error.then(|| self.error_id()),
            state.hint.then(|| self.hint_id()),
        ]
        .into_iter()
        .flatten()
        .collect();
        (!ids.is_empty()).then(|| ids.join(" "))
    }

    /// Whether the field shows an error (subscribes the caller).
    pub fn invalid(&self) -> bool {
        self.state.read().error
    }
}

/// Provides a [`FieldCtx`] to the children and keeps its hint / error flags current.
pub(crate) fn use_field_ctx(hint: bool, error: bool) -> FieldCtx {
    let ctx = use_context_provider(|| FieldCtx {
        n: next_serial(),
        state: Signal::new(FieldState { hint, error }),
    });
    let now = FieldState { hint, error };
    let mut state = ctx.state;
    if *state.peek() != now {
        state.set(now);
    }
    ctx
}

/// Id, description and invalid flag of a control: its own props win over the enclosing field.
fn control_attrs(
    field: Option<FieldCtx>,
    id: Option<String>,
    invalid: bool,
) -> (Option<String>, Option<String>, bool) {
    let id = id.or_else(|| field.map(|f| f.id()));
    let described = field.and_then(|f| f.described_by());
    let invalid = invalid || field.is_some_and(|f| f.invalid());
    (id, described, invalid)
}

/// A labelled control stacked vertically: label, the control (children), hint, error. Controls
/// of this module inside pick up the id, `aria-describedby` and `aria-invalid` automatically.
#[component]
pub fn Field(
    label: String,
    #[props(default)] hint: Option<String>,
    #[props(default)] error: Option<String>,
    children: Element,
) -> Element {
    let ctx = use_field_ctx(hint.is_some(), error.is_some());
    rsx! {
        div { class: "w-field", class: if error.is_some() { "is-invalid" },
            label { class: "w-field-label", id: "{ctx.label_id()}", r#for: "{ctx.id()}", "{label}" }
            {children}
            if let Some(error) = &error {
                p { class: "w-field-error", id: "{ctx.error_id()}", role: "alert", "{error}" }
            }
            if let Some(hint) = &hint {
                p { class: "w-field-hint", id: "{ctx.hint_id()}", "{hint}" }
            }
        }
    }
}

/// `type` of a [`TextInput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextKind {
    #[default]
    Text,
    Password,
    Search,
    Url,
}

impl TextKind {
    fn html(self) -> &'static str {
        match self {
            TextKind::Text => "text",
            TextKind::Password => "password",
            TextKind::Search => "search",
            TextKind::Url => "url",
        }
    }
}

/// A one-line text box. Enter calls `on_enter` and Escape `on_escape` (when given; the key is
/// then consumed, so it neither submits nor closes anything else).
#[component]
pub fn TextInput(
    value: String,
    oninput: EventHandler<String>,
    #[props(default)] kind: TextKind,
    #[props(default)] placeholder: Option<String>,
    #[props(default)] disabled: bool,
    #[props(default)] readonly: bool,
    #[props(default)] invalid: bool,
    #[props(default)] mono: bool,
    #[props(default)] id: Option<String>,
    /// Accessible name when there is no visible label (no [`Field`] / [`super::Row`] around).
    #[props(default)]
    aria_label: Option<String>,
    #[props(default)] maxlength: Option<u32>,
    #[props(default)] initial_focus: bool,
    #[props(default)] on_enter: Option<EventHandler<()>>,
    #[props(default)] on_escape: Option<EventHandler<()>>,
) -> Element {
    let field = try_use_context::<FieldCtx>();
    let (id, described, invalid) = control_attrs(field, id, invalid);
    rsx! {
        input {
            class: "w-input",
            class: if mono { "swiss-mono" },
            r#type: kind.html(),
            id,
            value: "{value}",
            placeholder,
            disabled,
            readonly,
            maxlength: maxlength.map(|m| m.to_string()),
            spellcheck: "false",
            autocomplete: "off",
            aria_label,
            aria_describedby: described,
            aria_invalid: invalid.then_some("true"),
            "data-w-autofocus": initial_focus.then_some("true"),
            oninput: move |evt| oninput.call(evt.value()),
            onkeydown: move |evt| on_text_key(evt, on_enter, on_escape, false),
        }
    }
}

/// Enter / Ctrl+Enter / Escape handling shared by the text controls.
fn on_text_key(
    evt: KeyboardEvent,
    on_enter: Option<EventHandler<()>>,
    on_escape: Option<EventHandler<()>>,
    needs_ctrl: bool,
) {
    let handler = match evt.key() {
        // Enter that confirms an IME composition is not a submit.
        Key::Enter if !evt.is_composing() && evt.modifiers().ctrl() == needs_ctrl => on_enter,
        Key::Escape => on_escape,
        _ => None,
    };
    if let Some(handler) = handler {
        evt.prevent_default();
        evt.stop_propagation();
        handler.call(());
    }
}

/// A multi-line text box; Ctrl+Enter calls `on_submit`.
#[component]
pub fn TextArea(
    value: String,
    oninput: EventHandler<String>,
    #[props(default = 4)] rows: u32,
    #[props(default)] placeholder: Option<String>,
    #[props(default)] disabled: bool,
    #[props(default)] readonly: bool,
    #[props(default)] invalid: bool,
    #[props(default)] mono: bool,
    #[props(default)] id: Option<String>,
    #[props(default)] aria_label: Option<String>,
    #[props(default)] on_submit: Option<EventHandler<()>>,
) -> Element {
    let field = try_use_context::<FieldCtx>();
    let (id, described, invalid) = control_attrs(field, id, invalid);
    rsx! {
        textarea {
            class: "w-input w-textarea",
            class: if mono { "swiss-mono" },
            id,
            rows: "{rows}",
            value: "{value}",
            placeholder,
            disabled,
            readonly,
            spellcheck: "false",
            aria_label,
            aria_describedby: described,
            aria_invalid: invalid.then_some("true"),
            oninput: move |evt| oninput.call(evt.value()),
            onkeydown: move |evt| on_text_key(evt, on_submit, None, true),
        }
    }
}

/// Outcome of committing the text of a [`NumberInput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberCommit {
    /// A number inside the range.
    Exact(i64),
    /// A number outside the range: `value` is the nearest bound, `typed` what the user wrote.
    Clamped { typed: i64, value: i64 },
    /// Not a whole number: the field returns to the last good value.
    Invalid,
}

/// Parses and clamps the text of a number field (ui-pages U-05: never on every keystroke).
/// Spaces between digit groups are allowed («1 000»); fractions are rejected; numbers too long
/// for `i64` clamp to the bound on their side.
pub fn commit_number(text: &str, min: i64, max: i64) -> NumberCommit {
    let (min, max) = (min.min(max), max.max(min));
    let cleaned: String = text
        .trim()
        .chars()
        .filter(|c| !matches!(c, ' ' | '\u{a0}' | '\u{202f}' | '_'))
        .collect();
    let (negative, digits) = match cleaned.strip_prefix('-').or(cleaned.strip_prefix('−')) {
        Some(rest) => (true, rest),
        None => (false, cleaned.strip_prefix('+').unwrap_or(&cleaned)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return NumberCommit::Invalid;
    }
    let typed = match digits.parse::<i64>() {
        Ok(n) if negative => -n,
        Ok(n) => n,
        Err(_) if negative => i64::MIN,
        Err(_) => i64::MAX,
    };
    let value = typed.clamp(min, max);
    if value == typed {
        NumberCommit::Exact(value)
    } else {
        NumberCommit::Clamped { typed, value }
    }
}

/// A whole-number box. While focused it keeps the raw text; on blur or Enter the text is parsed
/// and clamped to `min..=max` and `on_commit` gets the result (only when it changed). The range
/// is always shown next to it, and a clamp is shown as «typed → value». ArrowUp / ArrowDown step.
#[component]
pub fn NumberInput(
    value: i64,
    min: i64,
    max: i64,
    on_commit: EventHandler<i64>,
    #[props(default = 1)] step: i64,
    /// Unit after the range caption («с», «ms»).
    #[props(default)]
    unit: Option<String>,
    #[props(default)] disabled: bool,
    #[props(default)] id: Option<String>,
    #[props(default)] aria_label: Option<String>,
) -> Element {
    let field = try_use_context::<FieldCtx>();
    let (id, described, invalid) = control_attrs(field, id, false);
    let mut raw = use_signal(String::new);
    let mut editing = use_signal(|| false);
    let mut clamped = use_signal(|| None::<(i64, i64)>);
    let range_id = use_dom_id("w-num");
    let described = Some(match described {
        Some(d) => format!("{range_id} {d}"),
        None => range_id.clone(),
    });
    let mut commit = move |text: &str| match commit_number(text, min, max) {
        NumberCommit::Exact(v) => {
            clamped.set(None);
            if v != value {
                on_commit.call(v);
            }
            v
        }
        NumberCommit::Clamped { typed, value: v } => {
            clamped.set(Some((typed, v)));
            if v != value {
                on_commit.call(v);
            }
            v
        }
        NumberCommit::Invalid => value,
    };
    // The arrows step from what is typed (when it is a number) and stay inside the range.
    let stepped = move |up: bool| {
        let base = match commit_number(&raw.peek(), min, max) {
            NumberCommit::Exact(v) | NumberCommit::Clamped { value: v, .. } => v,
            NumberCommit::Invalid => value,
        };
        let next = if up {
            base.saturating_add(step)
        } else {
            base.saturating_sub(step)
        };
        next.clamp(min.min(max), max.max(min)).to_string()
    };
    let shown = if editing() { raw() } else { value.to_string() };
    let unit = unit.map(|u| format!(" {u}")).unwrap_or_default();
    // A clamp note describes the current value only (a later reset or reload drops it).
    let note = clamped().filter(|&(_, v)| v == value);
    rsx! {
        span { class: "w-num",
            input {
                class: "w-input w-num-input swiss-mono",
                r#type: "text",
                inputmode: "numeric",
                id,
                value: "{shown}",
                disabled,
                spellcheck: "false",
                autocomplete: "off",
                aria_label,
                aria_describedby: described,
                aria_invalid: invalid.then_some("true"),
                onfocus: move |_| {
                    raw.set(value.to_string());
                    editing.set(true);
                },
                oninput: move |evt| raw.set(evt.value()),
                onblur: move |_| {
                    commit(&raw.peek().clone());
                    editing.set(false);
                },
                onkeydown: move |evt| {
                    let next = match evt.key() {
                        Key::Enter => Some(commit(&raw.peek().clone())),
                        Key::ArrowUp => Some(commit(&stepped(true))),
                        Key::ArrowDown => Some(commit(&stepped(false))),
                        // Only a pending edit is reverted; otherwise Escape goes on (closes a dialog).
                        Key::Escape if *raw.peek() != value.to_string() => Some(value),
                        _ => None,
                    };
                    if let Some(v) = next {
                        evt.prevent_default();
                        evt.stop_propagation();
                        raw.set(v.to_string());
                    }
                },
            }
            span { class: "w-num-range swiss-mono", id: "{range_id}",
                "{min}–{max}{unit}"
                if let Some((typed, v)) = note {
                    span { class: "w-num-clamped", " · {typed} → {v}" }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// U-05: «120» typed into a 5–300 field is taken as is; out-of-range values clamp once, on commit.
    #[test]
    fn number_text_commits_with_clamp() {
        assert_eq!(commit_number("120", 5, 300), NumberCommit::Exact(120));
        assert_eq!(
            commit_number("520", 5, 300),
            NumberCommit::Clamped {
                typed: 520,
                value: 300
            }
        );
        assert_eq!(
            commit_number("1", 5, 300),
            NumberCommit::Clamped { typed: 1, value: 5 }
        );
        assert_eq!(commit_number(" 45 ", 5, 300), NumberCommit::Exact(45));
        assert_eq!(commit_number("1 000", 0, 5000), NumberCommit::Exact(1000));
        assert_eq!(commit_number("+7", 0, 9), NumberCommit::Exact(7));
        assert_eq!(
            commit_number("-3", 0, 9),
            NumberCommit::Clamped {
                typed: -3,
                value: 0
            }
        );
        assert_eq!(commit_number("−2", -5, 5), NumberCommit::Exact(-2));
    }

    #[test]
    fn number_text_rejects_garbage() {
        for text in ["", " ", "abc", "1.5", "12a", "--1", "-", "1e3"] {
            assert_eq!(
                commit_number(text, 0, 100),
                NumberCommit::Invalid,
                "{text:?}"
            );
        }
    }

    #[test]
    fn number_text_saturates_and_tolerates_swapped_bounds() {
        assert_eq!(
            commit_number("99999999999999999999999", 0, 65535),
            NumberCommit::Clamped {
                typed: i64::MAX,
                value: 65535
            }
        );
        assert_eq!(
            commit_number("-99999999999999999999999", -10, 10),
            NumberCommit::Clamped {
                typed: i64::MIN,
                value: -10
            }
        );
        assert_eq!(commit_number("50", 100, 0), NumberCommit::Exact(50));
    }
}
