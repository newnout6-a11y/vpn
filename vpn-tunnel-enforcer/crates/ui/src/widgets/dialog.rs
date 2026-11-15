//! [`Modal`] and [`ConfirmDialog`]: a native modal `<dialog>` (top layer, the page behind is
//! inert) with a focus trap, Escape, focus return to the opener and unique ids (ui-servers
//! §3.21 M-1; the old MacModal had none of these). The focus parts run in `assets/js/widgets.js`.
use dioxus::prelude::*;

use super::buttons::{Button, ButtonKind, IconButton, IconGlyph};
use super::use_dom_id;

/// Width of a [`Modal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModalSize {
    /// 420 px: confirmations.
    Sm,
    /// 560 px: forms.
    #[default]
    Md,
    /// 760 px: details and tables.
    Lg,
}

impl ModalSize {
    fn class(self) -> &'static str {
        match self {
            ModalSize::Sm => "is-sm",
            ModalSize::Md => "is-md",
            ModalSize::Lg => "is-lg",
        }
    }
}

/// A modal dialog. Keep it mounted and drive `open`; the content is rendered only while open.
/// On open the focus moves to the element marked `initial_focus` (else the first focusable one);
/// Tab cycles inside; Escape, the «×» button and a click on the backdrop call `on_close` unless
/// `can_close` is false (an operation that must not be interrupted); on close the focus returns
/// to the element that had it before.
#[component]
pub fn Modal(
    open: ReadSignal<bool>,
    title: String,
    on_close: EventHandler<()>,
    /// Accessible name of the «×» button.
    close_label: String,
    #[props(default)] description: Option<String>,
    #[props(default = true)] can_close: bool,
    #[props(default = true)] show_close: bool,
    #[props(default)] size: ModalSize,
    #[props(default)] footer: Option<Element>,
    children: Element,
) -> Element {
    let id = use_dom_id("w-modal");
    let js_id = id.clone();
    use_effect(move || {
        let call = if open() { "openModal" } else { "closeModal" };
        let _ = document::eval(&format!("window.vpnteWidgets?.{call}('{js_id}')"));
    });
    let close = move || {
        if can_close {
            on_close.call(());
        }
    };
    // A press that started on the backdrop: a click outside the box lands on the dialog element
    // itself (its ::backdrop), but so does a text selection dragged out of the box.
    let mut backdrop_press = use_signal(|| false);
    rsx! {
        dialog {
            id: "{id}",
            class: "w-modal c-swiss {size.class()}",
            "data-w-modal": "true",
            // Focus target of last resort (a dialog without focusable content).
            tabindex: "-1",
            aria_labelledby: "{id}-title",
            aria_describedby: description.is_some().then(|| format!("{id}-desc")),
            onkeydown: move |evt| {
                if evt.key() == Key::Escape {
                    evt.prevent_default();
                    evt.stop_propagation();
                    close();
                }
            },
            onmousedown: move |_| backdrop_press.set(true),
            onclick: move |evt| {
                evt.stop_propagation();
                if backdrop_press.replace(false) {
                    close();
                }
            },
            if open() {
                div {
                    class: "w-modal-box",
                    onmousedown: move |evt| {
                        evt.stop_propagation();
                        backdrop_press.set(false);
                    },
                    onmouseup: move |_| backdrop_press.set(false),
                    header { class: "w-modal-head",
                        h2 { class: "w-modal-title", id: "{id}-title", "{title}" }
                        if show_close {
                            IconButton {
                                glyph: IconGlyph::Close,
                                label: close_label,
                                disabled: !can_close,
                                onclick: move |_| close(),
                            }
                        }
                    }
                    if let Some(description) = &description {
                        p { class: "w-modal-desc", id: "{id}-desc", "{description}" }
                    }
                    div { class: "w-modal-body", {children} }
                    if let Some(footer) = footer {
                        footer { class: "w-modal-foot", {footer} }
                    }
                }
            }
        }
    }
}

/// A confirmation for bulk or irreversible actions (ui-pages U-29: in-app, focus-trapped,
/// localized; never `window.confirm`). The focus starts on Cancel, so Enter right away does not
/// confirm. While `busy` the dialog cannot be dismissed.
#[component]
pub fn ConfirmDialog(
    open: ReadSignal<bool>,
    title: String,
    message: String,
    confirm_label: String,
    cancel_label: String,
    on_confirm: EventHandler<()>,
    on_cancel: EventHandler<()>,
    /// The confirm button is the danger variant (deleting, resetting).
    #[props(default)]
    danger: bool,
    #[props(default)] busy: bool,
) -> Element {
    let confirm_kind = if danger {
        ButtonKind::Danger
    } else {
        ButtonKind::Primary
    };
    let cancel_text = cancel_label.clone();
    rsx! {
        Modal {
            open,
            title,
            on_close: on_cancel,
            close_label: cancel_label,
            can_close: !busy,
            show_close: false,
            size: ModalSize::Sm,
            footer: rsx! {
                Button {
                    kind: ButtonKind::Ghost,
                    initial_focus: true,
                    disabled: busy,
                    onclick: move |_| on_cancel.call(()),
                    "{cancel_text}"
                }
                Button { kind: confirm_kind, busy, onclick: move |_| on_confirm.call(()), "{confirm_label}" }
            },
            p { class: "w-confirm-text", "{message}" }
        }
    }
}
