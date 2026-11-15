//! Buttons: [`Button`] (primary / ghost / danger / link, with a busy state), [`IconButton`]
//! (always named) and the inline [`Icon`] set.
use dioxus::prelude::*;

use super::feedback::Spinner;
use super::title_with_reason;

/// Look of a [`Button`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ButtonKind {
    /// Ink fill, the signal wipe on hover: the one main action of a form or dialog.
    #[default]
    Primary,
    /// Hairline frame: secondary actions.
    Ghost,
    /// Signal frame and text: deletes, resets.
    Danger,
    /// Mono caption underlined, no frame: actions in panel headers and table rows.
    Link,
}

impl ButtonKind {
    fn class(self) -> &'static str {
        match self {
            ButtonKind::Primary => "w-btn is-primary",
            ButtonKind::Ghost => "w-btn is-ghost",
            ButtonKind::Danger => "w-btn is-danger",
            ButtonKind::Link => "w-btn is-link",
        }
    }
}

/// A text button. While `busy` it shows a spinner, is disabled and says so (`aria-busy`), so a
/// second click cannot start a second run.
#[component]
pub fn Button(
    #[props(default)] kind: ButtonKind,
    #[props(default)] busy: bool,
    #[props(default)] disabled: bool,
    /// Why the button is disabled: shown as its `title`.
    #[props(default)]
    disabled_reason: Option<String>,
    #[props(default)] title: Option<String>,
    #[props(default)] small: bool,
    #[props(default)] wide: bool,
    #[props(default)] id: Option<String>,
    /// Receives the focus when the enclosing dialog opens.
    #[props(default)]
    initial_focus: bool,
    #[props(default)] onclick: EventHandler<MouseEvent>,
    children: Element,
) -> Element {
    let off = disabled || busy;
    let reason = if disabled { disabled_reason } else { None };
    let title = match (title, reason) {
        (Some(t), r) => Some(title_with_reason(&t, r.as_deref())),
        (None, Some(r)) => Some(r),
        (None, None) => None,
    };
    rsx! {
        button {
            r#type: "button",
            id,
            class: "{kind.class()}",
            class: if small { "is-small" },
            class: if wide { "is-wide" },
            class: if busy { "is-busy" },
            disabled: off,
            aria_busy: busy.then_some("true"),
            title,
            "data-w-autofocus": initial_focus.then_some("true"),
            onclick: move |evt| {
                if !off {
                    onclick.call(evt);
                }
            },
            if busy {
                Spinner {}
            }
            span { class: "w-btn-text", {children} }
        }
    }
}

/// An icon-only button. `label` is required: it is the accessible name and the hover title
/// (old icon buttons had neither, ui-pages U-15).
#[component]
pub fn IconButton(
    glyph: IconGlyph,
    label: String,
    #[props(default)] danger: bool,
    #[props(default)] busy: bool,
    #[props(default)] disabled: bool,
    #[props(default)] disabled_reason: Option<String>,
    /// Ink fill instead of the quiet frameless look (the dashboard's square «+»).
    #[props(default)]
    solid: bool,
    #[props(default)] pressed: Option<bool>,
    #[props(default)] onclick: EventHandler<MouseEvent>,
) -> Element {
    let off = disabled || busy;
    let title = title_with_reason(
        &label,
        disabled.then_some(()).and(disabled_reason.as_deref()),
    );
    rsx! {
        button {
            r#type: "button",
            class: "w-icon-btn",
            class: if danger { "is-danger" },
            class: if solid { "is-solid" },
            disabled: off,
            aria_label: "{label}",
            aria_busy: busy.then_some("true"),
            aria_pressed: pressed.map(|p| if p { "true" } else { "false" }),
            title: "{title}",
            onclick: move |evt| {
                if !off {
                    onclick.call(evt);
                }
            },
            if busy {
                Spinner {}
            } else {
                Icon { glyph }
            }
        }
    }
}

/// The inline icon set (16 px grid, 1.5 px square-capped strokes in `currentColor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconGlyph {
    Close,
    Plus,
    Minus,
    Check,
    ChevronDown,
    ChevronUp,
    ArrowRight,
    Refresh,
    Copy,
    Trash,
    Edit,
    More,
    Search,
    Info,
    Warning,
}

impl IconGlyph {
    /// Stroked path data.
    fn path(self) -> &'static str {
        match self {
            IconGlyph::Close => "M4 4L12 12M12 4L4 12",
            IconGlyph::Plus => "M8 3V13M3 8H13",
            IconGlyph::Minus => "M3 8H13",
            IconGlyph::Check => "M3 8.5L6.5 12L13 4.5",
            IconGlyph::ChevronDown => "M4 6L8 10L12 6",
            IconGlyph::ChevronUp => "M4 10L8 6L12 10",
            IconGlyph::ArrowRight => "M3 8H13M9 4L13 8L9 12",
            IconGlyph::Refresh => "M12.6 9.5A5 5 0 1 1 11.5 4.4M12.5 2.5V5.5H9.5",
            IconGlyph::Copy => "M5.5 5.5H12.5V12.5H5.5ZM3.5 10.5V3.5H10.5",
            IconGlyph::Trash => "M3 4.5H13M6 4.5V2.5H10V4.5M4.5 4.5L5 13.5H11L11.5 4.5",
            IconGlyph::Edit => "M10.5 3L13 5.5L6 12.5H3.5V10Z",
            IconGlyph::More => "",
            IconGlyph::Search => "M10.5 10.5L13.5 13.5M11 7A4 4 0 1 1 3 7A4 4 0 1 1 11 7Z",
            IconGlyph::Info => "M2.5 2.5H13.5V13.5H2.5ZM8 7V11.5M8 4.5V5.5",
            IconGlyph::Warning => "M8 2.5L14 13.5H2Z M8 6.5V9.5M8 11V12",
        }
    }

    /// Filled squares (the «…» of overflow buttons).
    fn fill(self) -> &'static str {
        match self {
            IconGlyph::More => "M2.5 7H4.5V9H2.5ZM7 7H9V9H7ZM11.5 7H13.5V9H11.5Z",
            _ => "",
        }
    }
}

/// One glyph of the icon set, hidden from assistive technology (the control carries the name).
#[component]
pub fn Icon(glyph: IconGlyph, #[props(default = 16)] size: u32) -> Element {
    let (stroke, fill) = (glyph.path(), glyph.fill());
    rsx! {
        svg {
            class: "w-icon",
            width: "{size}",
            height: "{size}",
            view_box: "0 0 16 16",
            fill: "none",
            "aria-hidden": "true",
            "focusable": "false",
            if !stroke.is_empty() {
                path {
                    d: stroke,
                    stroke: "currentColor",
                    stroke_width: "1.5",
                    stroke_linecap: "square",
                }
            }
            if !fill.is_empty() {
                path { d: fill, fill: "currentColor" }
            }
        }
    }
}
