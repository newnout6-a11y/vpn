//! Inline lucide icons (same markup as lucide-react 0.378) and the round country flag coin.
use dioxus::prelude::*;

use crate::lang::translate;

/// A 24×24 lucide icon frame; `name` is the lucide class suffix.
#[component]
fn Lucide(
    name: &'static str,
    class: &'static str,
    #[props(default = 24)] size: u32,
    children: Element,
) -> Element {
    rsx! {
        svg {
            "xmlns": "http://www.w3.org/2000/svg",
            width: "{size}",
            height: "{size}",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            stroke_width: "2",
            stroke_linecap: "round",
            stroke_linejoin: "round",
            class: "lucide lucide-{name} {class}",
            {children}
        }
    }
}

/// `Loader2` (a spinning arc), e.g. `class: "h-3 w-3 animate-spin"`.
#[component]
pub(super) fn Spinner(class: &'static str) -> Element {
    rsx! {
        Lucide { name: "loader-circle", class,
            path { d: "M21 12a9 9 0 1 1-6.219-8.56" }
        }
    }
}

/// `Plus`.
#[component]
pub(super) fn Plus(class: &'static str) -> Element {
    rsx! {
        Lucide { name: "plus", class,
            path { d: "M5 12h14" }
            path { d: "M12 5v14" }
        }
    }
}

/// `RefreshCw`.
#[component]
pub(super) fn RefreshCw(class: &'static str) -> Element {
    rsx! {
        Lucide { name: "refresh-cw", class,
            path { d: "M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" }
            path { d: "M21 3v5h-5" }
            path { d: "M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" }
            path { d: "M8 16H3v5" }
        }
    }
}

/// `Square` (stop).
#[component]
pub(super) fn Square(class: &'static str) -> Element {
    rsx! {
        Lucide { name: "square", class,
            rect { width: "18", height: "18", x: "3", y: "3", rx: "2" }
        }
    }
}

/// `ChevronDown` of the picker, turned over while the list is open.
#[component]
pub(super) fn Chevron(open: bool) -> Element {
    let class = if open {
        "text-[var(--color-text-secondary)] transition-transform duration-[var(--transition-fast)] rotate-180"
    } else {
        "text-[var(--color-text-secondary)] transition-transform duration-[var(--transition-fast)]"
    };
    rsx! {
        Lucide { name: "chevron-down", class, size: 14,
            path { d: "m6 9 6 6 6-6" }
        }
    }
}

/// Round flag of `country` (ISO 3166-1 alpha-2) from the flag-icons rules in utilities.css; the
/// accessible name is the country's name in the UI language (the code when unknown).
#[component]
pub fn Flag(country: String, #[props(default = 14)] size: u32) -> Element {
    let iso = country.to_ascii_uppercase();
    let name = translate(&format!("ui.panels.country.{iso}"), &[], Some(&iso));
    let lower = iso.to_ascii_lowercase();
    rsx! {
        span {
            class: "fi fis inline-block shrink-0 rounded-full ring-1 ring-inset ring-[color-mix(in_srgb,var(--color-border-strong)_45%,transparent)] fi-{lower}",
            role: "img",
            aria_label: "{name}",
            title: "{name}",
            style: "width: {size}px; height: {size}px; font-size: {size}px;",
        }
    }
}
