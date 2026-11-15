//! The start page's lucide icons (markup of lucide-react 0.378: 24×24 view box, round caps,
//! `currentColor` stroke, class `lucide lucide-<name> <extra>`) and the round country flag coin.
//! The slab and the banners use them too, so the reference DOM has one source.
use dioxus::prelude::*;

use crate::lang::translate;

/// The icon frame; `size` sets width and height, `stroke` the stroke width.
#[component]
fn Lucide(
    name: &'static str,
    class: &'static str,
    #[props(default = 24)] size: u32,
    #[props(default = "2")] stroke: &'static str,
    children: Element,
) -> Element {
    let class = if class.is_empty() {
        format!("lucide lucide-{name}")
    } else {
        format!("lucide lucide-{name} {class}")
    };
    rsx! {
        svg {
            "xmlns": "http://www.w3.org/2000/svg",
            width: "{size}",
            height: "{size}",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            stroke_width: stroke,
            stroke_linecap: "round",
            stroke_linejoin: "round",
            class,
            {children}
        }
    }
}

/// `Loader2` (a spinning arc), e.g. `class: "h-3 w-3 animate-spin"`.
#[component]
pub(crate) fn Spinner(class: &'static str, #[props(default = 24)] size: u32) -> Element {
    rsx! {
        Lucide { name: "loader-circle", class, size,
            path { d: "M21 12a9 9 0 1 1-6.219-8.56" }
        }
    }
}

/// `Plus`.
#[component]
pub(crate) fn Plus(class: &'static str) -> Element {
    rsx! {
        Lucide { name: "plus", class,
            path { d: "M5 12h14" }
            path { d: "M12 5v14" }
        }
    }
}

/// `RefreshCw`.
#[component]
pub(crate) fn RefreshCw(class: &'static str) -> Element {
    rsx! {
        Lucide { name: "refresh-cw", class,
            path { d: "M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" }
            path { d: "M21 3v5h-5" }
            path { d: "M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" }
            path { d: "M8 16H3v5" }
        }
    }
}

/// `Square` (stop; the cancel button's mark).
#[component]
pub(crate) fn Square(
    #[props(default)] class: &'static str,
    #[props(default = 24)] size: u32,
) -> Element {
    rsx! {
        Lucide { name: "square", class, size,
            rect { width: "18", height: "18", x: "3", y: "3", rx: "2" }
        }
    }
}

/// `ChevronDown` of the picker, turned over while the list is open.
#[component]
pub(crate) fn Chevron(open: bool) -> Element {
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

/// `Lock` (kill-switch banner).
#[component]
pub(crate) fn Lock(class: &'static str) -> Element {
    rsx! {
        Lucide { name: "lock", class,
            rect { width: "18", height: "11", x: "3", y: "11", rx: "2", ry: "2" }
            path { d: "M7 11V7a5 5 0 0 1 10 0v4" }
        }
    }
}

/// `ShieldOff` (leak card, «Снять блокировку»).
#[component]
pub(crate) fn ShieldOff(class: &'static str) -> Element {
    rsx! {
        Lucide { name: "shield-off", class,
            path { d: "m2 2 20 20" }
            path { d: "M5 5a1 1 0 0 0-1 1v7c0 5 3.5 7.5 7.67 8.94a1 1 0 0 0 .67.01c2.35-.82 4.48-1.97 5.9-3.71" }
            path { d: "M9.309 3.652A12.252 12.252 0 0 0 11.24 2.28a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1v7a9.784 9.784 0 0 1-.08 1.264" }
        }
    }
}

/// `ArrowRight` of the power button (stroke 2.5).
#[component]
pub(crate) fn ArrowRight(class: &'static str, size: u32) -> Element {
    rsx! {
        Lucide { name: "arrow-right", class, size, stroke: "2.5",
            path { d: "M5 12h14" }
            path { d: "m12 5 7 7-7 7" }
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
