//! The lucide icons of the start page (markup of lucide-react 0.378: 24×24 view box, round caps,
//! `currentColor` stroke, class `lucide lucide-<name> <extra>`).
use dioxus::prelude::*;

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

/// `Loader2`: the spinning arc.
#[component]
pub(super) fn Spinner(class: &'static str, #[props(default = 24)] size: u32) -> Element {
    rsx! {
        Lucide { name: "loader-circle", class, size,
            path { d: "M21 12a9 9 0 1 1-6.219-8.56" }
        }
    }
}

/// `Lock` (kill-switch banner).
#[component]
pub(super) fn Lock(class: &'static str) -> Element {
    rsx! {
        Lucide { name: "lock", class,
            rect { width: "18", height: "11", x: "3", y: "11", rx: "2", ry: "2" }
            path { d: "M7 11V7a5 5 0 0 1 10 0v4" }
        }
    }
}

/// `ShieldOff` (leak card, «Снять блокировку»).
#[component]
pub(super) fn ShieldOff(class: &'static str) -> Element {
    rsx! {
        Lucide { name: "shield-off", class,
            path { d: "m2 2 20 20" }
            path { d: "M5 5a1 1 0 0 0-1 1v7c0 5 3.5 7.5 7.67 8.94a1 1 0 0 0 .67.01c2.35-.82 4.48-1.97 5.9-3.71" }
            path { d: "M9.309 3.652A12.252 12.252 0 0 0 11.24 2.28a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1v7a9.784 9.784 0 0 1-.08 1.264" }
        }
    }
}

/// `Square` (the cancel button's stop mark).
#[component]
pub(super) fn Square(size: u32) -> Element {
    rsx! {
        Lucide { name: "square", class: "", size,
            rect { width: "18", height: "18", x: "3", y: "3", rx: "2" }
        }
    }
}

/// `ArrowRight` of the power button (stroke 2.5).
#[component]
pub(super) fn ArrowRight(class: &'static str, size: u32) -> Element {
    rsx! {
        Lucide { name: "arrow-right", class, size, stroke: "2.5",
            path { d: "M5 12h14" }
            path { d: "m12 5 7 7-7 7" }
        }
    }
}
