//! The mascot drawn from plain absolutely positioned squares (`Mascot.tsx`): same DOM, classes and
//! computed inline styles as the reference so the metrics diff can match it element by element.
//!
//! Every inline style that can change is written as dioxus style-namespace attributes
//! (`style.setProperty` / `removeProperty`), never as a changing `style="…"` string: dioxus merges
//! an updated `style` attribute with the previous inline styles and, for shorthands holding
//! `var()` (whose longhands read back empty), deletes them; the eyes lost their colour that way.
use dioxus::prelude::*;
use vpnte_view::mascot::{Fx, MascotView};

use super::face::{self, Colors, Eye, Mouth};
use super::stage;

const BUTTON_CLASS: &str = "relative mx-auto block focus-visible:outline focus-visible:outline-2 \
     focus-visible:outline-offset-4 focus-visible:outline-[var(--signal)]";
const EYE_CLASS: &str = "flex items-center justify-center overflow-hidden transition-[width,height,background-color,transform] duration-200";
const MOUTH_CLASS: &str = "block transition-[width,height,background-color,transform] duration-200";

/// Everything one rendering of him needs.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Look {
    pub view: MascotView,
    pub colors: Colors,
    /// Bumps on every landing; 0 = never landed (no squash on the first placement).
    pub land: u32,
    /// Translated accessible name (`mascot.name`).
    pub label: String,
}

/// The button with the keyed inner layers. The button itself never remounts so keyboard focus
/// survives; the landing squash, one-shot body moves and confetti replay by remounting their layer.
pub(super) fn mascot(look: &Look, on_poke: EventHandler<()>) -> Element {
    let Look {
        view,
        colors: c,
        land,
        label,
    } = look;
    let f = face::face(view.mood);
    let land_class = if *land > 0 { "block m-land" } else { "block" };
    let body_class = match view.body.class() {
        "" => "block".to_string(),
        anim => format!("block {anim}"),
    };
    let loop_class = match f.idle {
        Some(anim) => format!("relative block {anim}"),
        None => "relative block".to_string(),
    };
    let body = c.body;
    rsx! {
        div { class: "relative w-[96px] select-none",
            button {
                r#type: "button",
                "data-mascot": "",
                aria_label: "{label}",
                title: "{label}",
                class: BUTTON_CLASS,
                onclick: move |_| on_poke.call(()),
                for id in [*land] {
                    span { key: "{id}", class: land_class,
                        for id in [view.body_id] {
                            span { key: "{id}", class: "{body_class}",
                                span { class: "{loop_class}",
                                    {effects(view, c)}
                                    span { class: "m-tag absolute -top-[22px] left-1/2 flex -translate-x-1/2 flex-col items-center",
                                        span { class: "h-3 w-3 border-2", border_color: body, background: c.tag_fill }
                                        span { class: "h-3 w-[2px]", background: body }
                                    }
                                    div {
                                        class: "relative h-[80px] w-[80px] transition-[background-color] duration-300",
                                        background: body,
                                        div { class: "absolute left-0 right-0 top-[22px] flex h-6 items-center justify-center gap-3",
                                            {eye(&f.left, c, "left")}
                                            {eye(&f.right, c, "right")}
                                        }
                                        if f.cheeks {
                                            span { class: "absolute left-[10px] top-[44px] h-[4px] w-[10px]", background: c.blush }
                                            span { class: "absolute right-[10px] top-[44px] h-[4px] w-[10px]", background: c.blush }
                                        }
                                        span {
                                            class: "absolute bottom-[14px] left-1/2 -ml-[13px] flex w-[26px] justify-center",
                                            aria_hidden: "true",
                                            {mouth(f.mouth, c.eye)}
                                        }
                                    }
                                    div { class: "mt-[3px] flex justify-between px-3",
                                        span { class: "h-1.5 w-4", background: body }
                                        span { class: "h-1.5 w-4", background: body }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The mouth in the eye colour: a filled rectangle (maybe moved) or a hollow ring.
fn mouth(m: Mouth, eye: &'static str) -> Element {
    match m {
        Mouth::Rect { w, h, transform } => rsx! {
            span {
                class: MOUTH_CLASS,
                width: "{w}px",
                height: "{h}px",
                background: eye,
                transform: transform,
            }
        },
        Mouth::Ring(size) => rsx! {
            span {
                class: MOUTH_CLASS,
                width: "{size}px",
                height: "{size}px",
                border: "2px solid {eye}",
            }
        },
    }
}

/// One eye (`EyeView`): a diamond, or a square with an optional pupil that is pinned, animated or
/// follows the pointer through the stage's `--lx` / `--ly`.
fn eye(spec: &Eye, c: &Colors, side: &str) -> Element {
    if spec.diamond {
        return rsx! {
            span { class: "flex h-[18px] w-[18px] items-center justify-center",
                span { class: "block h-[13px] w-[13px] rotate-45", background: c.eye }
            }
        };
    }
    let class = if spec.blink {
        format!("m-eye {side} {EYE_CLASS}")
    } else {
        EYE_CLASS.to_string()
    };
    let shift = (spec.dy != 0).then(|| format!("translateY({}px)", spec.dy));
    let pupil = spec.pupil;
    let look = match spec.fixed {
        Some((x, y)) => Some(format!("translate({x}px, {y}px)")),
        None => spec.free().then(|| stage::LOOK.to_string()),
    };
    let wrapper = spec.anim.map_or("", |a| a.class());
    rsx! {
        span {
            class: "{class}",
            background: c.eye,
            width: "{spec.w}px",
            height: "{spec.h}px",
            transform: shift,
            if pupil > 0 {
                span { class: wrapper,
                    span {
                        class: "block transition-transform duration-100",
                        background: c.body,
                        width: "{pupil}px",
                        height: "{pupil}px",
                        transform: look,
                    }
                }
            }
        }
    }
}

/// The effect around him (`Effects`). Confetti is keyed by `fx_id` so each burst replays.
fn effects(view: &MascotView, c: &Colors) -> Element {
    let body = c.body;
    match view.fx {
        None => rsx! {},
        Some(Fx::Confetti) => {
            let colors = face::confetti_colors(c);
            rsx! {
                for id in [view.fx_id] {
                    span {
                        key: "{id}",
                        class: "pointer-events-none absolute left-1/2 top-[40px] z-10",
                        aria_hidden: "true",
                        for (i, p) in face::confetti().enumerate() {
                            // Created once per burst; custom properties need the style string.
                            span {
                                class: "m-confetti absolute",
                                style: "width: {p.size}px; height: {p.size}px; background-color: {colors[i % colors.len()]}; animation-delay: {p.delay_ms}ms; --dx: {p.dx}px; --dy: {p.dy}px; --rot: {p.rot}deg;",
                            }
                        }
                    }
                }
            }
        }
        Some(Fx::Zzz) => rsx! {
            span {
                class: "swiss-mono pointer-events-none absolute -right-3 -top-1 font-bold",
                color: body,
                aria_hidden: "true",
                for (delay, size) in [("0s", "11px"), ("0.8s", "14px"), ("1.6s", "17px")] {
                    span { class: "m-zzz absolute", animation_delay: delay, font_size: size, "z" }
                }
            }
        },
        Some(Fx::Dots) => rsx! {
            span {
                class: "pointer-events-none absolute -top-[40px] left-1/2 flex -translate-x-1/2 gap-1",
                aria_hidden: "true",
                for delay in ["0s", "0.33s", "0.66s"] {
                    span { class: "m-dot h-2 w-2", background: body, animation_delay: delay }
                }
            }
        },
        Some(Fx::Sweat) => rsx! {
            span {
                class: "m-drop pointer-events-none absolute -left-1 top-1 z-10 h-[10px] w-[6px] border-2",
                border_color: body,
                background: c.eye,
                aria_hidden: "true",
            }
        },
        // Little diamonds rising off the head while he is being petted.
        Some(Fx::Hearts) => rsx! {
            span { class: "pointer-events-none absolute -top-[18px] left-1/2 z-10", aria_hidden: "true",
                for (x, delay) in [("-22px", "0s"), ("4px", "0.28s"), ("24px", "0.56s"), ("-6px", "0.84s")] {
                    span {
                        class: "m-heart absolute block h-[7px] w-[7px]",
                        left: x,
                        background: c.blush,
                        animation_delay: delay,
                    }
                }
            }
        },
        Some(Fx::Speed) => rsx! {
            span { class: "pointer-events-none absolute -left-8 top-[24px] flex flex-col gap-2.5", aria_hidden: "true",
                for (w, delay) in [("18px", "0s"), ("26px", "0.12s"), ("14px", "0.24s")] {
                    span { class: "m-speed block h-[3px]", width: w, background: body, animation_delay: delay }
                }
            }
        },
    }
}

/// The speech bubble (`Bubble`), keyed by the line's id so its entrance replays; where it hangs
/// (above or below, which point sits over him) comes from the stage's variables.
pub(super) fn bubble(id: u32, text: &str, below: bool) -> Element {
    let tail = if below {
        "absolute h-3 w-3 -translate-x-1/2 rotate-45 border-[var(--ink)] bg-[var(--paper)] -top-[7px] border-l-2 border-t-2"
    } else {
        "absolute h-3 w-3 -translate-x-1/2 rotate-45 border-[var(--ink)] bg-[var(--paper)] -bottom-[7px] border-b-2 border-r-2"
    };
    rsx! {
        for id in [id] {
            div {
                key: "{id}",
                class: "absolute",
                aria_hidden: "true",
                style: stage::BUBBLE_STYLE,
                div { class: "bubble-in swiss-mono relative w-max max-w-56 border-2 border-[var(--ink)] bg-[var(--paper)] px-2.5 py-1.5 text-[11px] leading-snug text-[var(--ink)]",
                    "{text}"
                    span { class: tail, style: stage::TAIL_STYLE }
                }
            }
        }
    }
}
