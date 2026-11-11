//! Traffic panel: download figure, upload and session read-outs, 48 bars with a hover read-out.
use dioxus::prelude::*;
use vpnte_view::fmt::to_fixed;
use vpnte_view::traffic::{Bar, TrafficHistory, TrafficSample};

use super::PanelHead;
use crate::lang::tr;
use crate::t;

fn bar_class(bar: &Bar) -> String {
    let mut class = String::from("swiss-bar");
    for (on, name) in [
        (bar.off, " is-off"),
        (bar.hot, " is-hot"),
        (bar.faded, " is-faded"),
    ] {
        if on {
            class.push_str(name);
        }
    }
    class
}

/// The traffic panel; `history` is fed by the root's traffic pump.
#[component]
pub(super) fn TrafficPanel(
    sample: Signal<TrafficSample>,
    history: Signal<TrafficHistory>,
) -> Element {
    let mut hover = use_signal(|| None::<usize>);
    let s = sample();
    let running = s.running;
    let (bars, hovered) = {
        let h = history.read();
        (
            h.bars(running, hover()),
            hover().and_then(|i| h.hover_msg(i)),
        )
    };
    let mbps = t!("swiss.mbps");
    let up = format!("{} {mbps}", to_fixed(s.up_mbps(), 1));
    let session = format!("{} {}", to_fixed(s.session_gb(), 2), t!("swiss.gb"));
    rsx! {
        section { class: "swiss-panel",
            PanelHead { title: t!("swiss.traffic"), perch: "traffic",
                span { class: "swiss-label flex items-center gap-2",
                    if let Some(msg) = hovered {
                        span { class: "swiss-label-ink", {tr(&msg)} }
                    } else if running {
                        span { class: "blink h-1.5 w-1.5 bg-[var(--signal)]" }
                        {t!("swiss.live")}
                    } else {
                        {t!("swiss.noData")}
                    }
                }
            }
            div { class: "swiss-traffic-figures",
                div { class: "min-w-0",
                    div { class: "swiss-label", {t!("swiss.download")} }
                    div {
                        class: "swiss-traffic-big",
                        class: if !running { "is-dim" },
                        {to_fixed(s.down_mbps(), 1)}
                    }
                }
                div { class: "swiss-traffic-small",
                    div {
                        span { class: "swiss-label", {t!("swiss.upload")} }
                        span { class: "swiss-mono", "{up}" }
                    }
                    div {
                        span { class: "swiss-label", {t!("swiss.session")} }
                        span { class: "swiss-mono", "{session}" }
                    }
                }
            }
            div { class: "swiss-bars", onmouseleave: move |_| hover.set(None),
                for (i , bar) in bars.iter().enumerate() {
                    div {
                        key: "{i}",
                        class: "swiss-bar-slot",
                        onmouseenter: move |_| hover.set(Some(i)),
                        div {
                            class: bar_class(bar),
                            style: "height: {bar.height_pct}%;",
                        }
                    }
                }
            }
        }
    }
}
