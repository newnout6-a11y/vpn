//! The facts strip: routing mode · Smart RU (with its toggle) · kill-switch · leaks (with the
//! check button). Each cell is a mascot perch.
use dioxus::prelude::*;
use vpnte_view::labels::{FactValue, kill_switch_fact, leak_fact, mode_fact, smart_fact};

use super::Dash;
use crate::lang::tr;
use crate::t;

/// `div.swiss-facts`.
#[component]
pub(super) fn FactsStrip() -> Element {
    let dash = use_context::<Dash>();
    let view = dash.view.read().clone();
    let smart = smart_fact(view.smart_ru);
    let saving = dash.smart.running();
    let checking = dash.leak.running();
    let leak = leak_fact(view.leak, checking);
    let pending = t!("swiss.smartPending");
    let (toggle, check) = (dash.clone(), dash.clone());
    rsx! {
        div { class: "swiss-facts",
            Fact { label: t!("swiss.labelMode"),
                Value { value: mode_fact(view.soft_mode) }
            }
            Fact { label: t!("swiss.labelSmart"), perch: "smart",
                Value { value: smart.value, title: pending.clone() }
                button {
                    r#type: "button",
                    class: "swiss-fact-action",
                    disabled: saving,
                    aria_label: tr(&smart.action_aria),
                    title: "{pending}",
                    onclick: move |_| toggle.toggle_smart(),
                    {tr(&smart.action)}
                }
            }
            Fact { label: t!("swiss.labelKs"), perch: "killswitch",
                Value { value: kill_switch_fact(&view.firewall.in_mode(view.soft_mode)) }
            }
            Fact { label: t!("swiss.labelLeaks"), perch: "leak",
                Value { value: leak, blink: checking }
                // keeps its space while checking (visibility, not display), so nothing jumps in
                button {
                    r#type: "button",
                    class: "swiss-fact-action",
                    class: if checking { "is-hidden" },
                    disabled: checking,
                    aria_label: t!("swiss.checkAria"),
                    onclick: move |_| check.check_leaks(),
                    {t!("swiss.check")}
                }
            }
        }
    }
}

/// One cell: the mono label, then the value and its action.
#[component]
fn Fact(
    label: String,
    #[props(default)] perch: Option<&'static str>,
    children: Element,
) -> Element {
    rsx! {
        div {
            class: "swiss-fact",
            "data-perch": perch,
            "data-perch-y": "bottom",
            "data-perch-x": "0.6",
            "data-perch-scale": "0.36",
            "data-perch-fit": "gap",
            span { class: "swiss-label shrink-0", "{label}" }
            {children}
        }
    }
}

/// `span.swiss-fact-value` with its emphasis; `blink` adds the blinking cursor of a running check.
#[component]
fn Value(
    value: FactValue,
    #[props(default)] title: Option<String>,
    #[props(default)] blink: bool,
) -> Element {
    rsx! {
        span {
            class: "swiss-fact-value",
            class: if value.alert { "is-alert" },
            class: if value.dim { "is-dim" },
            title,
            {tr(&value.text)}
            if blink {
                span { class: "blink", "_" }
            }
        }
    }
}
