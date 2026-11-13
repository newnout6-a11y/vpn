//! [`TunnelStrip`]: the start page's notice while Tunnel mode is chosen but cannot run.
use std::rc::Rc;

use dioxus::prelude::*;

use super::{Ability, HelperApi, use_capability};
use crate::lang::tr;
use crate::t;
use crate::widgets::use_job;

/// While the saved mode is Tunnel (`tunnel_mode`) and the helper service is missing, one calm
/// strip in the start page's own notice style says so before «Подключить» is pressed, with its
/// install. Nothing in every other state, and nothing without a helper backend in context.
#[component]
pub fn TunnelStrip(tunnel_mode: bool) -> Element {
    let cap = use_capability();
    let api = try_use_context::<Rc<dyn HelperApi>>();
    let install = use_job::<bool>();
    let waits = cap.is_some_and(|c| c.tunnel == Ability::NeedsService);
    let Some(api) = api.filter(|_| tunnel_mode && waits) else {
        return rsx! {};
    };
    let error = match install.last() {
        Some(Err(err)) => Some(tr(&err.msg)),
        _ => None,
    };
    rsx! {
        div { class: "overflow-hidden",
            div { class: "c-swiss swiss-notice", role: "status", "data-helper": "tunnel-strip",
                span { class: "swiss-label swiss-notice-tag", {t!("ui.helper.strip.title")} }
                p { class: "swiss-notice-body", {t!("ui.helper.strip.body")} }
                if let Some(error) = error {
                    p { class: "swiss-notice-body", role: "alert", "{error}" }
                }
                div { class: "swiss-confirm-actions",
                    button {
                        r#type: "button",
                        class: "swiss-confirm-yes",
                        disabled: install.running(),
                        onclick: move |_| {
                            let api = api.clone();
                            install.start(move |_| async move { api.install_service().await });
                        },
                        {t!("ui.helper.install")}
                    }
                }
            }
        }
    }
}
