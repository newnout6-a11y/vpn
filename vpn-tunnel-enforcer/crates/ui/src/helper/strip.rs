//! [`TunnelStrip`]: the start page's notice while Tunnel mode is chosen but cannot run.
use std::rc::Rc;

use dioxus::prelude::*;

use super::view::install_key;
use super::{Ability, HelperApi, use_capability};
use crate::lang::tr;
use crate::t;
use crate::widgets::use_job;

/// While the saved mode is Tunnel (`tunnel_mode`) and the helper service is missing, one calm
/// strip in the start page's own notice style says so before «Подключить» is pressed, with its
/// install; while the installed service is starting or stopped, the strip says that instead
/// (nothing to install); while it is too old to speak to, it says so with its update (review
/// wire5-a1). Nothing in every other state, and nothing without a helper backend in context.
#[component]
pub fn TunnelStrip(tunnel_mode: bool) -> Element {
    let cap = use_capability();
    let api = try_use_context::<Rc<dyn HelperApi>>();
    let install = use_job::<bool>();
    let (Some(cap), Some(api)) = (cap, api.filter(|_| tunnel_mode)) else {
        return rsx! {};
    };
    // The body, and the strip's one action: the install (`false`) or the update (`true`).
    let (body, action) = match cap.tunnel {
        Ability::Service => match cap.service.pause_key() {
            Some(key) => (key, cap.service.needs_update().then_some(true)),
            None => return rsx! {},
        },
        Ability::NeedsService => ("ui.helper.strip.body", Some(false)),
        Ability::InProcess | Ability::NotInVersion => return rsx! {},
    };
    let error = match install.last() {
        Some(Err(err)) => Some(tr(&err.msg)),
        _ => None,
    };
    rsx! {
        div { class: "overflow-hidden",
            div { class: "c-swiss swiss-notice", role: "status", "data-helper": "tunnel-strip",
                span { class: "swiss-label swiss-notice-tag", {t!("ui.helper.strip.title")} }
                p { class: "swiss-notice-body", {t!(body)} }
                if let Some(error) = error {
                    p { class: "swiss-notice-body", role: "alert", "{error}" }
                }
                if let Some(update) = action {
                    div { class: "swiss-confirm-actions",
                        button {
                            r#type: "button",
                            class: "swiss-confirm-yes",
                            disabled: install.running(),
                            onclick: move |_| {
                                let api = api.clone();
                                install.start(move |_| async move { api.install_service().await });
                            },
                            {t!(install_key(update))}
                        }
                    }
                }
            }
        }
    }
}
