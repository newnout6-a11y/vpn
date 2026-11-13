//! The quiet network banner (RU networks): while the latest network check of the current
//! network found a restriction (a mobile whitelist, the 16 KB freeze, a banned server address,
//! QUIC / UDP or DoH cut), one notice strip names the most limiting one; on a whitelist it also
//! says which servers the automatic choice tries first. The Maintenance backend owns the check
//! and forgets its result when the network changes; without that backend (demos, page tests)
//! there is no banner.
use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_view::netmode::{NetMode, net_banner};

use crate::hooks::use_watch;
use crate::lang::tr;
use crate::maintenance::MaintenanceApi;
use crate::t;

/// The banner when the app provides the network check.
#[component]
pub(super) fn NetBanner() -> Element {
    let provided = try_use_context::<Rc<dyn MaintenanceApi>>().is_some();
    rsx! {
        if provided {
            NetBannerShown {}
        }
    }
}

#[component]
fn NetBannerShown() -> Element {
    let api = use_context::<Rc<dyn MaintenanceApi>>();
    let state = use_watch(|| api.state());
    let modes = state
        .read()
        .network
        .last
        .as_ref()
        .map(|check| check.modes.clone())
        .unwrap_or_default();
    let Some(banner) = net_banner(&modes) else {
        return rsx! {};
    };
    rsx! {
        div { class: "overflow-hidden",
            div { class: "c-swiss swiss-notice", role: "note",
                span { class: "swiss-label swiss-notice-tag", {tr(&banner.title)} }
                p { class: "swiss-notice-body", {tr(&banner.body)} }
                if banner.mode == NetMode::Whitelist {
                    p { class: "swiss-notice-body", {t!("ui.dashboard.netmodeWhitelist")} }
                }
            }
        }
    }
}
