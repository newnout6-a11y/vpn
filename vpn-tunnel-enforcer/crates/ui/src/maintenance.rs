//! The Maintenance page («Починка», advanced mode; ui-pages §3.12, §3.16, §6.5): health check
//! (system diagnostics report + network protection read-back), the auto-repair (remove our
//! filters, legacy cleanup again, stale engines), the protection test with its leak result
//! panel, packet capture status, the diagnostics ZIP with progress, the last caught error and
//! the old-version data helpers.
//!
//! Everything renders from [`MaintenanceApi::state`] plus the page's own last outcome; the
//! auto-repair runs as one backend operation, so leaving the page never interrupts it.
use std::rc::Rc;

use dioxus::prelude::*;

use crate::hooks::use_watch;
use crate::pages::{Page, nav_number};
use crate::t;
use crate::widgets::{ConfirmDialog, SectionHeader};

mod api;
mod capture;
mod ctl;
pub mod demo;
mod legacy;
mod model;
mod network;
mod rules;
#[cfg(test)]
mod tests;
mod view;

pub use api::MaintenanceApi;
pub use model::*;
pub use rules::Outcome;

/// The page's backend from context.
fn use_api() -> Rc<dyn MaintenanceApi> {
    use_context::<Rc<dyn MaintenanceApi>>()
}

/// The Maintenance page root (register it for [`Page::Maintenance`]).
#[component]
pub fn MaintenancePage() -> Element {
    let api = use_api();
    let state = use_watch(|| api.state());
    let ctl = ctl::use_controller(api, state);
    let mut confirm_delete = use_signal(|| false);
    let number = Page::ALL
        .iter()
        .position(|p| *p == Page::Maintenance)
        .map(nav_number);
    let test = ctl.test.read().clone();
    let fault = state.read().fault.clone();
    rsx! {
        div { class: "c-swiss swiss-skin mt-page",
            SectionHeader {
                title: t!("ui.maintenance.title"),
                number,
                description: t!("ui.maintenance.subtitle"),
            }
            div { class: "mt-sections",
                view::StatePanel { ctl }
                view::StepsPanel { ctl }
                view::ResultsPanel { ctl }
                if let Some(test) = test {
                    view::LeakPanel { test: test.leak }
                }
                network::NetworkPanel { state }
                capture::CapturePanel { ctl }
                if let Some(fault) = fault {
                    capture::FaultPanel { fault }
                }
                legacy::LegacyPanel { ctl, on_delete: move |_| confirm_delete.set(true) }
            }
            ConfirmDialog {
                open: confirm_delete,
                title: t!("ui.maintenance.legacy.confirmTitle"),
                message: t!("ui.maintenance.legacy.confirm"),
                confirm_label: t!("ui.maintenance.legacy.delete"),
                cancel_label: t!("common.cancel"),
                danger: true,
                on_confirm: move |_| {
                    confirm_delete.set(false);
                    ctl.delete_legacy();
                },
                on_cancel: move |_| confirm_delete.set(false),
            }
        }
    }
}
