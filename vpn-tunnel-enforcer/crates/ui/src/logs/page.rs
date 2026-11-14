//! The page root: the header with «Сохранить для поддержки», the three tabs and their panels.
use std::rc::Rc;

use dioxus::prelude::*;
use jiff::tz::TimeZone;
use vpnte_base::{ErrorKind, Msg};

use super::connections::ConnectionsTab;
use super::events_view::EventsTab;
use super::state::{Tab, use_remembered};
use super::table::PageTz;
use super::viewer::TechnicalTab;
use super::{tr_now, use_api, use_watch};
use crate::lang::translate_now;
use crate::maintenance::MaintenanceApi;
use crate::pages::{Page, nav_number};
use crate::t;
use crate::widgets::{Button, ButtonKind, SectionHeader, Tabs, Toasts, use_job};

/// The «Журнал» page (register as `Page::Logs`). Needs `Rc<dyn LogsApi>` and the [`Toasts`]
/// provider in context; «Сохранить для поддержки» shows when an `Rc<dyn MaintenanceApi>` is
/// there too (its diagnostics ZIP).
#[component]
pub fn LogsPage() -> Element {
    let api = use_api();
    let snapshot = use_watch(move || api.snapshot());
    let tz = use_hook(TimeZone::system);
    use_context_provider(|| PageTz(tz.clone()));
    let mut tab = use_remembered(|s| s.tab, |s, v| s.tab = v);
    let support = try_use_context::<Rc<dyn MaintenanceApi>>().is_some();
    let snap = snapshot.read().clone();
    let tabs: Vec<(Tab, String)> = Tab::ALL.iter().map(|t| (*t, t!(t.label_key()))).collect();
    let current = tab();
    rsx! {
        div { class: "c-swiss swiss-skin lg",
            SectionHeader {
                title: t!("logs.title"),
                number: nav_number(Page::ALL.iter().position(|p| *p == Page::Logs).unwrap_or(7)),
                description: t!("logs.description"),
                if support {
                    SupportButton {}
                }
            }
            Tabs {
                tabs,
                value: current,
                on_change: move |t| tab.set(t),
                label: t!("logs.tabs.label"),
                div { class: "lg-panel", "data-tab": current.id(),
                    match current {
                        Tab::Events => rsx! {
                            EventsTab { events: snap.events }
                        },
                        Tab::Connections => rsx! {
                            ConnectionsTab { history: snap.history }
                        },
                        Tab::Technical => rsx! {
                            TechnicalTab {}
                        },
                    }
                }
            }
        }
    }
}

/// «Сохранить для поддержки»: the Maintenance page's diagnostics ZIP (save dialog, the same
/// single flight app-wide). A dismissed dialog is silent.
#[component]
fn SupportButton() -> Element {
    let maintenance = use_context::<Rc<dyn MaintenanceApi>>();
    let toasts = Toasts::use_context();
    let job = use_job::<()>();
    let save = move |_| {
        let maintenance = maintenance.clone();
        job.start(move |token| async move {
            match maintenance.export_diagnostics(token).await {
                Ok(Some(done)) => {
                    let body = Msg::new("logs.support.saved").arg("path", &done.path);
                    toasts.success(
                        translate_now("logs.support.title", &[]),
                        Some(tr_now(&body)),
                    );
                }
                Ok(None) => {}
                Err(err) if err.kind == ErrorKind::Cancelled => {}
                Err(err) => {
                    tracing::warn!(error = %err, "support archive not saved");
                    toasts.error(
                        translate_now("logs.support.failed", &[]),
                        Some(tr_now(&err.user_msg())),
                    );
                }
            }
            Ok(())
        });
    };
    rsx! {
        Button {
            kind: ButtonKind::Ghost,
            small: true,
            busy: job.running(),
            onclick: save,
            {t!("logs.support.save")}
        }
    }
}
