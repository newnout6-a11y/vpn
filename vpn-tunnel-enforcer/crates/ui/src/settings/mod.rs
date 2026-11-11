//! The Settings page («Настройки», ui-pages §3.1–3.8, §6.4) in the «Пломба» language: one panel
//! per section. Settings fields go through an explicit Save as a sparse patch over the live
//! settings ([`SettingsDraft`]); every other control applies at once and shows its own result.
//! Every section renders from a watch channel of [`SettingsApi`], so changes made elsewhere show
//! immediately and nothing is read "once at mount" (U-33).
//!
//! The shell keeps a visited Settings page mounted, so the draft and the operations started here
//! (export, import, refresh) survive navigation without app-level slots.
use std::rc::Rc;

use dioxus::prelude::*;

mod advanced;
mod api;
mod behaviour;
mod connection;
pub mod demo;
mod dns;
mod domains;
mod draft;
mod fmt;
mod general;
mod kill_switch;
mod model;
mod notifications;
mod privacy;
mod protection;
mod rotation;
mod save_bar;
mod smart_ru;
mod transfer;

#[cfg(test)]
mod tests;

pub use api::SettingsApi;
pub use draft::SettingsDraft;
pub use fmt::{Countdown, countdown};
pub use model::*;

use crate::hooks::use_watch;
use crate::lang::tr;
use crate::pages::{Page, nav_number};
use crate::t;
use crate::widgets::{SectionHeader, ToastKind, Toasts, UiError};

/// The page's signals, shared by the sections through context.
#[derive(Clone, Copy)]
pub(crate) struct Ctx {
    pub state: Signal<SettingsState>,
    pub kill: Signal<KillSwitchView>,
    pub rotation: Signal<RotationView>,
    pub dns: Signal<DnsView>,
    pub domains: Signal<DomainsView>,
    pub notifications: Signal<NotificationsView>,
    pub draft: Signal<SettingsDraft>,
}

impl Ctx {
    /// The settings as shown: live values with the edits on top (subscribes).
    pub fn view(&self) -> SettingsView {
        self.draft.read().view(&self.state.read().settings)
    }

    /// Records an edit of the draft.
    pub fn edit(&self, f: impl FnOnce(&mut SettingsPatch)) {
        let live = self.state.peek().settings.clone();
        let mut draft = self.draft;
        draft.write().edit(&live, f);
    }
}

pub(crate) fn use_ctx() -> Ctx {
    use_context::<Ctx>()
}

pub(crate) fn use_api() -> Rc<dyn SettingsApi> {
    use_context::<Rc<dyn SettingsApi>>()
}

/// Shows a toast when the app provides the queue (tests and bare demos may not).
pub(crate) fn toast(kind: ToastKind, title: String, description: Option<String>) {
    if let Some(toasts) = try_consume_context::<Toasts>() {
        toasts.push(kind, title, description);
    }
}

/// The inline error line of an action; renders nothing without an error.
#[component]
pub(crate) fn ActionError(error: Option<UiError>) -> Element {
    match error {
        Some(err) => rsx! {
            p { class: "set-error", role: "alert", {tr(&err.msg)} }
        },
        None => rsx! {},
    }
}

/// A settings line for a control that names itself (a segmented group): the same look as
/// [`crate::widgets::Row`] without a `<label for>` pointing at nothing.
#[component]
pub(crate) fn Line(
    label: String,
    #[props(default)] hint: Option<String>,
    children: Element,
) -> Element {
    rsx! {
        div { class: "w-row",
            div { class: "w-row-text",
                span { class: "w-row-label", "{label}" }
                if let Some(hint) = hint {
                    p { class: "w-row-hint", "{hint}" }
                }
            }
            div { class: "w-row-control", {children} }
        }
    }
}

/// The Settings page root (register it for [`Page::Settings`]).
#[component]
pub fn SettingsPage() -> Element {
    let api = use_api();
    let state = use_watch(|| api.state());
    let kill = use_watch(|| api.kill_switch());
    let rotation = use_watch(|| api.rotation());
    let dns = use_watch(|| api.dns());
    let domains = use_watch(|| api.domains());
    let notifications = use_watch(|| api.notifications());
    let mut draft = use_signal(SettingsDraft::default);
    // An outside change that makes an edit equal to the live value cleans that edit.
    use_effect(move || {
        let live = state.read().settings.clone();
        let mut pruned = draft.peek().clone();
        pruned.prune(&live);
        if *draft.peek() != pruned {
            draft.set(pruned);
        }
    });
    let ctx = use_context_provider(|| Ctx {
        state,
        kill,
        rotation,
        dns,
        domains,
        notifications,
        draft,
    });
    let advanced = ctx.view().advanced_mode;
    let number = Page::ALL
        .iter()
        .position(|p| *p == Page::Settings)
        .map(nav_number);
    rsx! {
        div { class: "c-swiss swiss-skin set-page",
            SectionHeader {
                title: t!("settings.title"),
                number,
                description: t!("ui.settings.subtitle"),
            }
            div { class: "set-sections",
                general::General {}
                connection::Connection {}
                protection::Protection {}
                smart_ru::SmartRu {}
                kill_switch::KillSwitch {}
                behaviour::Behaviour {}
                rotation::Rotation {}
                dns::Dns {}
                domains::Domains {}
                notifications::Notifications {}
                transfer::Transfer {}
                advanced::AdvancedMode {}
                if advanced {
                    advanced::AdvancedParams {}
                }
                advanced::Tools {}
            }
            save_bar::SaveBar {}
        }
    }
}
