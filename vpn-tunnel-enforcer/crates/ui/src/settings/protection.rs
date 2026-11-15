//! «Защита»: the disguise note, the protection switches (draft), the adaptive-bypass status line
//! (instant: retry / reset) and the privacy actions ([`super::privacy`]).
use dioxus::prelude::*;

use super::model::{AdaptivePhase, RoutingMode};
use super::privacy::{BrowserProtection, LocationPrivacy};
use super::{ActionError, use_api, use_ctx};
use crate::lang::tr;
use crate::t;
use crate::widgets::{Button, ButtonKind, Panel, Switch, use_job};

#[component]
pub(super) fn Protection() -> Element {
    let ctx = use_ctx();
    let view = ctx.view();
    // Proxy capture puts no WFP filters in place (NOADMIN §2): the switch is kept for Tunnel mode
    // and says so instead of looking like it protects now.
    let proxy_mode = view.routing_mode == RoutingMode::Soft;
    let leak_hint = if proxy_mode {
        t!("ui.settings.protection.leakTunnelOnly")
    } else {
        t!("ui.settings.protection.leakHint")
    };
    rsx! {
        Panel { title: t!("ui.settings.protection.title"), id: "set-protection",
            div { class: "set-note",
                p { class: "set-note-title", {t!("ui.settings.protection.disguiseTitle")} }
                p { {t!("ui.settings.protection.disguiseNow")} }
                p { {t!("ui.settings.protection.disguiseThen")} }
                p { class: "set-hint", {t!("ui.settings.protection.disguiseAuto")} }
            }
            Switch {
                label: t!("ui.settings.protection.leak"),
                hint: leak_hint,
                checked: view.leak_protection,
                disabled: proxy_mode,
                on_change: move |on| ctx.edit(|p| p.leak_protection = Some(on)),
            }
            Switch {
                label: t!("ui.settings.protection.wifi"),
                hint: t!("ui.settings.protection.wifiHint"),
                checked: view.public_wifi_compatibility,
                on_change: move |on| ctx.edit(|p| p.public_wifi_compatibility = Some(on)),
            }
            Switch {
                label: t!("ui.settings.protection.autoRestart"),
                hint: t!("ui.settings.protection.autoRestartHint"),
                checked: view.auto_restart_on_crash,
                on_change: move |on| ctx.edit(|p| p.auto_restart_on_crash = Some(on)),
            }
            Switch {
                label: t!("ui.settings.protection.stealth"),
                hint: t!("ui.settings.protection.stealthHint"),
                checked: view.stealth_mode,
                on_change: move |on| ctx.edit(|p| p.stealth_mode = Some(on)),
            }
            Switch {
                label: t!("ui.settings.protection.adaptive"),
                hint: t!("ui.settings.protection.adaptiveHint"),
                checked: view.adaptive_bypass,
                on_change: move |on| ctx.edit(|p| p.adaptive_bypass = Some(on)),
            }
            AdaptiveStatus {}
            Switch {
                label: t!("ui.settings.protection.geo"),
                hint: t!("ui.settings.protection.geoHint"),
                checked: view.disable_geo_lookup,
                on_change: move |on| ctx.edit(|p| p.disable_geo_lookup = Some(on)),
            }
            LocationPrivacy {}
            BrowserProtection {}
        }
    }
}

/// What the last adaptive action reported.
#[derive(Clone, Copy, PartialEq)]
enum AdaptiveDone {
    Retried(bool),
    Reset,
}

/// The adaptive status line, shown whatever the draft switch says (§3.1.5); «Повторить» only
/// after a failure, «Сбросить» always.
#[component]
fn AdaptiveStatus() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let job = use_job::<AdaptiveDone>();
    let adaptive = ctx.state.read().adaptive.clone();
    let line = adaptive
        .message
        .as_ref()
        .map_or_else(|| t!("ui.settings.protection.adaptiveUnavailable"), tr);
    let retry_api = api.clone();
    let retry = move |_| {
        let api = retry_api.clone();
        job.start(move |_| async move { api.retry_adaptive().await.map(AdaptiveDone::Retried) });
    };
    let reset = move |_| {
        let api = api.clone();
        job.start(move |_| async move {
            api.reset_adaptive_learning()
                .await
                .map(|()| AdaptiveDone::Reset)
        });
    };
    let (done, error) = match job.last() {
        Some(Ok(done)) => (Some(done), None),
        Some(Err(err)) => (None, Some(err)),
        None => (None, None),
    };
    let done_text = done.map(|d| match d {
        AdaptiveDone::Retried(true) => t!("ui.settings.protection.adaptiveRetried"),
        AdaptiveDone::Retried(false) => t!("ui.settings.protection.adaptiveNoSession"),
        AdaptiveDone::Reset => t!("ui.settings.protection.adaptiveCleared"),
    });
    rsx! {
        div { class: "set-status-line",
            class: if adaptive.phase == AdaptivePhase::Failed { "is-warn" },
            p { class: "set-status-text", role: "status", "{line}" }
            div { class: "set-status-actions",
                if adaptive.phase == AdaptivePhase::Failed {
                    Button { kind: ButtonKind::Link, busy: job.running(), onclick: retry,
                        {t!("common.retry")}
                    }
                }
                Button {
                    kind: ButtonKind::Link,
                    busy: job.running(),
                    title: t!("ui.settings.protection.adaptiveResetTitle"),
                    onclick: reset,
                    {t!("common.reset")}
                }
            }
        }
        if let Some(text) = done_text {
            p { class: "set-result", role: "status", "{text}" }
        }
        ActionError { error }
    }
}
