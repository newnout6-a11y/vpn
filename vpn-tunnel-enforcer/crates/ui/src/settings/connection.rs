//! «Подключение»: VPN source, routing mode (+ Soft targets), proxy engine. All draft fields.
use dioxus::prelude::*;

use super::model::{ConnectionMode, EnginePref, RoutingMode};
use super::{Line, use_ctx};
use crate::pages::{Page, use_nav};
use crate::t;
use crate::widgets::{Button, ButtonKind, Checkbox, Panel, Row, Segmented, Select, SelectOption};

#[component]
pub(super) fn Connection() -> Element {
    let ctx = use_ctx();
    let view = ctx.view();
    let nav = use_nav();
    let modes = vec![
        SelectOption::new(
            ConnectionMode::LocalProxy,
            t!("ui.settings.connection.sourceLocal"),
        ),
        SelectOption::new(
            ConnectionMode::DirectVpn,
            t!("ui.settings.connection.sourceDirect"),
        ),
    ];
    let engines = vec![
        SelectOption::new(EnginePref::Auto, t!("ui.settings.connection.engineAuto")),
        SelectOption::new(
            EnginePref::SingBox,
            t!("ui.settings.connection.engineSingBox"),
        ),
        SelectOption::new(EnginePref::Xray, t!("ui.settings.connection.engineXray")),
    ];
    let routing_hint = match view.routing_mode {
        RoutingMode::Hard => t!("ui.settings.connection.hardHint"),
        RoutingMode::Soft => t!("ui.settings.connection.softHint"),
    };
    // Without the TUN only Proxy can be saved: a stored Tunnel choice can still move to Proxy,
    // a Tunnel choice is ignored, and the reason stays on screen.
    let tun_available = ctx.state.read().tun_available;
    let pick_routing = move |mode: RoutingMode| {
        if mode == RoutingMode::Soft || tun_available {
            ctx.edit(|p| p.routing_mode = Some(mode));
        }
    };
    rsx! {
        Panel { title: t!("ui.settings.connection.title"), id: "set-connection",
            Row {
                label: t!("ui.settings.connection.source"),
                hint: t!("ui.settings.connection.sourceHint"),
                Select {
                    options: modes,
                    value: Some(view.connection_mode),
                    on_change: move |mode| ctx.edit(|p| p.connection_mode = Some(mode)),
                }
            }
            if view.connection_mode == ConnectionMode::DirectVpn {
                div { class: "set-note",
                    p { class: "set-note-title", {t!("ui.settings.connection.directTitle")} }
                    p { {t!("ui.settings.connection.directText")} }
                    Button {
                        kind: ButtonKind::Link,
                        onclick: move |_| nav.go(Page::Servers),
                        {t!("ui.settings.connection.openServers")}
                    }
                }
            }
            Line { label: t!("ui.settings.connection.routing"), hint: routing_hint,
                Segmented {
                    label: t!("ui.settings.connection.routing"),
                    options: vec![
                        (RoutingMode::Hard, t!("ui.settings.connection.hard")),
                        (RoutingMode::Soft, t!("ui.settings.connection.soft")),
                    ],
                    value: view.routing_mode,
                    disabled: !tun_available && view.routing_mode == RoutingMode::Soft,
                    on_change: pick_routing,
                }
            }
            if !tun_available {
                p { class: "set-hint", "data-unavailable": "tun", {t!("ui.settings.connection.tunUnavailable")} }
            }
            if view.routing_mode == RoutingMode::Soft {
                div { class: "set-subgroup", role: "group", aria_label: t!("ui.settings.connection.softTargets"),
                    p { class: "set-subgroup-title", {t!("ui.settings.connection.softTargets")} }
                    p { class: "set-hint", {t!("ui.settings.connection.softTargetsHint")} }
                    Checkbox {
                        label: "Git",
                        checked: view.soft_git,
                        on_change: move |on| ctx.edit(|p| p.soft_git = Some(on)),
                    }
                    Checkbox {
                        label: "Gradle",
                        checked: view.soft_gradle,
                        on_change: move |on| ctx.edit(|p| p.soft_gradle = Some(on)),
                    }
                    Checkbox {
                        label: "Android Studio",
                        checked: view.soft_studio,
                        on_change: move |on| ctx.edit(|p| p.soft_studio = Some(on)),
                    }
                }
            }
            Row {
                label: t!("ui.settings.connection.engine"),
                hint: t!("ui.settings.connection.engineHint"),
                Select {
                    options: engines,
                    value: Some(view.proxy_engine),
                    on_change: move |engine| ctx.edit(|p| p.proxy_engine = Some(engine)),
                }
            }
        }
    }
}
