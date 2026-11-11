//! One server row: flag, name (opens the detail), badges, Happ-style type line, the ping with its
//! status mark, the select / switch control and the «…» menu.
use dioxus::prelude::*;

use super::actions::Actions;
use super::menu::{MenuItem, OverflowMenu};
use super::model::{GroupView, ServerView};
use super::present::{
    RowSignal, Unusable, device_label, displayed_ping, happ_type, has_flag,
    is_removed_from_subscription, proxy_ready, relative_time, row_signal, stealth_badge, unusable,
};
use super::state::{Confirm, effective_health};
use crate::t;
use crate::widgets::{Badge, Button, ButtonKind, Icon, IconGlyph, Spinner, Tone};

/// Round flag coin, or the mono country code where the shared stylesheet has no flag.
#[component]
pub(crate) fn Flag(country: Option<String>) -> Element {
    match country {
        Some(code) if has_flag(&code) => {
            let lower = code.to_ascii_lowercase();
            rsx! {
                span { class: "fi fis srv-flag fi-{lower}", role: "img", aria_label: "{code}", title: "{code}" }
            }
        }
        Some(code) => rsx! {
            span { class: "srv-flag is-code swiss-mono", aria_hidden: "true", "{code}" }
        },
        None => rsx! {
            span { class: "srv-flag is-code is-none", aria_hidden: "true" }
        },
    }
}

/// The status mark left of the ping (fresh ping › key health › persisted ping status).
#[component]
fn SignalMark(signal: RowSignal) -> Element {
    let (class, title) = match &signal {
        RowSignal::FreshPing => ("is-ok", t!("ui.servers.row.freshPing")),
        RowSignal::Alive => ("is-ok", t!("servers.health.alive")),
        RowSignal::Dead(Some(reason)) => (
            "is-fail",
            crate::lang::translate(
                &format!("servers.health.reasons.{}", reason.code()),
                &[],
                Some(reason.code()),
            ),
        ),
        RowSignal::Dead(None) => ("is-fail", t!("servers.health.dead")),
        RowSignal::Online => ("is-online", t!("servers.online")),
        RowSignal::Offline => ("is-offline", t!("servers.offline")),
        RowSignal::Unknown => ("is-unknown", t!("ui.servers.row.notChecked")),
    };
    let glyph = match signal {
        RowSignal::FreshPing | RowSignal::Alive => Some(IconGlyph::Check),
        RowSignal::Dead(_) => Some(IconGlyph::Warning),
        _ => None,
    };
    rsx! {
        span { class: "srv-signal {class}", role: "img", aria_label: "{title}", title: "{title}",
            if let Some(glyph) = glyph {
                Icon { glyph, size: 14 }
            }
        }
    }
}

#[component]
pub(crate) fn ServerRow(server: ServerView, group: Option<GroupView>) -> Element {
    let actions = use_context::<Actions>();
    let store = actions.store;
    let view = store.view.read();
    let rt = store
        .rows
        .read()
        .get(&server.id)
        .cloned()
        .unwrap_or_default();
    let selecting = store.selecting.read().clone();
    let id = server.id.clone();
    let active = view.active_id.as_deref() == Some(id.as_str());
    let switching = view.switching_to.as_deref() == Some(id.as_str());
    let pending = switching || selecting.as_deref() == Some(id.as_str());
    let locked = view.switching_to.is_some() || selecting.is_some() || view.tunnel_busy;
    let connected = active && view.tunnel_running;
    drop(view);
    let blocked = unusable(&server);
    let dropped = is_removed_from_subscription(&server, group.as_ref());
    let purge_when = server
        .archived
        .filter(|_| blocked == Some(Unusable::Deleted))
        .map(|a| relative_time(a.purge_at, (store.now)(), *crate::lang::LANG.read()));
    let health = effective_health(Some(&rt), &server).cloned();
    let signal = row_signal(rt.ping, health.as_ref(), server.status);
    let ping = displayed_ping(server.ping_ms, rt.ping);
    let ping_failed = rt.ping == super::present::PingState::Done(None);
    let unusable_reason = blocked.map(|b| match b {
        Unusable::Deleted => t!("ui.servers.row.deletedReason"),
        Unusable::Disabled => t!("ui.servers.row.disabledReason"),
    });
    let select_reason = unusable_reason
        .clone()
        .or_else(|| locked.then(|| t!("ui.servers.row.switchBusy")));
    let proxy_reason = if active {
        Some(t!("ui.servers.menu.proxyActive"))
    } else if proxy_ready(&server, group.as_ref()) {
        None
    } else if dropped || blocked == Some(Unusable::Deleted) {
        Some(t!("servers.groups.removedProxyUnavailable"))
    } else {
        unusable_reason.clone()
    };
    let deleted = blocked == Some(Unusable::Deleted);
    let no_host =
        (server.host.is_empty() || server.port == 0).then(|| t!("ui.servers.menu.noHost"));
    let items = vec![
        MenuItem::new("proxy", t!("ui.servers.menu.proxy"))
            .blocked(proxy_reason)
            .busy(rt.starting_proxy),
        MenuItem::new("ping", t!("ui.servers.menu.ping"))
            .blocked(no_host.clone())
            .busy(rt.ping.is_measuring()),
        MenuItem::new("country", t!("ui.servers.menu.country"))
            .blocked(no_host)
            .busy(rt.verifying),
        MenuItem::new("details", t!("ui.servers.menu.details")),
        MenuItem::new("copy", t!("servers.exportKey")).busy(rt.exporting),
        MenuItem::new("save", t!("servers.saveKey")).busy(rt.exporting),
    ];
    let mut items = items;
    if deleted {
        items.insert(0, MenuItem::new("restore", t!("ui.servers.row.restore")));
        items.push(MenuItem::new("purge", t!("ui.servers.menu.purge")).destructive());
    } else {
        items.push(MenuItem::new("remove", t!("ui.servers.menu.remove")).destructive());
    }
    let (exit_title, ip_title) = ip_titles(&server);
    let stealth = server.stealth.map(stealth_badge);
    let server_for_menu = server.clone();
    let server_for_select = server.clone();
    let menu_label = t!("ui.servers.menu.label", name = server.name);
    let (actions_menu, actions_select, actions_cancel, actions_restore) = (
        actions.clone(),
        actions.clone(),
        actions.clone(),
        actions.clone(),
    );
    let server_for_restore = server.clone();
    let mut detail = store.detail;
    let (id_name, id_row) = (id.clone(), id.clone());
    rsx! {
        div {
            class: "srv-row",
            class: if active { "is-active" },
            class: if pending { "is-switching" },
            class: if blocked.is_some() { "is-unusable" },
            "data-server": "{id}",
            onclick: move |_| detail.set(Some(id_row.clone())),
            Flag { country: server.country.clone() }
            div { class: "srv-row-main",
                div { class: "srv-row-line",
                    button {
                        r#type: "button",
                        class: "srv-row-name",
                        title: t!("ui.servers.row.openDetail"),
                        onclick: move |evt| {
                            evt.stop_propagation();
                            detail.set(Some(id_name.clone()));
                        },
                        "{server.name}"
                    }
                    if let Some(when) = purge_when {
                        Badge { tone: Tone::Warn, title: t!("ui.servers.row.purgeTitle"),
                            {t!("ui.servers.row.deleted", when = when)}
                        }
                    } else if dropped {
                        Badge { tone: Tone::Warn, title: t!("ui.servers.row.droppedTitle"),
                            {t!("servers.groups.removedFromSub")}
                        }
                    }
                    if blocked == Some(Unusable::Disabled) {
                        Badge { tone: Tone::Unknown, {t!("ui.servers.row.off")} }
                    }
                    if pending {
                        Badge { tone: Tone::Warn, {t!("ui.servers.row.switching")} }
                    } else if connected {
                        Badge { tone: Tone::Ok, {t!("ui.servers.row.connected")} }
                    } else if active {
                        Badge { tone: Tone::Ok, {t!("servers.active")} }
                    }
                    span { class: "srv-row-cap swiss-mono", "{device_label(server.device)}" }
                    if let Some(code) = &server.country {
                        span { class: "srv-row-cap swiss-mono", "{code}" }
                    }
                }
                div { class: "srv-row-sub swiss-mono",
                    span { class: "srv-row-type", "{happ_type(&server.protocol, server.has_outbound)}" }
                    if let Some((label, key, tone)) = stealth {
                        Badge { tone, title: t!(key), "{label}" }
                    }
                    span { class: "srv-row-addr", title: "{server.host}:{server.port}", "{server.host}:{server.port}" }
                    if let (Some(exit), Some(title)) = (server.exit_ip, exit_title) {
                        span { class: "srv-row-exit", title: "{title}", {t!("ui.servers.row.exit", ip = exit)} }
                    }
                    span {
                        class: "srv-row-ip",
                        class: if server.exit_ip.is_some() { "is-muted" },
                        title: "{ip_title}",
                        "IP: "
                        {server.resolved_ip.map_or_else(|| "—".to_owned(), |ip| ip.to_string())}
                    }
                }
            }
            div { class: "srv-row-ping",
                SignalMark { signal }
                if rt.ping.is_measuring() {
                    Spinner {}
                }
                span {
                    class: "srv-row-ms swiss-mono",
                    title: ping_failed.then(|| t!("ui.servers.row.pingFailed")),
                    {ping.map_or_else(|| "—".to_owned(), |ms| t!("ui.servers.row.ms", ms = ms))}
                }
            }
            div { class: "srv-row-select", onclick: move |evt| evt.stop_propagation(),
                if pending {
                    Button { kind: ButtonKind::Ghost, small: true, busy: true, {t!("ui.servers.row.switchingShort")} }
                    if switching {
                        Button {
                            kind: ButtonKind::Link,
                            small: true,
                            onclick: move |_| actions_cancel.cancel_switch(),
                            {t!("common.cancel")}
                        }
                    }
                } else if active {
                    Button { kind: ButtonKind::Ghost, small: true, disabled: true, {t!("servers.selected")} }
                } else if deleted {
                    Button {
                        kind: ButtonKind::Ghost,
                        small: true,
                        busy: rt.restoring,
                        onclick: move |_| actions_restore.restore(&server_for_restore),
                        {t!("ui.servers.row.restore")}
                    }
                } else {
                    Button {
                        small: true,
                        disabled: select_reason.is_some(),
                        disabled_reason: select_reason,
                        // The provider dropped it: still selectable, but say it may not work.
                        title: dropped.then(|| t!("ui.servers.row.droppedTitle")),
                        onclick: move |_| actions_select.select(&server_for_select),
                        {t!("servers.select")}
                    }
                }
            }
            OverflowMenu {
                label: menu_label,
                items,
                on_select: move |item: &'static str| row_action(&actions_menu, &server_for_menu, connected, item),
            }
        }
    }
}

fn row_action(actions: &Actions, server: &ServerView, connected: bool, item: &str) {
    let store = actions.store;
    match item {
        "proxy" => actions.start_proxy(server),
        "ping" => actions.ping_one(&server.id),
        "country" => actions.verify_country(server),
        "details" => {
            let mut detail = store.detail;
            detail.set(Some(server.id.clone()));
        }
        "restore" => actions.restore(server),
        "purge" => {
            let mut confirm = store.confirm;
            confirm.set(Some(Confirm::PurgeServer {
                id: server.id.clone(),
                name: server.name.clone(),
            }));
        }
        "copy" => actions.export_key(server, false),
        "save" => actions.export_key(server, true),
        "remove" => {
            let mut confirm = store.confirm;
            confirm.set(Some(Confirm::DeleteServer {
                id: server.id.clone(),
                name: server.name.clone(),
                connected,
            }));
        }
        _ => {}
    }
}

/// Hover texts of the exit IP (verified exit vs entry bridge) and of the DNS address.
fn ip_titles(server: &ServerView) -> (Option<String>, String) {
    let resolved = server
        .resolved_ip
        .map_or_else(|| "—".to_owned(), |ip| ip.to_string());
    let exit = server.exit_ip.map(|ip| {
        t!(
            "ui.servers.row.exitTitle",
            ip = ip,
            host = server.host,
            resolved = resolved
        )
    });
    let ip = match (server.resolved_ip, server.exit_ip) {
        (Some(_), Some(_)) => t!("ui.servers.row.dnsBridgeTitle", host = server.host),
        (Some(_), None) => t!("ui.servers.row.dnsTitle", host = server.host),
        (None, _) => t!("ui.servers.row.ipUnresolved"),
    };
    (exit, ip)
}
