//! One server row: flag, name (opens the detail), badges, Happ-style type line, the engine a
//! connect would use, the last check's verdict, the ping with its status mark, the select /
//! switch control and the «…» menu.
use dioxus::prelude::*;
use vpnte_base::types::EnginePref;

use super::actions::Actions;
use super::menu::{MenuItem, OverflowMenu};
use super::model::{EnginePlan, GroupView, ServerView, ServersView};
use super::present::{
    ENGINE_ITEMS, RowSignal, Unusable, device_label, displayed_ping, engine_name, engine_of_item,
    happ_type, has_flag, is_removed_from_subscription, proxy_ready, relative_time, row_signal,
    stealth_badge, unusable,
};
use super::state::{Confirm, effective_health};
use super::verdict::VerdictCap;
use crate::lang::tr;
use crate::t;
use crate::widgets::{Badge, Button, ButtonKind, Icon, IconGlyph, Spinner, Tone};

/// The engine a connect would use (quiet mono caption, the reason as its title), or a warning
/// when the chosen engine cannot run the server.
#[component]
fn EngineCap(plan: EnginePlan) -> Element {
    match plan {
        EnginePlan::Runs { engine, reason } => rsx! {
            span { class: "srv-row-cap swiss-mono", title: tr(&reason), "{engine_name(engine)}" }
        },
        EnginePlan::Refused(why) => rsx! {
            Badge { tone: Tone::Warn, title: tr(&why), {t!("ui.servers.row.engineRefused")} }
        },
    }
}

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
        RowSignal::Engine => ("is-unknown", t!("servers.health.reasons.engine-setting")),
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

/// What a row shows of the page state besides its own server.
#[derive(Debug, Clone, Copy, PartialEq)]
struct RowMarks {
    active: bool,
    switching: bool,
    /// A switch to this row runs (the backend's or this page's `select`).
    pending: bool,
    /// Some switch runs: every Select waits.
    locked: bool,
    connected: bool,
}

impl RowMarks {
    fn of(view: &ServersView, selecting: Option<&str>, id: &str) -> Self {
        let active = view.active_id.as_deref() == Some(id);
        let switching = view.switching_to.as_deref() == Some(id);
        Self {
            active,
            switching,
            pending: switching || selecting == Some(id),
            locked: view.switching_to.is_some() || selecting.is_some() || view.tunnel_busy,
            connected: active && view.tunnel_running,
        }
    }
}

#[component]
pub(crate) fn ServerRow(server: ServerView, group: Option<GroupView>) -> Element {
    let actions = use_context::<Actions>();
    let store = actions.store;
    // Memos, not reads: a row redraws only when its own marks change. Reading the whole rows map
    // and snapshot here made every answer of a ping-all redraw every row.
    let rt = use_memo({
        let id = server.id.clone();
        move || store.rows.read().get(&id).cloned().unwrap_or_default()
    });
    let marks = use_memo({
        let id = server.id.clone();
        move || RowMarks::of(&store.view.read(), store.selecting.read().as_deref(), &id)
    });
    let rt = rt();
    let RowMarks {
        active,
        switching,
        pending,
        locked,
        connected,
    } = marks();
    let id = server.id.clone();
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
    items.extend(engine_items(server.engine));
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
                    if let Some(plan) = server.engine_plan.clone() {
                        EngineCap { plan }
                    }
                    if let Some(verdict) = server.verdict.clone() {
                        VerdictCap { verdict, now: (store.now)() }
                    }
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
                    // quiet in the list: the page header keeps the one primary action («Добавить»)
                    Button {
                        kind: ButtonKind::Ghost,
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

/// The per-server engine entries of the «…» menu; the current choice is listed, not offered.
fn engine_items(current: EnginePref) -> Vec<MenuItem> {
    ENGINE_ITEMS
        .iter()
        .map(|&(id, pref)| {
            let label = match pref {
                EnginePref::Auto => t!("ui.servers.menu.engineAuto"),
                EnginePref::SingBox => t!("ui.servers.menu.engineSingBox"),
                EnginePref::Xray => t!("ui.servers.menu.engineXray"),
            };
            let chosen = (pref == current).then(|| t!("ui.servers.menu.engineCurrent"));
            MenuItem::new(id, label).blocked(chosen)
        })
        .collect()
}

fn row_action(actions: &Actions, server: &ServerView, connected: bool, item: &str) {
    let store = actions.store;
    if let Some(engine) = engine_of_item(item) {
        actions.set_engine(server, engine);
        return;
    }
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
