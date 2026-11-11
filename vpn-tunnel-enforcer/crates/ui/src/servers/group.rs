//! One group: a real `<button aria-expanded>` header (name, status, counts) with a sibling toolbar
//! — no interactive element inside the toggle, so Enter / Space on a tool or a space typed while
//! renaming never toggles the group (S-1) — then the subscription facts and the servers by
//! protocol, removed ones in their own section.
use std::num::NonZeroU32;

use dioxus::prelude::*;
use vpnte_base::types::UnixMs;

use super::actions::{Actions, fetch_error_text};
use super::model::{GroupSource, GroupStatus, GroupView};
use super::present::{
    BucketKind, GROUP_NAME_MAX, GroupBucket, group_status_key, group_status_tone, is_deleted,
    is_removed_from_subscription, protocol_sections, proxy_ready, refresh_choices,
    refresh_label_key, relative_time, safe_http_url, traffic,
};
use super::row::ServerRow;
use super::state::Confirm;
use crate::lang::LANG;
use crate::t;
use crate::units::format_bytes;
use crate::widgets::{
    Badge, Button, ButtonKind, Icon, IconButton, IconGlyph, Select, SelectOption, Size, Tone,
};

#[component]
pub(crate) fn GroupCard(bucket: GroupBucket) -> Element {
    let actions = use_context::<Actions>();
    let store = actions.store;
    let GroupBucket {
        kind,
        group,
        servers,
    } = bucket;
    let id = group.id.clone();
    let expanded = store.expanded.read().contains(&id);
    let busy = store.busy.read().get(&id).copied().unwrap_or_default();
    let renaming = store
        .rename
        .read()
        .as_ref()
        .filter(|(rid, _)| rid == &id)
        .map(|(_, draft)| draft.clone());
    let real = kind == BucketKind::Real;
    let subscription = real && group.source == GroupSource::Subscription;
    let stored = real.then(|| group.clone());
    let name = match kind {
        BucketKind::Real => group.name.clone(),
        BucketKind::Recovered => t!("servers.groups.recovered"),
        BucketKind::Virtual => t!("servers.groups.all"),
    };
    let (removed, current): (Vec<_>, Vec<_>) = servers
        .iter()
        .cloned()
        .partition(|s| is_removed_from_subscription(s, stored.as_ref()) || is_deleted(s));
    let current_ids: Vec<String> = current
        .iter()
        .filter(|s| proxy_ready(s, stored.as_ref()))
        .map(|s| s.id.clone())
        .collect();
    let sections = protocol_sections(&current);
    let tag = if group.source == GroupSource::Subscription {
        "SUB"
    } else {
        "KEYS"
    };
    let body_id = format!("srv-group-{id}");
    let choices: Vec<SelectOption<Option<NonZeroU32>>> = refresh_choices(group.refresh_minutes)
        .into_iter()
        .map(|m| {
            let (key, count) = refresh_label_key(m);
            let label = match count {
                Some(n) => t!(key, count = n),
                None => t!(key),
            };
            SelectOption::new(m, label)
        })
        .collect();
    let current_interval = group.refresh_minutes;
    let a = actions.clone();
    let (a_toggle, a_proxy, a_refresh, a_interval, a_health) =
        (a.clone(), a.clone(), a.clone(), a.clone(), a.clone());
    let (id_toggle, id_proxy, id_refresh, id_interval, id_health, id_rename, id_delete) = (
        id.clone(),
        id.clone(),
        id.clone(),
        id.clone(),
        id.clone(),
        id.clone(),
        id.clone(),
    );
    let (name_proxy, name_refresh, name_health, name_rename, name_delete) = (
        name.clone(),
        name.clone(),
        name.clone(),
        group.name.clone(),
        name.clone(),
    );
    let server_count = servers.len();
    let (id_edit, name_edit) = (id.clone(), group.name.clone());
    let mut rename = store.rename;
    let mut confirm = store.confirm;
    rsx! {
        section { class: "srv-group", class: if expanded { "is-open" }, "data-group": "{id}",
            div { class: "srv-group-head",
                if let Some(draft) = renaming {
                    RenameInput { draft }
                } else {
                    button {
                        r#type: "button",
                        class: "srv-group-toggle",
                        aria_expanded: if expanded { "true" } else { "false" },
                        aria_controls: "{body_id}",
                        title: if expanded { t!("servers.groups.collapse") } else { t!("servers.groups.expand") },
                        onclick: move |_| a_toggle.toggle_expanded(&id_toggle),
                        ondoubleclick: move |_| {
                            if real {
                                rename.set(Some((id_rename.clone(), name_rename.clone())));
                            }
                        },
                        span { class: "srv-group-chev", Icon { glyph: IconGlyph::ChevronDown } }
                        span { class: "srv-group-tag swiss-mono", "{tag}" }
                        span { class: "srv-group-titles",
                            span { class: "srv-group-name", "{name}" }
                            span { class: "srv-group-sub",
                                if real {
                                    Badge { tone: group_status_tone(group.status), {t!(group_status_key(group.status))} }
                                }
                                span { class: "srv-group-count swiss-mono",
                                    {t!("servers.groups.serverCount", count = current.len())}
                                }
                                if !removed.is_empty() {
                                    Badge { tone: Tone::Warn, {t!("servers.groups.removedServerCount", count = removed.len())} }
                                }
                            }
                        }
                    }
                }
                div { class: "srv-group-tools",
                    Button {
                        kind: ButtonKind::Link,
                        small: true,
                        busy: busy.proxies,
                        disabled: current_ids.is_empty(),
                        title: t!("ui.servers.group.proxiesTitle"),
                        onclick: move |_| a_proxy.start_group_proxies(&id_proxy, &name_proxy, current_ids.clone()),
                        {if busy.proxies { t!("ui.servers.group.proxiesBusy") } else { t!("ui.servers.group.proxies") }}
                    }
                    if subscription {
                        Button {
                            kind: ButtonKind::Link,
                            small: true,
                            busy: busy.refresh,
                            onclick: move |_| a_refresh.refresh_group(&id_refresh, &name_refresh),
                            {if busy.refresh { t!("servers.groups.refreshing") } else { t!("servers.groups.refresh") }}
                        }
                        div { class: "srv-group-interval",
                            Select {
                                options: choices,
                                value: Some(current_interval),
                                on_change: move |next| a_interval.set_interval(&id_interval, current_interval, next),
                                aria_label: t!("servers.groups.refreshIntervalLabel"),
                                disabled: busy.policy,
                                size: Size::Sm,
                            }
                        }
                    }
                    if real {
                        Button {
                            kind: ButtonKind::Link,
                            small: true,
                            busy: busy.health,
                            disabled: current.is_empty(),
                            onclick: move |_| a_health.check_health(&id_health, &name_health),
                            {if busy.health { t!("servers.groups.checking") } else { t!("servers.groups.checkHealth") }}
                        }
                        IconButton {
                            glyph: IconGlyph::Edit,
                            label: t!("servers.groups.rename"),
                            onclick: move |_| rename.set(Some((id_edit.clone(), name_edit.clone()))),
                        }
                    }
                    if kind != BucketKind::Virtual {
                        IconButton {
                            glyph: IconGlyph::Trash,
                            label: t!("servers.groups.delete"),
                            danger: true,
                            onclick: move |_| confirm.set(Some(Confirm::DeleteGroup {
                                id: id_delete.clone(),
                                name: name_delete.clone(),
                                servers: server_count,
                            })),
                        }
                    }
                }
            }
            if expanded {
                div { class: "srv-group-body", id: "{body_id}",
                    if let Some(group) = stored.clone() {
                        GroupFacts { group }
                    }
                    if servers.is_empty() {
                        p { class: "srv-group-empty", {t!("servers.noServers")} }
                    } else if current.is_empty() {
                        p { class: "srv-group-empty", {t!("servers.groups.noActiveServers")} }
                    }
                    for (protocol , rows) in sections {
                        div { key: "{protocol}", class: "srv-proto",
                            h3 { class: "swiss-label srv-proto-cap", "{protocol}" }
                            for server in rows {
                                ServerRow { key: "{server.id}", server: server.clone(), group: stored.clone() }
                            }
                        }
                    }
                    if !removed.is_empty() {
                        div { class: "srv-proto is-removed", role: "group", aria_label: t!("servers.groups.removedServers"),
                            h3 { class: "swiss-label srv-proto-cap",
                                {t!("servers.groups.removedServers")}
                                Badge { tone: Tone::Warn, "{removed.len()}" }
                            }
                            for server in removed {
                                ServerRow { key: "{server.id}", server: server.clone(), group: stored.clone() }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The inline rename field (outside the toggle button): Enter or leaving it saves, Escape cancels.
#[component]
fn RenameInput(draft: String) -> Element {
    let actions = use_context::<Actions>();
    let mut rename = actions.store.rename;
    let (a_key, a_blur) = (actions.clone(), actions.clone());
    rsx! {
        input {
            class: "w-input srv-group-rename",
            r#type: "text",
            value: "{draft}",
            maxlength: "{GROUP_NAME_MAX}",
            aria_label: t!("servers.groups.renamePlaceholder"),
            placeholder: t!("servers.groups.renamePlaceholder"),
            onmounted: move |evt| async move {
                let _ = evt.set_focus(true).await;
            },
            oninput: move |evt| {
                if let Some((_, d)) = rename.write().as_mut() {
                    *d = evt.value();
                }
            },
            onkeydown: move |evt| match evt.key() {
                Key::Enter => {
                    evt.prevent_default();
                    evt.stop_propagation();
                    a_key.commit_rename();
                }
                Key::Escape => {
                    evt.prevent_default();
                    evt.stop_propagation();
                    rename.set(None);
                }
                _ => {}
            },
            onblur: move |_| a_blur.commit_rename(),
        }
    }
}

/// Subscription facts, each only when known: refresh error, expired note, trial end, traffic
/// quota, provider panel, last update.
#[component]
fn GroupFacts(group: GroupView) -> Element {
    let actions = use_context::<Actions>();
    let now: UnixMs = (actions.store.now)();
    let lang = *LANG.read();
    let when = |ts: UnixMs| relative_time(ts, now, lang);
    let quota = group
        .traffic_total
        .filter(|&total| total > 0)
        .map(|total| (group.traffic_used.unwrap_or(0), total));
    let panel = group
        .web_page_url
        .as_deref()
        .and_then(safe_http_url)
        .map(str::to_owned);
    let anything = group.last_fetch_error.is_some()
        || group.status == GroupStatus::Expired
        || group.expires_at.is_some()
        || quota.is_some()
        || panel.is_some()
        || group.last_fetched_at.is_some();
    if !anything {
        return rsx! {};
    }
    let a_open = actions.clone();
    rsx! {
        div { class: "srv-facts-block",
            if let Some(why) = group.last_fetch_error {
                p { class: "srv-strip is-fail", role: "alert",
                    {t!(
                        "servers.groups.refreshFailedDetail",
                        error = fetch_error_text(why),
                        when = group.last_fetch_attempt_at.map(when).unwrap_or_default()
                    )}
                }
            }
            if group.status == GroupStatus::Expired {
                p { class: "srv-strip is-warn", {t!("ui.servers.group.expiredBanner")} }
            }
            div { class: "srv-meta",
                if let Some(at) = group.expires_at {
                    span { class: "srv-meta-item", class: if at < now { "is-alert" },
                        if at < now {
                            {t!("servers.groups.expiredAt", when = when(at))}
                        } else {
                            {t!("servers.groups.expiresAt", when = when(at))}
                        }
                    }
                }
                if let Some(at) = group.last_fetched_at {
                    span { class: "srv-meta-item", {t!("servers.groups.lastUpdatedAt", when = when(at))} }
                }
                if let Some(url) = panel {
                    Button {
                        kind: ButtonKind::Link,
                        small: true,
                        title: t!("ui.servers.group.panelTitle"),
                        onclick: move |_| {
                            let (api, url) = (a_open.api.clone(), url.clone());
                            a_open.spawn(async move {
                                if let Err(err) = api.open_url(url).await {
                                    tracing::debug!(error = %err, "opening the provider panel failed");
                                }
                            });
                        },
                        {t!("servers.groups.providerPanel")}
                    }
                }
            }
            if let Some((used, total)) = quota {
                Quota { used, total }
            }
        }
    }
}

/// Traffic quota line with its bar (over the limit → signal, above 80 % → warning frame).
#[component]
fn Quota(used: u64, total: u64) -> Element {
    let (pct, tone, over) = traffic(used, total);
    let value = t!(
        "servers.groups.trafficUsed",
        used = format_bytes(used),
        total = format_bytes(total)
    );
    rsx! {
        div { class: "srv-quota", "data-tone": tone.name(),
            div { class: "srv-quota-line",
                span { class: "swiss-label", {t!("servers.groups.trafficUsage")} }
                span { class: "srv-quota-value swiss-mono", class: if over { "is-alert" }, "{value}" }
            }
            div {
                class: "srv-quota-bar",
                role: "progressbar",
                aria_label: t!("servers.groups.trafficUsage"),
                aria_valuemin: "0",
                aria_valuemax: "100",
                aria_valuenow: "{pct}",
                div { class: "srv-quota-fill", style: "width:{pct}%" }
            }
        }
    }
}
