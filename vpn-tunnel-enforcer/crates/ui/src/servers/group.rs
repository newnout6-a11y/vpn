//! One group: a real `<button aria-expanded>` header (name, status, counts) with a sibling toolbar
//! — no interactive element inside the toggle, so Enter / Space on a tool or a space typed while
//! renaming never toggles the group (S-1) — then the subscription facts and the servers by
//! protocol, removed ones in their own section.
use std::num::NonZeroU32;

use dioxus::prelude::*;

use super::actions::Actions;
use super::facts::GroupFacts;
use super::model::GroupSource;
use super::present::{
    BucketKind, GROUP_NAME_MAX, GroupBucket, group_status_key, group_status_tone, is_deleted,
    is_removed_from_subscription, protocol_sections, proxy_ready, refresh_choices,
    refresh_label_key,
};
use super::row::ServerRow;
use super::state::Confirm;
use crate::t;
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
    let (a_request, id_request, name_request) = (a.clone(), id.clone(), name.clone());
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
                        Button {
                            kind: ButtonKind::Link,
                            small: true,
                            title: t!("ui.servers.request.openTitle"),
                            onclick: move |_| a_request.open_request(&id_request, &name_request),
                            {t!("ui.servers.request.open")}
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
