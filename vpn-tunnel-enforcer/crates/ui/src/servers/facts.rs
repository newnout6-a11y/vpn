//! Subscription facts under a group header, each only when known: the refresh error (with the
//! HWID hint), the expired note, the provider's announcement and hide-settings note, trial end,
//! last update, the provider's interval, a move, the panel and support links, the traffic quota.
use dioxus::prelude::*;
use vpnte_base::types::UnixMs;

use super::actions::{Actions, fetch_error_text, toast_error};
use super::model::{FetchError, GroupStatus, GroupView};
use super::present::{relative_time, safe_http_url, traffic};
use crate::lang::{LANG, translate_now};
use crate::t;
use crate::units::format_bytes;
use crate::widgets::{Button, ButtonKind};

#[component]
pub(crate) fn GroupFacts(group: GroupView) -> Element {
    let actions = use_context::<Actions>();
    let now: UnixMs = (actions.store.now)();
    let lang = *LANG.read();
    let when = |ts: UnixMs| relative_time(ts, now, lang);
    let quota = group
        .traffic_total
        .filter(|&total| total > 0)
        .map(|total| (group.traffic_used.unwrap_or(0), total));
    let link = |url: &Option<String>| url.as_deref().and_then(safe_http_url).map(str::to_owned);
    let (panel, support) = (link(&group.web_page_url), link(&group.support_url));
    // HWID-bound panels answer an unknown device with an empty list (ru-2026 item 1).
    let hwid_hint = group.last_fetch_error == Some(FetchError::Empty) && !group.send_hwid;
    let anything = group.last_fetch_error.is_some()
        || group.status == GroupStatus::Expired
        || group.expires_at.is_some()
        || quota.is_some()
        || panel.is_some()
        || support.is_some()
        || group.announce.is_some()
        || group.settings_hidden
        || group.moved_at.is_some()
        || group.provider_refresh_hours.is_some()
        || group.last_fetched_at.is_some();
    if !anything {
        return rsx! {};
    }
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
            if hwid_hint {
                HwidHint { id: group.id.clone() }
            }
            if group.status == GroupStatus::Expired {
                p { class: "srv-strip is-warn", {t!("ui.servers.group.expiredBanner")} }
            }
            if let Some(text) = group.announce.clone() {
                // Provider text, shown as plain text: a link in it is never made clickable.
                p { class: "srv-strip", aria_label: t!("ui.servers.facts.announce"), "{text}" }
            }
            if group.settings_hidden {
                p { class: "srv-strip", {t!("ui.servers.facts.hidden")} }
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
                if let Some(hours) = group.provider_refresh_hours {
                    span { class: "srv-meta-item", {t!("ui.servers.facts.providerInterval", count = hours)} }
                }
                if let Some(at) = group.moved_at {
                    span { class: "srv-meta-item",
                        {t!("ui.servers.facts.moved", host = group.host.clone().unwrap_or_default(), when = when(at))}
                    }
                }
                if let Some(url) = panel {
                    OpenLink {
                        url,
                        label: t!("servers.groups.providerPanel"),
                        title: t!("ui.servers.group.panelTitle"),
                        failed: "ui.servers.group.panelFailed",
                    }
                }
                if let Some(url) = support {
                    OpenLink {
                        url,
                        label: t!("ui.servers.facts.support"),
                        title: t!("ui.servers.facts.supportTitle"),
                        failed: "ui.servers.facts.supportFailed",
                    }
                }
            }
            if let Some((used, total)) = quota {
                Quota { used, total }
            }
        }
    }
}

/// An `http(s)` provider link, opened in the browser on a click only.
#[component]
fn OpenLink(url: String, label: String, title: String, failed: &'static str) -> Element {
    let actions = use_context::<Actions>();
    rsx! {
        Button {
            kind: ButtonKind::Link,
            small: true,
            title,
            onclick: move |_| {
                let (api, toasts, url) = (actions.api.clone(), actions.toasts, url.clone());
                actions.spawn(async move {
                    if let Err(err) = api.open_url(url).await {
                        toast_error(toasts, translate_now(failed, &[]), &err);
                    }
                });
            },
            "{label}"
        }
    }
}

/// The empty-list hint of a subscription that does not send its HWID, with the switch at hand.
#[component]
fn HwidHint(id: String) -> Element {
    let actions = use_context::<Actions>();
    rsx! {
        div { class: "srv-strip is-warn",
            p { {t!("ui.servers.facts.hwidHint")} }
            Button {
                kind: ButtonKind::Link,
                small: true,
                onclick: move |_| actions.set_send_hwid(&id, true, true),
                {t!("ui.servers.request.hwid")}
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
