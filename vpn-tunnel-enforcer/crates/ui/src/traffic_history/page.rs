//! The page: header actions, search, the summary line, day groups of domains and the clear
//! confirmation.
use std::sync::Arc;

use dioxus::prelude::*;
use jiff::tz::TimeZone;
use vpnte_base::Msg;
use vpnte_base::types::UnixMs;

use super::model::{
    DomainRow, MAX_RENDERED, SiteInfo, by_day, day_heading, filter, moment, month_key, seen_line,
    site_url, totals,
};
use super::{use_api, use_coalesced};
use crate::lang::tr;
use crate::pages::{Page, nav_number};
use crate::t;
use crate::units::format_bytes;
use crate::widgets::{
    Badge, Button, ButtonKind, ConfirmDialog, EmptyState, IconButton, IconGlyph, Load, LoadError,
    Loading, Panel, SectionHeader, Spinner, TextInput, TextKind, Toasts, use_job,
};

/// The time zone of the visit (the page is active-only: read again on every visit).
#[derive(Clone)]
struct PageTz(TimeZone);

/// The Traffic page (register as `Page::TrafficHistory`). Needs `Rc<dyn TrafficHistoryApi>`
/// and the [`Toasts`] provider in context.
#[component]
pub fn TrafficHistoryPage() -> Element {
    let api = use_api();
    let state = use_coalesced({
        let api = api.clone();
        move || api.state()
    });
    let toasts = Toasts::use_context();
    let mut query = use_signal(String::new);
    let mut confirm_open = use_signal(|| false);
    let reload_job = use_job::<()>();
    let clear_job = use_job::<()>();
    use_context_provider(|| PageTz(TimeZone::system()));

    let reload = {
        let api = api.clone();
        move || {
            let api = api.clone();
            reload_job.start(move |_| async move {
                if let Err(err) = api.reload().await {
                    toasts.failed(&Msg::new("trafficHistory.refreshFailed"), &err);
                }
                Ok(())
            });
        }
    };
    let clear = {
        let api = api.clone();
        move |()| {
            let api = api.clone();
            clear_job.start(move |_| async move {
                let result = api.clear().await;
                confirm_open.set(false);
                if let Err(err) = result {
                    toasts.failed(&Msg::new("trafficHistory.clearFailed"), &err);
                }
                Ok(())
            });
        }
    };

    let refresh = reload.clone();
    let retry = reload;
    let snapshot = state.read().clone();
    let has_rows = snapshot
        .domains
        .ready()
        .is_some_and(|rows| !rows.is_empty());
    let number = Page::ALL
        .iter()
        .position(|p| *p == Page::TrafficHistory)
        .unwrap_or(5);
    rsx! {
        div { class: "c-swiss swiss-skin traffic",
            SectionHeader {
                title: t!("trafficHistory.title"),
                number: nav_number(number),
                description: t!("trafficHistory.description"),
                Button {
                    kind: ButtonKind::Ghost,
                    small: true,
                    busy: reload_job.running(),
                    onclick: move |_| refresh(),
                    {t!("common.refresh")}
                }
                Button {
                    kind: ButtonKind::Danger,
                    small: true,
                    busy: clear_job.running(),
                    disabled: !has_rows,
                    onclick: move |_| confirm_open.set(true),
                    {t!("common.delete")}
                }
            }
            div { class: "traffic-search",
                TextInput {
                    value: query(),
                    kind: TextKind::Search,
                    placeholder: t!("trafficHistory.searchPlaceholder"),
                    aria_label: t!("trafficHistory.searchLabel"),
                    oninput: move |v: String| query.set(v),
                    on_escape: move |()| query.set(String::new()),
                }
            }
            match snapshot.domains {
                Load::Loading => rsx! {
                    Panel {
                        Loading { label: t!("common.loading") }
                    }
                },
                Load::Failed(err) => rsx! {
                    Panel {
                        LoadError {
                            text: tr(&err.msg),
                            retry_label: t!("common.retry"),
                            on_retry: move |()| retry(),
                        }
                    }
                },
                Load::Ready(rows) => rsx! {
                    DomainList { rows, query: query(), tunnel_up: snapshot.tunnel_up }
                },
            }
            ConfirmDialog {
                open: confirm_open,
                title: t!("trafficHistory.clearTitle"),
                message: t!("trafficHistory.clearConfirm"),
                confirm_label: t!("common.delete"),
                cancel_label: t!("common.cancel"),
                danger: true,
                busy: clear_job.running(),
                on_confirm: clear,
                on_cancel: move |()| confirm_open.set(false),
            }
        }
    }
}

/// The summary line and the day groups of the rows matching the search (at most
/// [`MAX_RENDERED`] rows are drawn; the count and the bytes cover every match).
#[component]
fn DomainList(rows: Arc<[DomainRow]>, query: String, tunnel_up: bool) -> Element {
    let tz = use_context::<PageTz>().0;
    if rows.is_empty() {
        let detail = if tunnel_up {
            t!("trafficHistory.emptyHintConnected")
        } else {
            t!("trafficHistory.emptyHint")
        };
        return rsx! {
            Panel {
                EmptyState { title: t!("trafficHistory.empty"), detail }
            }
        };
    }
    let found = filter(&rows, &query);
    if found.is_empty() {
        return rsx! {
            Panel {
                EmptyState { title: t!("common.noResults") }
            }
        };
    }
    let (down, up) = totals(&found);
    let truncated = found.len() > MAX_RENDERED;
    let total = t!("trafficHistory.total", count = found.len());
    let shown = &found[..found.len().min(MAX_RENDERED)];
    let groups = by_day(shown, &tz);
    rsx! {
        div { class: "traffic-summary",
            span { "{total}" }
            if down + up > 0 {
                span { class: "swiss-mono", "↓ {format_bytes(down)} · ↑ {format_bytes(up)}" }
            }
            if truncated {
                span { class: "traffic-more", {t!("trafficHistory.showingLatest", count = MAX_RENDERED)} }
            }
        }
        for (day , items) in groups {
            Panel {
                key: "{day:?}",
                title: day.map(|d| tr(&day_heading(d))),
                flush: true,
                ul { class: "traffic-list",
                    for row in items {
                        DomainItem { key: "{row.domain}", row: row.clone() }
                    }
                }
            }
        }
    }
}

/// Local «11 нояб., 11:53:56» of `ms`.
fn when(ms: UnixMs, tz: &TimeZone) -> String {
    moment(ms, tz).map_or_else(String::new, |m| tr(&m.msg(t!(month_key(m.month)))))
}

/// One domain: name, «×count», site metadata state, bytes, first / last seen or the site title,
/// and a button that opens `https://<domain>` in the default browser.
#[component]
fn DomainItem(row: DomainRow) -> Element {
    let api = use_api();
    let toasts = Toasts::use_context();
    let tz = use_context::<PageTz>().0;
    let line = seen_line(&row, |ms| when(ms, &tz));
    let url = site_url(&row.domain);
    let has_site = url.is_some();
    let bytes = row.bytes_down.saturating_add(row.bytes_up) > 0;
    let open = move |_| {
        let Some(url) = url.clone() else {
            return;
        };
        let api = api.clone();
        spawn(async move {
            if let Err(err) = api.open_site(url).await {
                toasts.failed(&Msg::new("trafficHistory.openFailed"), &err);
            }
        });
    };
    rsx! {
        li { class: "traffic-item",
            div { class: "traffic-item-text",
                p { class: "traffic-item-head",
                    span { class: "traffic-domain", "{row.domain}" }
                    Badge { "×{row.count}" }
                    match &row.site {
                        SiteInfo::Pending => rsx! {
                            span {
                                class: "traffic-pending",
                                role: "img",
                                aria_label: t!("trafficHistory.sitePending"),
                                title: t!("trafficHistory.sitePending"),
                                Spinner {}
                            }
                        },
                        SiteInfo::Ready { name: Some(name), .. } if !name.trim().is_empty() => rsx! {
                            // a name, not a status: plain text (the badge would set it in upper case)
                            span { class: "traffic-site", "{name}" }
                        },
                        SiteInfo::Unavailable => rsx! {
                            Badge { {t!("trafficHistory.siteUnavailable")} }
                        },
                        _ => rsx! {},
                    }
                }
                p { class: "traffic-item-seen", "{line}" }
            }
            if bytes {
                span { class: "traffic-bytes swiss-mono",
                    "↓ {format_bytes(row.bytes_down)} · ↑ {format_bytes(row.bytes_up)}"
                }
            }
            if has_site {
                IconButton {
                    glyph: IconGlyph::ArrowRight,
                    label: t!("trafficHistory.openSite", host = row.domain),
                    onclick: open,
                }
            }
        }
    }
}
