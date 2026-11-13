//! [`ServersPage`]: the page root. It owns the page state ([`Store`]) and every long task, turns the
//! backend's [`ServersView`] watch channel into a signal (one pump, no polling) and lays out the
//! header, the facts strip, notices, the groups and the dialogs.
use dioxus::core::current_scope_id;
use dioxus::prelude::*;
use vpnte_base::types::now_ms;

use super::actions::Actions;
use super::add::AddDialog;
use super::api::use_servers_api;
use super::batch::BatchDialog;
use super::detail::ServerDetail;
use super::group::GroupCard;
use super::links::use_link_intake;
use super::model::{AddTarget, ServersView};
use super::present::{buckets, counts};
use super::request::RequestDialog;
use super::schemes::LinkSchemesDialog;
use super::state::{Bulk, BulkKind, Confirm, Store, reconcile_expanded};
use crate::pages::{Page, nav_number, use_page_active};
use crate::t;
use crate::widgets::{
    Button, ButtonKind, ConfirmDialog, EmptyState, Icon, IconGlyph, Loading, Modal, ModalSize,
    ProgressBar, SectionHeader, Toasts,
};

/// The Servers page (register as `Page::Servers`; needs `Rc<dyn ServersApi>` and [`Toasts`] in
/// context).
#[component]
pub fn ServersPage() -> Element {
    let api = use_servers_api();
    let toasts = Toasts::use_context();
    let store = use_hook({
        let api = api.clone();
        move || {
            let view = api.state().borrow().clone();
            Store::new(current_scope_id(), view, api.expanded_groups())
        }
    });
    let actions = use_context_provider(|| Actions {
        store,
        api: api.clone(),
        toasts,
    });
    use_future({
        let api = api.clone();
        move || {
            let mut rx = api.state();
            let mut view = store.view;
            async move {
                while rx.changed().await.is_ok() {
                    let next = rx.borrow_and_update().clone();
                    view.set(next);
                }
            }
        }
    });
    // A link Windows handed over (a browser or messenger) opens the add dialog with it.
    use_link_intake(&actions);
    // Hosts are resolved for the IP column on the first show (and after imports / refreshes).
    use_hook({
        let actions = actions.clone();
        move || actions.resolve_ips()
    });
    let active = use_page_active();
    use_future(move || async move {
        let mut now = store.now;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if *active.peek() {
                now.set(now_ms());
            }
        }
    });
    use_effect({
        let actions = actions.clone();
        move || follow_store(&actions, &store.view.read())
    });

    let view = store.view.read();
    let (usable, total) = counts(&view);
    let groups = buckets(&view);
    let loaded = view.loaded;
    let foreign = view.foreign_vpn;
    let empty = loaded && view.servers.is_empty() && view.groups.is_empty();
    drop(view);
    let pinging = store.ping_task.read().is_some();
    let checking = store.check_task.read().is_some();
    let number = Page::ALL
        .iter()
        .position(|p| *p == Page::Servers)
        .map(nav_number);
    let (a_ping, a_keys, a_proxies) = (actions.clone(), actions.clone(), actions.clone());
    let (a_schemes, a_check) = (actions.clone(), actions.clone());
    let (mut add_open, mut batch_open) = (store.add_open, store.batch_open);
    let exporting = matches!(*store.bulk.read(), Some(Bulk::Working(_)));
    rsx! {
        div { class: "c-swiss swiss-skin srv-page",
            SectionHeader {
                title: t!("servers.title"),
                number,
                description: t!("servers.description"),
                Button { onclick: move |_| add_open.set(true),
                    Icon { glyph: IconGlyph::Plus }
                    {t!("ui.servers.add.open")}
                }
                Button {
                    kind: ButtonKind::Ghost,
                    disabled: total == 0,
                    title: if pinging { t!("ui.servers.pingAllStopTitle") } else { t!("ui.servers.pingAllTitle") },
                    onclick: move |_| a_ping.ping_all(),
                    {if pinging { t!("ui.servers.pingAllStop") } else { t!("servers.pingAll") }}
                }
                Button {
                    kind: ButtonKind::Ghost,
                    disabled: total == 0,
                    title: if checking { t!("ui.servers.checkAll.stopTitle") } else { t!("ui.servers.checkAll.title") },
                    onclick: move |_| a_check.check_all(),
                    {if checking { t!("ui.servers.checkAll.stop") } else { t!("ui.servers.checkAll.open") }}
                }
                Button {
                    kind: ButtonKind::Ghost,
                    disabled: usable == 0,
                    title: t!("ui.servers.batch.openTitle"),
                    onclick: move |_| batch_open.set(true),
                    {t!("ui.servers.batch.open")}
                }
                Button {
                    kind: ButtonKind::Ghost,
                    title: t!("ui.servers.phones.schemesOpenTitle"),
                    onclick: move |_| a_schemes.open_schemes(),
                    {t!("ui.servers.phones.schemesOpen")}
                }
            }
            div { class: "srv-strip-facts",
                div { class: "srv-fact",
                    span { class: "swiss-label", {t!("ui.servers.facts.usable")} }
                    span { class: "srv-fact-value swiss-mono", "{usable}" }
                }
                if usable != total {
                    div { class: "srv-fact",
                        span { class: "swiss-label", {t!("ui.servers.facts.total")} }
                        span { class: "srv-fact-value swiss-mono", "{total}" }
                    }
                }
                div { class: "srv-fact is-export",
                    span { class: "swiss-label", {t!("ui.servers.facts.export")} }
                    Button {
                        kind: ButtonKind::Link,
                        small: true,
                        disabled: total == 0 || exporting,
                        onclick: move |_| a_keys.export_bulk(BulkKind::Keys),
                        {t!("servers.exportAllKeys")}
                    }
                    Button {
                        kind: ButtonKind::Link,
                        small: true,
                        disabled: total == 0 || exporting,
                        title: t!("ui.servers.export.proxyFormats"),
                        onclick: move |_| a_proxies.export_bulk(BulkKind::Proxies),
                        {t!("ui.servers.export.proxyList")}
                    }
                    span { class: "srv-fact-note", {t!("ui.servers.export.warning")} }
                }
            }
            if foreign {
                p { class: "srv-strip is-warn", role: "status", {t!("ui.servers.foreignVpn")} }
            }
            BulkNotice {}
            if !loaded {
                Loading { label: t!("ui.servers.loading") }
            } else if empty {
                EmptyState { title: t!("servers.emptyTitle"), detail: t!("servers.emptyHint"),
                    Button { onclick: move |_| add_open.set(true), {t!("ui.servers.add.open")} }
                }
            } else {
                div { class: "srv-groups",
                    for bucket in groups {
                        GroupCard { key: "{bucket.group.id}", bucket }
                    }
                }
            }
            AddDialog {}
            RequestDialog {}
            ServerDetail {}
            BatchDialog {}
            LinkSchemesDialog {}
            ConfirmDialogs {}
        }
    }
}

/// Keeps the page state consistent with a new snapshot: forgets expanded ids of deleted groups,
/// expands a sole group once, drops an add target that no longer exists (S-19), closes the
/// detail of a removed server (S-20: the detail renders from the live snapshot by id).
fn follow_store(actions: &Actions, view: &ServersView) {
    let store = actions.store;
    let ids: Vec<String> = buckets(view).into_iter().map(|b| b.group.id).collect();
    let (expanded, auto_done) = (
        store.expanded.peek().clone(),
        store.auto_expanded.peek().clone(),
    );
    if let Some((next, auto)) = reconcile_expanded(&expanded, &auto_done, &ids, view.loaded) {
        let (mut expanded, mut auto_expanded) = (store.expanded, store.auto_expanded);
        expanded.set(next);
        if let Some(id) = auto {
            auto_expanded.write().insert(id);
        }
        actions.save_expanded();
    }
    let mut add = store.add;
    let stale = matches!(&add.peek().target, AddTarget::Group(id) if !view.groups.iter().any(|g| &g.id == id));
    if stale {
        add.write().target = AddTarget::Auto;
    }
    let mut detail = store.detail;
    let gone = detail
        .peek()
        .as_ref()
        .is_some_and(|id| view.loaded && !view.servers.iter().any(|s| &s.id == id));
    if gone {
        detail.set(None);
    }
}

/// Progress and outcome of a bulk export (polite live region; the error is shown once).
#[component]
fn BulkNotice() -> Element {
    let actions = use_context::<Actions>();
    let mut bulk = actions.store.bulk;
    let Some(state) = bulk() else {
        return rsx! {};
    };
    let title = |kind: &BulkKind| match kind {
        BulkKind::Keys => t!("servers.exportAllKeys"),
        BulkKind::Proxies => t!("ui.servers.export.proxyList"),
    };
    let (class, head, body, working) = match &state {
        Bulk::Working(kind) => {
            let body = match kind {
                BulkKind::Keys => t!("ui.servers.export.keysWorking"),
                BulkKind::Proxies => t!("ui.servers.export.proxiesWorking"),
            };
            ("is-info", title(kind), body, true)
        }
        Bulk::Done(kind, report) => {
            let mut body = t!("ui.servers.export.done", count = report.exported);
            if report.skipped > 0 {
                body.push_str(&t!("ui.servers.export.skipped", count = report.skipped));
            }
            if report.hidden > 0 {
                body.push_str(&t!("ui.servers.export.hidden", count = report.hidden));
            }
            body.push_str(" · ");
            body.push_str(&t!("ui.servers.export.savedTo", path = report.path));
            ("is-ok", title(kind), body, false)
        }
        Bulk::Failed(kind, err) => {
            let head = match kind {
                BulkKind::Keys => t!("ui.servers.export.keysFailed"),
                BulkKind::Proxies => t!("ui.servers.export.proxiesFailed"),
            };
            ("is-fail", head, crate::lang::tr(&err.msg), false)
        }
    };
    rsx! {
        div { class: "srv-notice {class}", role: "status", aria_live: "polite",
            div { class: "srv-notice-text",
                p { class: "srv-notice-title", "{head}" }
                p { class: "srv-notice-body", "{body}" }
            }
            if working {
                div { class: "srv-notice-bar",
                    ProgressBar { value: None, label: body.clone() }
                }
            } else {
                crate::widgets::IconButton {
                    glyph: IconGlyph::Close,
                    label: t!("common.close"),
                    onclick: move |_| bulk.set(None),
                }
            }
        }
    }
}

/// Confirmations of the destructive actions: remove a server (S-6: it used to go at once; now a
/// restorable soft delete), delete a removed server for good, delete a group (keep or delete its
/// servers).
#[component]
fn ConfirmDialogs() -> Element {
    let actions = use_context::<Actions>();
    let store = actions.store;
    let mut confirm = store.confirm;
    let busy = (store.confirm_busy)();
    let server_open =
        use_memo(move || matches!(*store.confirm.read(), Some(Confirm::DeleteServer { .. })));
    let group_open =
        use_memo(move || matches!(*store.confirm.read(), Some(Confirm::DeleteGroup { .. })));
    let purge_open =
        use_memo(move || matches!(*store.confirm.read(), Some(Confirm::PurgeServer { .. })));
    let current = confirm();
    let (server_msg, server_target) = match &current {
        Some(Confirm::DeleteServer {
            id,
            name,
            connected,
        }) => {
            let mut msg = t!("ui.servers.remove.body", name = name);
            if *connected {
                msg.push(' ');
                msg.push_str(&t!("ui.servers.remove.connected"));
            }
            (msg, Some((id.clone(), name.clone())))
        }
        _ => (String::new(), None),
    };
    let purge_target = match &current {
        Some(Confirm::PurgeServer { id, name }) => Some((id.clone(), name.clone())),
        _ => None,
    };
    let purge_msg = purge_target
        .as_ref()
        .map(|(_, name)| t!("ui.servers.purge.body", name = name))
        .unwrap_or_default();
    let a_purge = actions.clone();
    let group_target = match &current {
        Some(Confirm::DeleteGroup { id, name, servers }) => {
            Some((id.clone(), name.clone(), *servers))
        }
        _ => None,
    };
    let (a_remove, a_keep, a_drop) = (actions.clone(), actions.clone(), actions.clone());
    let (keep_target, drop_target) = (group_target.clone(), group_target.clone());
    let mut cancel = move || {
        if !*store.confirm_busy.peek() {
            confirm.set(None);
        }
    };
    rsx! {
        ConfirmDialog {
            open: server_open,
            title: t!("ui.servers.remove.title"),
            message: server_msg,
            confirm_label: t!("ui.servers.remove.confirm"),
            cancel_label: t!("common.cancel"),
            danger: true,
            busy,
            on_confirm: move |_| {
                if let Some((id, name)) = server_target.clone() {
                    a_remove.remove(id, name);
                }
            },
            on_cancel: move |_| cancel(),
        }
        ConfirmDialog {
            open: purge_open,
            title: t!("ui.servers.purge.title"),
            message: purge_msg,
            confirm_label: t!("ui.servers.menu.purge"),
            cancel_label: t!("common.cancel"),
            danger: true,
            busy,
            on_confirm: move |_| {
                if let Some((id, name)) = purge_target.clone() {
                    a_purge.purge(id, name);
                }
            },
            on_cancel: move |_| cancel(),
        }
        Modal {
            open: group_open,
            title: t!("servers.groups.deletePromptTitle"),
            on_close: move |_| cancel(),
            close_label: t!("common.close"),
            can_close: !busy,
            size: ModalSize::Sm,
            footer: rsx! {
                Button { kind: ButtonKind::Ghost, initial_focus: true, disabled: busy, onclick: move |_| cancel(),
                    {t!("servers.groups.deleteCancel")}
                }
                Button {
                    kind: ButtonKind::Ghost,
                    busy,
                    onclick: move |_| {
                        if let Some((id, name, _)) = keep_target.clone() {
                            a_keep.delete_group(id, name, false);
                        }
                    },
                    {t!("servers.groups.deleteOnlyGroup")}
                }
                Button {
                    kind: ButtonKind::Danger,
                    busy,
                    onclick: move |_| {
                        if let Some((id, name, _)) = drop_target.clone() {
                            a_drop.delete_group(id, name, true);
                        }
                    },
                    {t!("servers.groups.deleteWithServers")}
                }
            },
            if let Some((_, name, servers)) = group_target {
                p { class: "w-confirm-text", {t!("ui.servers.group.deleteBody")} }
                p { class: "srv-confirm-target",
                    strong { "{name}" }
                    " · "
                    {t!("servers.groups.serverCount", count = servers)}
                }
            }
        }
    }
}
