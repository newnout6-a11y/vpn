//! The page: header actions (rescan, add a program), the scope switch, search, the
//! bypass-command card, the Happ routing panel and the app table with a rule control per row.
use dioxus::prelude::*;
use vpnte_base::{ErrorKind, Msg};

use super::model::{
    AppKind, AppRule, AppScope, SplitApp, display_path, icon_src, initial, matches, scope_hint_key,
};
use super::routing_panel::RoutingPanel;
use super::{tr_now, use_api, use_watch};
use crate::lang::tr;
use crate::pages::{Page, nav_number};
use crate::t;
use crate::widgets::{
    Badge, Button, ButtonKind, Cell, EmptyState, HeadCell, IconButton, IconGlyph, Load, LoadError,
    Loading, Panel, SectionHeader, Spinner, Switch, Table, TextInput, TextKind, Toasts, use_job,
};

/// The Apps page (register as `Page::Apps`). Needs `Rc<dyn SplitTunnelApi>` and the [`Toasts`]
/// provider in context.
#[component]
pub fn SplitTunnelPage() -> Element {
    let api = use_api();
    let state = use_watch({
        let api = api.clone();
        move || api.state()
    });
    let toasts = Toasts::use_context();
    let mut query = use_signal(String::new);
    let refresh_job = use_job::<()>();
    let add_job = use_job::<()>();
    let reload_job = use_job::<()>();

    let refresh = {
        let api = api.clone();
        move |_| {
            let api = api.clone();
            refresh_job.start(move |_| async move {
                match api.refresh().await {
                    Ok(added) => {
                        let detail = if added > 0 {
                            Msg::new("splitTunneling.refreshAdded").arg("n", added)
                        } else {
                            Msg::new("splitTunneling.refreshNone")
                        };
                        toasts.success(
                            tr_now(&Msg::new("splitTunneling.refreshed")),
                            Some(tr_now(&detail)),
                        );
                    }
                    Err(err) => toasts.failed(&Msg::new("splitTunneling.refreshFailed"), &err),
                }
                Ok(())
            });
        }
    };
    let add_app = {
        let api = api.clone();
        move |_| {
            let api = api.clone();
            add_job.start(move |_| async move {
                match api.add_app().await {
                    // A new row the search would hide: clear the search so it is seen.
                    Ok(Some(app)) if !matches(&app, &query.peek()) => query.set(String::new()),
                    Ok(_) => {}
                    Err(err) => toasts.failed(&Msg::new("splitTunneling.addFailed"), &err),
                }
                Ok(())
            });
        }
    };
    let reload = {
        let api = api.clone();
        move |()| {
            let api = api.clone();
            reload_job.start(move |_| async move { api.reload().await });
        }
    };

    let apps = state.read().apps.clone();
    let offers = state.read().offers.clone();
    let (scope, older_service) = (state.read().scope, state.read().older_service);
    let hint_key = scope_hint_key(scope, &apps);
    let number = Page::ALL.iter().position(|p| *p == Page::Apps).unwrap_or(1);
    rsx! {
        div { class: "c-swiss swiss-skin apps",
            SectionHeader {
                title: t!("splitTunneling.title"),
                number: nav_number(number),
                description: t!("splitTunneling.description"),
                Button {
                    kind: ButtonKind::Ghost,
                    small: true,
                    busy: refresh_job.running(),
                    title: t!("splitTunneling.refreshTitle"),
                    onclick: refresh,
                    {t!("splitTunneling.refresh")}
                }
                Button {
                    small: true,
                    busy: add_job.running(),
                    onclick: add_app,
                    {t!("splitTunneling.addApp")}
                }
            }
            ScopeSwitch { scope, hint_key, older_service }
            div { class: "apps-search",
                TextInput {
                    value: query(),
                    kind: TextKind::Search,
                    placeholder: t!("splitTunneling.searchPlaceholder"),
                    aria_label: t!("splitTunneling.searchLabel"),
                    oninput: move |v: String| query.set(v),
                    on_escape: move |()| query.set(String::new()),
                }
            }
            BypassCommand {}
            RoutingPanel { offers }
            match apps {
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
                            on_retry: reload,
                        }
                    }
                },
                Load::Ready(list) => rsx! {
                    AppTable { apps: list, query: query() }
                },
            }
        }
    }
}

/// «Только выбранные приложения»: the switch and one line on what it does with the list as it
/// is; with a helper service too old for it, one calm line more (Tunnel mode there routes every
/// app). A change applies from the next connection, as the list's own changes do.
#[component]
fn ScopeSwitch(scope: AppScope, hint_key: &'static str, older_service: bool) -> Element {
    let api = use_api();
    let toasts = Toasts::use_context();
    let job = use_job::<()>();
    let on = scope == AppScope::OnlyListed;
    let change = move |want: bool| {
        let api = api.clone();
        let next = if want {
            AppScope::OnlyListed
        } else {
            AppScope::All
        };
        job.start(move |_| async move {
            match api.set_scope(next).await {
                Ok(()) => {
                    toasts.success(
                        tr_now(&Msg::new("splitTunneling.routing.nextConnect")),
                        None,
                    );
                }
                Err(err) => toasts.failed(&Msg::new("splitTunneling.scope.failed"), &err),
            }
            Ok(())
        });
    };
    rsx! {
        Panel {
            div { class: "apps-scope",
                Switch {
                    label: t!("splitTunneling.scope.label"),
                    checked: on,
                    hint: t!(hint_key),
                    busy: job.running(),
                    on_change: change,
                }
                if on && older_service {
                    p { class: "apps-scope-note", role: "status",
                        {t!("splitTunneling.scope.olderService")}
                    }
                }
            }
        }
    }
}

/// «Команда мимо VPN»: a bare process name whose traffic goes around the VPN. The service
/// normalises the name and the card shows the name it got back; a bad name is explained inline
/// (the old page logged it to the journal only).
#[component]
fn BypassCommand() -> Element {
    let api = use_api();
    let job = use_job::<()>();
    let mut text = use_signal(String::new);
    let mut outcome = use_signal(|| None::<Result<String, Msg>>);
    let submit = move || {
        let raw = text.peek().trim().to_owned();
        if raw.is_empty() {
            return;
        }
        let api = api.clone();
        job.start(move |_| async move {
            match api.add_process(raw).await {
                Ok(app) => {
                    tracing::info!("process bypass added");
                    text.set(String::new());
                    outcome.set(Some(Ok(app.path)));
                }
                Err(err) if err.kind == ErrorKind::Cancelled => {}
                Err(err) => {
                    tracing::warn!(error = %err, "process bypass not added");
                    outcome.set(Some(Err(err.user_msg())));
                }
            }
            Ok(())
        });
    };
    let enter = submit.clone();
    let blank = text.read().trim().is_empty();
    let input_id = crate::widgets::use_dom_id("apps-cmd");
    rsx! {
        Panel { title: t!("splitTunneling.bypassCommandTitle"),
            div { class: "apps-cmd",
                label { class: "apps-cmd-hint", r#for: "{input_id}", {t!("splitTunneling.bypassCommandHint")} }
                div { class: "apps-cmd-row",
                    TextInput {
                        id: input_id.clone(),
                        value: text(),
                        mono: true,
                        maxlength: 260,
                        placeholder: t!("splitTunneling.bypassCommandPlaceholder"),
                        invalid: matches!(&*outcome.read(), Some(Err(_))),
                        oninput: move |v: String| {
                            text.set(v);
                            outcome.set(None);
                        },
                        on_enter: move |()| enter(),
                    }
                    Button {
                        busy: job.running(),
                        disabled: blank,
                        onclick: move |_| submit(),
                        {t!("splitTunneling.bypassCommandAdd")}
                    }
                }
                match outcome() {
                    Some(Ok(name)) => rsx! {
                        p { class: "apps-cmd-result", role: "status",
                            {t!("splitTunneling.commandAdded", name = name)}
                        }
                    },
                    Some(Err(msg)) => rsx! {
                        p { class: "apps-cmd-result is-error", role: "alert",
                            {format!("{}: {}", t!("splitTunneling.commandAddFailed"), tr(&msg))}
                        }
                    },
                    None => rsx! {},
                }
            }
        }
    }
}

/// The table of apps matching the search («Приложение | Маршрут»).
#[component]
fn AppTable(apps: Vec<SplitApp>, query: String) -> Element {
    let shown: Vec<SplitApp> = apps.into_iter().filter(|a| matches(a, &query)).collect();
    if shown.is_empty() {
        let title = if query.trim().is_empty() {
            t!("splitTunneling.noApps")
        } else {
            t!("common.noResults")
        };
        return rsx! {
            Panel {
                EmptyState { title }
            }
        };
    }
    rsx! {
        Panel { flush: true,
            Table { caption: t!("splitTunneling.title"),
                thead {
                    tr {
                        HeadCell { label: t!("splitTunneling.columnApp") }
                        HeadCell { label: t!("splitTunneling.columnRule"), width: "320px" }
                        th { class: "w-th apps-th-actions", scope: "col",
                            span { class: "w-sr", {t!("splitTunneling.columnActions")} }
                        }
                    }
                }
                tbody {
                    for app in shown {
                        AppRow { key: "{app.id}", app }
                    }
                }
            }
        }
    }
}

/// One app: icon, name (+ «команда»), path or the command note; the rule control and remove.
/// A rule change shows the new rule at once with a spinner; the row is tinted and locked until
/// the service answers; on failure the old rule is back and a toast says why.
#[component]
fn AppRow(app: SplitApp) -> Element {
    let api = use_api();
    let toasts = Toasts::use_context();
    let rule_job = use_job::<()>();
    let remove_job = use_job::<()>();
    let mut pending = use_signal(|| None::<AppRule>);
    let busy = rule_job.running() || remove_job.running();
    let shown = pending().unwrap_or(app.rule);

    let pick = {
        let (api, id, current) = (api.clone(), app.id.clone(), app.rule);
        move |rule: AppRule| {
            if rule == current || rule_job.running() {
                return;
            }
            pending.set(Some(rule));
            let (api, id) = (api.clone(), id.clone());
            rule_job.start(move |_| async move {
                let result = api.set_rule(id, rule).await;
                pending.set(None);
                if let Err(err) = result {
                    toasts.failed(&Msg::new("splitTunneling.ruleFailed"), &err);
                }
                Ok(())
            });
        }
    };
    let remove = {
        let (api, id) = (api.clone(), app.id.clone());
        move |_| {
            let (api, id) = (api.clone(), id.clone());
            remove_job.start(move |_| async move {
                if let Err(err) = api.remove(id).await {
                    toasts.failed(&Msg::new("splitTunneling.removeFailed"), &err);
                }
                Ok(())
            });
        }
    };
    let process = app.kind == AppKind::Process;
    let path = display_path(&app);
    let subtitle = if process {
        t!("splitTunneling.commandSubtitle")
    } else {
        path.clone()
    };
    rsx! {
        tr { class: "apps-row", class: if busy { "is-busy" },
            Cell { grow: true,
                div { class: "apps-app",
                    {app_icon(&app)}
                    div { class: "apps-app-text",
                        p { class: "apps-app-name",
                            span { class: "apps-app-title", "{app.name}" }
                            if process {
                                Badge { {t!("splitTunneling.commandTag")} }
                            }
                        }
                        p {
                            class: "apps-app-path",
                            class: if !process { "swiss-mono" },
                            title: (!process).then_some(path),
                            "{subtitle}"
                        }
                    }
                }
            }
            Cell {
                RuleControl {
                    name: app.name.clone(),
                    shown,
                    pending: rule_job.running(),
                    disabled: busy,
                    on_pick: pick,
                }
            }
            Cell {
                IconButton {
                    glyph: IconGlyph::Trash,
                    label: t!("splitTunneling.removeItem", name = app.name),
                    danger: true,
                    busy: remove_job.running(),
                    disabled: rule_job.running(),
                    onclick: remove,
                }
            }
        }
    }
}

/// VPN | Напрямую | Нет as pressed buttons with hover help; the pending choice carries the
/// spinner.
#[component]
fn RuleControl(
    name: String,
    shown: AppRule,
    pending: bool,
    disabled: bool,
    on_pick: EventHandler<AppRule>,
) -> Element {
    rsx! {
        div {
            class: "w-seg apps-rule",
            role: "group",
            aria_label: t!("splitTunneling.ruleFor", name = name),
            aria_busy: pending.then_some("true"),
            for rule in AppRule::ALL {
                button {
                    key: "{rule:?}",
                    r#type: "button",
                    class: "w-seg-item apps-rule-item",
                    class: if rule == shown { "is-on" },
                    "data-rule": "{rule:?}",
                    aria_pressed: if rule == shown { "true" } else { "false" },
                    title: t!(rule.title_key()),
                    disabled,
                    onclick: move |_| on_pick.call(rule),
                    if pending && rule == shown {
                        Spinner {}
                    }
                    {t!(rule.label_key())}
                }
            }
        }
    }
}

/// The icon cell: a terminal glyph for a process, the app's PNG, else its first letter.
fn app_icon(app: &SplitApp) -> Element {
    if app.kind == AppKind::Process {
        return rsx! {
            span { class: "apps-icon is-process", aria_hidden: "true",
                svg {
                    width: "16",
                    height: "16",
                    view_box: "0 0 16 16",
                    fill: "none",
                    stroke: "currentColor",
                    stroke_width: "1.5",
                    rect { x: "1.5", y: "2.5", width: "13", height: "11" }
                    polyline { points: "4.5,6 6.5,8 4.5,10" }
                    line { x1: "8", y1: "10.5", x2: "11.5", y2: "10.5" }
                }
            }
        };
    }
    match app.icon.as_deref().and_then(icon_src) {
        Some(src) => rsx! {
            img { class: "apps-icon", src, alt: "", width: "28", height: "28" }
        },
        None => rsx! {
            span { class: "apps-icon is-letter", aria_hidden: "true", "{initial(&app.name)}" }
        },
    }
}
