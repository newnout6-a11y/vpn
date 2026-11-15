//! Servers panel: one row per server with flag, name (select), ping button, health; «ping all».
use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use dioxus::prelude::*;
use vpnte_base::Msg;
use vpnte_base::types::{Level, Notice, now_ms};
use vpnte_view::identity::{LocalPing, ServerHealth};

use super::icons::{Flag, Spinner};
use super::model::{Selected, ServersView};
use super::rules::{DASH, LocalPings, ServerLine, server_lines};
use super::{PanelHead, PanelsApi, notify};
use crate::lang::tr;
use crate::t;

/// Health ages («3 мин») advance between pushes on this tick.
const AGE_TICK: Duration = Duration::from_secs(30);

fn health_dot(health: ServerHealth) -> &'static str {
    match health {
        ServerHealth::Offline => "swiss-health-dot is-offline",
        ServerHealth::Unknown => "swiss-health-dot is-unknown",
        ServerHealth::Online => "swiss-health-dot",
    }
}

/// The servers panel.
#[component]
pub(super) fn ServersPanel(
    view: Signal<ServersView>,
    local: Signal<LocalPings>,
    on_notice: Option<EventHandler<Notice>>,
) -> Element {
    let api = use_context::<Rc<dyn PanelsApi>>();
    let mut pinging_all = use_signal(|| false);
    let mut selecting = use_signal(|| false);
    let mut now = use_signal(now_ms);
    use_future(move || async move {
        loop {
            tokio::time::sleep(AGE_TICK).await;
            now.set(now_ms());
        }
    });
    // Endpoint round trips depend on the route: a connect or disconnect voids the panel's pings.
    let last_route = use_hook(|| Rc::new(Cell::new(None::<bool>)));
    use_effect(move || {
        let running = view.read().tun_running;
        if last_route.get().is_some_and(|was| was != running) {
            local.write().new_route();
        }
        last_route.set(Some(running));
    });

    // A second click can arrive before the re-render has disabled the button: ignore it.
    let ping_all = {
        let api = api.clone();
        move |_| {
            if *pinging_all.peek() {
                return;
            }
            let api = api.clone();
            pinging_all.set(true);
            spawn(async move {
                match api.ping_all().await {
                    Ok(()) => local.write().clear(),
                    Err(err) => {
                        tracing::warn!(%err, "ping all failed");
                        let notice = Notice::new(Level::Error, Msg::new("swiss.pingFailed"));
                        notify(on_notice, notice.body(err.user_msg()));
                    }
                }
                pinging_all.set(false);
            });
        }
    };
    let ping_one = use_callback({
        let api = api.clone();
        move |id: String| {
            if local.peek().get(&id) == Some(LocalPing::Pinging) {
                return;
            }
            let api = api.clone();
            let route = local.write().begin(&id);
            spawn(async move {
                let ms = api.ping_one(&id).await.unwrap_or_else(|err| {
                    tracing::debug!(%err, "server ping failed");
                    None
                });
                local.write().finish(&id, route, ms);
            });
        }
    });
    let select = use_callback(move |id: String| {
        let skip = {
            let v = view.read();
            v.locked || v.active_id.as_deref() == Some(id.as_str())
        };
        if skip || selecting() {
            return;
        }
        let api = api.clone();
        selecting.set(true);
        spawn(async move {
            match api.select_server(&id).await {
                Ok(Selected::Done) => tracing::info!("server selected from the panel"),
                Ok(Selected::Cancelled) => tracing::info!("server switch cancelled"),
                Err(err) => {
                    tracing::warn!(%err, "server select failed");
                    let notice = Notice::new(Level::Error, Msg::new("swiss.serverSelectFailed"));
                    notify(on_notice, notice.body(err.user_msg()));
                }
            }
            selecting.set(false);
        });
    });

    let lines = server_lines(&view.read(), &local.read(), now());
    rsx! {
        section { class: "swiss-panel",
            PanelHead { title: t!("swiss.servers"), perch: "servers",
                button {
                    r#type: "button",
                    class: "swiss-fact-action",
                    disabled: pinging_all() || lines.is_empty(),
                    onclick: ping_all,
                    if pinging_all() {
                        Spinner { class: "mr-1 inline h-3 w-3 animate-spin" }
                    }
                    {t!("swiss.pingAll")}
                }
            }
            div { class: "swiss-panel-body",
                if lines.is_empty() {
                    p { class: "swiss-empty", {t!("swiss.serversEmpty")} }
                }
                for line in lines {
                    ServerRow {
                        key: "{line.id}",
                        line: line.clone(),
                        on_select: select,
                        on_ping: ping_one,
                    }
                }
            }
        }
    }
}

/// One server row.
#[component]
fn ServerRow(line: ServerLine, on_select: Callback<String>, on_ping: Callback<String>) -> Element {
    let ping_title = if line.best {
        t!("swiss.bestPing")
    } else {
        t!("swiss.pingOne")
    };
    let mut ping_aria = format!("{}: {}", t!("swiss.pingOne"), line.name);
    if line.best {
        ping_aria.push_str(&format!(", {}", t!("swiss.best")));
    }
    let ping = line
        .ping
        .map_or_else(|| DASH.to_owned(), |ms| ms.to_string());
    let offline = line.health == ServerHealth::Offline;
    let (select_id, ping_id) = (line.id.clone(), line.id.clone());
    rsx! {
        div {
            class: "swiss-server-row group",
            class: if line.selected { "is-selected" },
            class: if line.muted { "is-offline" },
            "data-perch": "server-{line.id}",
            "data-perch-y": "bottom",
            "data-perch-x": "0.55",
            "data-perch-scale": "0.3",
            "data-perch-fit": "gap",
            span { class: "swiss-server-flag",
                if let Some(country) = line.country.clone() {
                    Flag { country, size: 14 }
                }
            }
            button {
                r#type: "button",
                class: "swiss-server-name",
                title: "{line.name}",
                onclick: move |_| on_select.call(select_id.clone()),
                span { class: "truncate", "{line.name}" }
            }
            button {
                r#type: "button",
                class: "swiss-mono swiss-server-ping",
                class: if line.best { "is-best" },
                disabled: line.pinging,
                title: "{ping_title}",
                aria_label: "{ping_aria}",
                onclick: move |_| on_ping.call(ping_id.clone()),
                if line.pinging {
                    Spinner { class: "h-3 w-3 animate-spin" }
                } else {
                    span { "{ping}" }
                }
            }
            span {
                class: "swiss-mono swiss-server-health",
                class: if offline { "is-offline" },
                span { class: health_dot(line.health) }
                {tr(&line.health_text)}
            }
        }
    }
}
