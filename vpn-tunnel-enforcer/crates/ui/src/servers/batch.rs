//! The batch comparison: sequential extended checks of up to 12 enabled servers (same-size probes,
//! one after another, so parallel load does not skew the numbers). «Остановить» is a soft stop:
//! the run ends after the current server and the receipts so far are shown (B-2); closing while
//! running aborts (B-6). Rows best first (B-3); a 13th server cannot be ticked (B-1).
use std::rc::Rc;

use dioxus::core::Task;
use dioxus::prelude::*;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;

use super::actions::Actions;
use super::api::ServersApi;
use super::live_model::{BatchProgress, BatchResult, LiveCheck, ProgressStatus};
use super::live_present::{
    BATCH_MAX, RouteSummary, batch_bar, batch_filter, batch_label, batch_sort, batch_toggle,
    format_mbps, route_summary, throughput_route_key,
};
use super::model::ServerView;
use crate::lang::tr;
use crate::t;
use crate::widgets::{
    Align, Badge, Button, ButtonKind, Cell, HeadCell, Modal, ModalSize, Table, TextInput, TextKind,
    Tone, UiError,
};

/// State and actions of the comparison (`Copy`; its run belongs to the dialog's scope).
#[derive(Clone, Copy, PartialEq)]
pub(crate) struct BatchCtl {
    pub query: Signal<String>,
    pub selected: Signal<Vec<String>>,
    pub run: Signal<Option<(Task, CancellationToken)>>,
    pub stopping: Signal<bool>,
    pub progress: Signal<Option<BatchProgress>>,
    pub result: Signal<Option<BatchResult>>,
    pub error: Signal<Option<UiError>>,
}

impl BatchCtl {
    /// Creates the state in the calling component (inside `use_hook`).
    pub fn new() -> Self {
        Self {
            query: Signal::new(String::new()),
            selected: Signal::new(Vec::new()),
            run: Signal::new(None),
            stopping: Signal::new(false),
            progress: Signal::new(None),
            result: Signal::new(None),
            error: Signal::new(None),
        }
    }

    /// A fresh selection screen with `first` ticked.
    pub fn reset(&self, first: Vec<String>) {
        let Self {
            mut query,
            mut selected,
            mut progress,
            mut result,
            mut error,
            ..
        } = *self;
        query.set(String::new());
        selected.set(first);
        progress.set(None);
        result.set(None);
        error.set(None);
    }

    /// Starts the comparison of the ticked servers unless one runs.
    pub fn start(&self, api: Rc<dyn ServersApi>) {
        let Self {
            mut run,
            mut stopping,
            mut progress,
            mut result,
            mut error,
            selected,
            ..
        } = *self;
        let ids = selected.peek().clone();
        if run.peek().is_some() || ids.is_empty() {
            return;
        }
        progress.set(None);
        result.set(None);
        error.set(None);
        let stop = CancellationToken::new();
        let token = stop.clone();
        let task = spawn(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let batch = api.live_batch(ids, token, tx);
            futures_util::pin_mut!(batch);
            let outcome = loop {
                tokio::select! {
                    outcome = &mut batch => break outcome,
                    Some(p) = rx.recv() => progress.set(Some(p)),
                }
            };
            run.set(None);
            stopping.set(false);
            match outcome {
                Ok(done) => result.set(Some(done)),
                Err(err) if err.kind == ErrorKind::Cancelled => {}
                Err(err) => error.set(Some(UiError::from(err))),
            }
        });
        run.set(Some((task, stop)));
    }

    /// Soft stop: the run finishes the current server and returns what it measured (B-2).
    pub fn stop(&self) {
        let mut stopping = self.stopping;
        if let Some((_, token)) = self.run.peek().as_ref() {
            token.cancel();
            stopping.set(true);
        }
    }

    /// Hard abort (closing while running, B-6): the run is dropped, nothing is shown.
    pub fn abort(&self) {
        let Self {
            mut run,
            mut stopping,
            mut progress,
            ..
        } = *self;
        if let Some((task, _)) = run.take() {
            task.cancel();
        }
        stopping.set(false);
        progress.set(None);
    }
}

#[component]
pub(crate) fn BatchDialog() -> Element {
    let actions = use_context::<Actions>();
    let store = actions.store;
    let mut open = store.batch_open;
    let ctl = use_hook(BatchCtl::new);
    let BatchCtl {
        mut query,
        mut selected,
        run,
        stopping,
        progress,
        mut result,
        error,
    } = ctl;
    let usable: Vec<ServerView> = store
        .view
        .read()
        .servers
        .iter()
        .filter(|s| s.enabled && s.archived.is_none())
        .cloned()
        .collect();
    // Each opening starts fresh with the first 12 enabled servers ticked.
    let first: Vec<String> = usable
        .iter()
        .take(BATCH_MAX)
        .map(|s| s.id.clone())
        .collect();
    let fresh = first.clone();
    use_effect(move || {
        if open() {
            ctl.reset(fresh.clone());
        }
    });
    let mut close = move || {
        ctl.abort();
        open.set(false);
    };
    let api = actions.api.clone();
    let start = move |_| ctl.start(api.clone());
    let stop = move |_| ctl.stop();
    let running = run.read().is_some();
    let done = result();
    let footer = if running {
        rsx! {
            Button { kind: ButtonKind::Ghost, onclick: move |_| close(), {t!("ui.servers.batch.abortClose")} }
            Button { kind: ButtonKind::Danger, busy: stopping(), onclick: stop, {t!("ui.servers.batch.stop")} }
        }
    } else if done.is_some() {
        rsx! {
            Button { kind: ButtonKind::Ghost, onclick: move |_| close(), {t!("common.close")} }
            Button { onclick: move |_| result.set(None), {t!("ui.servers.batch.again")} }
        }
    } else {
        rsx! {
            Button { kind: ButtonKind::Ghost, onclick: move |_| close(), {t!("common.close")} }
            Button { disabled: selected.read().is_empty(), onclick: start, {t!("ui.servers.batch.start")} }
        }
    };
    let chosen = selected();
    rsx! {
        Modal {
            open,
            title: t!("ui.servers.batch.title"),
            description: t!("ui.servers.batch.description"),
            on_close: move |_| close(),
            close_label: t!("common.close"),
            size: ModalSize::Lg,
            footer,
            if let Some(err) = error() {
                p { class: "srv-strip is-fail", role: "alert", {tr(&err.msg)} }
            }
            if running {
                Running { progress: progress(), stopping: stopping(), servers: usable.clone() }
            } else if let Some(done) = done {
                Results { result: done, selected: chosen, servers: usable.clone() }
            } else {
                Selection {
                    servers: usable,
                    selected: chosen,
                    query: query(),
                    on_query: move |q| query.set(q),
                    on_toggle: move |id: String| {
                        batch_toggle(&mut selected.write(), &id);
                    },
                    on_clear: move |_| selected.set(Vec::new()),
                    on_first: move |_| selected.set(first.clone()),
                }
            }
        }
    }
}

/// Picking up to 12 servers: search, quick actions, checkbox rows (`role=checkbox`, B-7).
#[component]
fn Selection(
    servers: Vec<ServerView>,
    selected: Vec<String>,
    query: String,
    on_query: EventHandler<String>,
    on_toggle: EventHandler<String>,
    on_clear: EventHandler<()>,
    on_first: EventHandler<()>,
) -> Element {
    let visible: Vec<ServerView> = batch_filter(&servers, &query)
        .into_iter()
        .cloned()
        .collect();
    let full = selected.len() >= BATCH_MAX;
    rsx! {
        div { class: "srv-batch",
            div { class: "srv-batch-bar",
                span { class: "srv-batch-count", {t!("ui.servers.batch.available", count = servers.len())} }
                Badge { tone: if full { Tone::Warn } else { Tone::Neutral }, "{selected.len()}/{BATCH_MAX}" }
                if full {
                    span { class: "srv-detail-note", {t!("ui.servers.batch.max")} }
                }
                span { class: "srv-batch-gap" }
                Button { kind: ButtonKind::Link, small: true, onclick: move |_| on_clear.call(()), {t!("ui.servers.batch.clear")} }
                Button { kind: ButtonKind::Link, small: true, onclick: move |_| on_first.call(()), {t!("ui.servers.batch.first")} }
            }
            TextInput {
                value: query,
                oninput: move |q| on_query.call(q),
                kind: TextKind::Search,
                placeholder: t!("ui.servers.batch.search"),
                aria_label: t!("ui.servers.batch.search"),
            }
            div { class: "srv-batch-list", role: "group", aria_label: t!("ui.servers.batch.title"),
                for server in visible {
                    BatchPick {
                        key: "{server.id}",
                        checked: selected.contains(&server.id),
                        disabled: full && !selected.contains(&server.id),
                        on_toggle,
                        server,
                    }
                }
            }
        }
    }
}

#[component]
fn BatchPick(
    server: ServerView,
    checked: bool,
    disabled: bool,
    on_toggle: EventHandler<String>,
) -> Element {
    let id = server.id.clone();
    rsx! {
        button {
            r#type: "button",
            class: "srv-batch-pick",
            class: if checked { "is-checked" },
            role: "checkbox",
            aria_checked: if checked { "true" } else { "false" },
            disabled,
            title: disabled.then(|| t!("ui.servers.batch.max")),
            onclick: move |_| on_toggle.call(id.clone()),
            span { class: "srv-batch-box", aria_hidden: "true" }
            span { class: "srv-batch-name", "{server.name}" }
            span { class: "swiss-mono srv-batch-addr", "{server.host}:{server.port}" }
        }
    }
}

/// «Профиль i из n: name», stage, bar (never under 4 %); before the first event «Подготовка…».
#[component]
fn Running(progress: Option<BatchProgress>, stopping: bool, servers: Vec<ServerView>) -> Element {
    let Some(p) = progress else {
        return rsx! {
            p { class: "srv-live-progress", role: "status", {t!("liveCheck.preparing")} }
        };
    };
    let name = servers
        .iter()
        .find(|s| s.id == p.profile_id)
        .map_or_else(|| p.profile_id.clone(), |s| s.name.clone());
    let stage = match (p.stage, p.status) {
        (_, ProgressStatus::Failed) => t!("ui.servers.batch.failedStage"),
        (Some(stage), _) => t!(&format!("ui.servers.stage.{}", stage.key())),
        (None, _) => String::new(),
    };
    let pct = batch_bar(&p);
    rsx! {
        div { class: "srv-live-progress", role: "status",
            div { class: "srv-live-progress-line",
                span { {t!("ui.servers.batch.profile", index = p.index + 1, total = p.total, name = name)} }
                span { class: "swiss-mono", "{stage}" }
            }
            div { class: "srv-live-bar", div { class: "srv-live-bar-fill", style: "width:{pct:.1}%" } }
            if stopping {
                p { class: "srv-detail-note", {t!("ui.servers.batch.stopping")} }
            }
        }
    }
}

/// The comparison table, best first, with the path note and the servers that failed.
#[component]
fn Results(result: BatchResult, selected: Vec<String>, servers: Vec<ServerView>) -> Element {
    let mut rows: Vec<&LiveCheck> = result.results.iter().collect();
    batch_sort(&mut rows);
    let route = match route_summary(result.results.iter()) {
        RouteSummary::Unknown => String::new(),
        RouteSummary::Mixed => t!("ui.servers.batch.routesMixed"),
        RouteSummary::Single(r) => t!(
            "ui.servers.batch.routeSingle",
            route = throughput_route_key(Some(r), true).map_or_else(|| "—".to_owned(), |k| t!(k))
        ),
    };
    let state = if result.cancelled {
        t!("ui.servers.batch.stopped")
    } else {
        t!("ui.servers.batch.done")
    };
    let name_of = |c: &LiveCheck| {
        let id = c.profile_id.clone().unwrap_or_default();
        servers
            .iter()
            .find(|s| s.id == id)
            .map_or(id, |s| s.name.clone())
    };
    let table_rows: Vec<(String, String, LiveCheck)> = rows
        .iter()
        .map(|c| (name_of(c), format!("{}:{}", c.host, c.port), (*c).clone()))
        .collect();
    let deferred = result
        .results
        .iter()
        .filter(|c| c.deferred.is_some())
        .count();
    rsx! {
        div { class: "srv-batch",
            p { class: "srv-batch-summary",
                strong { {t!("ui.servers.batch.checked", count = result.results.len(), total = selected.len())} }
                " · {state}{route}"
            }
            Table { caption: t!("ui.servers.batch.title"),
                thead {
                    tr {
                        HeadCell { label: t!("ui.servers.batch.colServer") }
                        HeadCell { label: t!("ui.servers.batch.colMedian"), align: Align::End }
                        HeadCell { label: t!("ui.servers.batch.colSpread"), align: Align::End }
                        HeadCell { label: t!("ui.servers.batch.colStalls"), align: Align::End }
                        HeadCell { label: t!("ui.servers.batch.colPath") }
                        HeadCell { label: t!("ui.servers.batch.colStatus") }
                    }
                }
                tbody {
                    for (name , addr , check) in table_rows {
                        tr { key: "{check.id}",
                            Cell { grow: true,
                                span { class: "srv-batch-name", "{name}" }
                                span { class: "swiss-mono srv-batch-addr", "{addr}" }
                            }
                            Cell { align: Align::End, mono: true,
                                {format_mbps(check.throughput.as_ref().and_then(|t| t.median_mbps))}
                            }
                            Cell { align: Align::End, mono: true,
                                {check.throughput.as_ref().and_then(|t| t.variability_pct).map_or_else(|| "—".to_owned(), |v| format!("{v:.0}%"))}
                            }
                            Cell { align: Align::End, mono: true,
                                {check.throughput.as_ref().and_then(|t| t.stall_count).map_or_else(|| "—".to_owned(), |v| v.to_string())}
                            }
                            Cell { muted: true,
                                {throughput_route_key(check.throughput.as_ref().and_then(|t| t.route), true).map_or_else(|| "—".to_owned(), |k| t!(k))}
                            }
                            Cell {
                                // A server whose budget left requests out says which on hover.
                                Badge { tone: batch_label(&check).tone(), title: check.deferred.clone(),
                                    {t!(batch_label(&check).key())}
                                }
                            }
                        }
                    }
                }
            }
            if !result.errors.is_empty() {
                p { class: "srv-detail-note is-alert", {t!("ui.servers.batch.errors", count = result.errors.len())} }
            }
            if deferred > 0 {
                p { class: "srv-detail-note", {t!("ui.servers.batch.deferred", count = deferred)} }
            }
        }
    }
}
