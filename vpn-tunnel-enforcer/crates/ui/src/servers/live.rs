//! [`LiveCheckPanel`]: the live check of one server — mode, run / cancel, progress, the history
//! drawer and the report. The run is a task of this panel: changing the server, closing the
//! dialog or «Отмена» drops it, which aborts the probe; an aborted check is never stored, so
//! there is no partial single result. Progress comes on the run's own channel (no request ids,
//! no sequence fences); a history reload never touches a running check (L-7).
use std::rc::Rc;

use dioxus::core::Task;
use dioxus::prelude::*;
use tokio::sync::mpsc;
use vpnte_base::ErrorKind;

use super::actions::Actions;
use super::api::ServersApi;
use super::live_model::{LiveCheck, LiveMode, LiveProgress};
use super::live_present::{
    Dot, findings_tone, format_mbps, history_merge, progress_step, throughput_badge,
};
use super::present::local_stamp;
use super::report::LiveReport;
use crate::lang::{LANG, tr};
use crate::t;
use crate::widgets::{Badge, Button, ButtonKind, Segmented, Tone, UiError};

/// History load state (typed: the old panel branched on a Russian sentinel string, L-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum History {
    Loading,
    Ready,
    Failed,
}

/// State and actions of one panel (`Copy`; its tasks belong to the scope that created it).
#[derive(Clone, Copy, PartialEq)]
pub(crate) struct LiveCtl {
    pub mode: Signal<LiveMode>,
    pub run: Signal<Option<Task>>,
    pub progress: Signal<Option<LiveProgress>>,
    pub result: Signal<Option<LiveCheck>>,
    pub history: Signal<Vec<LiveCheck>>,
    pub history_state: Signal<History>,
    pub error: Signal<Option<UiError>>,
    pub show_history: Signal<bool>,
}

impl LiveCtl {
    /// Creates the state in the calling component (inside `use_hook`).
    pub fn new() -> Self {
        Self {
            mode: Signal::new(LiveMode::Basic),
            run: Signal::new(None),
            progress: Signal::new(None),
            result: Signal::new(None),
            history: Signal::new(Vec::new()),
            history_state: Signal::new(History::Loading),
            error: Signal::new(None),
            show_history: Signal::new(false),
        }
    }

    /// (Re)loads the stored receipts; never touches a running check (L-7). The newest receipt
    /// is shown until a run replaces it.
    pub fn load_history(&self, api: Rc<dyn ServersApi>, id: String) {
        let Self {
            mut result,
            mut history,
            mut history_state,
            ..
        } = *self;
        history_state.set(History::Loading);
        spawn(async move {
            match api.live_history(&id).await {
                Ok(items) => {
                    if result.peek().is_none() {
                        result.set(items.first().cloned());
                    }
                    history.set(items);
                    history_state.set(History::Ready);
                }
                Err(err) if err.kind == ErrorKind::Cancelled => {}
                Err(_) => history_state.set(History::Failed),
            }
        });
    }

    /// Starts a check in the chosen mode unless one runs.
    pub fn start(&self, api: Rc<dyn ServersApi>, id: String) {
        let Self {
            mut run,
            mut progress,
            mut result,
            mut history,
            mut error,
            mode,
            ..
        } = *self;
        if run.peek().is_some() {
            return;
        }
        let chosen = *mode.peek();
        error.set(None);
        progress.set(None);
        let task = spawn(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let check = api.live_check(&id, chosen, tx);
            futures_util::pin_mut!(check);
            let outcome = loop {
                tokio::select! {
                    outcome = &mut check => break outcome,
                    Some(p) = rx.recv() => progress.set(Some(p)),
                }
            };
            run.set(None);
            progress.set(None);
            match outcome {
                Ok(fresh) => {
                    let merged = history_merge(&history.peek(), fresh.clone());
                    history.set(merged);
                    result.set(Some(fresh));
                }
                Err(err) if err.kind == ErrorKind::Cancelled => {}
                Err(err) => error.set(Some(UiError::from(err))),
            }
        });
        run.set(Some(task));
    }

    /// «Отмена»: the panel is idle at once; dropping the run aborts the probe (nothing stored).
    pub fn cancel(&self) {
        let Self {
            mut run,
            mut progress,
            ..
        } = *self;
        if let Some(task) = run.take() {
            task.cancel();
        }
        progress.set(None);
    }
}

#[component]
pub(crate) fn LiveCheckPanel(id: String) -> Element {
    let actions = use_context::<Actions>();
    let ctl = use_hook(LiveCtl::new);
    use_hook({
        let (api, id) = (actions.api.clone(), id.clone());
        move || ctl.load_history(api, id)
    });
    let LiveCtl {
        mut mode,
        progress,
        mut result,
        history_state,
        error,
        mut show_history,
        ..
    } = ctl;
    let running = ctl.run.read().is_some();
    let items = ctl.history.read().clone();
    let current = result.read().clone();
    let modes = vec![
        (LiveMode::Basic, t!("ui.servers.live.modeBasic")),
        (LiveMode::Extended, t!("ui.servers.live.modeExtended")),
    ];
    let lang = *LANG.read();
    let (api_start, id_start) = (actions.api.clone(), id.clone());
    let start_click = move || ctl.start(api_start.clone(), id_start.clone());
    let (api_retry, id_retry) = (actions.api.clone(), id.clone());
    let retry = move || ctl.load_history(api_retry.clone(), id_retry.clone());
    let cancel = move || ctl.cancel();
    rsx! {
        section { class: "srv-live", aria_busy: running.then_some("true"),
            header { class: "srv-live-head",
                h3 { class: "srv-live-title",
                    span { class: "srv-live-mark", class: if running { "is-running" } }
                    {t!("ui.servers.live.title")}
                }
                Segmented {
                    options: modes,
                    value: mode(),
                    on_change: move |m| mode.set(m),
                    label: t!("ui.servers.live.modeLabel"),
                    disabled: running,
                }
                if running {
                    Button { kind: ButtonKind::Danger, small: true, onclick: move |_| cancel(), {t!("common.cancel")} }
                } else {
                    Button { small: true, onclick: move |_| start_click(), {t!("ui.servers.live.run")} }
                }
                if !items.is_empty() {
                    Button {
                        kind: ButtonKind::Ghost,
                        small: true,
                        title: t!("ui.servers.live.historyTitle"),
                        onclick: move |_| show_history.toggle(),
                        {t!("ui.servers.live.historyButton", count = items.len())}
                    }
                }
            }
            if history_state() == History::Failed {
                div { class: "srv-strip is-fail srv-live-alert", role: "alert",
                    span { {t!("ui.servers.live.historyFailed")} }
                    Button { kind: ButtonKind::Link, small: true, onclick: move |_| retry(),
                        {t!("ui.servers.live.historyRetry")}
                    }
                }
            }
            if let Some(err) = error() {
                p { class: "srv-strip is-fail", role: "alert", {tr(&err.msg)} }
            }
            if running {
                Progress { progress: progress() }
            }
            if mode() == LiveMode::Extended {
                p { class: "srv-detail-note srv-live-warning", {t!("ui.servers.live.extendedWarning")} }
            }
            if show_history() && !items.is_empty() {
                div { class: "srv-history",
                    p { class: "srv-history-head",
                        span { class: "swiss-label", {t!("ui.servers.live.recent")} }
                        span { class: "swiss-mono", {t!("ui.servers.live.records", count = items.len())} }
                    }
                    div { class: "srv-history-list",
                        for item in items {
                            HistoryEntry {
                                key: "{item.id}",
                                selected: current.as_ref().is_some_and(|c| c.id == item.id),
                                stamp: local_stamp(item.started_at, lang),
                                on_pick: move |picked: LiveCheck| result.set(Some(picked)),
                                check: item,
                            }
                        }
                    }
                }
            }
            if let Some(check) = current {
                LiveReport { check }
            }
        }
    }
}

/// Stage caption, «Этап i из n • t с» and the bar (never under 5 %); before the first event
/// «Подготовка проверки…».
#[component]
fn Progress(progress: Option<LiveProgress>) -> Element {
    let Some(p) = progress else {
        return rsx! {
            p { class: "srv-live-progress", role: "status", {t!("liveCheck.preparing")} }
        };
    };
    let (step, total, pct) = progress_step(&p);
    let seconds = format!("{:.1}", f64::from(p.elapsed_ms) / 1000.0);
    let stage = t!(&format!("ui.servers.stage.{}", p.stage.key()));
    rsx! {
        div { class: "srv-live-progress", role: "status",
            div { class: "srv-live-progress-line",
                span { "{stage}" }
                span { class: "swiss-mono", {t!("ui.servers.live.step", step = step, total = total, seconds = seconds)} }
            }
            div { class: "srv-live-bar", div { class: "srv-live-bar-fill", style: "width:{pct:.1}%" } }
        }
    }
}

/// One stored receipt in the history drawer (a real button, `aria-pressed` = shown, L-5).
#[component]
fn HistoryEntry(
    check: LiveCheck,
    selected: bool,
    stamp: String,
    on_pick: EventHandler<LiveCheck>,
) -> Element {
    let dot = Dot::from(check.reachability.status);
    let mode = match check.mode {
        LiveMode::Basic => t!("ui.servers.live.modeBasic"),
        LiveMode::Extended => t!("ui.servers.live.modeExtended"),
    };
    let throughput = check.throughput.clone();
    let findings = check.findings.len();
    let findings_mark = findings_tone(&check.findings);
    let diff = check
        .infrastructure
        .as_ref()
        .is_some_and(|i| i.changes.any());
    let latency = check.latency.as_ref().map(|l| l.avg);
    let first_a = check.dns.a.first().cloned();
    let picked = check.clone();
    rsx! {
        button {
            r#type: "button",
            class: "srv-history-item",
            class: if selected { "is-selected" },
            aria_pressed: if selected { "true" } else { "false" },
            onclick: move |_| on_pick.call(picked.clone()),
            span { class: "srv-dot is-{dot.name()}", aria_hidden: "true" }
            span { class: "srv-history-stamp swiss-mono", "{stamp}" }
            Badge { tone: if check.mode == LiveMode::Extended { Tone::Ok } else { Tone::Neutral }, "{mode}" }
            if let Some(a) = first_a {
                span { class: "swiss-mono srv-history-ip", "{a}" }
            }
            if let Some(t) = throughput {
                span { class: "swiss-mono", {format_mbps(t.median_mbps)} }
                if let Some(v) = t.variability_pct {
                    span { class: "swiss-mono srv-history-muted", title: t!("ui.servers.live.spreadTitle"), "±{v:.0}%" }
                }
                Badge { tone: throughput_badge(t.status).1, {throughput_badge(t.status).0} }
            }
            if let Some(ms) = latency {
                span { class: "swiss-mono", {t!("ui.servers.row.ms", ms = ms)} }
            }
            if diff {
                Badge { tone: Tone::Warn, title: t!("ui.servers.live.diffTitle"), "Diff" }
            }
            Badge { tone: findings_mark, {t!("ui.servers.live.findingsCount", count = findings)} }
        }
    }
}
