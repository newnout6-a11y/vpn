//! A key check in numbers (p-check-live): each row's line says where its key is as it happens
//! (queued, the countdown to its next connection to the server under the app's own pacing, the
//! engine starting, the request, the answer or the failure), and a strip sums up the run with
//! «Отменить» while it runs. Calm mono text; red only for a key that failed. Countdowns read the
//! clock when they render (a2); the strip announces its totals, never the countdown (b6).
use std::collections::HashMap;

use dioxus::prelude::*;
use vpnte_base::types::{UnixMs, now_ms};

use super::actions::Actions;
use super::check_model::{CheckAnswer, CheckStage};
use super::model::{KeyHealthReason, ServersView};
use super::present::engine_name;
use super::state::{RowRt, RunKey, RunState};
use crate::t;
use crate::widgets::{Button, ButtonKind};

/// The numbers of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Totals {
    /// Keys in the run.
    pub total: u32,
    /// Keys with a result.
    pub done: u32,
    /// Keys waiting for their server name, and the longest wait left (seconds).
    pub waiting: u32,
    pub wait_secs: u64,
    /// Results that are failures of the key.
    pub failed: u32,
    /// Keys the run ended without.
    pub not_checked: u32,
}

/// The tag of the key each row of the list holds now.
pub(crate) fn row_tags(view: &ServersView) -> HashMap<&str, u64> {
    (view.servers.iter())
        .map(|s| (s.id.as_str(), s.key_tag))
        .collect()
}

/// Counts the rows of `run` at `now`: only rows still in the list (`tags`) that hold the key the
/// check was about (b2).
pub(crate) fn totals(
    rows: &HashMap<String, RowRt>,
    tags: &HashMap<&str, u64>,
    run: &RunKey,
    now: UnixMs,
) -> Totals {
    let mut t = Totals::default();
    let checks = rows.iter().filter_map(|(id, r)| {
        let check = r.check.as_ref()?;
        (check.run == *run && tags.get(id.as_str()) == Some(&check.tag)).then_some(check)
    });
    for check in checks {
        t.total += 1;
        match &check.stage {
            CheckStage::Done(answer) => {
                t.done += 1;
                t.failed += u32::from(answer.is_failure());
            }
            CheckStage::NotChecked => t.not_checked += 1,
            CheckStage::Waiting { until } => {
                t.waiting += 1;
                t.wait_secs = t.wait_secs.max(secs_left(*until, now));
            }
            _ => {}
        }
    }
    t
}

/// Whole seconds until `until`, at least one while the wait lasts (the next stage follows the
/// end of a wait within milliseconds; «через 0 с» would read as stuck).
fn secs_left(until: UnixMs, now: UnixMs) -> u64 {
    let left = u64::try_from(until.saturating_sub(now)).unwrap_or(0);
    left.div_ceil(1000).max(1)
}

/// The strip's line in its parts: what the live region announces as results land (`totals`,
/// then `rest` after the countdown) and the per-second countdown kept out of it (b6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StripLine {
    pub totals: String,
    pub left: Option<String>,
    pub rest: String,
}

#[cfg(test)]
impl StripLine {
    /// The line as it reads.
    pub(crate) fn text(&self) -> String {
        let left = self.left.as_deref().unwrap_or_default();
        format!("{}{left}{}", self.totals, self.rest)
    }
}

/// The strip's line: the progress while the run goes on, its sum once it is over.
pub(crate) fn strip_line(t: &Totals, state: RunState) -> StripLine {
    let (done, total) = (t.done.to_string(), t.total.to_string());
    let mut totals = match state {
        RunState::Ended { stopped: true } => {
            t!("ui.servers.check.stopped", done = done, total = total)
        }
        _ => t!("ui.servers.check.totals", done = done, total = total),
    };
    let mut left = None;
    if t.waiting > 0 && state.running() {
        totals.push_str(" · ");
        totals.push_str(&t!("ui.servers.check.waitingTotal", count = t.waiting));
        left = Some(t!("ui.servers.check.waitLeft", seconds = t.wait_secs));
    }
    let mut rest = String::new();
    if t.failed > 0 {
        rest.push_str(" · ");
        rest.push_str(&t!("ui.servers.check.failedTotal", count = t.failed));
    }
    if t.not_checked > 0 && state == (RunState::Ended { stopped: false }) {
        rest.push_str(" · ");
        rest.push_str(&t!(
            "ui.servers.check.notCheckedTotal",
            count = t.not_checked
        ));
    }
    StripLine { totals, left, rest }
}

/// A row's line for `stage` at `now`, and whether it is a failure.
pub(crate) fn stage_text(stage: &CheckStage, now: UnixMs) -> (String, bool) {
    let text = match stage {
        CheckStage::Queued => t!("ui.servers.check.queued"),
        CheckStage::Waiting { until } => {
            t!("ui.servers.check.waiting", seconds = secs_left(*until, now))
        }
        CheckStage::Starting { engine } => {
            t!("ui.servers.check.starting", engine = engine_name(*engine))
        }
        CheckStage::Requesting {
            engine,
            engine_ms,
            since,
        } => request_text(*engine, *engine_ms, now.saturating_sub(*since)),
        // The request is over: its time stands while the engine stops (b4).
        CheckStage::Asked {
            engine,
            engine_ms,
            asked_ms,
        } => request_text(*engine, *engine_ms, i64::from(*asked_ms)),
        CheckStage::Done(answer) => return (answer_text(answer), answer.is_failure()),
        CheckStage::NotChecked => t!("ui.servers.check.notChecked"),
    };
    (text, false)
}

/// The engine's start time and how long the handshake and the test request took (`ms`).
fn request_text(engine: vpnte_base::types::Engine, engine_ms: u32, ms: i64) -> String {
    let engine = engine_name(engine);
    match ms.max(0) / 1000 {
        0 => t!(
            "ui.servers.check.requesting",
            engine = engine,
            ms = engine_ms
        ),
        s => t!(
            "ui.servers.check.requestingFor",
            engine = engine,
            ms = engine_ms,
            seconds = s
        ),
    }
}

/// What came back, in plain words with its numbers.
fn answer_text(answer: &CheckAnswer) -> String {
    match answer {
        CheckAnswer::Http { status, ms } => t!("ui.servers.check.http", status = status, ms = ms),
        CheckAnswer::Stalled { bytes } => {
            t!("ui.servers.check.stalled", kb = bytes.div_ceil(1024))
        }
        CheckAnswer::Silent { ms } => {
            t!("ui.servers.check.silent", seconds = (*ms).div_ceil(1000))
        }
        CheckAnswer::Session => t!("ui.servers.check.session"),
        CheckAnswer::Failed(reason) => t!(failure_key(reason)),
    }
}

/// The short plain reason of a failure (the row's title keeps the long one).
fn failure_key(reason: &KeyHealthReason) -> &'static str {
    match reason {
        KeyHealthReason::HandshakeFailed
        | KeyHealthReason::TlsFailed
        | KeyHealthReason::Hy2TlsFailed
        | KeyHealthReason::Hy2HandshakeFailed => "ui.servers.check.failed.handshake",
        KeyHealthReason::AuthFailed | KeyHealthReason::Hy2AuthFailed => {
            "ui.servers.check.failed.rejected"
        }
        KeyHealthReason::ConfigFailed | KeyHealthReason::Hy2ConfigFailed => {
            "ui.servers.check.failed.config"
        }
        KeyHealthReason::NoOutbound => "ui.servers.check.failed.unreadable",
        KeyHealthReason::Hy2UdpBlocked => "ui.servers.check.failed.udp",
        KeyHealthReason::EngineSetting => "ui.servers.check.failed.engine",
        KeyHealthReason::Timeout => "ui.servers.check.failed.timeout",
        KeyHealthReason::Other(code) if code == "connection-refused" => {
            "ui.servers.check.failed.refused"
        }
        KeyHealthReason::Other(_) => "ui.servers.check.failed.other",
    }
}

/// A row's line in its last key check; it reads the clock only while it counts, when it
/// renders (the page's tick only makes it render again each second).
#[component]
pub(crate) fn CheckLine(stage: CheckStage) -> Element {
    let store = use_context::<Actions>().store;
    let counts = matches!(
        stage,
        CheckStage::Waiting { .. } | CheckStage::Requesting { .. }
    );
    let now = if counts {
        (store.tick)();
        now_ms()
    } else {
        0
    };
    let (text, failed) = stage_text(&stage, now);
    let title = match &stage {
        CheckStage::Waiting { .. } => Some(t!("ui.servers.check.waitingTitle")),
        CheckStage::Done(CheckAnswer::Failed(reason)) => {
            let key = format!("servers.health.reasons.{}", reason.code());
            Some(crate::lang::translate(&key, &[], Some(reason.code())))
        }
        _ => None,
    };
    rsx! {
        span {
            class: "srv-check-line swiss-mono",
            class: if failed { "is-fail" },
            "data-stage": stage_name(&stage),
            title,
            "{text}"
        }
    }
}

/// The stage's name for the markup (styles and tests).
fn stage_name(stage: &CheckStage) -> &'static str {
    match stage {
        CheckStage::Queued => "queued",
        CheckStage::Waiting { .. } => "waiting",
        CheckStage::Starting { .. } => "starting",
        CheckStage::Requesting { .. } => "requesting",
        CheckStage::Asked { .. } => "asked",
        CheckStage::Done(_) => "done",
        CheckStage::NotChecked => "not-checked",
    }
}

/// The sum of a key check, with «Отменить» while it runs; nothing before the run's first stage.
/// An ended run keeps the numbers it ended with. The totals are a live region; the countdown
/// in them is not (it would be read out every second, b6).
#[component]
pub(crate) fn CheckStrip(run: RunKey) -> Element {
    let actions = use_context::<Actions>();
    let store = actions.store;
    let Some((state, frozen)) = store.checks.read().get(&run).map(|c| (c.state, c.totals)) else {
        return rsx! {};
    };
    let numbers = frozen.unwrap_or_else(|| {
        (store.tick)();
        let view = store.view.read();
        totals(&store.rows.read(), &row_tags(&view), &run, now_ms())
    });
    let line = strip_line(&numbers, state);
    let stopping = state == RunState::Stopping;
    rsx! {
        div { class: "srv-check",
            span { class: "srv-check-totals swiss-mono", role: "status",
                "{line.totals}"
                if let Some(left) = &line.left {
                    span { aria_live: "off", "{left}" }
                }
                "{line.rest}"
            }
            if state.running() {
                Button {
                    kind: ButtonKind::Link,
                    small: true,
                    busy: stopping,
                    disabled: stopping,
                    title: t!("ui.servers.check.stopTitle"),
                    onclick: move |_| store.stop_run(&run),
                    {t!("ui.servers.check.stop")}
                }
            }
        }
    }
}
