//! Markup of the state, steps, results and leak result panels.
use dioxus::prelude::*;
use vpnte_base::types::{UnixMs, Verdict};

use super::ctl::{Controller, render};
use super::model::{
    AdapterProbe, DiagCategory, DiagItem, LeakTestView, LeakVerdict, ProbeReach, StepState,
    SystemReport,
};
use super::rules::{self, Outcome};
use crate::lang::tr;
use crate::t;
use crate::widgets::{Badge, Button, ButtonKind, Panel, ProgressBar, Tone};

/// Local wall-clock time of a timestamp («14:03:27», with the date when not today).
pub(crate) fn fmt_time(ms: UnixMs) -> String {
    let Ok(ts) = jiff::Timestamp::from_millisecond(ms) else {
        return "—".into();
    };
    let tz = jiff::tz::TimeZone::system();
    let at = ts.to_zoned(tz.clone());
    let today = jiff::Timestamp::now().to_zoned(tz).date();
    if at.date() == today {
        at.strftime("%H:%M:%S").to_string()
    } else {
        at.strftime("%d.%m.%Y %H:%M").to_string()
    }
}

/// Badge text of a verdict.
pub(crate) fn verdict_label(v: Verdict) -> String {
    match v {
        Verdict::Ok => t!("ui.maintenance.verdict.ok"),
        Verdict::Warn => t!("ui.maintenance.verdict.warn"),
        Verdict::Fail => t!("ui.maintenance.verdict.fail"),
        Verdict::NotChecked => t!("ui.maintenance.verdict.notChecked"),
    }
}

/// A square status mark; `None` = informational, `running` = a step in progress.
#[component]
pub(crate) fn Mark(verdict: Option<Verdict>, #[props(default)] running: bool) -> Element {
    let name = match (running, verdict) {
        (true, _) => "running",
        (_, Some(v)) => Tone::from(v).name(),
        (_, None) => "info",
    };
    rsx! {
        span { class: "mt-mark", "data-state": name, aria_hidden: "true" }
    }
}

/// A result line (`role=status`), tinted by its verdict.
#[component]
pub(crate) fn OutcomeLine(outcome: Option<Outcome>) -> Element {
    let Some(outcome) = outcome else {
        return rsx! {
            p { class: "mt-outcome is-empty", role: "status" }
        };
    };
    rsx! {
        p {
            class: "mt-outcome",
            role: "status",
            "data-verdict": Tone::from(outcome.verdict).name(),
            {render(&outcome)}
        }
    }
}

/// «Состояние»: the summary badge, the four actions, export progress and the result line.
#[component]
pub(crate) fn StatePanel(ctl: Controller) -> Element {
    let state = ctl.state.read();
    let report = ctl.report.read();
    let summary = rules::health_summary(state.protection.as_ref(), report.as_ref());
    let busy = ctl.busy();
    let export = state.export.clone();
    let exporting = ctl.export.running() || export.running;
    rsx! {
        Panel {
            title: t!("ui.maintenance.state.title"),
            id: "mt-state",
            actions: rsx! {
                Badge { tone: Tone::from(summary), "{verdict_label(summary)}" }
            },
            div { class: "mt-actions",
                Button {
                    kind: ButtonKind::Ghost,
                    busy: ctl.health.running(),
                    disabled: busy,
                    onclick: move |_| ctl.health_check(),
                    {t!("ui.maintenance.actions.check")}
                }
                Button {
                    busy: ctl.repair.running() || state.repair.running,
                    disabled: busy,
                    onclick: move |_| ctl.repair(),
                    {t!("ui.maintenance.actions.repair")}
                }
                Button {
                    kind: ButtonKind::Ghost,
                    busy: ctl.protect.running(),
                    disabled: busy,
                    onclick: move |_| ctl.protection_test(),
                    {t!("ui.maintenance.actions.protectionTest")}
                }
                Button {
                    kind: ButtonKind::Link,
                    busy: exporting,
                    disabled: busy,
                    title: t!("ui.maintenance.actions.zipTitle"),
                    onclick: move |_| ctl.export_zip(),
                    {t!("ui.maintenance.actions.zip")}
                }
            }
            if exporting {
                div { class: "mt-export",
                    ProgressBar {
                        value: export.progress,
                        label: t!("ui.maintenance.export.progress"),
                        show_value: true,
                    }
                    if let Some(stage) = &export.stage {
                        span { class: "mt-export-stage swiss-mono", {tr(stage)} }
                    }
                }
            }
            OutcomeLine { outcome: ctl.outcome.read().clone() }
        }
    }
}

/// «Что делает авто-починка»: a status readout, not controls (no row looks pressable).
#[component]
pub(crate) fn StepsPanel(ctl: Controller) -> Element {
    let steps = ctl.state.read().repair.steps.clone();
    rsx! {
        Panel { title: t!("ui.maintenance.steps.title"), id: "mt-steps",
            ul { class: "mt-steps",
                for (step , state) in steps {
                    li { key: "{step.id()}", class: "mt-step", "data-step": step.id(),
                        StepMark { state: state.clone() }
                        div { class: "mt-step-text",
                            p { class: "mt-step-label", {t!(step.label_key())} }
                            StepDetail { state }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn StepMark(state: StepState) -> Element {
    match state {
        StepState::Running => rsx! {
            Mark { verdict: None, running: true }
        },
        StepState::Done(o) => rsx! {
            Mark { verdict: Some(rules::step_status(&o)) }
        },
        StepState::Idle | StepState::Pending => rsx! {
            Mark { verdict: None }
        },
    }
}

#[component]
fn StepDetail(state: StepState) -> Element {
    let (text, tone) = match &state {
        StepState::Idle => return rsx! {},
        StepState::Pending => (t!("ui.maintenance.steps.pending"), "info"),
        StepState::Running => (t!("ui.maintenance.steps.running"), "running"),
        StepState::Done(o) => (
            tr(&rules::step_detail(o)),
            Tone::from(rules::step_status(o)).name(),
        ),
    };
    rsx! {
        p { class: "mt-step-detail", "data-state": tone, "{text}" }
    }
}

/// «Результаты проверки»: the protection read-back, the important report items and the whole
/// report folded away.
#[component]
pub(crate) fn ResultsPanel(ctl: Controller) -> Element {
    let state = ctl.state.read();
    let report = ctl.report.read().clone();
    let protection = state.protection.clone();
    if protection.is_none() && report.is_none() {
        return rsx! {};
    }
    rsx! {
        Panel { title: t!("ui.maintenance.results.title"), id: "mt-results",
            if let Some(p) = protection {
                div { class: "mt-block", "data-block": "protection",
                    div { class: "mt-block-head",
                        span { class: "mt-block-title", {t!("ui.maintenance.protection.title")} }
                        Badge { tone: Tone::from(rules::protection_verdict(&p)),
                            "{verdict_label(rules::protection_verdict(&p))}"
                        }
                    }
                    ul { class: "mt-lines",
                        for (i , line) in rules::protection_lines(&p).into_iter().enumerate() {
                            li { key: "{i}", class: "mt-line",
                                Mark { verdict: Some(line.verdict) }
                                span { {tr(&line.text)} }
                            }
                        }
                    }
                    if let Some(at) = p.last_verified {
                        p { class: "mt-meta swiss-mono",
                            {t!("ui.maintenance.protection.verified", time = fmt_time(at))}
                        }
                    }
                }
            }
            if let Some(report) = report {
                ReportBlock { report }
            }
        }
    }
}

#[component]
fn ReportBlock(report: SystemReport) -> Element {
    let important: Vec<DiagItem> = rules::important_items(&report)
        .into_iter()
        .cloned()
        .collect();
    let total = report.items.len();
    rsx! {
        div { class: "mt-block", "data-block": "report",
            div { class: "mt-block-head",
                span { class: "mt-block-title", {t!("ui.maintenance.results.important")} }
                span { class: "mt-meta swiss-mono",
                    {t!("ui.maintenance.results.ranAt", time = fmt_time(report.ran_at))}
                }
            }
            if important.is_empty() {
                p { class: "mt-quiet", {t!("ui.maintenance.results.nothingCritical")} }
            } else {
                ul { class: "mt-items",
                    for item in important {
                        ItemRow { key: "{item.id}", item }
                    }
                }
            }
            details { class: "mt-report",
                summary { class: "mt-report-toggle",
                    {t!("ui.maintenance.results.fullReport", count = total)}
                }
                for category in DiagCategory::ALL {
                    CategoryGroup { category, report: report.clone() }
                }
            }
        }
    }
}

#[component]
fn CategoryGroup(category: DiagCategory, report: SystemReport) -> Element {
    let items: Vec<DiagItem> = report
        .items
        .into_iter()
        .filter(|i| i.category == category)
        .collect();
    if items.is_empty() {
        return rsx! {};
    }
    rsx! {
        section { class: "mt-group", "data-category": category.label_key(),
            h3 { class: "mt-group-title", {t!(category.label_key())} }
            ul { class: "mt-items",
                for item in items {
                    ItemRow { key: "{item.id}", item }
                }
            }
        }
    }
}

/// One report item: mark, label, value; notes and technical rows under it.
#[component]
fn ItemRow(item: DiagItem) -> Element {
    let tone = item.verdict.map_or("info", |v| Tone::from(v).name());
    rsx! {
        li { class: "mt-item", "data-id": "{item.id}", "data-state": tone,
            div { class: "mt-item-head",
                Mark { verdict: item.verdict }
                span { class: "mt-item-label", {tr(&item.label)} }
                span { class: "mt-item-value swiss-mono", {tr(&item.value)} }
            }
            for (i , note) in item.notes.iter().enumerate() {
                p { key: "n{i}", class: "mt-item-note", {tr(note)} }
            }
            if !item.details.is_empty() {
                pre { class: "mt-item-details swiss-mono", {item.details.join("\n")} }
            }
        }
    }
}

/// «Результат проверки утечек» (DiagnosticsCard's panel, re-homed): the verdict with its
/// evidence, never a stored summary; an inconclusive run never takes the success colour.
#[component]
pub(crate) fn LeakPanel(test: LeakTestView) -> Element {
    let tone = match test.verdict {
        LeakVerdict::Leak => Tone::Fail,
        LeakVerdict::PossibleLeak => Tone::Warn,
        LeakVerdict::Ok => Tone::Ok,
        LeakVerdict::Inconclusive => Tone::Unknown,
    };
    let label = t!("ui.maintenance.leak.title");
    let tun_ip = test.tun_ip.clone().unwrap_or_else(|| "—".into());
    rsx! {
        Panel { title: label.clone(), id: "mt-leak",
            div {
                class: "mt-leak",
                role: "status",
                aria_label: "{label}",
                "data-verdict": test.verdict.name(),
                "data-tone": tone.name(),
                p { class: "mt-leak-headline", {tr(&test.headline)} }
                if let Some(d) = &test.disagreement {
                    p { class: "mt-leak-note", {tr(d)} }
                }
                p { class: "mt-meta swiss-mono",
                    {t!("ui.maintenance.leak.checkedAt", time = fmt_time(test.at))}
                }
                p { class: "mt-meta swiss-mono", {t!("ui.maintenance.leak.tunIp", ip = tun_ip)} }
                ul { class: "mt-lines",
                    for (i , probe) in test.adapters.iter().enumerate() {
                        ProbeRow { key: "{i}", probe: probe.clone() }
                    }
                }
            }
        }
    }
}

#[component]
fn ProbeRow(probe: AdapterProbe) -> Element {
    let local = probe
        .local
        .clone()
        .unwrap_or_else(|| t!("ui.maintenance.leak.noIp"));
    let (verdict, text) = match &probe.reach {
        ProbeReach::Reached { public_ip } => (
            Verdict::Fail,
            t!("ui.maintenance.leak.reached", ip = public_ip.clone()),
        ),
        ProbeReach::NotReached { curl_exit } => (
            Verdict::Ok,
            t!("ui.maintenance.leak.notReached", code = curl_exit),
        ),
        ProbeReach::Unknown { curl_exit, why } => (
            Verdict::NotChecked,
            t!(
                "ui.maintenance.leak.unknown",
                code = curl_exit.map_or_else(|| "?".to_owned(), |c| c.to_string()),
                why = tr(why)
            ),
        ),
    };
    rsx! {
        li { class: "mt-line mt-probe", "data-state": Tone::from(verdict).name(),
            Mark { verdict: Some(verdict) }
            div {
                p {
                    span { class: "mt-probe-alias", "{probe.alias} ({local})" }
                    " "
                    span { class: "mt-probe-result", "{text}" }
                }
                if let Some(tail) = &probe.stderr_tail {
                    pre { class: "mt-item-details swiss-mono", "{tail}" }
                }
            }
        }
    }
}
