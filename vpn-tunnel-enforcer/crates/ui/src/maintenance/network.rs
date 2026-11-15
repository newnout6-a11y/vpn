//! «Режим сети»: the network-mode check for RU networks — one button, the stages (DNS, TCP,
//! TLS, bytes after 16 KB, UDP, the user's servers, DNS capture) with their marks, the plain
//! verdict and what helps. The backend also runs the check at start and after a network
//! change, so the latest result of the current network is usually already here. Next to it,
//! «Проверить все серверы» runs the Servers page's engine check over every group (RU item 6:
//! the list-wide check through the engine, each key behind its server's handshake budget).
use std::rc::Rc;

use dioxus::prelude::*;

use vpnte_base::{AppResult, Msg};

use super::MaintenanceApi;
use super::model::{MaintenanceState, NetCheckView, NetStepKind, NetStepView};
use super::view::{Mark, fmt_time};
use crate::lang::tr;
use crate::servers::{HealthReport, ServersApi};
use crate::t;
use crate::widgets::{Button, ButtonKind, Panel, Tone, use_job};

/// Caption of a stage.
fn step_label(kind: NetStepKind) -> String {
    match kind {
        NetStepKind::Dns => t!("ui.maintenance.network.step.dns"),
        NetStepKind::Tcp => t!("ui.maintenance.network.step.tcp"),
        NetStepKind::Tls => t!("ui.maintenance.network.step.tls"),
        NetStepKind::Bytes => t!("ui.maintenance.network.step.bytes"),
        NetStepKind::Udp => t!("ui.maintenance.network.step.udp"),
        NetStepKind::Servers => t!("ui.maintenance.network.step.servers"),
        NetStepKind::DnsCapture => t!("ui.maintenance.network.step.dnsCapture"),
    }
}

/// The panel; `state` is the page's pushed snapshot.
#[component]
pub(crate) fn NetworkPanel(state: Signal<MaintenanceState>) -> Element {
    let api = use_context::<Rc<dyn MaintenanceApi>>();
    let job = use_job::<NetCheckView>();
    let network = state.read().network.clone();
    let running = network.running || job.running();
    let failure = match job.last() {
        Some(Err(err)) => Some(tr(&err.msg)),
        _ => None,
    };
    let check = move |_| {
        let api = api.clone();
        job.start(move |token| async move { api.check_network(token).await });
    };
    rsx! {
        Panel { title: t!("ui.maintenance.network.title"), id: "mt-network",
            p { class: "mt-meta", {t!("ui.maintenance.network.subtitle")} }
            div { class: "mt-actions",
                Button {
                    kind: ButtonKind::Ghost,
                    busy: running,
                    disabled: running,
                    onclick: check,
                    if running {
                        {t!("ui.maintenance.network.checking")}
                    } else {
                        {t!("ui.maintenance.network.check")}
                    }
                }
            }
            if let Some(msg) = failure {
                p { class: "mt-outcome", role: "status", "data-verdict": "fail", "{msg}" }
            }
            ServersCheck {}
            match network.last {
                Some(last) => rsx! {
                    CheckResult { check: last }
                },
                None => rsx! {
                    p { class: "mt-meta", {t!("ui.maintenance.network.never")} }
                },
            }
        }
    }
}

/// The verdict, the advice and the stage lines of one check.
#[component]
fn CheckResult(check: NetCheckView) -> Element {
    // No internet or nothing proven never takes the success colour (review b7).
    let tone = Tone::from(check.verdict).name();
    rsx! {
        div { class: "mt-leak", role: "status", "data-tone": tone,
            p { class: "mt-leak-headline", {tr(&check.headline)} }
            for (i , advice) in check.advice.iter().enumerate() {
                p { key: "{i}", class: "mt-leak-note", {tr(advice)} }
            }
            p { class: "mt-meta swiss-mono",
                {t!("ui.maintenance.network.checkedAt", time = fmt_time(check.at))}
            }
            if check.via_session {
                p { class: "mt-meta", {t!("ui.maintenance.network.viaSession")} }
            }
            ul { class: "mt-lines",
                for step in check.steps.iter() {
                    StepLine { key: "{step.kind:?}", step: step.clone() }
                }
            }
        }
    }
}

#[component]
fn StepLine(step: NetStepView) -> Element {
    rsx! {
        li { class: "mt-line mt-probe", "data-state": Tone::from(step.verdict).name(),
            Mark { verdict: Some(step.verdict) }
            div {
                p {
                    span { class: "mt-probe-alias", {step_label(step.kind)} }
                    " "
                    span { class: "mt-probe-result", {tr(&step.detail)} }
                }
            }
        }
    }
}

/// What the list-wide check found, summed over the groups.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct ListCheck {
    pub(crate) online: usize,
    pub(crate) offline: usize,
    pub(crate) deferred: u32,
    /// Groups whose check failed as a whole (an engine missing or blocked, another check of the
    /// group running, every key postponed), with the first reason.
    pub(crate) failed: usize,
    pub(crate) reason: Option<Msg>,
}

/// Group check refusals that only mean "nothing to check here": an empty group, or one deleted
/// since the list was read. The UI sees the backend's error by its message key only.
const NOTHING_TO_CHECK: [&str; 2] = ["probes.keyHealth.groupEmpty", "servers.group.notFound"];

impl ListCheck {
    /// Adds one group's outcome; a failed group is counted and shown, never dropped.
    pub(crate) fn add(&mut self, outcome: AppResult<HealthReport>) {
        match outcome {
            Ok(report) => {
                let online = report.results.iter().filter(|(_, h)| h.online).count();
                self.online += online;
                self.offline += report.results.len() - online;
                self.deferred += report.not_checked;
            }
            Err(err) if NOTHING_TO_CHECK.contains(&err.user_msg().key.as_ref()) => {}
            Err(err) => {
                self.failed += 1;
                self.reason.get_or_insert_with(|| err.user_msg());
            }
        }
    }
}

/// «Проверить все серверы»: every group through the per-group engine check, one after the
/// other (shown only where the app provides the server list).
#[component]
fn ServersCheck() -> Element {
    let provided = try_use_context::<Rc<dyn ServersApi>>().is_some();
    rsx! {
        if provided {
            ServersCheckShown {}
        }
    }
}

#[component]
fn ServersCheckShown() -> Element {
    let api = use_context::<Rc<dyn ServersApi>>();
    let job = use_job::<ListCheck>();
    let running = job.running();
    let check = move |_| {
        let api = api.clone();
        job.start(move |token| async move {
            let groups: Vec<String> = api
                .state()
                .borrow()
                .groups
                .iter()
                .map(|g| g.id.clone())
                .collect();
            let mut sum = ListCheck::default();
            for id in groups {
                if token.is_cancelled() {
                    return Err(vpnte_base::AppError::cancelled());
                }
                sum.add(api.check_group_health(&id).await);
            }
            Ok(sum)
        });
    };
    let (summary, failure) = match job.last() {
        Some(Ok(sum)) => (
            Some(t!(
                "ui.maintenance.network.servers.summary",
                online = sum.online,
                offline = sum.offline,
                deferred = sum.deferred
            )),
            sum.reason.as_ref().map(|reason| {
                t!(
                    "ui.maintenance.network.servers.failed",
                    count = sum.failed,
                    reason = tr(reason)
                )
            }),
        ),
        Some(Err(err)) => (None, Some(tr(&err.msg))),
        None => (None, None),
    };
    rsx! {
        div { class: "mt-actions",
            Button {
                kind: ButtonKind::Ghost,
                busy: running,
                disabled: running,
                title: t!("ui.maintenance.network.servers.hint"),
                onclick: check,
                if running {
                    {t!("ui.maintenance.network.servers.checking")}
                } else {
                    {t!("ui.maintenance.network.servers.check")}
                }
            }
        }
        if let Some(text) = summary {
            p { class: "mt-meta", role: "status", "{text}" }
        }
        if let Some(text) = failure {
            p { class: "mt-outcome", role: "status", "data-verdict": "fail", "{text}" }
        }
    }
}
