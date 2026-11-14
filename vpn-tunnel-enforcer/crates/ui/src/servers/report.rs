//! [`LiveReport`]: pure render of one live-check receipt — the header, findings and one box per
//! stage, each shown only when the stage produced data. Wording keeps the old panel's honesty
//! notes (Reality certificates, OS-chosen route, probe time ≠ VPN start time).
use dioxus::prelude::*;

use super::live_model::{LiveCheck, LiveMode, Severity};
use super::live_present::{Dot, InfraError, infrastructure_error};
use super::present::local_stamp;
use crate::lang::{LANG, tr};
use crate::t;
use crate::widgets::{Badge, Tone};

mod endpoint;
mod tunnel;

use endpoint::{DnsBox, HttpBox, InfraBox, LatencyBox, PortsBox, RouteBox, TlsBox};
use tunnel::{EgressBox, HandshakeBox, MediaBox, PathBox, PmtuBox, SplitBox, ThroughputBox};

/// A diagnostic box: title, duration and the status mark.
#[component]
fn DiagBox(
    title: String,
    #[props(default)] dot: Option<Dot>,
    #[props(default)] duration_ms: Option<u32>,
    children: Element,
) -> Element {
    rsx! {
        section { class: "srv-diag",
            header { class: "srv-diag-head",
                h4 { class: "srv-diag-title", "{title}" }
                if let Some(ms) = duration_ms {
                    span { class: "swiss-mono srv-diag-ms", "{ms} ms" }
                }
                if let Some(dot) = dot {
                    {
                        let label = dot_label(dot);
                        rsx! {
                            span { class: "srv-dot is-{dot.name()}", role: "img", aria_label: "{label}", title: "{label}" }
                        }
                    }
                }
            }
            div { class: "srv-diag-body", {children} }
        }
    }
}

/// The spoken and hover name of a status dot (its class name is not a word for people).
fn dot_label(dot: Dot) -> String {
    t!(match dot {
        Dot::Ok => "ui.servers.live.dot.ok",
        Dot::Warn => "ui.servers.live.dot.warn",
        Dot::Fail => "ui.servers.live.dot.fail",
        Dot::Muted => "ui.servers.live.dot.muted",
    })
}

/// One label / value line of a box.
#[component]
fn Kv(label: String, #[props(default)] mono: bool, children: Element) -> Element {
    rsx! {
        div { class: "srv-kv-line",
            span { class: "srv-kv-label", "{label}" }
            span { class: "srv-kv-value", class: if mono { "swiss-mono" }, {children} }
        }
    }
}

/// Infrastructure / geo errors, worded for people (L-3: only geo errors go through this).
fn infra_text(raw: &str) -> Option<String> {
    infrastructure_error(raw).map(|e| match e {
        InfraError::RateLimited => t!("ui.servers.live.infra.rateLimited"),
        InfraError::Unreachable => t!("ui.servers.live.infra.unreachable"),
        InfraError::Cancelled => t!("ui.servers.live.infra.cancelled"),
        InfraError::Raw(text) => text,
    })
}

fn yes_no(value: Option<bool>) -> String {
    match value {
        Some(true) => t!("ui.servers.live.yes"),
        Some(false) => t!("ui.servers.live.no"),
        None => "—".to_owned(),
    }
}

#[component]
pub(crate) fn LiveReport(check: LiveCheck) -> Element {
    let lang = *LANG.read();
    let reach = check.reachability.clone();
    let mode = match check.mode {
        LiveMode::Basic => t!("ui.servers.live.modeBasic"),
        LiveMode::Extended => t!("ui.servers.live.modeExtended"),
    };
    let infra_error = check
        .infrastructure
        .as_ref()
        .and_then(|i| i.error.as_deref())
        .and_then(infra_text);
    rsx! {
        div { class: "srv-report-live",
            div { class: "srv-live-result",
                span { class: "srv-dot is-{Dot::from(reach.status).name()}", aria_hidden: "true" }
                strong {
                    if reach.tcp_reachable { {t!("ui.servers.live.reachable")} } else { {t!("ui.servers.live.unreachable")} }
                }
                Badge { tone: if check.mode == LiveMode::Extended { Tone::Ok } else { Tone::Neutral }, "{mode}" }
                if check.cancelled {
                    Badge { tone: Tone::Warn, {t!("ui.servers.live.cancelled")} }
                }
                span { class: "swiss-mono srv-live-meta", {local_stamp(check.finished_at, lang)} }
                span { class: "swiss-mono srv-live-meta", "{check.duration_ms} ms" }
            }
            if let Some(err) = &check.ports_error {
                p { class: "srv-strip is-warn", role: "alert", "{err}" }
            }
            if let Some(err) = infra_error {
                p { class: "srv-strip is-warn", role: "alert", "{err}" }
            }
            // The budget's left-out requests are named up front: their rows are missing on
            // purpose, so no box may read as a failure of the server.
            if let Some(note) = &check.deferred {
                p { class: "srv-strip is-warn", role: "status", "{note}" }
            }
            if !check.findings.is_empty() {
                div { class: "srv-findings",
                    h4 { class: "swiss-label", {t!("ui.servers.live.findings", count = check.findings.len())} }
                    for (i , f) in check.findings.iter().enumerate() {
                        div {
                            key: "{f.code}-{i}",
                            class: "srv-finding {severity_class(f.severity)}",
                            div { class: "srv-finding-head",
                                strong { {tr(&f.title)} }
                                span { class: "swiss-mono srv-finding-code", "{f.code}" }
                            }
                            p { {tr(&f.detail)} }
                        }
                    }
                }
            }
            div { class: "srv-diag-grid",
                DnsBox { check: check.clone() }
                LatencyBox { check: check.clone() }
                TlsBox { check: check.clone() }
                HttpBox { check: check.clone() }
                PortsBox { check: check.clone() }
                RouteBox { check: check.clone() }
                InfraBox { check: check.clone() }
                HandshakeBox { check: check.clone() }
                EgressBox { check: check.clone() }
                PathBox { check: check.clone() }
                PmtuBox { check: check.clone() }
                MediaBox { check: check.clone() }
                ThroughputBox { check: check.clone() }
                SplitBox { check }
            }
        }
    }
}

fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "is-error",
        Severity::Warning => "is-warning",
        Severity::Info => "is-info",
    }
}
