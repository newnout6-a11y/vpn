//! «Сбор пакетов» (packet capture / ETW status, re-homed from the old DiagnosticsCard) and the
//! box of the last caught error.
use dioxus::prelude::*;

use super::ctl::Controller;
use super::model::{CaptureView, Counted, EtwView, FaultView};
use super::rules;
use super::view::{OutcomeLine, fmt_time};
use crate::lang::tr;
use crate::t;
use crate::units::format_bytes;
use crate::widgets::{Badge, Button, ButtonKind, Panel};

/// The capture panel: badge, alert or first warning, tiles, ETW detail, actions.
#[component]
pub(crate) fn CapturePanel(ctl: Controller) -> Element {
    let capture = ctl.state.read().capture.clone();
    let badge = rules::capture_badge(&capture);
    let busy = ctl.capture.running();
    rsx! {
        Panel {
            title: t!("ui.maintenance.capture.title"),
            id: "mt-capture",
            actions: rsx! {
                Badge { tone: badge.tone, title: tr(&badge.title), {tr(&badge.label)} }
            },
            if let Some(alert) = &badge.alert {
                p { class: "mt-alert", role: "alert", {tr(alert)} }
            } else if let Some(warning) = capture.warnings.first() {
                p { class: "mt-warning", {tr(warning)} }
            }
            if !capture.enabled {
                p { class: "mt-quiet", {t!("ui.maintenance.capture.disabled")} }
            }
            Tiles { capture: capture.clone() }
            if let Some(etw) = capture.etw.clone().filter(rules::show_etw_detail) {
                EtwDetail { etw }
            }
            div { class: "mt-actions",
                Button {
                    kind: ButtonKind::Ghost,
                    busy,
                    onclick: move |_| ctl.restart_capture(),
                    {t!("ui.maintenance.capture.restart")}
                }
                Button {
                    kind: ButtonKind::Link,
                    disabled: busy,
                    onclick: move |_| ctl.open_snapshots(),
                    {t!("ui.maintenance.capture.folder")}
                }
            }
            OutcomeLine { outcome: ctl.capture_outcome.read().clone() }
        }
    }
}

#[component]
fn Tile(label: String, value: String, #[props(default)] warn: bool) -> Element {
    rsx! {
        div { class: "mt-tile", class: if warn { "is-warn" },
            span { class: "mt-tile-label", "{label}" }
            span { class: "mt-tile-value swiss-mono", "{value}" }
        }
    }
}

#[component]
fn Tiles(capture: CaptureView) -> Element {
    // Without pktmon a running session is ETW-only; a stopped one has no engine at all.
    let engine = match &capture.engine {
        Some(name) => Some(name.clone()),
        None if capture.running => Some(t!("ui.maintenance.capture.etwOnly")),
        None => None,
    };
    let size = capture
        .etl_bytes
        .map_or_else(|| "—".to_owned(), format_bytes);
    let snapshot = capture
        .live_snapshot_at
        .map_or_else(|| "—".to_owned(), fmt_time);
    let (etw_value, etw_warn) = match &capture.etw {
        Some(e) => (
            format!(
                "{} · {}",
                tr(&rules::etw_engine_label(e.engine.as_deref())),
                tr(&rules::etw_state(e))
            ),
            e.only_lifecycle,
        ),
        None => (t!("ui.maintenance.capture.etwNone"), false),
    };
    // A stopped session keeps its last ETL size; no engine is named for it.
    let capture_value = match engine {
        Some(engine) => format!("{engine} · {size}"),
        None => size,
    };
    rsx! {
        div { class: "mt-tiles",
            Tile { label: t!("ui.maintenance.capture.tileCapture"), value: capture_value }
            Tile { label: t!("ui.maintenance.capture.tileSnapshot"), value: snapshot }
            Tile { label: t!("ui.maintenance.capture.tileEtw"), value: etw_value, warn: etw_warn }
            Tile {
                label: t!("ui.maintenance.capture.tileArtifacts"),
                value: capture.artifact_count.to_string(),
            }
        }
    }
}

#[component]
fn EtwDetail(etw: EtwView) -> Element {
    let last = etw.last_event_at.map_or_else(|| "—".to_owned(), fmt_time);
    let categories = rules::ordered_categories(&etw.categories);
    let empty = if etw.warming_up {
        t!("ui.maintenance.capture.etwWarmingHint")
    } else {
        t!("ui.maintenance.capture.etwNoData")
    };
    rsx! {
        div { class: "mt-block", "data-block": "etw",
            div { class: "mt-block-head",
                span { class: "mt-block-title", {t!("ui.maintenance.capture.etwTitle")} }
                span { class: "mt-meta swiss-mono", {t!("ui.maintenance.capture.lastEvent", time = last)} }
            }
            if etw.data_events == 0 {
                p { class: "mt-quiet", "{empty}" }
            } else {
                div { class: "mt-chips",
                    for c in categories {
                        span { key: "{c.name}", class: "mt-chip swiss-mono", "{c.name} {c.count}" }
                    }
                    if etw.wfp_blocks > 0 {
                        span { class: "mt-chip is-warn swiss-mono",
                            {t!("ui.maintenance.capture.wfpBlocks", count = etw.wfp_blocks)}
                        }
                    }
                }
                TopList { title: t!("ui.maintenance.capture.topDomains"), rows: etw.top_domains.clone() }
                TopList { title: t!("ui.maintenance.capture.topRemotes"), rows: etw.top_remotes.clone() }
            }
        }
    }
}

#[component]
fn TopList(title: String, rows: Vec<Counted>) -> Element {
    if rows.is_empty() {
        return rsx! {};
    }
    rsx! {
        div { class: "mt-top",
            span { class: "mt-top-title", "{title}" }
            ol { class: "mt-top-list swiss-mono",
                for row in rows {
                    li { key: "{row.name}",
                        span { class: "mt-top-name", title: "{row.name}", "{row.name}" }
                        span { class: "mt-top-count", "{row.count}" }
                    }
                }
            }
        }
    }
}

/// «Последняя ошибка»: an error the app caught without crashing (advanced-mode developer aid).
#[component]
pub(crate) fn FaultPanel(fault: FaultView) -> Element {
    rsx! {
        Panel { title: t!("ui.maintenance.fault.title"), id: "mt-fault",
            p { class: "mt-warning", {t!("ui.maintenance.fault.caught")} }
            pre { class: "mt-item-details swiss-mono", "{fault.code}: {fault.detail}" }
            p { class: "mt-meta swiss-mono", {fmt_time(fault.at)} }
        }
    }
}
