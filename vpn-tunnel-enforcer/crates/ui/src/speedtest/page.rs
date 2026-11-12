//! Speed test page markup: the root reads the controller (`ctl.rs`) and the pushed state; the
//! panels below only render.
use std::rc::Rc;

use dioxus::prelude::*;
use jiff::tz::TimeZone;
use vpnte_base::i18n::Lang;

use super::SpeedTestApi;
use super::ctl::use_controller;
use super::format::{egress_look, fmt_mbps, format_date_time, phase_key};
use super::model::{Egress, SpeedResult, SpeedTestState};
use crate::availability::{text, text_with};
use crate::hooks::use_watch;
use crate::lang::LANG;
use crate::pages::{Page, nav_number};
use crate::widgets::{
    Align, Badge, Button, ButtonKind, Cell, EmptyState, HeadCell, Panel, ProgressBar,
    SectionHeader, Table,
};

/// The page root; register it as [`Page::SpeedTest`]. Needs `Rc<dyn SpeedTestApi>` in context.
/// The shell keeps a visited page mounted, so a running test survives navigation (as in the old
/// app); Cancel or unmounting cancels it.
#[component]
pub fn SpeedTestPage() -> Element {
    let api = use_context::<Rc<dyn SpeedTestApi>>();
    let state = use_watch(|| api.state());
    let ctl = use_controller(api);
    let lang = *LANG.read();
    let snapshot = state.read();
    let running = ctl.job.running();
    let error = ctl.error().map(|msg| msg.render(lang));
    let shown = ctl.shown(&snapshot.history);
    let progress = ctl.progress;
    let off_reason = text(lang, "speedTest.vpnNotConnected");
    let number = Page::ALL
        .iter()
        .position(|p| *p == Page::SpeedTest)
        .unwrap_or(3);
    rsx! {
        div { class: "c-swiss swiss-skin",
            div { class: "st",
                SectionHeader {
                    number: nav_number(number),
                    title: text(lang, "sidebar.speedTest"),
                    description: text(lang, "speedTest.description"),
                }
                if !snapshot.tunnel_running {
                    p { class: "st-notice", id: "st-tunnel-off", role: "status", "{off_reason}" }
                }
                Panel { title: text(lang, "speedTest.results"), id: "st-run", flush: true,
                    Figures { result: shown, dim: running }
                    div { class: "st-controls",
                        Button {
                            id: "st-start",
                            busy: running,
                            disabled: !snapshot.tunnel_running,
                            disabled_reason: off_reason.clone(),
                            onclick: move |_| ctl.start(),
                            if running {
                                {text(lang, "speedTest.running")}
                            } else {
                                {text(lang, "speedTest.runTest")}
                            }
                        }
                        if running {
                            Button { id: "st-cancel", kind: ButtonKind::Ghost, onclick: move |_| ctl.cancel(),
                                {text(lang, "common.cancel")}
                            }
                        }
                        if let Some(p) = progress() {
                            div { class: "st-progress",
                                ProgressBar {
                                    value: f64::from(p.percent.min(100)) / 100.0,
                                    label: text(lang, "speedTest.title"),
                                    show_value: true,
                                }
                                p { class: "st-phase", id: "st-phase", {text(lang, phase_key(p.phase))} }
                            }
                        }
                    }
                    if let Some(error) = error {
                        p { class: "st-error", id: "st-error", role: "alert", "{error}" }
                    }
                }
                HistoryPanel { state: snapshot.clone() }
            }
        }
    }
}

/// The three big readouts of a result, its source line and its warnings.
#[component]
fn Figures(result: Option<SpeedResult>, dim: bool) -> Element {
    let lang = *LANG.read();
    let mbps = text(lang, "speedTest.mbps");
    let Some(result) = result else {
        return rsx! {
            div { class: "st-figures", class: if dim { "is-dim" },
                Figure { id: "st-down", label: text(lang, "speedTest.download"), value: None, unit: mbps.clone() }
                Figure { id: "st-up", label: text(lang, "speedTest.upload"), value: None, unit: mbps }
                Figure { id: "st-latency", label: text(lang, "speedTest.latency"), value: None, unit: text(lang, "speedTest.ms") }
            }
            p { class: "st-meta", id: "st-meta", {text(lang, "ui.speedTest.noResult")} }
        };
    };
    let when = format_date_time(lang, result.timestamp, &TimeZone::system());
    let seen = match result.egress {
        Egress::Changed { seen: Some(ip) } | Egress::Direct { seen: ip } => Some(ip),
        _ => None,
    };
    rsx! {
        div { class: "st-figures", class: if dim { "is-dim" },
            Figure {
                id: "st-down",
                label: text(lang, "speedTest.download"),
                value: fmt_mbps(result.download_mbps),
                unit: mbps.clone(),
            }
            Figure {
                id: "st-up",
                label: text(lang, "speedTest.upload"),
                value: result.upload_mbps.map(fmt_mbps),
                unit: mbps,
                missing: text(lang, "ui.speedTest.uploadMissing"),
            }
            Figure {
                id: "st-latency",
                label: text(lang, "speedTest.latency"),
                value: result.latency_ms.to_string(),
                unit: text(lang, "speedTest.ms"),
            }
        }
        p { class: "st-meta swiss-mono", id: "st-meta",
            "{result.server_name} · {result.profile_used} · {when}"
        }
        if let Some((key, _, tone)) = egress_look(result.egress) {
            p { class: "st-note", id: "st-egress", "data-tone": tone.name(),
                {text(lang, key)}
                if let Some(ip) = seen {
                    " "
                    span { class: "swiss-mono",
                        {text_with(lang, "ui.speedTest.egressSeen", &[("ip", ip.to_string())])}
                    }
                }
            }
        }
        if result.plain_http {
            p { class: "st-note", id: "st-plain-http", "data-tone": "warn", {text(lang, "ui.speedTest.plainHttp")} }
        }
        if result.upload_mbps.is_none() {
            p { class: "st-note", "data-tone": "unknown", {text(lang, "ui.speedTest.uploadMissing")} }
        }
    }
}

/// One readout: mono caption, big number, unit; «—» without a unit when there is no value.
#[component]
fn Figure(
    id: &'static str,
    label: String,
    value: Option<String>,
    unit: String,
    #[props(default)] missing: Option<String>,
) -> Element {
    rsx! {
        div { class: "st-figure", id,
            span { class: "swiss-label", "{label}" }
            if let Some(value) = value {
                div { class: "st-big",
                    span { class: "st-value", "{value}" }
                    span { class: "st-unit", "{unit}" }
                }
            } else {
                div { class: "st-big is-empty", title: missing,
                    span { class: "st-value", "—" }
                }
            }
        }
    }
}

/// Saved results in the backend's order, with the exit-IP mark (U-06: a failed read is shown).
#[component]
fn HistoryPanel(state: SpeedTestState) -> Element {
    let lang = *LANG.read();
    let tz = TimeZone::system();
    let mbps = text(lang, "speedTest.mbps");
    let ms = text(lang, "speedTest.ms");
    rsx! {
        Panel { title: text(lang, "speedTest.history"), id: "st-history", flush: true,
            if let Some(error) = &state.history_error {
                p { class: "st-error st-history-note", role: "alert", {error.render(lang)} }
            } else if state.history.is_empty() {
                EmptyState { title: text(lang, "speedTest.noHistory") }
            } else {
                Table { caption: text(lang, "speedTest.history"),
                    thead {
                        tr {
                            HeadCell { label: text(lang, "ui.speedTest.time") }
                            HeadCell { label: text(lang, "speedTest.download"), align: Align::End }
                            HeadCell { label: text(lang, "speedTest.upload"), align: Align::End }
                            HeadCell { label: text(lang, "speedTest.latency"), align: Align::End }
                            HeadCell { label: text(lang, "ui.speedTest.server") }
                        }
                    }
                    tbody {
                        for row in state.history.iter() {
                            HistoryRow { key: "{row.id}", row: row.clone(), lang, tz: tz.clone(), mbps: mbps.clone(), ms: ms.clone() }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn HistoryRow(row: SpeedResult, lang: Lang, tz: TimeZone, mbps: String, ms: String) -> Element {
    let upload = row
        .upload_mbps
        .map_or_else(|| "—".to_owned(), |v| format!("{} {mbps}", fmt_mbps(v)));
    let mark = egress_look(row.egress);
    rsx! {
        tr { class: "st-row",
            Cell { mono: true, muted: true, {format_date_time(lang, row.timestamp, &tz)} }
            Cell { align: Align::End, mono: true, "↓ {fmt_mbps(row.download_mbps)} {mbps}" }
            Cell { align: Align::End, mono: true, "↑ {upload}" }
            Cell { align: Align::End, mono: true, "{row.latency_ms} {ms}" }
            Cell { grow: true,
                span { class: "st-server",
                    span { class: "w-trunc", title: "{row.server_name} · {row.profile_used}",
                        "{row.server_name} · {row.profile_used}"
                    }
                    if let Some((sentence, mark_key, tone)) = mark {
                        Badge { tone, title: text(lang, sentence), {text(lang, mark_key)} }
                    }
                    if row.plain_http {
                        Badge { tone: crate::widgets::Tone::Warn, title: text(lang, "ui.speedTest.plainHttp"), "HTTP" }
                    }
                }
            }
        }
    }
}
