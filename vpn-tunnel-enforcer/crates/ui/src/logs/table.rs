//! History blocks of the page: filters, stats, the sessions table with its detail rows, the
//! start failures.
use dioxus::prelude::*;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use vpnte_base::types::UnixMs;

use super::format::{date_parts, duration_msg};
use super::history::{
    Filters, Period, SortField, SortState, Stats, chip_kind, connection_duration_ms, extra_message,
};
use super::model::{DisconnectReason, EvidenceValue, OutcomeTone, SessionRow};
use super::report::{diagnostics_text, evidence_items, evidence_text, fault_label, headline_text};
use super::{COPIED_FLASH, tr_now, use_api};
use crate::lang::tr;
use crate::t;
use crate::units::format_bytes;
use crate::widgets::{
    Badge, Button, ButtonKind, Cell, EmptyState, Field, FieldCtx, HeadCell, Icon, IconGlyph, Panel,
    Segmented, Sort, Table, TextInput, TextKind, Tone, Trunc,
};

/// The time zone of every date on the page (the system zone), from the page root.
#[derive(Clone)]
pub(super) struct PageTz(pub TimeZone);

/// The page's time zone (the system zone outside the page, e.g. in tests).
pub(super) fn use_tz() -> TimeZone {
    try_use_context::<PageTz>().map_or_else(TimeZone::system, |tz| tz.0)
}

/// `11 нояб., 11:53` / `Nov 11, 11:53` (subscribes to the language).
pub(super) fn date_time(ms: UnixMs, tz: &TimeZone) -> String {
    match date_parts(ms, tz) {
        Some(p) => t!(
            "logs.dateTime",
            day = p.day,
            month = t!(&format!("logs.month.{}", p.month)),
            time = p.time
        ),
        None => "—".to_owned(),
    }
}

/// Badge tone of an outcome chip: deliberate ends stay quiet, failures are loud.
pub(super) fn chip_tone(tone: OutcomeTone) -> Tone {
    match tone {
        OutcomeTone::Intended => Tone::Neutral,
        OutcomeTone::Warn => Tone::Warn,
        OutcomeTone::Bad => Tone::Fail,
        OutcomeTone::Unknown => Tone::Unknown,
    }
}

/// Reasons (multi-select chips), local days «С» / «По», text search.
#[component]
pub(super) fn FiltersPanel(filters: Signal<Filters>) -> Element {
    let current = filters.read().clone();
    let reset = (!current.is_empty()).then(|| {
        rsx! {
            Button {
                kind: ButtonKind::Link,
                onclick: move |_| filters.set(Filters::default()),
                {t!("logs.resetFilters")}
            }
        }
    });
    rsx! {
        Panel { title: t!("logs.filter"), actions: reset,
            div { class: "lg-filters",
                div { class: "lg-reasons", role: "group", aria_label: t!("logs.reason"),
                    span { class: "lg-caption", aria_hidden: "true", {t!("logs.reason")} }
                    div { class: "lg-chips",
                        for reason in DisconnectReason::ALL {
                            button {
                                r#type: "button",
                                class: "lg-chip",
                                aria_pressed: if current.reasons.contains(&reason) { "true" } else { "false" },
                                onclick: move |_| {
                                    let mut f = filters.write();
                                    if !f.reasons.remove(&reason) {
                                        f.reasons.insert(reason);
                                    }
                                },
                                {t!(reason.label_key())}
                            }
                        }
                    }
                }
                div { class: "lg-dates",
                    Field { label: t!("logs.dateFrom"),
                        DateInput {
                            value: current.from,
                            max: current.to,
                            on_change: move |d| filters.write().from = d,
                        }
                    }
                    Field { label: t!("logs.dateTo"),
                        DateInput {
                            value: current.to,
                            min: current.from,
                            on_change: move |d| filters.write().to = d,
                        }
                    }
                }
                div { class: "lg-search",
                    TextInput {
                        kind: TextKind::Search,
                        value: current.text.clone(),
                        oninput: move |v| filters.write().text = v,
                        placeholder: t!("logs.search"),
                        aria_label: t!("logs.searchLabel"),
                    }
                }
            }
        }
    }
}

/// A native date picker (`YYYY-MM-DD`; empty = no bound) styled as a text box, labelled by the
/// surrounding [`Field`].
#[component]
fn DateInput(
    value: Option<Date>,
    #[props(default)] min: Option<Date>,
    #[props(default)] max: Option<Date>,
    on_change: EventHandler<Option<Date>>,
) -> Element {
    let field = try_use_context::<FieldCtx>();
    let iso = |d: Option<Date>| d.map(|d| d.strftime("%Y-%m-%d").to_string());
    rsx! {
        input {
            class: "w-input lg-date",
            r#type: "date",
            id: field.as_ref().map(FieldCtx::id),
            aria_describedby: field.as_ref().and_then(FieldCtx::described_by),
            value: iso(value).unwrap_or_default(),
            min: iso(min),
            max: iso(max),
            oninput: move |evt| on_change.call(evt.value().parse::<Date>().ok()),
        }
    }
}

/// Totals of the chosen period (the on-screen filters do not apply).
#[component]
pub(super) fn StatsPanel(stats: Stats, period: Signal<Period>) -> Element {
    let options: Vec<(Period, String)> = Period::ALL
        .iter()
        .map(|p| (*p, t!(p.label_key())))
        .collect();
    let total = duration_msg(stats.total_time_ms).map_or_else(|| "—".to_owned(), |m| tr(&m));
    rsx! {
        Panel {
            title: t!("logs.stats"),
            actions: rsx! {
                Segmented {
                    options,
                    value: period(),
                    on_change: move |p| period.set(p),
                    label: t!("logs.period"),
                }
            },
            dl { class: "lg-stats",
                div { class: "lg-stat",
                    dt { {t!("logs.totalTime")} }
                    dd { class: "swiss-mono", "{total}" }
                }
                div { class: "lg-stat",
                    dt { {t!("logs.totalDown")} }
                    dd { class: "swiss-mono", "↓ {format_bytes(stats.bytes_down)}" }
                }
                div { class: "lg-stat",
                    dt { {t!("logs.totalUp")} }
                    dd { class: "swiss-mono", "↑ {format_bytes(stats.bytes_up)}" }
                }
                div { class: "lg-stat",
                    dt { {t!("logs.connections")} }
                    dd { class: "swiss-mono", "{stats.sessions}" }
                }
            }
        }
    }
}

/// The sessions table (or why it is empty).
pub(super) fn history_panel(
    rows: &[&SessionRow],
    filtered: bool,
    mut sort: Signal<SortState>,
    expanded: Signal<Option<String>>,
    mut filters: Signal<Filters>,
) -> Element {
    let count = t!("logs.connectionsCount", count = rows.len());
    let current = sort();
    let head = move |field: SortField, label: String| {
        let state = (current.field == field).then_some(if current.descending {
            Sort::Desc
        } else {
            Sort::Asc
        });
        rsx! {
            HeadCell { label, sort: state, on_sort: move |()| sort.set(sort().toggle(field)) }
        }
    };
    let open = expanded.read().clone();
    rsx! {
        Panel {
            title: t!("logs.connectionHistory"),
            flush: true,
            actions: rsx! { span { class: "lg-count swiss-mono", "{count}" } },
            if rows.is_empty() && !filtered {
                EmptyState { title: t!("logs.noLogs") }
            } else if rows.is_empty() {
                EmptyState { title: t!("common.noResults"), detail: t!("logs.noMatches"),
                    Button {
                        kind: ButtonKind::Ghost,
                        small: true,
                        onclick: move |_| filters.set(Filters::default()),
                        {t!("logs.resetFilters")}
                    }
                }
            } else {
                Table { caption: t!("logs.connectionHistory"),
                    thead {
                        tr {
                            {head(SortField::Profile, t!("logs.profile"))}
                            {head(SortField::Mode, t!("logs.mode"))}
                            {head(SortField::Started, t!("logs.startTime"))}
                            {head(SortField::Ended, t!("logs.endTime"))}
                            {head(SortField::Duration, t!("logs.duration"))}
                            {head(SortField::Traffic, t!("logs.traffic"))}
                            {head(SortField::Outcome, t!("logs.reasonColumn"))}
                        }
                    }
                    tbody {
                        for row in rows.iter() {
                            SessionLine {
                                key: "{row.id}",
                                row: (*row).clone(),
                                open: open.as_deref() == Some(row.id.as_str()),
                                expanded,
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Opens `id`'s detail, or closes it when it is the open one (one detail at a time).
fn toggle(mut expanded: Signal<Option<String>>, id: &str) {
    let mut open = expanded.write();
    if open.as_deref() == Some(id) {
        *open = None;
    } else {
        *open = Some(id.to_owned());
    }
}

/// One session: the row (a click anywhere toggles the detail; the outcome cell is the keyboard
/// way, a real button) and, when open, the detail row.
#[component]
fn SessionLine(row: SessionRow, open: bool, expanded: Signal<Option<String>>) -> Element {
    let tz = use_tz();
    let kind = chip_kind(&row);
    let detail_id = format!("lg-detail-{}", row.id);
    let (row_id, button_id) = (row.id.clone(), row.id.clone());
    let duration = match row.ended_at {
        Some(_) => {
            duration_msg(connection_duration_ms(&row)).map_or_else(|| "—".to_owned(), |m| tr(&m))
        }
        None => "—".to_owned(),
    };
    rsx! {
        tr {
            class: "lg-row",
            class: if open { "is-open" },
            onclick: move |_| toggle(expanded, &row_id),
            Cell { grow: true,
                Trunc { text: row.profile_name.clone(), max: 40 }
            }
            Cell { muted: true,
                // «Direct VPN» stays on one line: a wrapped mode doubles the row height
                span { class: "truncate", {t!(row.mode.label_key())} }
            }
            Cell { mono: true, "{date_time(row.started_at, &tz)}" }
            Cell { mono: true,
                if let Some(end) = row.ended_at {
                    "{date_time(end, &tz)}"
                } else {
                    Badge { tone: Tone::Ok, {t!("logs.active")} }
                }
            }
            Cell { mono: true, "{duration}" }
            Cell { mono: true,
                span { class: "lg-traffic",
                    span { "↓ {format_bytes(row.bytes_down)}" }
                    span { "↑ {format_bytes(row.bytes_up)}" }
                }
            }
            td { class: "w-td lg-outcome",
                button {
                    r#type: "button",
                    class: "lg-expand",
                    aria_expanded: if open { "true" } else { "false" },
                    aria_controls: open.then(|| detail_id.clone()),
                    onclick: move |evt| {
                        evt.stop_propagation();
                        toggle(expanded, &button_id);
                    },
                    if let Some(kind) = kind {
                        Badge { tone: chip_tone(kind.tone()), {tr(&kind.label())} }
                    } else {
                        span { class: "lg-running", "—" }
                    }
                    span { class: "w-sr", {t!("logs.details")} }
                    Icon { glyph: if open { IconGlyph::ChevronUp } else { IconGlyph::ChevronDown }, size: 12 }
                }
            }
        }
        if open {
            tr { class: "lg-detail-row",
                td { class: "lg-detail-cell", colspan: "7", id: "{detail_id}",
                    DetailBody { row: row.clone() }
                }
            }
        }
    }
}

/// The detail of a session: headline, the stored message when it says more, the evidence grid
/// and «Скопировать диагностику».
#[component]
fn DetailBody(row: SessionRow) -> Element {
    let api = use_api();
    let mut copied = use_signal(|| false);
    let headline = headline_text(&row, &tr);
    let extra = extra_message(&row, &headline).map(str::to_owned);
    let items = row
        .outcome
        .as_ref()
        .map(|o| evidence_items(&o.evidence))
        .unwrap_or_default();
    let copy = move |_| {
        let api = api.clone();
        let text = diagnostics_text(&row, &tr_now);
        spawn(async move {
            // A clipboard failure is silent (the old behaviour): the label just does not flip.
            if api.copy_text(text).await.is_ok() {
                copied.set(true);
                tokio::time::sleep(COPIED_FLASH).await;
                copied.set(false);
            }
        });
    };
    rsx! {
        div { class: "lg-detail",
            p { class: "lg-headline", "{headline}" }
            if let Some(extra) = extra {
                p { class: "lg-extra swiss-mono", "{extra}" }
            }
            if !items.is_empty() {
                dl { class: "lg-evidence",
                    for (key, value) in items {
                        {evidence_cell(key.label(), &value)}
                    }
                }
            }
            div { class: "lg-detail-actions",
                Button { kind: ButtonKind::Ghost, small: true, onclick: copy,
                    Icon { glyph: if copied() { IconGlyph::Check } else { IconGlyph::Copy }, size: 14 }
                    if copied() {
                        {t!("logs.copied")}
                    } else {
                        {t!("logs.copyDiagnostics")}
                    }
                }
            }
        }
    }
}

/// Attempts that never came up, folded by default; nothing when there are none.
pub(super) fn failures_panel(rows: &[&SessionRow], mut open: Signal<bool>) -> Element {
    if rows.is_empty() {
        return rsx! {};
    }
    let is_open = open();
    let count = rows.len();
    rsx! {
        section { class: "w-panel lg-fails",
            button {
                r#type: "button",
                class: "lg-fold",
                aria_expanded: if is_open { "true" } else { "false" },
                aria_controls: is_open.then_some("lg-fails-body"),
                onclick: move |_| open.set(!is_open),
                span { class: "swiss-label", {t!("logs.startFailuresCount", count = count)} }
                Icon { glyph: if is_open { IconGlyph::ChevronUp } else { IconGlyph::ChevronDown }, size: 12 }
            }
            if is_open {
                div { class: "lg-fails-body", id: "lg-fails-body",
                    p { class: "lg-hint", {t!("logs.startFailuresHint")} }
                    ul { class: "lg-fail-list",
                        for row in rows.iter() {
                            FailureLine { key: "{row.id}", row: (*row).clone() }
                        }
                    }
                }
            }
        }
    }
}

/// One failed start: profile, time, what went wrong, the node fault when known.
#[component]
fn FailureLine(row: SessionRow) -> Element {
    let tz = use_tz();
    let headline = headline_text(&row, &tr);
    let fault = row.outcome.as_ref().and_then(|o| o.evidence.outbound_fault);
    rsx! {
        li { class: "lg-fail",
            span { class: "lg-fail-name", "{row.profile_name}" }
            span { class: "lg-fail-time swiss-mono", "{date_time(row.started_at, &tz)}" }
            span { class: "lg-fail-text", "{headline}" }
            if let Some(fault) = fault {
                span { class: "lg-fail-fault swiss-mono",
                    {t!("logs.outcomeEvidence.outboundFault")}
                    ": "
                    {tr(&fault_label(fault))}
                }
            }
        }
    }
}

/// Text evidence longer than this (or with line breaks: an engine output tail) takes a whole
/// line of the grid.
const WIDE_EVIDENCE_CHARS: usize = 48;

/// One label / value pair of the evidence grid.
fn evidence_cell(label: vpnte_base::Msg, value: &EvidenceValue) -> Element {
    let text = evidence_text(value, &tr);
    let is_text = matches!(value, EvidenceValue::Text(_));
    let wide = is_text && (text.contains('\n') || text.chars().count() > WIDE_EVIDENCE_CHARS);
    rsx! {
        div { class: "lg-ev", class: if wide { "is-wide" },
            dt { {tr(&label)} }
            dd { class: if is_text { "is-text" }, "{text}" }
        }
    }
}
