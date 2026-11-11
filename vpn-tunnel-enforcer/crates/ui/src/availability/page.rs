//! Availability page markup: the root reads the controller (`ctl.rs`) and the pushed state; the
//! panels below only render.
use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_base::types::UnixMs;

use super::AvailabilityApi;
use super::ctl::{use_controller, use_now, use_state_pump};
use super::format::{
    HISTORY_ROWS, format_age, path_status, routing_look, stage_rows, text, text_with, verdict_look,
};
use super::model::{AvailabilityState, PathReport, PathSource, RoutingReport, UrlCheck};
use crate::lang::LANG;
use crate::pages::{Page, nav_number};
use crate::widgets::{
    Badge, Button, ButtonKind, EmptyState, IconButton, IconGlyph, JobSlot, Panel, SectionHeader,
    Trunc,
};

/// The page root; register it as [`Page::Availability`]. Needs `Rc<dyn AvailabilityApi>` in
/// context. The shell keeps a visited page mounted, so a running check, the typed link and the
/// last result survive navigation (they did in the old app); unmounting cancels the runs.
#[component]
pub fn AvailabilityPage() -> Element {
    let api = use_context::<Rc<dyn AvailabilityApi>>();
    let state = use_state_pump(api.clone());
    let ctl = use_controller(api);
    let now = use_now();
    let lang = *LANG.read();
    let mut input = ctl.input;
    let snapshot = state.read();
    let checking = ctl.url_job.running();
    let check_error = ctl.check_error().map(|msg| msg.render(lang));
    let invalid = check_error.is_some();
    let result = ctl.result(&snapshot.history);
    let current = result.as_ref().map(|check| check.id.clone());
    let number = Page::ALL
        .iter()
        .position(|p| *p == Page::Availability)
        .unwrap_or(4);
    rsx! {
        div { class: "c-swiss swiss-skin",
            div { class: "av",
                SectionHeader {
                    number: nav_number(number),
                    title: text(lang, "sidebar.availability"),
                    description: text(lang, "ui.availability.description"),
                }
                div { class: "av-grid",
                    div { class: "av-main",
                        Panel { title: text(lang, "ui.availability.check.title"),
                            div { class: "av-form",
                                div { class: "av-input",
                                    // Uncontrolled on purpose: dioxus rewrites `value` (a volatile
                                    // attribute) on every render of a controlled input, which dropped
                                    // keys typed while a render was in flight (CDP, 40 ms per key).
                                    input {
                                        class: "w-input",
                                        r#type: "url",
                                        id: "av-url",
                                        placeholder: text(lang, "ui.availability.check.placeholder"),
                                        aria_label: text(lang, "ui.availability.check.label"),
                                        aria_invalid: invalid.then_some("true"),
                                        aria_describedby: invalid.then_some("av-check-error"),
                                        disabled: checking,
                                        spellcheck: "false",
                                        autocomplete: "off",
                                        oninput: move |evt| input.set(evt.value()),
                                        onkeydown: move |evt| {
                                            if evt.key() == Key::Enter {
                                                evt.prevent_default();
                                                ctl.check();
                                            }
                                        },
                                    }
                                }
                                Button {
                                    id: "av-check",
                                    busy: checking,
                                    disabled: input().trim().is_empty(),
                                    onclick: move |_| ctl.check(),
                                    if checking {
                                        {text(lang, "ui.availability.check.running")}
                                    } else {
                                        {text(lang, "ui.availability.check.run")}
                                    }
                                }
                            }
                            if let Some(error) = check_error {
                                p { class: "av-error", id: "av-check-error", role: "alert", "{error}" }
                            }
                            if !snapshot.tunnel_running {
                                p { class: "av-hint", id: "av-tunnel-off", {text(lang, "ui.availability.check.tunnelOff")} }
                            }
                        }
                        if let Some(check) = result {
                            ResultPanel { check, now }
                        }
                    }
                    div { class: "av-side",
                        RoutingPanel { job: ctl.route_job, tunnel_running: snapshot.tunnel_running, on_run: move |()| ctl.run_routing() }
                        HistoryPanel {
                            state: snapshot.clone(),
                            clear_job: ctl.clear_job,
                            now,
                            current,
                            on_clear: move |()| ctl.clear_history(),
                            on_pick: move |check: UrlCheck| ctl.pick(check),
                        }
                    }
                }
            }
        }
    }
}

/// The result of the check on screen: verdict, recommendation and the two paths.
#[component]
fn ResultPanel(check: UrlCheck, now: UnixMs) -> Element {
    let lang = *LANG.read();
    let (verdict_key, tone) = verdict_look(check.verdict);
    let missing_protected = if check.tunnel_active {
        text(lang, "ui.availability.path.noData")
    } else {
        text(lang, "ui.availability.path.tunnelWasOff")
    };
    rsx! {
        Panel { title: text(lang, "ui.availability.result.title"), id: "av-result",
            div { class: "av-result-head",
                p { class: "av-result-url",
                    {text_with(lang, "ui.availability.result.for", &[("url", check.url.clone())])}
                }
                span { class: "av-age swiss-mono", {format_age(lang, now, check.tested_at)} }
            }
            div { class: "av-verdict", "data-verdict": "{verdict_key}",
                Badge { tone, {text(lang, verdict_key)} }
                p { class: "av-reco", {check.recommendation.render(lang)} }
            }
            div { class: "av-paths",
                PathCard {
                    title: text(lang, "ui.availability.path.protected"),
                    path: check.protected.clone(),
                    missing: missing_protected,
                    side: "protected",
                }
                PathCard {
                    title: text(lang, "ui.availability.path.direct"),
                    path: check.direct.clone(),
                    missing: text(lang, "ui.availability.path.noDirect"),
                    side: "direct",
                }
            }
        }
    }
}

/// One path: status, total time, notes and the stage lines.
#[component]
fn PathCard(
    title: String,
    path: Option<PathReport>,
    missing: String,
    side: &'static str,
) -> Element {
    let lang = *LANG.read();
    let ms = |v: u32| text_with(lang, "ui.availability.ms", &[("n", v.to_string())]);
    let Some(path) = path else {
        return rsx! {
            article { class: "av-path", "data-side": side,
                header { class: "av-path-head",
                    h3 { class: "swiss-label av-path-title", "{title}" }
                }
                p { class: "av-path-missing", "{missing}" }
            }
        };
    };
    let (status_key, tone) = path_status(&path);
    let source_key = match path.source {
        PathSource::Native => "ui.availability.path.full",
        PathSource::DirectInbound => "ui.availability.path.httpOnly",
    };
    let rows = stage_rows(lang, &path);
    rsx! {
        article { class: "av-path", "data-side": side,
            header { class: "av-path-head",
                h3 { class: "swiss-label av-path-title", "{title}" }
                span { class: "swiss-label av-path-source", {text(lang, source_key)} }
            }
            div { class: "av-path-status",
                Badge { tone, {text(lang, status_key)} }
                if let Some(total) = path.total_ms {
                    span { class: "av-ms swiss-mono", {ms(total)} }
                }
            }
            if path.geo_blocked {
                p { class: "av-note is-warn", {text(lang, "ui.availability.path.geoBlocked")} }
            }
            if let Some(message) = &path.message {
                p { class: "av-note", {message.render(lang)} }
            }
            if !rows.is_empty() {
                dl { class: "av-stages",
                    for row in rows {
                        div { class: "av-stage",
                            dt { class: "av-stage-label swiss-mono", "{row.label}" }
                            dd { class: row.mark.class(), title: "{row.value}", "{row.value}" }
                            if let Some(v) = row.ms {
                                dd { class: "av-stage-ms swiss-mono", {ms(v)} }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The routing self-test: button, explanation and the last report or error (U-06: a failure is
/// shown, not only logged).
#[component]
fn RoutingPanel(
    job: JobSlot<RoutingReport>,
    tunnel_running: bool,
    on_run: Callback<()>,
) -> Element {
    let lang = *LANG.read();
    let running = job.running();
    let off_reason = text(lang, "ui.availability.routing.tunnelOff");
    let ip = |v: Option<std::net::IpAddr>| v.map_or_else(|| "—".to_owned(), |ip| ip.to_string());
    rsx! {
        Panel {
            title: text(lang, "ui.availability.routing.title"),
            id: "av-routing",
            actions: rsx! {
                Button {
                    id: "av-routing-run",
                    kind: ButtonKind::Ghost,
                    small: true,
                    busy: running,
                    disabled: !tunnel_running,
                    disabled_reason: off_reason.clone(),
                    onclick: move |_| on_run.call(()),
                    if running {
                        {text(lang, "ui.availability.routing.running")}
                    } else {
                        {text(lang, "ui.availability.routing.run")}
                    }
                }
            },
            p { class: "av-hint", {text(lang, "ui.availability.routing.description")} }
            if !tunnel_running {
                p { class: "av-hint is-strong", "{off_reason}" }
            }
            match job.last() {
                Some(Ok(report)) => {
                    let (key, tone) = routing_look(report.verdict);
                    rsx! {
                        div { class: "av-routing", "data-verdict": "{key}", role: "status",
                            Badge { tone, {text(lang, key)} }
                            p { class: "av-routing-msg", {report.message.render(lang)} }
                            dl { class: "av-ips",
                                div { class: "av-ip",
                                    dt { {text(lang, "ui.availability.routing.viaVpn")} }
                                    dd { class: "swiss-mono", {ip(report.vpn_ip)} }
                                }
                                div { class: "av-ip",
                                    dt { {text(lang, "ui.availability.routing.direct")} }
                                    dd { class: "swiss-mono", {ip(report.direct_ip)} }
                                }
                                if report.smart_ru {
                                    div { class: "av-ip",
                                        dt { {text(lang, "ui.availability.routing.ruSite")} }
                                        dd { class: "swiss-mono", {ip(report.ru_ip)} }
                                    }
                                }
                            }
                        }
                    }
                }
                Some(Err(err)) => rsx! {
                    p { class: "av-error", role: "alert", {err.msg.render(lang)} }
                },
                None => rsx! {},
            }
        }
    }
}

/// The saved checks (always on the page, U-12): a row puts its result back on screen.
#[component]
fn HistoryPanel(
    state: AvailabilityState,
    clear_job: JobSlot<()>,
    now: UnixMs,
    /// Id of the check on screen (its row is marked).
    current: Option<String>,
    on_clear: Callback<()>,
    on_pick: EventHandler<UrlCheck>,
) -> Element {
    let lang = *LANG.read();
    let clear_label = text(lang, "ui.availability.history.clear");
    let has_rows = !state.history.is_empty();
    rsx! {
        Panel {
            title: text(lang, "ui.availability.history.title"),
            id: "av-history",
            flush: true,
            actions: rsx! {
                if has_rows {
                    IconButton {
                        glyph: IconGlyph::Trash,
                        label: clear_label.clone(),
                        busy: clear_job.running(),
                        onclick: move |_| on_clear.call(()),
                    }
                }
            },
            if let Some(Err(err)) = clear_job.last() {
                p { class: "av-error av-history-note", role: "alert", {err.msg.render(lang)} }
            }
            if let Some(error) = &state.history_error {
                p { class: "av-error av-history-note", role: "alert", {error.render(lang)} }
            } else if !has_rows {
                EmptyState { title: text(lang, "ui.availability.history.empty") }
            }
            if has_rows {
                ul { class: "av-history",
                    for check in state.history.iter().take(HISTORY_ROWS).cloned() {
                        HistoryRow {
                            key: "{check.id}",
                            current: current.as_deref() == Some(check.id.as_str()),
                            check,
                            now,
                            on_pick,
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn HistoryRow(
    check: UrlCheck,
    current: bool,
    now: UnixMs,
    on_pick: EventHandler<UrlCheck>,
) -> Element {
    let lang = *LANG.read();
    let (key, tone) = verdict_look(check.verdict);
    let verdict = text(lang, key);
    let meta = format!("{} · {verdict}", format_age(lang, now, check.tested_at));
    let picked = check.clone();
    rsx! {
        li {
            button {
                r#type: "button",
                class: "av-history-row",
                class: if current { "is-current" },
                aria_current: current.then_some("true"),
                onclick: move |_| on_pick.call(picked.clone()),
                span { class: "av-dot", "data-tone": tone.name(), aria_hidden: "true" }
                span { class: "av-history-text",
                    Trunc { text: check.url.clone(), max: 40 }
                    span { class: "av-history-meta", "{meta}" }
                }
            }
        }
    }
}
