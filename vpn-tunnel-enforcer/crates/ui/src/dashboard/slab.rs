//! The status slab: the big word (FitWord), the live caption and uptime, the identity column, the
//! transient cancel / confirm block, the power button, the ten-cell ruler and the mascot overlay.
use std::iter;
use std::time::{Duration, Instant};

use dioxus::prelude::*;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_view::fmt::{elapsed, format_uptime};
use vpnte_view::labels::{
    ExitLine, PowerLook, RealLine, cancel_label, exit_line, power_button, real_line, status_label,
};
use vpnte_view::mascot::MascotEvent;
use vpnte_view::swiss::{self, OpWindow, RULER_CELLS, SwissInput};

use super::model::{Hold, NodeLine, engine_caption, node_line};
use super::{Dash, EngineLine};
use crate::lang::tr;
use crate::mascot::MascotHost;
use crate::pages::{nav_number, use_page_active};
use crate::panels::icons::{ArrowRight, Spinner, Square};
use crate::panels::{Flag, LocalPings, ServersView};
use crate::t;

/// Delay between the letters of the big word.
const LETTER_STEP_MS: usize = 38;

/// `section.swiss-slab`.
#[component]
pub(super) fn Slab(servers: Signal<ServersView>, local_pings: Signal<LocalPings>) -> Element {
    let dash = use_context::<Dash>();
    let view = dash.snapshot();
    let conn = &view.conn;
    let state = swiss::derive_swiss_state(&SwissInput::new(conn, &view.exit));
    let busy = conn.swiss_busy();
    let word = tr(&state.word());
    rsx! {
        section {
            class: "c-swiss swiss-slab",
            class: if state.is_on() { "is-on" },
            class: if state.is_alert() { "is-alert" },
            div { class: "swiss-slab-main",
                if busy {
                    div { class: "swiss-stripes", aria_hidden: "true" }
                }
                // the slab itself carries no visible heading
                h2 { class: "sr-only", {t!("dashboard.vpnToggle")} }
                div { class: "swiss-word-row relative",
                    // keyed by the word: a new word remounts and replays the letters
                    for word in iter::once(word) {
                        FitWord { key: "{word}", text: word.clone(), busy_dot: busy }
                    }
                    div {
                        class: "swiss-home",
                        "data-perch": "home",
                        "data-perch-y": "bottom",
                        "data-perch-scale": "0.8",
                        aria_hidden: "true",
                    }
                }
                div { class: "swiss-caption-row relative",
                    // while cancelling the power button shows the text; screen readers keep it here
                    p {
                        id: "{dash.caption_id}",
                        class: if conn.cancelling { "sr-only" } else { "swiss-caption" },
                        role: "status",
                        aria_live: "polite",
                        {tr(&status_label(conn))}
                    }
                    if let Some(since) = conn.uptime_since() {
                        Uptime { since }
                    }
                }
            }
            Side { servers, local_pings }
            Progress { op: conn.operation, busy }
            MascotHost {}
        }
    }
}

/// The big state word, sized by `dashboard.js` so every word is equally wide (decorative: the
/// caption is the live status). The invisible probe is the same word at 100 px.
#[component]
fn FitWord(text: String, busy_dot: bool) -> Element {
    rsx! {
        div { class: "swiss-word-wrap relative", aria_hidden: "true",
            span {
                class: "swiss-word pointer-events-none invisible absolute left-0 top-0",
                style: "font-size: 100px;",
                "{text}"
                if busy_dot {
                    "."
                }
            }
            div { class: "swiss-word", style: "font-size: 96px;",
                span {
                    for (i , letter) in text.chars().enumerate() {
                        span {
                            key: "{i}",
                            class: "letter",
                            style: "animation-delay: {i * LETTER_STEP_MS}ms;",
                            "{letter}"
                        }
                    }
                }
                if busy_dot {
                    span { class: "blink", "." }
                }
            }
        }
    }
}

/// «· 00:12:34 в туннеле»: its own second ticker. Like the sidebar clock (D-14) the loop ends
/// while the page is not shown (another page, the window in the tray) and restarts, correct at
/// once, when it is shown again.
#[component]
fn Uptime(since: UnixMs) -> Element {
    let active = use_page_active();
    let mut now = use_signal(now_ms);
    use_resource(move || {
        let shown = active();
        async move {
            if !shown {
                return;
            }
            loop {
                now.set(now_ms());
                // wake on the next whole second of the session clock
                let ms = 1_000 - (now_ms() - since).rem_euclid(1_000);
                tokio::time::sleep(Duration::from_millis(ms as u64 + 5)).await;
            }
        }
    });
    let text = format!(
        "· {} {}",
        format_uptime(elapsed(since, now())),
        t!("dashboard.swissInTunnel")
    );
    rsx! {
        span { class: "swiss-uptime", "{text}" }
    }
}

/// `div.swiss-slab-side`: identity column, transient block, power button.
#[component]
fn Side(servers: Signal<ServersView>, local_pings: Signal<LocalPings>) -> Element {
    let dash = use_context::<Dash>();
    let view = dash.snapshot();
    let conn = &view.conn;
    let exit = exit_line(conn, &view.exit);
    let real = real_line(conn, &view.exit, *dash.home.read());
    let node = node_line(&servers.read(), &local_pings.read());
    let cancel = cancel_label(conn);
    let confirm_open = dash.confirm.read().is_open();
    rsx! {
        div { class: "swiss-slab-side",
            div { class: "swiss-identity",
                ExitBlock { line: exit, country: view.exit_country.clone() }
                RealBlock { line: real }
                NodeBlock { node, engine: view.engine.clone() }
            }
            if confirm_open || cancel.is_some() {
                div { class: "swiss-transient",
                    if confirm_open {
                        ConfirmRow {}
                    }
                    if let Some(label) = cancel {
                        CancelButton { label: tr(&label), cancelling: conn.cancelling }
                    }
                }
            }
            PowerButton {}
        }
    }
}

/// «Выходной IP»: the address (click copies it) and its sub-line.
#[component]
fn ExitBlock(line: ExitLine, country: Option<String>) -> Element {
    let dash = use_context::<Dash>();
    let copied = dash.copied.read().is_some();
    let sub = &line.sub;
    let text = if sub.dash {
        format!("— {}", tr(&sub.text))
    } else {
        tr(&sub.text)
    };
    // the coin needs the code; the line's own country is the geo name
    let flag = sub.flag.as_ref().and(country);
    rsx! {
        div {
            div { class: "swiss-label", {t!("dashboard.swissSitesSee")} }
            if let Some(ip) = line.ip {
                button {
                    r#type: "button",
                    class: "swiss-ip",
                    class: if line.dim { "is-dim" },
                    title: t!("dashboard.swissCopy"),
                    onclick: move |_| dash.copy_ip(ip),
                    // keyed by the address: a new address rolls in
                    for shown in iter::once(ip.to_string()) {
                        span { key: "{shown}", class: "roll", "{shown}" }
                    }
                    span {
                        class: "swiss-ip-copy",
                        class: if copied { "is-copied" },
                        if copied {
                            {t!("dashboard.swissCopied")}
                        } else {
                            {t!("dashboard.swissCopy")}
                        }
                    }
                }
            } else if line.unmeasured {
                // words at the real address's size inside the address's own line box: nothing moves
                div { class: "swiss-ip is-dim is-words",
                    span { {t!("view.identity.unmeasured")} }
                }
            } else {
                div { class: "swiss-ip is-dim", "—" }
            }
            div {
                class: "swiss-sub",
                class: if sub.alert { "is-alert" },
                "data-perch": "ip",
                "data-perch-y": "bottom",
                "data-perch-x": "1",
                "data-perch-scale": "0.24",
                "data-perch-fit": "gap",
                if let Some(code) = flag {
                    Flag { country: code, size: 14 }
                }
                span { "{text}" }
            }
        }
    }
}

/// «Настоящий адрес»: struck through behind a settled tunnel, «открыт всем» when exposed, dim
/// while nothing is proven either way.
#[component]
fn RealBlock(line: RealLine) -> Element {
    let address = match line.ip {
        Some(ip) => ip.to_string(),
        None if line.unmeasured() => t!("view.identity.unmeasured"),
        None => "—".to_owned(),
    };
    let dim = line.look == vpnte_view::labels::RealLook::Neutral || line.unmeasured();
    rsx! {
        div {
            div { class: "swiss-label", {t!("dashboard.swissRealAddress")} }
            div {
                class: "swiss-real",
                class: if line.struck() { "is-hidden" },
                class: if dim { "is-dim" },
                "{address}"
            }
            if let Some(sub) = line.sub() {
                div { class: "swiss-sub is-alert", {tr(&sub.text)} }
            }
        }
    }
}

/// «Узел»: the active server with its flag, protocol and ping, and the engine that carries the
/// running session (the choice is never hidden). The engine joins the node's meta line («VLESS ·
/// 38 мс · Xray · REALITY», cut with an ellipsis, the whole line in its title): a line of its own
/// made the slab 20 px taller than the reference and the panel row below clipped its lists at the
/// default window size.
#[component]
fn NodeBlock(node: Option<NodeLine>, engine: Option<EngineLine>) -> Element {
    let engine = engine.map(|line| {
        let reason = line.reason.as_ref().map(tr);
        engine_caption(&line, reason)
    });
    let engine_title = t!("ui.dashboard.engineTitle");
    rsx! {
        div {
            div { class: "swiss-label", {t!("dashboard.swissNode")} }
            if let Some(node) = node {
                div { class: "swiss-node",
                    if let Some(country) = node.country {
                        Flag { country, size: 14 }
                    }
                    span { class: "truncate", "{node.name}" }
                }
                NodeMeta { meta: tr(&node.meta), engine, engine_title }
            } else {
                div { class: "swiss-node is-dim", {t!("dashboard.swissNoServer")} }
                if let Some(caption) = engine {
                    div { class: "swiss-sub", "data-engine": "", title: engine_title, "{caption}" }
                }
            }
        }
    }
}

/// The node's meta line, with the engine caption appended when one runs.
#[component]
fn NodeMeta(meta: String, engine: Option<String>, engine_title: String) -> Element {
    // the whole line as the title only when the engine may push it past the column
    let title = engine.as_ref().map(|caption| format!("{meta} · {caption}"));
    rsx! {
        div {
            class: "swiss-sub",
            class: if title.is_some() { "truncate" },
            title,
            "{meta}"
            if let Some(caption) = engine {
                span { "data-engine": "", title: engine_title, " · {caption}" }
            }
        }
    }
}

/// «Отключить VPN…?» with «Да, отключить» / «Отмена»; the pointer or the focus over it holds the
/// 3 s timer (D-01).
#[component]
fn ConfirmRow() -> Element {
    let dash = use_context::<Dash>();
    let (yes, no) = (dash.clone(), dash.clone());
    rsx! {
        div {
            class: "flex flex-col gap-2 enter-up",
            onmouseenter: holder::<MouseEvent>(&dash, Hold::Pointer, true),
            onmouseleave: holder::<MouseEvent>(&dash, Hold::Pointer, false),
            onfocusin: holder::<FocusEvent>(&dash, Hold::Focus, true),
            onfocusout: holder::<FocusEvent>(&dash, Hold::Focus, false),
            p { class: "swiss-confirm-text", {t!("dashboard.disconnectConfirmation")} }
            div { class: "swiss-confirm-actions",
                button {
                    r#type: "button",
                    class: "swiss-confirm-yes",
                    onclick: move |_| yes.confirm_yes(),
                    {t!("dashboard.confirmDisconnect")}
                }
                button {
                    r#type: "button",
                    class: "swiss-confirm-no",
                    onclick: move |_| no.confirm_no(),
                    {t!("dashboard.cancelDisconnect")}
                }
            }
        }
    }
}

/// An event handler that holds (`on`) or releases the confirmation's timer.
fn holder<E: 'static>(dash: &Dash, by: Hold, on: bool) -> impl FnMut(E) + 'static {
    let dash = dash.clone();
    move |_| dash.hold_confirm(by, on)
}

/// «Отменить подключение» / «Отменить смену сервера»; «Отменяем…» with a spinner once pressed.
#[component]
fn CancelButton(label: String, cancelling: bool) -> Element {
    let dash = use_context::<Dash>();
    rsx! {
        button {
            r#type: "button",
            class: "swiss-cancel-btn",
            disabled: cancelling,
            aria_busy: if cancelling { "true" } else { "false" },
            onclick: move |_| dash.cancel_transition(),
            if cancelling {
                Spinner { class: "animate-spin", size: 13 }
            } else {
                Square { size: 13 }
            }
            "{label}"
        }
    }
}

/// The power button. Its visible text is its name (D-02: no `aria-label`); the status caption
/// describes it.
#[component]
fn PowerButton() -> Element {
    let dash = use_context::<Dash>();
    let conn = dash.conn();
    let power = power_button(&conn);
    let look = match power.look {
        PowerLook::Plain => None,
        PowerLook::On => Some("is-on"),
        PowerLook::Switching => Some("is-busy"),
        PowerLook::Cancelling => Some("is-cancel"),
    };
    let (press, enter, leave) = (dash.clone(), dash.bus.clone(), dash.bus.clone());
    rsx! {
        button {
            r#type: "button",
            class: "swiss-power",
            class: if let Some(look) = look { "{look}" },
            class: if power.waiting { "is-wait" },
            disabled: power.waiting,
            title: tr(&power.title),
            aria_describedby: "{dash.caption_id}",
            "data-perch": "toggle",
            "data-perch-y": "bottom",
            "data-perch-x": "0.6",
            "data-perch-scale": "0.48",
            "data-perch-fit": "gap",
            onmouseenter: move |_| enter.send(MascotEvent::HoverIn),
            onmouseleave: move |_| leave.send(MascotEvent::HoverOut),
            onclick: move |_| press.press_power(),
            if power.look == PowerLook::Switching {
                div { class: "absolute inset-0 border-2 border-[var(--signal)] power-ring" }
            }
            if power.look == PowerLook::On {
                // one-shot flash when the slab turns on (replays only on a new mount)
                div { class: "absolute inset-0 bg-[var(--signal)] power-flash" }
            }
            div { class: "swiss-power-content",
                span { class: "truncate", {tr(&power.label)} }
                if power.waiting {
                    Spinner { class: "shrink-0 animate-spin", size: 20 }
                } else {
                    ArrowRight { class: "swiss-power-arrow shrink-0", size: 20 }
                }
            }
        }
    }
}

/// The ten-cell ruler: filled by elapsed time against the operation's deadline while busy.
#[component]
fn Progress(op: Option<OpWindow>, busy: bool) -> Element {
    if busy {
        rsx! {
            LiveProgress { op }
        }
    } else {
        rsx! {
            Cells { ruler: swiss::Ruler::default(), busy: false }
        }
    }
}

/// The busy ruler with its 250 ms ticker (paused while the page is not shown).
#[component]
fn LiveProgress(op: Option<OpWindow>) -> Element {
    let active = use_page_active();
    let mut now = use_signal(Instant::now);
    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if *active.peek() {
                now.set(Instant::now());
            }
        }
    });
    let ruler = swiss::ruler(op.as_ref(), true, now());
    rsx! {
        Cells { ruler, busy: true }
    }
}

#[component]
fn Cells(ruler: swiss::Ruler, busy: bool) -> Element {
    rsx! {
        div {
            class: "swiss-progress",
            class: if ruler.indeterminate { "is-indeterminate" },
            title: busy.then(|| t!("swiss.progressHint")),
            aria_hidden: "true",
            for i in 0..RULER_CELLS {
                span {
                    key: "{i}",
                    class: "swiss-progress-cell",
                    class: if i < ruler.lit { "is-done" },
                    span { class: "swiss-mono", {nav_number(usize::from(i))} }
                }
            }
        }
    }
}
