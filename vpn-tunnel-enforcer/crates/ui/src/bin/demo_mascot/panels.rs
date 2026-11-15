//! The stand-in panel row (servers, traffic) and the bench controls that drive the brain.
use vpnte_ui::mascot::MascotBus;
use vpnte_ui::t;

use super::*;

pub(super) const SERVERS: [(&str, &str, &str, &str, u32); 3] = [
    (
        "srv-nl-ams",
        "nl",
        "Netherlands",
        "Netherlands · Amsterdam",
        38,
    ),
    ("srv-de-fra", "de", "Germany", "Germany · Frankfurt", 31),
    ("srv-fi-hel", "fi", "Finland", "Finland · Helsinki", 54),
];

/// Bench buttons: `(action, label key)`; phases switch the stand-in page with them.
pub(super) const BENCH: [(&str, &str); 22] = [
    ("off", "ui.mascot.demo.phaseOff"),
    ("connecting", "ui.mascot.demo.phaseConnecting"),
    ("on", "ui.mascot.demo.phaseOn"),
    ("alert", "ui.mascot.demo.phaseAlert"),
    ("leak-ok", "ui.mascot.demo.leakOk"),
    ("leak-warn", "ui.mascot.demo.leakWarn"),
    ("leak-fail", "ui.mascot.demo.leakFail"),
    ("proxy-start", "ui.mascot.demo.proxyStart"),
    ("proxy-rotate", "ui.mascot.demo.proxyRotate"),
    ("proxy-stop", "ui.mascot.demo.proxyStop"),
    ("proxy-stop-all", "ui.mascot.demo.stopAll"),
    ("notice-error", "ui.mascot.demo.noticeError"),
    ("notice-warn", "ui.mascot.demo.noticeWarn"),
    ("notice-ok", "ui.mascot.demo.noticeOk"),
    ("fast", "ui.mascot.demo.fast"),
    ("slow", "ui.mascot.demo.slow"),
    ("idle", "ui.mascot.demo.idle"),
    ("milestone", "ui.mascot.demo.milestone"),
    ("page", "ui.mascot.demo.page"),
    ("theme", "ui.mascot.demo.theme"),
    ("smart", "swiss.labelSmart"),
    ("leak-start", "swiss.check"),
];

/// The panel row: `servers` and `proxies` heads are spots on paper; the traffic panel holds the
/// bench controls in the bench scene.
pub(super) fn panels(bus: &MascotBus, b: Bench, bench: bool) -> Element {
    let running = (b.proxies)();
    let (stop_bus, start_bus) = (bus.clone(), bus.clone());
    rsx! {
        div { class: "swiss-panels",
            section { class: "swiss-panel",
                header {
                    class: "swiss-panel-head",
                    "data-perch": "traffic",
                    "data-perch-y": "bottom",
                    "data-perch-scale": "0.32",
                    "data-perch-fit": "gap",
                    span { class: "swiss-label swiss-label-ink", {t!("swiss.traffic")} }
                    span { class: "swiss-label flex items-center gap-1.5", {t!("swiss.noData")} }
                }
                if bench {
                    {bench_controls(bus, b)}
                } else {
                    {traffic_body()}
                }
            }
            section { class: "swiss-panel",
                header {
                    class: "swiss-panel-head",
                    "data-perch": "servers",
                    "data-perch-y": "bottom",
                    "data-perch-scale": "0.32",
                    "data-perch-fit": "gap",
                    span { class: "swiss-label swiss-label-ink", {t!("swiss.servers")} }
                    button { r#type: "button", class: "swiss-fact-action", {t!("swiss.pingAll")} }
                }
                div { class: "swiss-panel-body",
                    for (i, (id, cc, country, name, ping)) in SERVERS.into_iter().enumerate() {
                        div {
                            class: if i == 0 { "swiss-server-row group is-selected" } else { "swiss-server-row group" },
                            "data-perch": "server-{id}",
                            "data-perch-y": "bottom",
                            "data-perch-x": "0.55",
                            "data-perch-scale": "0.3",
                            "data-perch-fit": "gap",
                            span { class: "swiss-server-flag", {flag(cc, country)} }
                            button { r#type: "button", class: "swiss-server-name",
                                span { class: "truncate", "{name}" }
                            }
                            button { r#type: "button", class: "swiss-mono swiss-server-ping",
                                span { "{ping}" }
                            }
                            span { class: "swiss-mono swiss-server-health",
                                span { class: "swiss-health-dot" }
                                {t!("swiss.minAgo", n = 3)}
                            }
                        }
                    }
                }
            }
            section { class: "swiss-panel",
                header {
                    class: "swiss-panel-head",
                    "data-perch": "proxies",
                    "data-perch-y": "bottom",
                    "data-perch-scale": "0.32",
                    "data-perch-fit": "gap",
                    span { class: "swiss-label swiss-label-ink", {t!("ui.mascot.demo.proxies")} }
                    button {
                        r#type: "button",
                        class: "swiss-fact-action",
                        disabled: running == 0,
                        title: t!("ui.mascot.demo.stopAllTitle"),
                        onclick: move |_| act(&stop_bus, b, "proxy-stop-all"),
                        {t!("ui.mascot.demo.stopAll")}
                    }
                }
                div { class: "swiss-proxy-top",
                    div { class: "swiss-proxy-summary",
                        span { class: "swiss-proxy-count", "{running}" }
                        span { class: "swiss-label", {t!("ui.mascot.demo.running")} }
                    }
                    div { class: "swiss-proxy-add",
                        div { class: "relative flex flex-col gap-1.5 swiss-proxy-select",
                            label { class: "text-sm font-medium text-[var(--color-text)]", {t!("ui.mascot.demo.proxyServer")} }
                            div { class: "relative",
                                button {
                                    r#type: "button",
                                    class: "w-full flex items-center justify-between h-8 px-2 text-xs bg-[var(--color-card)] rounded-[var(--radius-sm)] border border-[var(--color-border)]",
                                    span { class: "truncate", "Germany · Frankfurt · DE · VLESS" }
                                }
                            }
                        }
                        button {
                            r#type: "button",
                            class: "swiss-proxy-start",
                            aria_label: t!("ui.mascot.demo.startProxy"),
                            onclick: move |_| act(&start_bus, b, "proxy-start"),
                            "+"
                        }
                    }
                }
                div { class: "swiss-panel-body",
                    if running == 0 {
                        p { class: "swiss-empty swiss-proxy-empty", {t!("ui.mascot.demo.noProxies")} }
                    }
                    for i in 0..running {
                        div { class: "swiss-proxy-row",
                            span { class: "swiss-proxy-name", "127.0.0.1:{10900 + i}" }
                        }
                    }
                }
            }
        }
    }
}

/// The traffic panel of the reference scenes (no data).
pub(super) fn traffic_body() -> Element {
    let mbps = t!("swiss.mbps");
    let gb = t!("swiss.gb");
    rsx! {
        div { class: "swiss-traffic-figures",
            div { class: "min-w-0",
                div { class: "swiss-label", {t!("swiss.download")} }
                div { class: "swiss-traffic-big is-dim", "0.0" }
            }
            div { class: "swiss-traffic-small",
                div {
                    span { class: "swiss-label", {t!("swiss.upload")} }
                    span { class: "swiss-mono", "0.0 {mbps}" }
                }
                div {
                    span { class: "swiss-label", {t!("swiss.session")} }
                    span { class: "swiss-mono", "0.00 {gb}" }
                }
            }
        }
        div { class: "swiss-bars",
            for _ in 0..48 {
                div { class: "swiss-bar-slot",
                    div { class: "swiss-bar is-off", style: "height: 4%;" }
                }
            }
        }
    }
}

pub(super) fn bench_controls(bus: &MascotBus, b: Bench) -> Element {
    rsx! {
        div { class: "swiss-panel-body mascot-bench",
            span { class: "swiss-label", {t!("ui.mascot.demo.bench")} }
            for (action, key) in BENCH {
                button {
                    r#type: "button",
                    "data-action": action,
                    onclick: {
                        let bus = bus.clone();
                        move |_| act(&bus, b, action)
                    },
                    {t!(key)}
                }
            }
        }
    }
}
