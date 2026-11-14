//! The stand-in start page: sidebar, facts strip, slab with the identity column, the leak
//! banner; every `data-perch` spot the brain uses.
use std::time::Duration;

use vpnte_ui::mascot::{MascotBus, MascotEvent, MascotHost};
use vpnte_ui::pages::Page;
use vpnte_ui::t;

use super::*;

/// The real sidebar's labels («Журнал» for the logs); Maintenance is advanced-only, so not here.
pub(super) const NAV: [(&str, &str); 9] = [
    ("dashboard", Page::Dashboard.label_key()),
    ("apps", Page::Apps.label_key()),
    ("servers", Page::Servers.label_key()),
    ("speedtest", Page::SpeedTest.label_key()),
    ("availability", Page::Availability.label_key()),
    ("trafficHistory", Page::TrafficHistory.label_key()),
    ("schedule", Page::Schedule.label_key()),
    ("logs", Page::Logs.label_key()),
    ("settings", Page::Settings.label_key()),
];

/// The reference sidebar: wordmark, numbered nav (`nav-*` spots) and the clock spot.
pub(super) fn sidebar() -> Element {
    let version = env!("CARGO_PKG_VERSION");
    rsx! {
        aside { class: "c-swiss swiss-sidebar flex h-full shrink-0 flex-col border-r border-[var(--rule)] bg-[var(--paper)] p-5 text-[var(--ink)]",
            div { class: "swiss-brand", "Tunnel" br {} "Enforcer" }
            div { class: "swiss-mono mt-1.5 text-[10px] text-[var(--mute)]", "v{version} / win-x64" }
            nav { class: "mt-10 flex flex-col",
                for (i, (id, key)) in NAV.into_iter().enumerate() {
                    button {
                        r#type: "button",
                        class: "swiss-nav-item",
                        aria_current: if i == 0 { "page" },
                        "data-perch": "nav-{id}",
                        "data-perch-y": "bottom",
                        "data-perch-x": "0.85",
                        "data-perch-scale": "0.3",
                        "data-perch-fit": "gap",
                        span { class: "swiss-nav-num swiss-mono", "{i + 1:02}" }
                        span { class: "swiss-nav-label", {t!(key)} }
                        span { class: "swiss-nav-mark", aria_hidden: "true" }
                    }
                }
            }
            div { class: "mt-auto pt-3", "data-perch": "clock", "data-perch-x": "0.55", "data-perch-scale": "0.5",
                span { class: "swiss-mono text-[15px] font-medium text-[var(--mute)]",
                    span { class: "tabular-nums",
                        "12"
                        span { class: "opacity-30", ":" }
                        "34"
                    }
                }
            }
        }
    }
}

/// The facts strip: `smart` and `leak` spots on paper; their actions drive the mascot.
pub(super) fn facts(bus: &MascotBus, b: Bench) -> Element {
    let smart = (b.smart)();
    let connected = (b.look)().connected();
    let (smart_bus, leak_bus) = (bus.clone(), bus.clone());
    rsx! {
        div { class: "swiss-facts",
            div { class: "swiss-fact", "data-perch-y": "bottom", "data-perch-x": "0.6", "data-perch-scale": "0.36", "data-perch-fit": "gap",
                span { class: "swiss-label shrink-0", {t!("swiss.labelMode")} }
                span { class: "swiss-fact-value", {t!("view.fact.modeTunnel")} }
            }
            div { class: "swiss-fact", "data-perch": "smart", "data-perch-y": "bottom", "data-perch-x": "0.6", "data-perch-scale": "0.36", "data-perch-fit": "gap",
                span { class: "swiss-label shrink-0", {t!("swiss.labelSmart")} }
                span { class: "swiss-fact-value", title: t!("swiss.smartPending"),
                    if smart { {t!("swiss.on")} } else { {t!("swiss.off")} }
                }
                button {
                    r#type: "button",
                    class: "swiss-fact-action",
                    aria_label: if smart { t!("swiss.smartTurnOff") } else { t!("swiss.smartTurnOn") },
                    title: t!("swiss.smartPending"),
                    onclick: move |_| act(&smart_bus, b, "smart"),
                    if smart { {t!("swiss.turnOff")} } else { {t!("swiss.turnOn")} }
                }
            }
            div { class: "swiss-fact", "data-perch": "killswitch", "data-perch-y": "bottom", "data-perch-x": "0.6", "data-perch-scale": "0.36", "data-perch-fit": "gap",
                span { class: "swiss-label shrink-0", {t!("dashboard.killSwitchStatus")} }
                if connected {
                    span { class: "swiss-fact-value", {t!("swiss.ksHolding")} }
                } else {
                    span { class: "swiss-fact-value is-dim", {t!("swiss.ksOff")} }
                }
            }
            div { class: "swiss-fact", "data-perch": "leak", "data-perch-y": "bottom", "data-perch-x": "0.6", "data-perch-scale": "0.36", "data-perch-fit": "gap",
                span { class: "swiss-label shrink-0", {t!("swiss.labelLeaks")} }
                span { class: "swiss-fact-value is-dim", "—" }
                button {
                    r#type: "button",
                    class: "swiss-fact-action",
                    aria_label: t!("swiss.checkAria"),
                    onclick: move |_| act(&leak_bus, b, "leak-start"),
                    {t!("swiss.check")}
                }
            }
        }
    }
}

/// The status slab: the `home` spot beside the big word (orange = signal surface when connected),
/// the ink power button (`toggle`, inverse surface while off), and the mascot overlay itself,
/// mounted where the reference has it.
pub(super) fn slab(bus: &MascotBus, look: Look, greet_time: Option<Duration>) -> Element {
    // FitWord results of the reference at 1100x720 (the dashboard package fits the word live).
    let (word_key, word_px, slab_class) = match look {
        Look::Exposed => (
            "dashboard.swissWordExposed",
            "95.5543px",
            "c-swiss swiss-slab",
        ),
        Look::Linking => (
            "dashboard.swissWordLinking",
            "107.072px",
            "c-swiss swiss-slab",
        ),
        Look::Secure => (
            "dashboard.swissWordSecure",
            "108px",
            "c-swiss swiss-slab is-on",
        ),
        Look::Leak => (
            "dashboard.swissWordLeak",
            "108px",
            "c-swiss swiss-slab is-alert",
        ),
    };
    let word = t!(word_key);
    let caption = match look {
        Look::Exposed => t!("dashboard.disconnected"),
        Look::Linking => t!("dashboard.connecting"),
        Look::Secure | Look::Leak => t!("dashboard.connected"),
    };
    let in_tunnel = t!("dashboard.swissInTunnel");
    let (power_class, power_text) = if look.connected() {
        ("swiss-power is-on", t!("dashboard.swissDisable"))
    } else {
        ("swiss-power", t!("dashboard.swissEnable"))
    };
    let (in_bus, out_bus) = (bus.clone(), bus.clone());
    rsx! {
        section { class: slab_class,
            div { class: "swiss-slab-main",
                h2 { class: "sr-only", {t!("dashboard.vpnToggle")} }
                div { class: "swiss-word-row relative",
                    div { class: "swiss-word-wrap relative", aria_hidden: "true",
                        span {
                            class: "swiss-word pointer-events-none invisible absolute left-0 top-0",
                            style: "font-size: 100px;",
                            "{word}"
                        }
                        div { class: "swiss-word", style: "font-size: {word_px};",
                            span {
                                for (i, ch) in word.chars().enumerate() {
                                    span { class: "letter", style: "animation-delay: {i * 38}ms;", "{ch}" }
                                }
                            }
                        }
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
                    p { class: "swiss-caption", role: "status", aria_live: "polite", "{caption}" }
                    if look.connected() {
                        span { class: "swiss-uptime", "· 00:00:05 {in_tunnel}" }
                    }
                }
            }
            div { class: "swiss-slab-side",
                div { class: "swiss-identity", {identity(look)} }
                button {
                    aria_label: "{caption}",
                    class: power_class,
                    title: "{power_text}",
                    "data-perch": "toggle",
                    "data-perch-y": "bottom",
                    "data-perch-x": "0.6",
                    "data-perch-scale": "0.48",
                    "data-perch-fit": "gap",
                    tabindex: "0",
                    onmouseenter: move |_| in_bus.send(MascotEvent::HoverIn),
                    onmouseleave: move |_| out_bus.send(MascotEvent::HoverOut),
                    div { class: "swiss-power-content",
                        span { class: "truncate", "{power_text}" }
                        svg {
                            xmlns: "http://www.w3.org/2000/svg",
                            width: "20",
                            height: "20",
                            view_box: "0 0 24 24",
                            fill: "none",
                            stroke: "currentColor",
                            stroke_width: "2.5",
                            stroke_linecap: "round",
                            stroke_linejoin: "round",
                            class: "lucide lucide-arrow-right swiss-power-arrow shrink-0",
                            path { d: "M5 12h14" }
                            path { d: "m12 5 7 7-7 7" }
                        }
                    }
                }
            }
            div { class: "swiss-progress", aria_hidden: "true",
                for i in 1..=10 {
                    span { class: "swiss-progress-cell",
                        span { class: "swiss-mono", "{i:02}" }
                    }
                }
            }
            MascotHost { greet_time }
        }
    }
}

pub(super) fn flag(cc: &str, country: &str) -> Element {
    rsx! {
        span {
            class: "fi fis inline-block shrink-0 rounded-full ring-1 ring-inset ring-[color-mix(in_srgb,var(--color-border-strong)_45%,transparent)] fi-{cc}",
            role: "img",
            aria_label: "{country}",
            title: "{country}",
            style: "width: 14px; height: 14px; font-size: 14px;",
        }
    }
}

/// Exit IP (the `ip` spot), real address and node, as the reference fixtures show them.
pub(super) fn identity(look: Look) -> Element {
    let exit_ip = if look == Look::Secure {
        "198.51.100.23"
    } else {
        "203.0.113.47"
    };
    let copy = t!("dashboard.swissCopy");
    let leak = t!("dashboard.swissIpLeak");
    rsx! {
        div {
            div { class: "swiss-label", {t!("dashboard.swissSitesSee")} }
            button { r#type: "button", class: "swiss-ip", title: "{copy}",
                span { class: "roll", "{exit_ip}" }
                span { class: "swiss-ip-copy", "{copy}" }
            }
            div {
                class: if look == Look::Leak { "swiss-sub is-alert" } else { "swiss-sub" },
                "data-perch": "ip",
                "data-perch-y": "bottom",
                "data-perch-x": "1",
                "data-perch-scale": "0.24",
                "data-perch-fit": "gap",
                if look == Look::Secure {
                    {flag("nl", "Netherlands")}
                    span { "Netherlands, Amsterdam" }
                } else if look == Look::Leak {
                    span { "— {leak}" }
                } else {
                    span { {t!("dashboard.swissIpYourIsp")} }
                }
            }
        }
        div {
            div { class: "swiss-label", {t!("dashboard.swissRealAddress")} }
            if look == Look::Secure {
                div { class: "swiss-real is-hidden", "203.0.113.47" }
            } else {
                div { class: "swiss-real", "203.0.113.47" }
                div { class: "swiss-sub is-alert", {t!("dashboard.swissExposedToAll")} }
            }
        }
        div {
            div { class: "swiss-label", {t!("dashboard.swissNode")} }
            div { class: "swiss-node",
                {flag("nl", "Netherlands")}
                span { class: "truncate", "Netherlands · Amsterdam" }
            }
            div { class: "swiss-sub", {t!("view.identity.metaPing", protocol = "VLESS", ms = 38)} }
        }
    }
}

/// The leak banner above the facts strip (the `mascot-alert` reference has it).
pub(super) fn leak_banner() -> Element {
    rsx! {
        div { class: "glass rounded-[var(--radius-md)] transition-colors duration-[var(--transition-normal)] p-5 !border-[var(--color-danger)]/40 !bg-[var(--color-danger)]/10",
            div { class: "flex items-center gap-3",
                svg {
                    xmlns: "http://www.w3.org/2000/svg",
                    width: "24",
                    height: "24",
                    view_box: "0 0 24 24",
                    fill: "none",
                    stroke: "currentColor",
                    stroke_width: "2",
                    stroke_linecap: "round",
                    stroke_linejoin: "round",
                    class: "lucide lucide-shield-off w-6 h-6 text-[var(--color-danger)] flex-shrink-0",
                    path { d: "m2 2 20 20" }
                    path { d: "M5 5a1 1 0 0 0-1 1v7c0 5 3.5 7.5 7.67 8.94a1 1 0 0 0 .67.01c2.35-.82 4.48-1.97 5.9-3.71" }
                    path { d: "M9.309 3.652A12.252 12.252 0 0 0 11.24 2.28a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1v7a9.784 9.784 0 0 1-.08 1.264" }
                }
                div {
                    p { class: "text-sm font-semibold text-[var(--color-danger)]", {t!("ui.mascot.demo.leakTitle")} }
                    p { class: "text-xs text-[var(--color-danger)]/80", {t!("ui.mascot.demo.leakBody")} }
                }
            }
        }
    }
}
