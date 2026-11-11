//! The notices above the facts strip, in the reference markup: auto-restart, a second TUN, the
//! kill-switch banner, the leak card and the foreign-VPN notice strip. The old Tailwind classes
//! are kept (utilities.css draws them; the inert `…/NN` tint classes stay inert, as shipped).
use dioxus::prelude::*;

use super::Dash;
use super::icons::{Lock, ShieldOff, Spinner};
use super::model::banners;
use crate::lang::tr;
use crate::t;

/// Every notice the snapshot calls for.
#[component]
pub(super) fn Banners() -> Element {
    let dash = use_context::<Dash>();
    let shown = banners(&dash.snapshot());
    rsx! {
        if let Some(progress) = shown.restart {
            RestartBanner { progress }
        }
        if let Some(name) = shown.competing_tun {
            CompetingTunBanner { name }
        }
        if let Some(banner) = shown.kill_switch {
            KillSwitchBanner { title: tr(&banner.title), body: tr(&banner.body) }
        }
        if shown.leak {
            LeakCard {}
        }
        if let Some(name) = shown.foreign_vpn {
            ForeignVpnNotice { name }
        }
    }
}

/// Auto-restart after an engine crash, «1/3».
#[component]
fn RestartBanner(progress: String) -> Element {
    rsx! {
        div {
            class: "rounded-[var(--radius-md)] border-2 border-[var(--color-warning)]/60 bg-[var(--color-warning)]/10 p-4 shadow-[0_0_20px_rgba(255,165,0,0.15)] enter-down",
            role: "alert",
            div { class: "flex items-center gap-3",
                Spinner { class: "w-6 h-6 text-[var(--color-warning)] animate-spin flex-shrink-0" }
                div {
                    // two text nodes, as the reference: the title and the progress
                    p { class: "text-sm font-semibold text-[var(--color-warning)]",
                        {format!("{} ", t!("ui.dashboard.restartTitle"))}
                        "{progress}"
                    }
                    p { class: "text-xs text-[var(--color-warning)]/80 mt-0.5",
                        {t!("ui.dashboard.restartBody")}
                    }
                }
            }
        }
    }
}

/// A second TUN adapter next to ours.
#[component]
fn CompetingTunBanner(name: String) -> Element {
    rsx! {
        div {
            class: "rounded-[var(--radius-md)] border border-[var(--color-warning)]/60 bg-[var(--color-warning)]/10 p-4 enter-down",
            role: "alert",
            aria_live: "polite",
            p { class: "text-sm font-semibold text-[var(--color-warning)]",
                {format!("{} ", t!("ui.dashboard.competingTitle"))}
                "{name}"
            }
            p { class: "text-xs text-[var(--color-text-secondary)] mt-1",
                {t!("ui.dashboard.competingBody")}
            }
        }
    }
}

/// Our kill-switch holds (or cannot be confirmed) while no tunnel runs. The old third button,
/// the Windows Firewall factory reset, is gone (D-10): our filters live in our own WFP provider.
#[component]
fn KillSwitchBanner(title: String, body: String) -> Element {
    let dash = use_context::<Dash>();
    let checking = dash.view.read().firewall.checking || dash.recheck.running();
    let releasing = dash.release.running();
    let (recheck, release) = (dash.clone(), dash.clone());
    rsx! {
        div {
            class: "rounded-[var(--radius-md)] border-2 border-[var(--color-danger)]/60 bg-[var(--color-danger)]/15 p-5 shadow-[0_0_30px_rgba(255,69,58,0.25)] enter-down",
            role: "alert",
            aria_live: "assertive",
            div { class: "flex items-start gap-4",
                Lock { class: "w-8 h-8 text-[var(--color-danger)] flex-shrink-0 mt-0.5" }
                div { class: "flex-1",
                    p { class: "text-lg font-semibold text-[var(--color-danger)]", "{title}" }
                    p { class: "text-sm text-[var(--color-danger)]/90 mt-1", "{body}" }
                    div { class: "flex flex-wrap gap-2 mt-3",
                        button {
                            class: "text-sm font-medium px-4 py-2 rounded-[var(--radius-sm)] border border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger)]/10 transition-colors duration-[var(--transition-fast)] disabled:opacity-50",
                            disabled: checking || releasing,
                            aria_busy: if checking { "true" } else { "false" },
                            onclick: move |_| recheck.recheck_firewall(),
                            if checking {
                                {t!("dashboard.firewallChecking")}
                            } else {
                                {t!("dashboard.firewallRecheck")}
                            }
                        }
                        button {
                            class: "text-sm font-medium flex items-center gap-2 px-4 py-2 rounded-[var(--radius-sm)] bg-[var(--color-danger)] text-white hover:bg-[var(--color-danger)]/90 transition-colors duration-[var(--transition-fast)] disabled:opacity-50",
                            disabled: releasing,
                            onclick: move |_| release.release_kill_switch(),
                            if releasing {
                                Spinner { class: "w-4 h-4 animate-spin" }
                            } else {
                                ShieldOff { class: "w-4 h-4" }
                            }
                            {t!("ui.dashboard.releaseKillSwitch")}
                        }
                    }
                }
            }
        }
    }
}

/// The real address is visible while protection should be on.
#[component]
fn LeakCard() -> Element {
    rsx! {
        div { class: "glass rounded-[var(--radius-md)] transition-colors duration-[var(--transition-normal)] p-5 !border-[var(--color-danger)]/40 !bg-[var(--color-danger)]/10",
            div { class: "flex items-center gap-3",
                ShieldOff { class: "w-6 h-6 text-[var(--color-danger)] flex-shrink-0" }
                div {
                    p { class: "text-sm font-semibold text-[var(--color-danger)]",
                        {t!("ui.dashboard.leakTitle")}
                    }
                    p { class: "text-xs text-[var(--color-danger)]/80",
                        {t!("ui.dashboard.leakBody")}
                    }
                }
            }
        }
    }
}

/// Another VPN's adapter is up while ours is down: its stack answers our pings.
#[component]
fn ForeignVpnNotice(name: String) -> Element {
    rsx! {
        div { class: "overflow-hidden",
            div { class: "c-swiss swiss-notice", role: "note",
                // two text nodes, as the reference: the title and «: Happ»
                span { class: "swiss-label swiss-notice-tag",
                    {t!("ui.dashboard.foreignVpn.title")}
                    ": {name}"
                }
                p { class: "swiss-notice-body", {t!("ui.dashboard.foreignVpn.body")} }
            }
        }
    }
}
