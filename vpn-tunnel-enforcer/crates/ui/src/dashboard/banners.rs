//! The notices above the facts strip, in the reference markup: the paused kill switch, auto-
//! restart, a second TUN, the kill-switch banner, the leak card, the foreign-VPN notice strip,
//! the automatic server choice's strip, the network-mode strip and the strip of a saved Tunnel
//! mode that waits for the helper service.
//! The old Tailwind classes are kept (utilities.css draws them; the inert `…/NN` tint classes
//! stay inert, as shipped).
use std::time::Duration;

use dioxus::prelude::*;
use vpnte_base::types::now_ms;

use super::model::{banners, countdown};
use super::{Dash, PauseLine};
use crate::lang::tr;
use crate::pages::use_page_active;
use crate::panels::icons::{Lock, ShieldOff, Spinner};
use crate::t;

/// Every notice the snapshot calls for.
#[component]
pub(super) fn Banners() -> Element {
    let dash = use_context::<Dash>();
    let shown = banners(&dash.snapshot());
    rsx! {
        if let Some(line) = shown.pause {
            PauseStrip { line }
        }
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
            ForeignVpnNotice { name: name.clone() }
            super::always::AllowVpnOffer { name }
        }
        if let Some(name) = shown.no_pause_vpn {
            NoPauseNotice { name }
        }
        if shown.proxy_taken {
            ProxyTakenStrip {}
        }
        if let Some(line) = dash.snapshot().autopick {
            PickStrip { title: tr(&line.title), body: line.body.as_ref().map(tr) }
        }
        super::netmode::NetBanner {}
        crate::helper::TunnelStrip { tunnel_mode: !dash.snapshot().soft_mode }
        crate::updates::UpdateBanner {}
    }
}

/// «Интернет на паузе: VPN переподключается… следующая попытка через 0:40» with «Подключить»
/// and «Продолжить без VPN» (research killswitch 5.2; in "Always" «Выключить «Всегда»», ks-d):
/// calm, in the start page's own notice style; the countdown ticks only while the page is shown.
#[component]
fn PauseStrip(line: PauseLine) -> Element {
    let dash = use_context::<Dash>();
    let active = use_page_active();
    let mut now = use_signal(now_ms);
    let next = line.next_attempt;
    use_resource(move || {
        let shown = active();
        async move {
            while shown && next.is_some() {
                now.set(now_ms());
                tokio::time::sleep(Duration::from_millis(1_000)).await;
            }
        }
    });
    let body = match (pause_key(&line), next) {
        (key @ NEXT_ATTEMPT, Some(at)) => t!(key, wait = countdown(at, now())),
        (key, _) => t!(key),
    };
    let busy = dash.command.running();
    let retry = dash.clone();
    rsx! {
        div { class: "overflow-hidden",
            div { class: "c-swiss swiss-notice", role: "status", aria_live: "polite",
                span { class: "swiss-label swiss-notice-tag", {t!("ui.dashboard.pause.title")} }
                p { class: "swiss-notice-body", "{body}" }
                div { class: "swiss-confirm-actions",
                    button {
                        r#type: "button",
                        class: "swiss-confirm-yes",
                        disabled: busy,
                        onclick: move |_| retry.retry_now(),
                        {t!("ui.dashboard.pause.connect")}
                    }
                    super::always::LeaveButton { busy }
                }
            }
        }
    }
}

const NEXT_ATTEMPT: &str = "ui.dashboard.pause.nextAttempt";

/// The paused strip's line: «переподключается» only while something retries; with nothing
/// retrying by itself (auto-restart off) it asks for «Подключить» (fix-ks a3).
pub(super) fn pause_key(line: &PauseLine) -> &'static str {
    match (line.key_rejected, line.next_attempt) {
        (true, _) => "ui.dashboard.pause.keyRejected",
        (false, Some(_)) => NEXT_ATTEMPT,
        (false, None) if line.manual => "ui.dashboard.pause.manual",
        (false, None) => "ui.dashboard.pause.reconnecting",
    }
}

/// Another VPN carries all traffic while ours runs: a drop of ours pauses nothing.
#[component]
fn NoPauseNotice(name: String) -> Element {
    rsx! {
        div { class: "overflow-hidden",
            div { class: "c-swiss swiss-notice", role: "note",
                span { class: "swiss-label swiss-notice-tag",
                    {t!("ui.dashboard.noPause.title")}
                    ": {name}"
                }
                p { class: "swiss-notice-body", {t!("ui.dashboard.noPause.body")} }
            }
        }
    }
}

/// Another program took over the system proxy while our session holds it (another VPN client, a
/// policy): one calm line with «Вернуть» instead of fighting it silently (research killswitch 5.5).
#[component]
fn ProxyTakenStrip() -> Element {
    let dash = use_context::<Dash>();
    let busy = dash.reclaim.running();
    rsx! {
        div { class: "overflow-hidden",
            div { class: "c-swiss swiss-notice", role: "status", aria_live: "polite",
                span { class: "swiss-label swiss-notice-tag", {t!("ui.dashboard.proxyTaken.title")} }
                p { class: "swiss-notice-body", {t!("ui.dashboard.proxyTaken.body")} }
                div { class: "swiss-confirm-actions",
                    button {
                        r#type: "button",
                        class: "swiss-confirm-yes",
                        disabled: busy,
                        onclick: move |_| dash.reclaim_proxy(),
                        {t!("ui.dashboard.proxyTaken.restore")}
                    }
                }
            }
        }
    }
}

/// The automatic server choice's step: a quiet strip (it never claims a success it has not seen;
/// during the retries the body says whether traffic goes direct or is held) with «Отменить»,
/// which ends the step like any action of the user (RU-2026 item 8).
#[component]
fn PickStrip(title: String, body: Option<String>) -> Element {
    let dash = use_context::<Dash>();
    let busy = dash.snapshot().conn.cancelling;
    rsx! {
        div { class: "overflow-hidden",
            div { class: "c-swiss swiss-notice", role: "status", aria_live: "polite",
                span { class: "swiss-label swiss-notice-tag", "{title}" }
                if let Some(body) = body {
                    p { class: "swiss-notice-body", "{body}" }
                }
                div { class: "swiss-confirm-actions",
                    button {
                        r#type: "button",
                        class: "swiss-confirm-no",
                        disabled: busy,
                        onclick: move |_| dash.stop_autopick(),
                        {t!("ui.dashboard.pick.cancel")}
                    }
                }
            }
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
