//! "Always" on the start page (ks-d, research killswitch §5.2-5.4): the paused state's second
//! button reads «Выключить «Всегда»» and switches the level to "If the VPN drops", and another
//! full-tunnel VPN gets one calm line offering to let its program through. Both read the
//! kill-switch view of the Settings backend in context (the app provides it at the root; without
//! it, as in the demo, "Always" never shows here).
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use dioxus::prelude::*;
use tokio::sync::watch;

use super::Dash;
use crate::hooks::use_watch;
use crate::settings::{ExceptionKind, KillSwitchLevel, KillSwitchView, SettingsApi};
use crate::t;
use crate::widgets::use_job;

thread_local! {
    /// Foreign VPNs whose program was let through in this run: offered once.
    static ALLOWED: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
}

/// The Settings backend in context and whether "Always" is in force.
fn use_always() -> (Option<Rc<dyn SettingsApi>>, bool) {
    let api = try_use_context::<Rc<dyn SettingsApi>>();
    let source = api.clone();
    let kill = use_watch(move || match source {
        Some(api) => api.kill_switch(),
        None => watch::channel(KillSwitchView::default()).1,
    });
    let always = always_in_force(&kill.read());
    (api, always)
}

/// "Always" is chosen and kept here (the helper service holds it); a stored "Always" without
/// the service works as "If the VPN drops", where «Продолжить без VPN» gives the internet back.
fn always_in_force(kill: &KillSwitchView) -> bool {
    kill.level == KillSwitchLevel::Strict && kill.always_available
}

/// The paused state's second button: «Продолжить без VPN» (a disconnect gives the internet
/// back), or in "Always", which blocks without a session too, «Выключить «Всегда»»: the level
/// goes to "If the VPN drops" and the pause then offers «Продолжить без VPN».
#[component]
pub(super) fn LeaveButton(busy: bool) -> Element {
    let dash = use_context::<Dash>();
    let (api, always) = use_always();
    let job = use_job::<()>();
    let Some(api) = api.filter(|_| always) else {
        return rsx! {
            button {
                r#type: "button",
                class: "swiss-confirm-no",
                disabled: busy,
                onclick: move |_| dash.continue_without_vpn(),
                {t!("ui.dashboard.pause.continue")}
            }
        };
    };
    rsx! {
        button {
            r#type: "button",
            class: "swiss-confirm-no",
            disabled: busy || job.running(),
            onclick: move |_| {
                let (api, dash) = (api.clone(), dash.clone());
                job.start(move |_| async move {
                    if let Err(err) = api.set_kill_switch_level(KillSwitchLevel::Standard).await {
                        dash.fail(t!("ui.dashboard.pause.turnOffAlwaysFailed"), &err);
                    }
                    Ok(())
                });
            },
            {t!("ui.dashboard.pause.turnOffAlways")}
        }
    }
}

/// Another full-tunnel VPN while "Always" blocks everything outside ours: its program cannot
/// reach its server. One calm line offers to let it through (the user picks the program, which
/// joins the exceptions); once done it is not offered again in this run.
#[component]
pub(super) fn AllowVpnOffer(name: String) -> Element {
    let dash = use_context::<Dash>();
    let (api, always) = use_always();
    let job = use_job::<()>();
    let allowed = ALLOWED.with(|a| a.borrow().contains(&name));
    let Some(api) = api.filter(|_| always && !allowed) else {
        return rsx! {};
    };
    rsx! {
        div { class: "overflow-hidden",
            div { class: "c-swiss swiss-notice", role: "note",
                p { class: "swiss-notice-body", {t!("ui.dashboard.allowVpn.body")} }
                div { class: "swiss-confirm-actions",
                    button {
                        r#type: "button",
                        class: "swiss-confirm-yes",
                        disabled: job.running(),
                        onclick: move |_| {
                            let (api, dash, name) = (api.clone(), dash.clone(), name.clone());
                            job.start(move |_| async move {
                                if let Err(err) = allow(&api, &dash, name).await {
                                    dash.fail(t!("ui.dashboard.allowVpn.failed"), &err);
                                }
                                Ok(())
                            });
                        },
                        {t!("ui.dashboard.allowVpn.pick")}
                    }
                }
            }
        }
    }
}

/// Picks the program and adds it to the exceptions; a cancelled pick changes nothing.
async fn allow(api: &Rc<dyn SettingsApi>, dash: &Dash, vpn: String) -> vpnte_base::AppResult<()> {
    let Some(app) = api.pick_app().await? else {
        return Ok(());
    };
    api.add_exception(ExceptionKind::App, app.path, app.name.clone())
        .await?;
    ALLOWED.with(|a| a.borrow_mut().insert(vpn));
    let added = t!("ui.dashboard.allowVpn.added");
    dash.toasts.success(added, Some(app.name));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ks-d (research killswitch §5.2): «Выключить «Всегда»» only where "Always" really holds.
    #[test]
    fn the_always_button_needs_always_in_force() {
        let view = |level, always_available| KillSwitchView {
            level,
            always_available,
            ..KillSwitchView::default()
        };
        assert!(always_in_force(&view(KillSwitchLevel::Strict, true)));
        assert!(!always_in_force(&view(KillSwitchLevel::Strict, false)));
        assert!(!always_in_force(&view(KillSwitchLevel::Standard, true)));
        assert!(!always_in_force(&view(KillSwitchLevel::Off, true)));
    }
}
