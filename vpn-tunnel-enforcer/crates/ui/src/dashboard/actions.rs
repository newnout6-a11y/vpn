//! What the page's controls do: the power button rule, the cancel button,
//! Smart RU, the leak check, copying the exit address and the kill-switch banner's buttons.
//! Results go to the toast queue and the mascot; the new state arrives with the next snapshot.
use std::net::IpAddr;
use std::time::{Duration, Instant};

use dioxus::prelude::*;
use vpnte_base::types::Verdict;
use vpnte_view::mascot::MascotEvent;

use super::Dash;
use super::model::{COPIED_MS, PowerAction, power_click};
use crate::lang::tr;
use crate::t;

impl Dash {
    /// A press of the power button (a click, or Ctrl+Enter through `dashboard.js`).
    pub(super) fn press_power(&self) {
        match power_click(&self.conn(), self.command.running()) {
            PowerAction::Connect => self.connect(),
            PowerAction::Disconnect => self.disconnect(),
            PowerAction::Ignore => {}
        }
    }

    fn connect(&self) {
        let (api, dash) = (self.api.clone(), self.clone());
        self.command.start(move |_| async move {
            if let Err(err) = api.connect().await {
                dash.fail(t!("dashboard.connectionError"), &err);
            }
            Ok(())
        });
    }

    fn disconnect(&self) {
        let (api, dash) = (self.api.clone(), self.clone());
        self.command.start(move |_| async move {
            match api.disconnect().await {
                Ok(Some(warning)) => {
                    dash.toasts
                        .warning(t!("ui.dashboard.offWithWarnings"), Some(tr(&warning)));
                }
                Ok(None) => {}
                Err(err) => dash.fail(t!("dashboard.connectionError"), &err),
            }
            Ok(())
        });
    }

    /// «Отменить подключение» / «Отменить смену сервера». A connect cancel reports its outcome; a
    /// switch cancel is acknowledged and the state shows «Отменяем…» until the old server is back.
    pub(super) fn cancel_transition(&self) {
        let conn = self.conn();
        if !conn.circle_busy() || conn.cancelling {
            return;
        }
        let switch = conn.switching.is_some();
        let (api, dash) = (self.api.clone(), self.clone());
        self.cancel.start(move |_| async move {
            match api.cancel().await {
                Ok(_) if switch => {}
                Ok(Some(warning)) => {
                    dash.toasts
                        .warning(t!("dashboard.cancelledWithWarnings"), Some(tr(&warning)));
                }
                Ok(None) => {
                    dash.toasts.info(t!("dashboard.connectionCancelled"), None);
                }
                Err(err) => dash.fail(t!("dashboard.cancelFailed"), &err),
            }
            Ok(())
        });
    }

    /// The Smart RU toggle: saved at once, applied on the next connect. Only a saved change gets
    /// the mascot's comment.
    pub(super) fn toggle_smart(&self) {
        let next = !self.view.peek().smart_ru;
        let (api, dash) = (self.api.clone(), self.clone());
        self.smart.start(move |_| async move {
            match api.set_smart_ru(next).await {
                Ok(()) => dash.bus.send(if next {
                    MascotEvent::SmartOn
                } else {
                    MascotEvent::SmartOff
                }),
                Err(err) => dash.fail(t!("swiss.smartSaveFailed"), &err),
            }
            Ok(())
        });
    }

    /// «проверить»: the route / leak check; the mascot sniffs, then reacts to the verdict.
    pub(super) fn check_leaks(&self) {
        if self.leak.running() {
            return;
        }
        self.bus.send(MascotEvent::LeakStart);
        let (api, dash) = (self.api.clone(), self.clone());
        self.leak.start(move |_| async move {
            match api.run_leak_check().await {
                Ok(verdict) => dash.bus.send(match verdict {
                    Verdict::Ok => MascotEvent::LeakOk,
                    Verdict::Fail => MascotEvent::LeakFail,
                    Verdict::Warn | Verdict::NotChecked => MascotEvent::LeakWarn,
                }),
                Err(err) => {
                    let message = tr(&err.user_msg());
                    if err.kind != vpnte_base::ErrorKind::Cancelled {
                        tracing::warn!(error = %err, "leak check failed");
                        dash.toasts
                            .error(t!("dashboard.routeCheckFailed", message = message), None);
                    }
                }
            }
            Ok(())
        });
    }

    /// Copies the exit address; «скопировано» only after the clipboard took it.
    pub(super) fn copy_ip(&self, ip: IpAddr) {
        let (api, mut copied) = (self.api.clone(), self.copied);
        spawn(async move {
            if let Err(err) = api.copy_ip(ip).await {
                tracing::warn!(error = %err, "copying the exit address failed");
                return;
            }
            let at = Instant::now();
            copied.set(Some(at));
            tokio::time::sleep(Duration::from_millis(COPIED_MS)).await;
            if *copied.peek() == Some(at) {
                copied.set(None);
            }
        });
    }

    /// «Проверить снова» on the kill-switch banner.
    pub(super) fn recheck_firewall(&self) {
        let (api, dash) = (self.api.clone(), self.clone());
        self.recheck.start(move |_| async move {
            if let Err(err) = api.recheck_firewall().await {
                dash.fail(t!("ui.dashboard.recheckFailed"), &err);
            }
            Ok(())
        });
    }

    /// «Снять блокировку» on the kill-switch banner.
    pub(super) fn release_kill_switch(&self) {
        let (api, dash) = (self.api.clone(), self.clone());
        self.release.start(move |_| async move {
            if let Err(err) = api.release_kill_switch().await {
                dash.fail(t!("ui.dashboard.releaseFailed"), &err);
            }
            Ok(())
        });
    }

    /// «Подключить» in the paused state: the paused session retries at once.
    pub(super) fn retry_now(&self) {
        let (api, dash) = (self.api.clone(), self.clone());
        self.command.start(move |_| async move {
            if let Err(err) = api.retry_now().await {
                dash.fail(t!("dashboard.connectionError"), &err);
            }
            Ok(())
        });
    }

    /// «Продолжить без VPN» in the paused state: a disconnect, the internet is back at once.
    pub(super) fn continue_without_vpn(&self) {
        self.disconnect();
    }
}
