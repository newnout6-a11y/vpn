//! What the page's controls do: the power button rule, the confirmation timer, the cancel button,
//! Smart RU, the leak check, copying the exit address and the kill-switch banner's buttons.
//! Results go to the toast queue and the mascot; the new state arrives with the next snapshot.
use std::net::IpAddr;
use std::time::{Duration, Instant};

use dioxus::prelude::*;
use vpnte_base::types::Verdict;
use vpnte_view::mascot::MascotEvent;

use super::Dash;
use super::model::{CONFIRM_TTL_MS, COPIED_MS, Hold, PowerAction, power_click};
use crate::lang::tr;
use crate::t;

/// Moves the focus to the power button (after the confirmation row it was in went away).
const FOCUS_POWER_JS: &str = "document.querySelector('.swiss-skin .swiss-power')?.focus()";

impl Dash {
    /// A press of the power button (a click, or Ctrl+Enter through `dashboard.js`).
    pub(super) fn press_power(&self) {
        let conn = self.conn();
        let open = self.confirm.peek().is_open();
        match power_click(&conn, open, self.command.running()) {
            PowerAction::AskConfirm => {
                let mut confirm = self.confirm;
                let generation = confirm.write().open();
                self.arm_confirm(generation);
            }
            PowerAction::Connect => self.connect(),
            PowerAction::Disconnect => self.disconnect(),
            PowerAction::Ignore => {}
        }
    }

    /// «Да, отключить»: disconnects unless the state moved on meanwhile (then it only closes).
    pub(super) fn confirm_yes(&self) {
        let conn = self.conn();
        if power_click(&conn, true, self.command.running()) == PowerAction::Disconnect {
            self.disconnect();
        } else {
            let mut confirm = self.confirm;
            confirm.write().close();
        }
    }

    /// «Отмена»: the row goes away, the focus goes back to the power button.
    pub(super) fn confirm_no(&self) {
        let mut confirm = self.confirm;
        confirm.write().close();
        let _ = document::eval(FOCUS_POWER_JS);
    }

    /// Pointer / focus over the confirmation row holds its timer.
    pub(super) fn hold_confirm(&self, by: Hold, on: bool) {
        let mut confirm = self.confirm;
        let rearm = confirm.write().hold(by, on);
        if let Some(generation) = rearm {
            self.arm_confirm(generation);
        }
    }

    fn arm_confirm(&self, generation: u64) {
        let mut confirm = self.confirm;
        spawn(async move {
            tokio::time::sleep(Duration::from_millis(CONFIRM_TTL_MS)).await;
            confirm.write().expire(generation);
        });
    }

    fn connect(&self) {
        let mut confirm = self.confirm;
        confirm.write().close();
        let (api, dash) = (self.api.clone(), self.clone());
        self.command.start(move |_| async move {
            if let Err(err) = api.connect().await {
                dash.fail(t!("dashboard.connectionError"), &err);
            }
            Ok(())
        });
    }

    fn disconnect(&self) {
        let mut confirm = self.confirm;
        confirm.write().close();
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
        let mut confirm = self.confirm;
        confirm.write().close();
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
}
