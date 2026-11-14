//! «Поведение»: autostart (instant, read back from Windows), connect at launch (instant), and the
//! tray / autopilot / site metadata switches (draft).
use dioxus::prelude::*;

use super::{ActionError, use_api, use_ctx};
use crate::lang::tr;
use crate::t;
use crate::widgets::{Panel, Switch, UiError, use_job};

#[component]
pub(super) fn Behaviour() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let view = ctx.view();
    let job = use_job::<(bool, bool)>();
    let autostart = ctx.state.read().autostart;
    let set_autostart = move |on: bool| {
        let api = api.clone();
        job.start(move |_| async move {
            let actual = api.set_autostart(on).await?;
            tracing::info!(target: "ui", requested = on, actual, "autostart switched");
            Ok((on, actual))
        });
    };
    let error = match job.last() {
        Some(Err(err)) => Some(UiError {
            kind: err.kind,
            msg: vpnte_base::Msg::new("ui.settings.behaviour.autostartFailed")
                .arg("reason", tr(&err.msg)),
        }),
        _ => None,
    };
    let unconfirmed = matches!(job.last(), Some(Ok((wanted, actual))) if wanted != actual);
    rsx! {
        Panel { title: t!("ui.settings.behaviour.title"), id: "set-behaviour",
            Switch {
                label: t!("settings.autoStart"),
                hint: t!("ui.settings.behaviour.autostartHint"),
                checked: autostart,
                busy: job.running(),
                on_change: set_autostart,
            }
            ActionError { error }
            if unconfirmed {
                p { class: "set-result is-warn", role: "status", {t!("ui.settings.behaviour.autostartUnconfirmed")} }
            }
            Switch {
                label: t!("ui.settings.behaviour.tray"),
                hint: t!("ui.settings.behaviour.trayHint"),
                checked: view.minimize_to_tray,
                on_change: move |on| ctx.edit(|p| p.minimize_to_tray = Some(on)),
            }
            super::launch::Launch {}
            Switch {
                label: t!("ui.settings.behaviour.autopilot"),
                hint: t!("ui.settings.behaviour.autopilotHint"),
                checked: view.autopilot,
                on_change: move |on| ctx.edit(|p| p.autopilot = Some(on)),
            }
            Switch {
                label: t!("ui.settings.behaviour.enrichment"),
                hint: t!("ui.settings.behaviour.enrichmentHint"),
                checked: view.domain_enrichment,
                on_change: move |on| ctx.edit(|p| p.domain_enrichment = Some(on)),
            }
        }
    }
}
