//! «Данные старой версии»: the old Electron data directory, keys still to import, corrupt
//! documents opened read-only and unfinished network cleanup of the old version (storage B9,
//! B16, secrets-only pass; firewall-recovery §6.6).
use dioxus::prelude::*;

use super::ctl::Controller;
use super::model::LegacyView;
use super::view::{Mark, OutcomeLine, fmt_bytes};
use crate::lang::tr;
use crate::t;
use crate::widgets::{Button, ButtonKind, Panel};
use vpnte_base::types::Verdict;

/// The legacy panel; `on_delete` asks for confirmation first.
#[component]
pub(crate) fn LegacyPanel(ctl: Controller, on_delete: EventHandler<()>) -> Element {
    let legacy: LegacyView = ctl.state.read().legacy.clone();
    let busy = ctl.legacy.running();
    let nothing = legacy.data_dir.is_none()
        && !legacy.secrets_pending
        && legacy.corrupt.is_empty()
        && legacy.cleanup_failures.is_empty();
    rsx! {
        Panel { title: t!("ui.maintenance.legacy.title"), id: "mt-legacy",
            if nothing {
                p { class: "mt-quiet", {t!("ui.maintenance.legacy.none")} }
            }
            if let Some(dir) = &legacy.data_dir {
                div { class: "mt-block", "data-block": "legacy-dir",
                    p { class: "mt-line",
                        Mark { verdict: Some(if dir.plaintext_files > 0 { Verdict::Warn } else { Verdict::Ok }) }
                        span {
                            {t!("ui.maintenance.legacy.dir")}
                            " "
                            span { class: "swiss-mono mt-path", "{dir.path}" }
                            if let Some(bytes) = dir.bytes {
                                " · "
                                {tr(&fmt_bytes(bytes))}
                            }
                        }
                    }
                    if dir.plaintext_files > 0 {
                        p { class: "mt-warning",
                            {t!("ui.maintenance.legacy.plaintext", count = dir.plaintext_files)}
                        }
                    }
                    // Deleting the folder while keys still wait there would lose them.
                    if legacy.secrets_pending {
                        p { class: "mt-hint", {t!("ui.maintenance.legacy.deleteBlocked")} }
                    } else {
                        p { class: "mt-hint", {t!("ui.maintenance.legacy.deleteHint")} }
                    }
                    div { class: "mt-actions",
                        Button {
                            kind: ButtonKind::Danger,
                            disabled: busy || legacy.secrets_pending,
                            disabled_reason: t!("ui.maintenance.legacy.deleteBlocked"),
                            onclick: move |_| on_delete.call(()),
                            {t!("ui.maintenance.legacy.delete")}
                        }
                    }
                }
            }
            if legacy.secrets_pending {
                div { class: "mt-block", "data-block": "legacy-secrets",
                    p { class: "mt-warning", {t!("ui.maintenance.legacy.secretsPending")} }
                    div { class: "mt-actions",
                        Button {
                            kind: ButtonKind::Ghost,
                            busy,
                            onclick: move |_| ctl.retry_secrets(),
                            {t!("ui.maintenance.legacy.retrySecrets")}
                        }
                    }
                }
            }
            for store in legacy.corrupt.clone() {
                div { key: "{store.id}", class: "mt-block", "data-block": "legacy-corrupt",
                    p { class: "mt-warning",
                        {t!("ui.maintenance.legacy.corrupt", name = tr(&store.name))}
                        " "
                        span { class: "swiss-mono mt-path", "{store.file}" }
                    }
                    div { class: "mt-actions",
                        Button {
                            kind: ButtonKind::Ghost,
                            disabled: busy,
                            onclick: move |_| ctl.set_aside(store.id.clone()),
                            {t!("ui.maintenance.legacy.setAside")}
                        }
                    }
                }
            }
            if !legacy.cleanup_failures.is_empty() {
                div { class: "mt-block", "data-block": "legacy-cleanup",
                    p { class: "mt-warning", {t!("ui.maintenance.legacy.cleanupIncomplete")} }
                    ul { class: "mt-lines",
                        for (i , failure) in legacy.cleanup_failures.iter().enumerate() {
                            li { key: "{i}", class: "mt-line",
                                Mark { verdict: Some(Verdict::Fail) }
                                span { {tr(failure)} }
                            }
                        }
                    }
                    p { class: "mt-hint", {t!("ui.maintenance.legacy.cleanupHint")} }
                }
            }
            OutcomeLine { outcome: ctl.legacy_outcome.read().clone() }
        }
    }
}
