//! «Расширенный режим» (the switch + «Пройти мастер заново», U-20), «Расширенные параметры»
//! (only while the draft has advanced mode on) and «Логи и диагностика».
use dioxus::prelude::*;

use super::fmt::size_text;
use super::model::{
    BootstrapRouteMode, CAPTURE_MAX_MB, CAPTURE_QUOTA_MB, CHECK_INTERVAL_SECS, DiagnosticsExport,
    ProxyKind,
};
use super::{ActionError, toast, use_api, use_ctx};
use crate::lang::tr;
use crate::t;
use crate::widgets::{
    Button, ButtonKind, ConfirmDialog, NumberInput, Panel, Row, Select, SelectOption, Switch,
    TextInput, ToastKind, UiError, use_job,
};

#[component]
pub(super) fn AdvancedMode() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let view = ctx.view();
    let job = use_job::<()>();
    let wizard = move |_| {
        let api = api.clone();
        job.start(move |_| async move { api.open_wizard().await });
    };
    let error = match job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    rsx! {
        Panel { title: t!("settings.advancedMode"), id: "set-advanced-mode",
            Switch {
                label: t!("settings.advancedMode"),
                hint: t!("ui.settings.advanced.modeHint"),
                checked: view.advanced_mode,
                on_change: move |on| ctx.edit(|p| p.advanced_mode = Some(on)),
            }
            div { class: "w-row",
                div { class: "w-row-text",
                    span { class: "w-row-label", {t!("ui.settings.advanced.wizard")} }
                    p { class: "w-row-hint", {t!("ui.settings.advanced.wizardHint")} }
                }
                div { class: "w-row-control",
                    Button { kind: ButtonKind::Ghost, small: true, busy: job.running(), onclick: wizard,
                        {t!("ui.settings.advanced.wizardOpen")}
                    }
                }
            }
            ActionError { error }
        }
    }
}

#[component]
pub(super) fn AdvancedParams() -> Element {
    let ctx = use_ctx();
    let view = ctx.view();
    let credentials = ctx.state.read().proxy_credentials_saved;
    let proxy_hint = if credentials {
        format!(
            "{} {}",
            t!("ui.settings.advanced.proxyHint"),
            t!("ui.settings.advanced.proxyCredentials")
        )
    } else {
        t!("ui.settings.advanced.proxyHint")
    };
    let types = vec![
        SelectOption::new(ProxyKind::Socks5, "SOCKS5"),
        SelectOption::new(ProxyKind::Http, "HTTP"),
    ];
    let routes = vec![
        SelectOption::new(
            BootstrapRouteMode::Auto,
            t!("ui.settings.advanced.bootstrapAuto"),
        ),
        SelectOption::new(
            BootstrapRouteMode::Direct,
            t!("ui.settings.advanced.bootstrapDirect"),
        ),
        SelectOption::new(
            BootstrapRouteMode::LocalProxy,
            t!("ui.settings.advanced.bootstrapProxy"),
        ),
    ];
    rsx! {
        Panel { title: t!("ui.settings.advanced.title"), id: "set-advanced",
            Row { label: t!("ui.settings.advanced.proxy"), hint: proxy_hint,
                TextInput {
                    value: view.proxy_override.clone(),
                    oninput: move |v: String| ctx.edit(|p| p.proxy_override = Some(v)),
                    placeholder: t!("ui.settings.advanced.proxyPlaceholder"),
                    mono: true,
                    maxlength: 512u32,
                }
            }
            Row { label: t!("ui.settings.advanced.proxyType"),
                Select {
                    options: types,
                    value: Some(view.proxy_type),
                    on_change: move |kind| ctx.edit(|p| p.proxy_type = Some(kind)),
                }
            }
            Row { label: t!("ui.settings.advanced.bootstrap"), hint: t!("ui.settings.advanced.bootstrapHint"),
                Select {
                    options: routes,
                    value: Some(view.bootstrap_route_mode),
                    on_change: move |mode| ctx.edit(|p| p.bootstrap_route_mode = Some(mode)),
                }
            }
            Row { label: t!("ui.settings.advanced.checkInterval"),
                NumberInput {
                    value: i64::from(view.check_interval_ms / 1000),
                    min: CHECK_INTERVAL_SECS.0,
                    max: CHECK_INTERVAL_SECS.1,
                    unit: t!("ui.settings.units.sec"),
                    on_commit: move |secs: i64| {
                        let ms = u32::try_from(secs * 1000).unwrap_or(30_000);
                        ctx.edit(|p| p.check_interval_ms = Some(ms));
                    },
                }
            }
            Switch {
                label: t!("ui.settings.advanced.fallback"),
                hint: t!("ui.settings.advanced.fallbackHint"),
                checked: view.adaptive_bypass_server_fallback,
                on_change: move |on| ctx.edit(|p| p.adaptive_bypass_server_fallback = Some(on)),
            }
            Capture {}
        }
    }
}

/// Packet capture: enabling asks once (owner 10.6 B); size limit, disk quota, used space and
/// «Очистить захваты» (instant, confirmed).
#[component]
fn Capture() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let view = ctx.view();
    let clear_job = use_job::<()>();
    let mut consent_open = use_signal(|| false);
    let mut clear_open = use_signal(|| false);
    let (consented, used) = {
        let state = ctx.state.read();
        (state.capture_consent_given, state.capture_used_bytes)
    };
    let toggle = move |on: bool| {
        if on && !consented {
            consent_open.set(true);
        } else {
            ctx.edit(|p| p.deep_inspection = Some(on));
        }
    };
    let clear = move |()| {
        let api = api.clone();
        clear_job.start(move |_| async move {
            let result = api.clear_captures().await;
            clear_open.set(false);
            result
        });
    };
    let error = match clear_job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    let off = !view.deep_inspection;
    rsx! {
        div { class: "set-subgroup", role: "group", aria_label: t!("ui.settings.capture.title"),
            Switch {
                label: t!("ui.settings.capture.title"),
                hint: t!("ui.settings.capture.hint"),
                checked: view.deep_inspection,
                on_change: toggle,
            }
            Row { label: t!("ui.settings.capture.maxSize"), hint: t!("ui.settings.capture.maxSizeHint"),
                NumberInput {
                    value: i64::from(view.deep_inspection_max_mb),
                    min: CAPTURE_MAX_MB.0,
                    max: CAPTURE_MAX_MB.1,
                    step: 64,
                    unit: t!("ui.settings.units.mbShort"),
                    disabled: off,
                    on_commit: move |mb: i64| {
                        let mb = u32::try_from(mb).unwrap_or(512);
                        ctx.edit(|p| p.deep_inspection_max_mb = Some(mb));
                    },
                }
            }
            Row { label: t!("ui.settings.capture.quota"), hint: t!("ui.settings.capture.quotaHint"),
                NumberInput {
                    value: i64::from(view.capture_quota_mb),
                    min: CAPTURE_QUOTA_MB.0,
                    max: CAPTURE_QUOTA_MB.1,
                    step: 1024,
                    unit: t!("ui.settings.units.mbShort"),
                    disabled: off,
                    on_commit: move |mb: i64| {
                        let mb = u32::try_from(mb).unwrap_or(8192);
                        ctx.edit(|p| p.capture_quota_mb = Some(mb));
                    },
                }
            }
            div { class: "set-status-line",
                p { class: "set-status-text", role: "status",
                    match used {
                        Some(bytes) => t!("ui.settings.capture.used", size = size_text(bytes)),
                        None => t!("ui.settings.capture.usedUnknown"),
                    }
                }
                div { class: "set-status-actions",
                    Button {
                        kind: ButtonKind::Link,
                        busy: clear_job.running(),
                        disabled: used == Some(0),
                        onclick: move |_| clear_open.set(true),
                        {t!("ui.settings.capture.clear")}
                    }
                }
            }
            ActionError { error }
            ConfirmDialog {
                open: consent_open(),
                title: t!("ui.settings.capture.consentTitle"),
                message: t!("ui.settings.capture.consentText"),
                confirm_label: t!("ui.settings.capture.consentOk"),
                cancel_label: t!("common.cancel"),
                on_confirm: move |()| {
                    consent_open.set(false);
                    ctx.edit(|p| p.deep_inspection = Some(true));
                },
                on_cancel: move |()| consent_open.set(false),
            }
            ConfirmDialog {
                open: clear_open(),
                title: t!("ui.settings.capture.clearTitle"),
                message: t!("ui.settings.capture.clearText"),
                confirm_label: t!("ui.settings.capture.clear"),
                cancel_label: t!("common.cancel"),
                danger: true,
                busy: clear_job.running(),
                on_confirm: clear,
                on_cancel: move |()| clear_open.set(false),
            }
        }
    }
}

/// The text of a failed diagnostics export (§3.8; permission adds the folder advice).
pub(super) fn export_error_text(err: &UiError) -> String {
    let base = t!("ui.settings.tools.exportFailed", reason = tr(&err.msg));
    if err.kind == vpnte_base::ErrorKind::Permission {
        format!("{base} {}", t!("ui.settings.tools.exportFolderAdvice"))
    } else {
        base
    }
}

#[component]
pub(super) fn Tools() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let folder_job = use_job::<()>();
    let export_job = use_job::<DiagnosticsExport>();
    let running_elsewhere = ctx.state.read().diagnostics_export_running;
    let folder_api = api.clone();
    let open_folder = move |_| {
        let api = folder_api.clone();
        folder_job.start(move |_| async move { api.open_logs_folder().await });
    };
    let export = move |_| {
        if running_elsewhere {
            return;
        }
        let api = api.clone();
        export_job.start(move |_| async move {
            tracing::info!(target: "ui", "collecting the diagnostics archive");
            let result = api.export_diagnostics().await;
            match &result {
                Ok(done) => {
                    tracing::info!(target: "ui", cleanup_failed = done.cleanup_failed, "diagnostics archive created");
                    if done.cleanup_failed {
                        toast(
                            ToastKind::Warning,
                            t!("ui.settings.tools.cleanupFailed"),
                            Some(t!("ui.settings.tools.cleanupFailedBody")),
                        );
                    }
                }
                Err(err) if err.kind == vpnte_base::ErrorKind::Cancelled => {
                    tracing::info!(target: "ui", "diagnostics export cancelled by the user");
                }
                Err(err) => tracing::error!(target: "ui", error = %err, "diagnostics export failed"),
            }
            result
        });
    };
    let busy = export_job.running() || running_elsewhere;
    let folder_error = match folder_job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    rsx! {
        Panel { title: t!("ui.settings.tools.title"), id: "set-tools",
            p { class: "set-hint", {t!("ui.settings.tools.hint")} }
            div { class: "set-form-actions",
                Button { kind: ButtonKind::Ghost, busy: folder_job.running(), onclick: open_folder,
                    {t!("ui.settings.tools.openLogs")}
                }
                Button { kind: ButtonKind::Ghost, busy, onclick: export,
                    {t!("ui.settings.tools.export")}
                }
            }
            ActionError { error: folder_error }
            match export_job.last() {
                Some(Ok(done)) => rsx! {
                    p { class: "set-result", role: "status", {t!("ui.settings.tools.exported", path = done.path)} }
                },
                Some(Err(err)) => rsx! {
                    p { class: "set-error", role: "alert", {export_error_text(&err)} }
                },
                None => rsx! {},
            }
        }
    }
}
