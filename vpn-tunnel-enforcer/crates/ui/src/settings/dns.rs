//! «DNS-профили» (instant): the explicit automatic entry first (routing-dns B-DNS-2), then the
//! built-in and the user's profiles; create with validation on blur, delete, select. The
//! secondary address is not offered: sing-box never uses it (B-DNS-9).
use dioxus::prelude::*;

use super::model::{DnsKind, DnsProfileView};
use super::{ActionError, use_api, use_ctx};
use crate::lang::tr;
use crate::t;
use crate::widgets::{
    Badge, Button, ButtonKind, Field, IconButton, IconGlyph, Panel, TextInput, Tone, UiError,
    use_job,
};

fn kind_badge(kind: DnsKind) -> (Tone, String) {
    match kind {
        DnsKind::Plain => (Tone::Neutral, t!("settings.dnsTypePlain")),
        DnsKind::Doh => (Tone::Ok, t!("settings.dnsTypeDoh")),
        DnsKind::Dot => (Tone::Warn, t!("settings.dnsTypeDot")),
    }
}

#[component]
pub(super) fn Dns() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let select_job = use_job::<()>();
    let delete_job = use_job::<()>();
    let dns = ctx.dns.read().clone();
    let busy = select_job.running();
    let select_api = api.clone();
    let select = use_callback(move |id: Option<String>| {
        let api = select_api.clone();
        select_job.start(move |_| async move { api.select_dns(id).await });
    });
    let select_error = match select_job.last() {
        Some(Err(err)) => Some(UiError {
            kind: err.kind,
            msg: vpnte_base::Msg::new("ui.settings.dns.selectFailed").arg("reason", tr(&err.msg)),
        }),
        _ => None,
    };
    let delete_error = match delete_job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    rsx! {
        Panel { title: t!("settings.dns"), id: "set-dns",
            p { class: "set-hint", {t!("settings.dnsDescription")} }
            div { class: "set-radios", role: "radiogroup", aria_label: t!("settings.dnsActiveProfile"),
                aria_busy: busy.then_some("true"),
                DnsEntry {
                    name: t!("ui.settings.dns.auto"),
                    detail: t!("ui.settings.dns.autoHint"),
                    checked: dns.active.is_none(),
                    busy,
                    on_select: move |()| select.call(None),
                }
                for profile in dns.profiles.iter().cloned() {
                    DnsRow {
                        key: "{profile.id}",
                        checked: dns.active.as_deref() == Some(profile.id.as_str()),
                        busy,
                        profile: profile.clone(),
                        on_select: move |id: String| select.call(Some(id)),
                        on_delete: {
                            let api = api.clone();
                            move |id: String| {
                                let api = api.clone();
                                delete_job.start(move |_| async move { api.delete_dns(id).await });
                            }
                        },
                        deleting: delete_job.running(),
                    }
                }
            }
            ActionError { error: select_error }
            ActionError { error: delete_error }
            CreateDns {}
        }
    }
}

/// One choice (also the automatic entry). A `role=radio` button rather than a native radio: the
/// check mark always shows the pushed selection, also after a refused switch (a native radio
/// would keep the clicked one checked).
#[component]
fn DnsEntry(
    name: String,
    detail: String,
    checked: bool,
    busy: bool,
    on_select: EventHandler<()>,
    #[props(default = VNode::empty())] badges: Element,
) -> Element {
    rsx! {
        button {
            r#type: "button",
            class: "set-radio-line",
            class: if checked { "is-on" },
            role: "radio",
            aria_checked: if checked { "true" } else { "false" },
            aria_disabled: busy.then_some("true"),
            onclick: move |_| {
                if !busy {
                    on_select.call(());
                }
            },
            span { class: "set-radio-mark", aria_hidden: "true" }
            span { class: "set-radio-text",
                span { class: "set-radio-name", "{name}" {badges} }
                span { class: "set-radio-detail swiss-mono", "{detail}" }
            }
        }
    }
}
#[component]
fn DnsRow(
    profile: DnsProfileView,
    checked: bool,
    busy: bool,
    deleting: bool,
    on_select: EventHandler<String>,
    on_delete: EventHandler<String>,
) -> Element {
    let (tone, kind) = kind_badge(profile.kind);
    let id = profile.id.clone();
    let delete_id = profile.id.clone();
    rsx! {
        div { class: "set-radio-row",
            DnsEntry {
                name: profile.name.clone(),
                detail: profile.address.clone(),
                checked,
                busy,
                on_select: move |()| on_select.call(id.clone()),
                badges: rsx! {
                    Badge { tone, "{kind}" }
                    if profile.builtin {
                        Badge { tone: Tone::Neutral, {t!("settings.dnsBuiltin")} }
                    }
                },
            }
            if !profile.builtin {
                IconButton {
                    glyph: IconGlyph::Trash,
                    label: format!("{} {}", t!("settings.dnsDelete"), profile.name),
                    danger: true,
                    disabled: deleting,
                    onclick: move |_| on_delete.call(delete_id.clone()),
                }
            }
        }
    }
}

/// The create form: the address is checked when the field loses focus (the detected type is
/// shown, or why it is not usable); typing clears the verdict.
#[component]
fn CreateDns() -> Element {
    let api = use_api();
    let check_job = use_job::<DnsKind>();
    let create_job = use_job::<()>();
    let mut name = use_signal(String::new);
    let mut address = use_signal(String::new);
    let check_api = api.clone();
    let check = move |_| {
        let addr = address.peek().trim().to_owned();
        if addr.is_empty() {
            check_job.clear();
            return;
        }
        let api = check_api.clone();
        check_job.start(move |_| async move { api.validate_dns(addr).await });
    };
    let checked = check_job.last();
    let address_error = match &checked {
        Some(Err(err)) => Some(tr(&err.msg)),
        _ => None,
    };
    let can_create = !name().trim().is_empty()
        && !address().trim().is_empty()
        && address_error.is_none()
        && !create_job.running();
    let create = move |_| {
        let (n, a) = (
            name.peek().trim().to_owned(),
            address.peek().trim().to_owned(),
        );
        let api = api.clone();
        create_job.start(move |_| async move {
            api.create_dns(n, a).await?;
            name.set(String::new());
            address.set(String::new());
            check_job.clear();
            Ok(())
        });
    };
    let create_error = match create_job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    rsx! {
        div { class: "set-form", role: "group", aria_label: t!("settings.dnsCreateCustom"),
            p { class: "set-form-title", {t!("settings.dnsCreateCustom")} }
            div { class: "set-form-grid",
                Field { label: t!("settings.dnsProfileName"),
                    TextInput {
                        value: name(),
                        oninput: move |v| name.set(v),
                        placeholder: t!("settings.dnsProfileNamePlaceholder"),
                        maxlength: 120u32,
                    }
                }
                Field {
                    label: t!("ui.settings.dns.address"),
                    hint: t!("ui.settings.dns.addressHint"),
                    error: address_error,
                    div { class: "set-input-with", onfocusout: check,
                        TextInput {
                            value: address(),
                            oninput: move |v| {
                                address.set(v);
                                check_job.clear();
                            },
                            placeholder: t!("settings.dnsPrimaryPlaceholder"),
                            mono: true,
                            maxlength: 2048u32,
                        }
                        if check_job.running() {
                            span { class: "set-hint", {t!("settings.dnsValidating")} }
                        } else if let Some(Ok(kind)) = checked {
                            {
                                let (tone, text) = kind_badge(kind);
                                rsx! { Badge { tone, "{text}" } }
                            }
                        }
                    }
                }
            }
            ActionError { error: create_error }
            div { class: "set-form-actions",
                Button {
                    kind: ButtonKind::Primary,
                    small: true,
                    busy: create_job.running(),
                    disabled: !can_create,
                    onclick: create,
                    {t!("settings.dnsCreate")}
                }
            }
        }
    }
}
